"""Authentication: credential login, identity-token validation and revocation.

Identity tokens are short-lived bearer tokens. On every request the gateway
re-validates the token *and* re-loads the principal from the database, so a
deactivated agent, a deleted user or a demoted role takes effect immediately
(the role claim inside the token is never trusted on its own).
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.ratelimit import login_rate_limiter
from app.core.security import security_engine
from app.models.entities import Agent, RevokedToken, User, as_utc

PLATFORM_ADMIN_ROLE = "platform_admin"


@dataclass
class Principal:
    id: str
    type: str  # user | agent
    tenant_id: str
    role: str
    is_admin: bool = False
    token_jti: Optional[str] = None
    token_exp: Optional[int] = None

    @property
    def is_platform_admin(self) -> bool:
        return self.type == "user" and self.role == PLATFORM_ADMIN_ROLE

    @property
    def is_tenant_admin(self) -> bool:
        return self.type == "user" and (self.is_admin or self.is_platform_admin)

    def can_manage_tenant(self, tenant_id: Optional[str]) -> bool:
        return self.is_platform_admin or (self.is_tenant_admin and tenant_id == self.tenant_id)

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "tenant_id": self.tenant_id,
            "role": self.role,
            "is_admin": self.is_tenant_admin,
            "is_platform_admin": self.is_platform_admin,
        }


AuthResult = Tuple[Optional[Principal], str, str]


def _is_revoked(db: Session, jti: str) -> bool:
    return db.get(RevokedToken, jti) is not None


def authenticate_token(db: Session, token: Optional[str]) -> AuthResult:
    """Returns (principal, code, message). Principal is None on any failure."""
    if not token:
        return None, "AUTHN_MISSING_IDENTITY", "No identity token supplied"
    ok, payload, code, msg = security_engine.verify_identity_token(token)
    if not ok or payload is None:
        return None, code, msg
    if _is_revoked(db, payload["jti"]):
        return None, "TOKEN_REVOKED", "Identity token has been revoked"

    ptyp, sub, tid = payload.get("ptyp"), payload["sub"], payload["tid"]
    if ptyp == "user":
        user = db.get(User, sub)
        if not user or user.tenant_id != tid:
            return None, "PRINCIPAL_UNKNOWN", f"User '{sub}' does not exist in tenant '{tid}'"
        if not user.is_active:
            return None, "PRINCIPAL_INACTIVE", f"User '{sub}' is deactivated"
        return Principal(user.id, "user", user.tenant_id, user.role, user.is_admin,
                         payload["jti"], payload["exp"]), "AUTHN_OK", "Authenticated user"
    if ptyp == "agent":
        agent = db.get(Agent, sub)
        if payload.get("aid") not in (None, sub):
            return None, "PRINCIPAL_UNKNOWN", "Agent token 'aid' does not match subject"
        if not agent or agent.tenant_id != tid:
            return None, "PRINCIPAL_UNKNOWN", f"Agent '{sub}' does not exist in tenant '{tid}'"
        if not agent.is_active:
            return None, "PRINCIPAL_INACTIVE", f"Agent '{sub}' is deactivated"
        return Principal(agent.id, "agent", agent.tenant_id, agent.role, False,
                         payload["jti"], payload["exp"]), "AUTHN_OK", "Authenticated agent"
    return None, "TOKEN_MALFORMED", f"Unknown principal type '{ptyp}'"


def issue_token_for(principal: Principal) -> str:
    return security_engine.create_identity_token(
        subject=principal.id,
        tenant_id=principal.tenant_id,
        role=principal.role,
        principal_type=principal.type,
        agent_id=principal.id if principal.type == "agent" else None,
    )


def login_user(db: Session, username: str, password: str, client_key: str = "") -> AuthResult:
    allowed, retry = login_rate_limiter.hit(f"user:{username}:{client_key}", settings.LOGIN_ATTEMPTS_PER_MINUTE)
    if not allowed:
        return None, "LOGIN_RATE_LIMITED", f"Too many login attempts; retry in {retry}s"
    user = db.query(User).filter(User.username == username).first() if username else None
    if user is None:
        security_engine.dummy_verify()  # equalise timing to avoid user enumeration
        return None, "LOGIN_INVALID_CREDENTIALS", "Invalid username or password"
    if not security_engine.verify_secret(password or "", user.password_hash):
        return None, "LOGIN_INVALID_CREDENTIALS", "Invalid username or password"
    if not user.is_active:
        return None, "PRINCIPAL_INACTIVE", "Account is deactivated"
    return Principal(user.id, "user", user.tenant_id, user.role, user.is_admin), "LOGIN_OK", "Login successful"


def login_agent(db: Session, agent_id: str, client_secret: str, client_key: str = "") -> AuthResult:
    allowed, retry = login_rate_limiter.hit(f"agent:{agent_id}:{client_key}", settings.LOGIN_ATTEMPTS_PER_MINUTE)
    if not allowed:
        return None, "LOGIN_RATE_LIMITED", f"Too many login attempts; retry in {retry}s"
    agent = db.get(Agent, agent_id) if agent_id else None
    if agent is None or not agent.client_secret_hash:
        security_engine.dummy_verify()
        return None, "LOGIN_INVALID_CREDENTIALS", "Invalid agent id or client secret"
    if not security_engine.verify_secret(client_secret or "", agent.client_secret_hash):
        return None, "LOGIN_INVALID_CREDENTIALS", "Invalid agent id or client secret"
    if not agent.is_active:
        return None, "PRINCIPAL_INACTIVE", "Agent is deactivated"
    return Principal(agent.id, "agent", agent.tenant_id, agent.role), "LOGIN_OK", "Agent authenticated"


def revoke_token(db: Session, principal: Principal, revoked_by: Optional[str] = None) -> None:
    """Adds the token's jti to the denylist until it would have expired anyway."""
    if not principal.token_jti:
        return
    now = datetime.now(timezone.utc)
    db.query(RevokedToken).filter(RevokedToken.expires_at < now).delete()
    exp = datetime.fromtimestamp(principal.token_exp or now.timestamp(), tz=timezone.utc)
    db.add(RevokedToken(jti=principal.token_jti, subject=principal.id, revoked_by=revoked_by or principal.id,
                        revoked_at=now, expires_at=as_utc(exp)))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # already revoked


def authorize_management(
    db: Session,
    token: Optional[str],
    *,
    require_admin: bool = False,
    require_platform_admin: bool = False,
    endpoint: str = "",
) -> Tuple[Optional[Principal], int, str, str]:
    """Authentication + function-level authorization for the management API.

    Returns ``(principal, http_status, code, message)``; ``principal`` is None
    unless the caller may use the endpoint. Every refusal is audited.
    """
    from app.audit.service import audit_service  # local import: audit depends on security only

    principal, code, msg = authenticate_token(db, token)
    status = 200
    if principal is None:
        status = 401
    elif require_platform_admin and not principal.is_platform_admin:
        status, code, msg = 403, "FORBIDDEN_PLATFORM_ADMIN_REQUIRED", "This endpoint requires a platform administrator"
    elif require_admin and not principal.is_tenant_admin:
        status, code, msg = 403, "FORBIDDEN_ADMIN_REQUIRED", "This endpoint requires a tenant administrator"
    if status == 200:
        return principal, 200, "AUTHZ_OK", "Authorized"

    audit_service.log_event(
        db,
        event_type="api.access_denied",
        tenant_id=principal.tenant_id if principal else "unauthenticated",
        user_id=principal.id if principal and principal.type == "user" else None,
        agent_id=principal.id if principal and principal.type == "agent" else None,
        decision="DENY",
        reason_code=code,
        denial_reason=msg,
        attack_classification="unauthenticated_api" if status == 401 else "broken_function_authz",
        execution_outcome="blocked",
        details={"endpoint": endpoint, "http_status": status},
    )
    return None, status, code, msg

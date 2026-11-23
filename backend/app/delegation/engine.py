"""AgentFence delegation engine: issuance with attenuation, verification and replay protection.

Authority model
---------------
* Authority originates from a human user. A *root* delegation can only be
  issued by an authenticated **user**, and only for tool/resource combinations
  the policy engine would allow that user to use directly ("you cannot give
  away what you do not hold").
* An **agent** can only re-delegate authority it received: it must name a
  parent grant issued *to it*, and the child scope must be a subset of the
  parent scope (tools, resources, expiry, depth). Agents never create roots.
* The delegator is always the authenticated caller and the tenant is always
  the caller's tenant. Neither is ever taken from the request body.
* Actions are a property of each tool (``MCPTool.action``) and are derived on
  the server; the audience is fixed by gateway configuration.

Only a SHA-256 fingerprint of each credential is stored. The raw credential is
returned once, to the delegator, at creation time.
"""
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit.service import audit_service
from app.core.auth import Principal
from app.core.config import settings
from app.core.security import security_engine
from app.models.entities import Agent, DelegationGrant, MCPTool, ReplayIdentifier, User, as_utc
from app.policies.engine import policy_engine

# Maps a credential-verification failure to a delegation reason code.
_TOKEN_CODE_MAP = {
    "TOKEN_EXPIRED": "DELEGATION_EXPIRED",
    "TOKEN_AUDIENCE_MISMATCH": "DELEGATION_AUDIENCE_MISMATCH",
    "TOKEN_SIGNATURE_INVALID": "DELEGATION_TAMPERING_DETECTED",
    "TOKEN_ALGORITHM_REJECTED": "DELEGATION_TAMPERING_DETECTED",
    "TOKEN_UNKNOWN_KEY": "DELEGATION_TAMPERING_DETECTED",
}

_CREATE_ATTACK_CLASS = {
    "DELEGATION_ATTENUATION_ESCALATION": "privilege_escalation",
    "DELEGATION_EXCEEDS_DELEGATOR_AUTHORITY": "privilege_escalation",
    "DELEGATOR_HAS_NO_AUTHORITY": "privilege_escalation",
    "DELEGATION_DEPTH_EXCEEDED": "excessive_depth",
    "DELEGATION_CHAIN_MISMATCH": "stolen_delegation",
}


@dataclass
class DelegationResult:
    ok: bool
    code: str
    message: str
    grant: Optional[DelegationGrant] = None
    token: Optional[str] = None  # raw credential: only on success, shown once
    audit_event_id: Optional[str] = None


@dataclass
class VerificationResult:
    ok: bool
    code: str
    message: str
    payload: Optional[Dict[str, Any]] = None
    grant: Optional[DelegationGrant] = None


class DelegationEngine:
    def __init__(self) -> None:
        self.security = security_engine

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _is_unrestricted(resources: List[str]) -> bool:
        return not resources or "*" in resources

    def chain_of(self, db: Session, grant: DelegationGrant) -> Tuple[List[DelegationGrant], Optional[str]]:
        """Returns ``(ancestors closest-first, error)``; ``error`` is set if the chain is broken."""
        chain: List[DelegationGrant] = []
        seen = {grant.delegation_id}
        current = grant
        while current.parent_delegation_id:
            parent = db.query(DelegationGrant).filter(
                DelegationGrant.delegation_id == current.parent_delegation_id,
                DelegationGrant.tenant_id == grant.tenant_id,
            ).first()
            if parent is None:
                return chain, f"Ancestor delegation '{current.parent_delegation_id}' is missing"
            if parent.delegation_id in seen:
                return chain, f"Delegation chain contains a cycle at '{parent.delegation_id}'"
            if parent.receiving_agent_id != current.delegating_agent_id:
                return chain, (f"'{current.delegation_id}' was issued by '{current.delegating_agent_id}', "
                               f"who is not the recipient of parent '{parent.delegation_id}'")
            seen.add(parent.delegation_id)
            chain.append(parent)
            current = parent
        return chain, None

    def _check_chain(self, db: Session, grant: DelegationGrant) -> Tuple[bool, str, str]:
        chain, error = self.chain_of(db, grant)
        if error:
            return False, "BROKEN_DELEGATION_CHAIN", error
        now = self._now()
        for parent in chain:
            if parent.is_revoked:
                return False, "PARENT_DELEGATION_REVOKED", f"Ancestor delegation '{parent.delegation_id}' is revoked"
            if as_utc(parent.expires_at) < now:
                return False, "PARENT_DELEGATION_EXPIRED", (
                    f"Ancestor delegation '{parent.delegation_id}' expired at {as_utc(parent.expires_at).isoformat()}"
                )
        return True, "CHAIN_VALID", "Delegation chain verified"

    def _log_create(self, db: Session, delegator: Principal, ok: bool, code: str, message: str,
                    receiving_agent_id: Optional[str], parent_delegation_id: Optional[str],
                    delegation_id: Optional[str], details: Dict[str, Any]) -> str:
        event = audit_service.log_event(
            db,
            event_type="delegation.create",
            tenant_id=delegator.tenant_id,
            user_id=delegator.id if delegator.type == "user" else None,
            agent_id=delegator.id if delegator.type == "agent" else receiving_agent_id,
            parent_delegation_id=parent_delegation_id,
            delegation_id=delegation_id,
            decision="ALLOW" if ok else "DENY",
            reason_code=code,
            denial_reason=None if ok else message,
            attack_classification=None if ok else _CREATE_ATTACK_CLASS.get(code),
            execution_outcome="issued" if ok else "rejected",
            details={"delegator": delegator.id, "delegator_type": delegator.type,
                     "receiving_agent_id": receiving_agent_id, **details},
        )
        return event.id

    # --------------------------------------------------------------- issuance
    def create_delegation(
        self,
        db: Session,
        delegator: Principal,
        receiving_agent_id: str,
        permitted_tools: List[str],
        resource_restrictions: Optional[List[str]] = None,
        parent_delegation_id: Optional[str] = None,
        duration_minutes: int = 60,
        is_single_use: bool = False,
        max_depth: Optional[int] = None,
        delegation_id: Optional[str] = None,
    ) -> DelegationResult:
        """Issues a signed, attenuated delegation credential on behalf of ``delegator``."""
        resources = [str(r) for r in (resource_restrictions or [])]
        tools_req = [str(t) for t in (permitted_tools or [])]
        details = {"permitted_tools": tools_req, "resource_restrictions": resources,
                   "duration_minutes": duration_minutes, "is_single_use": is_single_use}

        def reject(code: str, message: str) -> DelegationResult:
            audit_id = self._log_create(db, delegator, False, code, message, receiving_agent_id,
                                        parent_delegation_id, None, details)
            return DelegationResult(False, code, message, audit_event_id=audit_id)

        tenant_id = delegator.tenant_id
        now = self._now()

        # --- request sanity -------------------------------------------------
        if not tools_req:
            return reject("INVALID_DELEGATION_REQUEST", "At least one tool must be delegated")
        if "*" in tools_req:
            return reject("INVALID_DELEGATION_REQUEST", "Wildcard tool delegation is not allowed; list tools explicitly")
        try:
            duration = int(duration_minutes)
        except (TypeError, ValueError):
            return reject("INVALID_DELEGATION_REQUEST", "duration_minutes must be an integer")
        if duration < 1 or duration > settings.MAX_DELEGATION_TTL_MINUTES:
            return reject("INVALID_DELEGATION_REQUEST",
                          f"duration_minutes must be between 1 and {settings.MAX_DELEGATION_TTL_MINUTES}")
        expires_at = now + timedelta(minutes=duration)

        tools: List[MCPTool] = []
        for name in dict.fromkeys(tools_req):
            tool = db.query(MCPTool).filter(MCPTool.name == name).first()
            if tool is None or not tool.is_enabled or tool.is_quarantined:
                return reject("INVALID_DELEGATION_REQUEST", f"Tool '{name}' is not registered, disabled or quarantined")
            tools.append(tool)
        tool_names = [t.name for t in tools]
        actions = sorted({t.action for t in tools})

        receiver = db.get(Agent, receiving_agent_id) if receiving_agent_id else None
        if receiver is None or receiver.tenant_id != tenant_id:
            return reject("INVALID_RECEIVING_AGENT",
                          f"Receiving agent '{receiving_agent_id}' does not exist in tenant '{tenant_id}'")
        if not receiver.is_active:
            return reject("AGENT_INACTIVE", f"Receiving agent '{receiving_agent_id}' is deactivated")
        if receiver.id == delegator.id:
            return reject("INVALID_DELEGATION_REQUEST", "An agent cannot delegate to itself")

        global_max = settings.MAX_DELEGATION_DEPTH
        original_user_id = delegator.id

        if parent_delegation_id is None:
            # --- root delegation: only a user, only what the user holds -------
            if delegator.type != "user":
                return reject("DELEGATOR_HAS_NO_AUTHORITY",
                              f"Agent '{delegator.id}' holds no authority of its own; it can only re-delegate "
                              f"a grant issued to it (parent_delegation_id required)")
            for tool in tools:
                targets: List[Optional[str]] = [None]
                if tool.resource_param and not self._is_unrestricted(resources):
                    targets = list(resources)
                for target in targets:
                    decision = policy_engine.evaluate(
                        db=db, principal_id=delegator.id, principal_type="user", principal_role=delegator.role,
                        acting_agent_id=None, tenant_id=tenant_id, tool_name=tool.name,
                        requested_action=tool.action, resource_id=target,
                        correlation_id=self.security.generate_id("delchk"),
                    )
                    if decision.decision != "ALLOW":
                        return reject(
                            "DELEGATION_EXCEEDS_DELEGATOR_AUTHORITY",
                            f"'{delegator.id}' cannot delegate '{tool.name}' on '{target or 'any resource'}': "
                            f"the delegator does not hold that permission ({decision.reason_code})",
                        )
            current_depth = 1
            depth_cap = global_max if max_depth is None else int(max_depth)
            if depth_cap < 1 or depth_cap > global_max:
                return reject("DELEGATION_DEPTH_EXCEEDED",
                              f"max_depth must be between 1 and the gateway limit {global_max}")
        else:
            # --- child delegation: strict attenuation of the parent ------------
            parent = db.query(DelegationGrant).filter(
                DelegationGrant.delegation_id == parent_delegation_id,
                DelegationGrant.tenant_id == tenant_id,
            ).first()
            if parent is None:
                return reject("PARENT_DELEGATION_NOT_FOUND",
                              f"Parent delegation '{parent_delegation_id}' not found in tenant '{tenant_id}'")
            if delegator.type != "agent" or parent.receiving_agent_id != delegator.id:
                return reject("DELEGATION_CHAIN_MISMATCH",
                              f"'{delegator.id}' cannot delegate from grant '{parent_delegation_id}' "
                              f"issued to '{parent.receiving_agent_id}'")
            if parent.is_revoked:
                return reject("PARENT_DELEGATION_REVOKED", f"Parent delegation '{parent_delegation_id}' is revoked")
            if as_utc(parent.expires_at) < now:
                return reject("PARENT_DELEGATION_EXPIRED", f"Parent delegation '{parent_delegation_id}' has expired")
            if parent.is_single_use:
                return reject("DELEGATION_ATTENUATION_ESCALATION", "A single-use delegation cannot be re-delegated")
            chain_ok, chain_code, chain_msg = self._check_chain(db, parent)
            if not chain_ok:
                return reject(chain_code, chain_msg)

            escalated_tools = sorted(set(tool_names) - set(parent.get_permitted_tools()))
            if escalated_tools:
                return reject("DELEGATION_ATTENUATION_ESCALATION",
                              f"Permission escalation: tools {escalated_tools} are not in the parent delegation")
            parent_resources = parent.get_resource_restrictions()
            if not self._is_unrestricted(parent_resources):
                if self._is_unrestricted(resources):
                    return reject("DELEGATION_ATTENUATION_ESCALATION",
                                  f"Permission escalation: parent is restricted to {parent_resources}; "
                                  f"the child must list a subset")
                outside = sorted(set(resources) - set(parent_resources))
                if outside:
                    return reject("DELEGATION_ATTENUATION_ESCALATION",
                                  f"Permission escalation: resources {outside} are outside the parent boundary")
            current_depth = parent.current_depth + 1
            depth_cap = min(parent.max_depth, global_max)
            if max_depth is not None:
                depth_cap = min(depth_cap, int(max_depth))
            if current_depth > depth_cap:
                return reject("DELEGATION_DEPTH_EXCEEDED",
                              f"Delegation depth exceeded: depth {current_depth} is above the permitted "
                              f"maximum {depth_cap}")
            # A child can never outlive its parent.
            expires_at = min(expires_at, as_utc(parent.expires_at))
            original_user_id = parent.original_user_id

        new_id = delegation_id or self.security.generate_id("del")
        token = self.security.create_delegation_credential(
            delegation_id=new_id,
            parent_delegation_id=parent_delegation_id,
            original_user_id=original_user_id,
            delegating_agent_id=delegator.id,
            receiving_agent_id=receiver.id,
            tenant_id=tenant_id,
            permitted_tools=tool_names,
            permitted_actions=actions,
            resource_restrictions=resources,
            max_depth=depth_cap,
            current_depth=current_depth,
            expires_at=expires_at,
            is_single_use=is_single_use,
        )
        ok, payload, _, msg = self.security.verify_delegation_credential(token)
        if not ok or payload is None:  # pragma: no cover - would indicate a key-ring bug
            raise RuntimeError(f"Freshly issued delegation credential failed verification: {msg}")

        grant = DelegationGrant(
            id=self.security.generate_id("grant"),
            delegation_id=new_id,
            parent_delegation_id=parent_delegation_id,
            tenant_id=tenant_id,
            original_user_id=original_user_id,
            delegating_agent_id=delegator.id,
            delegator_type=delegator.type,
            receiving_agent_id=receiver.id,
            permitted_tools_json=json.dumps(tool_names),
            permitted_actions_json=json.dumps(actions),
            resource_restrictions_json=json.dumps(resources),
            issued_at=now,
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            max_depth=depth_cap,
            current_depth=current_depth,
            jti=payload["jti"],
            audience=payload["aud"],
            token_fingerprint=self.security.fingerprint(token),
            is_single_use=is_single_use,
            is_consumed=False,
            is_revoked=False,
            created_at=now,
        )
        db.add(grant)
        db.commit()
        db.refresh(grant)
        audit_id = self._log_create(db, delegator, True, "DELEGATION_CREATED", "Delegation created",
                                    receiver.id, parent_delegation_id, new_id,
                                    {**details, "depth": current_depth, "max_depth": depth_cap})
        return DelegationResult(True, "DELEGATION_CREATED", "Delegation created successfully", grant, token, audit_id)

    # ------------------------------------------------------------- revocation
    def revoke(self, db: Session, actor: Principal, delegation_id: str) -> Tuple[int, str, str]:
        """Returns (http_status, code, message). Revoking a grant invalidates all descendants."""
        grant = db.query(DelegationGrant).filter(DelegationGrant.delegation_id == delegation_id).first()
        allowed = grant is not None and (
            actor.can_manage_tenant(grant.tenant_id)
            or (actor.tenant_id == grant.tenant_id and actor.id in (grant.original_user_id, grant.delegating_agent_id))
        )
        if grant is None or not allowed:
            # Same answer for "missing" and "not yours": no cross-tenant probing.
            audit_service.log_event(
                db, event_type="delegation.revoke", tenant_id=actor.tenant_id,
                user_id=actor.id if actor.type == "user" else None,
                agent_id=actor.id if actor.type == "agent" else None,
                delegation_id=delegation_id, decision="DENY", reason_code="DELEGATION_NOT_FOUND",
                denial_reason="Delegation not found or caller may not revoke it",
                execution_outcome="rejected",
            )
            return 404, "DELEGATION_NOT_FOUND", "Delegation not found"
        if not grant.is_revoked:
            grant.is_revoked = True
            grant.revoked_by = actor.id
            grant.revoked_at = self._now()
            db.commit()
        audit_service.log_event(
            db, event_type="delegation.revoke", tenant_id=grant.tenant_id,
            user_id=actor.id if actor.type == "user" else None,
            agent_id=actor.id if actor.type == "agent" else grant.receiving_agent_id,
            parent_delegation_id=grant.parent_delegation_id, delegation_id=grant.delegation_id,
            decision="ALLOW", reason_code="DELEGATION_REVOKED", execution_outcome="revoked",
            details={"revoked_by": actor.id},
        )
        return 200, "DELEGATION_REVOKED", f"Delegation '{delegation_id}' revoked (descendants are invalidated)"

    # ----------------------------------------------------------- verification
    def verify_active_delegation(
        self,
        db: Session,
        delegation_token: str,
        acting_agent_id: str,
        acting_tenant_id: str,
        tool_name: str,
        action: str,
        resource_id: Optional[str] = None,
    ) -> VerificationResult:
        """Verifies a presented credential, its registry record, scope and full chain.

        Single-use credentials are *not* consumed here; the gateway calls
        :meth:`consume_single_use` only after every other check passed.
        """
        ok, payload, token_code, msg = self.security.verify_delegation_credential(delegation_token)
        if not ok or payload is None:
            code = _TOKEN_CODE_MAP.get(token_code, "DELEGATION_TOKEN_INVALID")
            return VerificationResult(False, code, f"{msg} [{token_code}]")

        del_id = payload["del_id"]
        if payload["rcv_aid"] != acting_agent_id:
            return VerificationResult(False, "AGENT_IDENTITY_MISMATCH",
                                      f"Delegation issued to '{payload['rcv_aid']}' was presented by "
                                      f"'{acting_agent_id}'", payload)
        if payload["tid"] != acting_tenant_id:
            return VerificationResult(False, "DELEGATION_TENANT_MISMATCH",
                                      f"Delegation belongs to tenant '{payload['tid']}', caller is in "
                                      f"'{acting_tenant_id}'", payload)

        grant = db.query(DelegationGrant).filter(
            DelegationGrant.delegation_id == del_id,
            DelegationGrant.tenant_id == payload["tid"],
        ).first()
        if grant is None:
            return VerificationResult(False, "DELEGATION_NOT_FOUND",
                                      f"Delegation '{del_id}' is not in the registry", payload)
        if grant.jti != payload["jti"] or grant.token_fingerprint != self.security.fingerprint(delegation_token):
            return VerificationResult(False, "DELEGATION_TOKEN_MISMATCH",
                                      f"Credential does not match the registered grant '{del_id}'", payload, grant)
        if grant.is_revoked:
            return VerificationResult(False, "DELEGATION_REVOKED", f"Delegation '{del_id}' was revoked", payload, grant)
        if as_utc(grant.expires_at) < self._now():
            return VerificationResult(False, "DELEGATION_EXPIRED", f"Delegation '{del_id}' has expired", payload, grant)
        if grant.is_single_use and grant.is_consumed:
            return VerificationResult(False, "REPLAY_ATTACK_DETECTED",
                                      f"Single-use delegation '{del_id}' has already been consumed", payload, grant)
        if grant.current_depth > grant.max_depth or grant.current_depth > settings.MAX_DELEGATION_DEPTH:
            return VerificationResult(False, "EXCESSIVE_DELEGATION_DEPTH",
                                      f"Delegation depth {grant.current_depth} exceeds the permitted maximum "
                                      f"{min(grant.max_depth, settings.MAX_DELEGATION_DEPTH)}", payload, grant)

        tools = grant.get_permitted_tools()
        if tool_name not in tools:
            return VerificationResult(False, "UNAUTHORIZED_TOOL_EXECUTION",
                                      f"Tool '{tool_name}' is not in the delegated tool scope {tools}", payload, grant)
        actions = grant.get_permitted_actions()
        if action not in actions:
            return VerificationResult(False, "UNAUTHORIZED_ACTION",
                                      f"Action '{action}' is not in the delegated actions {actions}", payload, grant)
        restrictions = grant.get_resource_restrictions()
        if resource_id is not None and not self._is_unrestricted(restrictions) and resource_id not in restrictions:
            return VerificationResult(False, "RESOURCE_ACCESS_RESTRICTED",
                                      f"Resource '{resource_id}' is outside the delegation boundary {restrictions}",
                                      payload, grant)

        chain_ok, chain_code, chain_msg = self._check_chain(db, grant)
        if not chain_ok:
            return VerificationResult(False, chain_code, chain_msg, payload, grant)
        return VerificationResult(True, "DELEGATION_VALID", "Delegation credential and chain verified", payload, grant)

    def consume_single_use(self, db: Session, grant: DelegationGrant, jti: str,
                           consumer_agent_id: str) -> Tuple[bool, str, str]:
        """Atomically and durably burns a single-use credential.

        Two guards, both enforced by the database (so they hold across threads,
        worker processes and restarts):
        1. INSERT into ``replay_identifiers`` (UNIQUE ``jti``);
        2. conditional ``UPDATE ... SET is_consumed = 1 WHERE is_consumed = 0``.
        Only the request that wins both commits; every other one is a replay.
        """
        try:
            db.add(ReplayIdentifier(
                id=self.security.generate_id("rpl"),
                jti=jti,
                delegation_id=grant.delegation_id,
                consumer_agent_id=consumer_agent_id,
                consumed_at=self._now(),
                expires_at=as_utc(grant.expires_at),
            ))
            db.flush()
            updated = (
                db.query(DelegationGrant)
                .filter(DelegationGrant.id == grant.id, DelegationGrant.is_consumed.is_(False))
                .update({DelegationGrant.is_consumed: True}, synchronize_session=False)
            )
            if updated != 1:
                db.rollback()
                return False, "REPLAY_ATTACK_DETECTED", f"Single-use delegation '{grant.delegation_id}' already consumed"
            db.commit()
        except IntegrityError:
            db.rollback()
            return False, "REPLAY_ATTACK_DETECTED", f"Credential jti '{jti}' has already been used (replay)"
        return True, "CONSUMED", "Single-use delegation consumed"

    # ------------------------------------------------------------- inspection
    @staticmethod
    def serialize(grant: DelegationGrant) -> Dict[str, Any]:
        """Public view of a grant. Never includes the bearer credential."""
        return {
            "id": grant.id,
            "delegation_id": grant.delegation_id,
            "parent_delegation_id": grant.parent_delegation_id,
            "tenant_id": grant.tenant_id,
            "original_user_id": grant.original_user_id,
            "delegating_agent_id": grant.delegating_agent_id,
            "delegator_type": grant.delegator_type,
            "receiving_agent_id": grant.receiving_agent_id,
            "permitted_tools": grant.get_permitted_tools(),
            "permitted_actions": grant.get_permitted_actions(),
            "resource_restrictions": grant.get_resource_restrictions(),
            "current_depth": grant.current_depth,
            "max_depth": grant.max_depth,
            "is_single_use": grant.is_single_use,
            "is_consumed": grant.is_consumed,
            "is_revoked": grant.is_revoked,
            "revoked_by": grant.revoked_by,
            "expires_at": as_utc(grant.expires_at).isoformat(),
            "jti": grant.jti,
            "token_fingerprint": grant.token_fingerprint,
        }

    @staticmethod
    def load_principal(db: Session, principal_id: str, principal_type: str) -> Optional[Principal]:
        """Loads an active principal from the database (used for chain-wide authorization)."""
        if principal_type == "user":
            user = db.get(User, principal_id)
            if user is None or not user.is_active:
                return None
            return Principal(user.id, "user", user.tenant_id, user.role, user.is_admin)
        agent = db.get(Agent, principal_id)
        if agent is None or not agent.is_active:
            return None
        return Principal(agent.id, "agent", agent.tenant_id, agent.role)


delegation_engine = DelegationEngine()

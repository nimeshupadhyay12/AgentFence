"""AgentFence security core: signed tokens, password hashing and audit hashing.

Token hardening (see docs/IMPROVEMENTS.md):

* Algorithm pinned to the configured HMAC algorithm; ``none``/other algorithms
  are rejected before signature verification.
* Every token carries a ``kid`` header; verification only uses keys from the
  configured key ring (supports rotation without invalidating live tokens).
* ``iss``, ``aud``, ``sub``, ``exp``, ``nbf``, ``iat``, ``jti``, ``tid`` and
  ``token_use`` are *required* claims, with a small clock-skew leeway.
* ``token_use`` separates identity tokens from delegation credentials, so a
  delegation credential can never be replayed as an identity token (or the
  other way round).
"""
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import settings

TOKEN_USE_IDENTITY = "identity"
TOKEN_USE_DELEGATION = "delegation"

_IDENTITY_REQUIRED = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti", "tid", "token_use"]
_DELEGATION_REQUIRED = _IDENTITY_REQUIRED + ["del_id", "rcv_aid"]

# Argon2id (OWASP first choice for password storage). argon2-cffi defaults:
# time_cost=3, memory_cost=64 MiB, parallelism=4, 16-byte salt, 32-byte hash.
_PASSWORD_HASHER = PasswordHasher()


class SecurityEngine:
    def __init__(
        self,
        signing_keys: Optional[Dict[str, str]] = None,
        active_kid: Optional[str] = None,
        algorithm: str = settings.ALGORITHM,
        issuer: str = settings.TOKEN_ISSUER,
        audience: str = settings.DEFAULT_AUDIENCE,
        leeway_seconds: int = settings.CLOCK_SKEW_LEEWAY_SECONDS,
    ):
        self.signing_keys = dict(signing_keys or settings.SIGNING_KEYS)
        self.active_kid = active_kid or settings.ACTIVE_KID
        self.algorithm = algorithm
        self.issuer = issuer
        self.default_audience = audience
        self.leeway = leeway_seconds

    # ------------------------------------------------------------------ ids
    @staticmethod
    def generate_id(prefix: str = "") -> str:
        uid = uuid.uuid4().hex
        return f"{prefix}_{uid[:16]}" if prefix else uid

    @staticmethod
    def fingerprint(token: str) -> str:
        """Stable, non-reversible identifier for a token (safe to display/store)."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    # ------------------------------------------------------ password hashing
    @staticmethod
    def hash_secret(secret: str) -> str:
        """Salted Argon2id hash in PHC string format (``$argon2id$v=19$m=...``)."""
        return _PASSWORD_HASHER.hash(secret)

    @staticmethod
    def verify_secret(secret: str, encoded: Optional[str]) -> bool:
        """Constant-time verification of a password / client secret."""
        if not secret or not encoded:
            return False
        try:
            return _PASSWORD_HASHER.verify(encoded, secret)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    # A valid hash for a random secret: used to equalise timing when the
    # username does not exist (prevents user enumeration through timing).
    _DUMMY_HASH: Optional[str] = None

    def dummy_verify(self) -> None:
        if SecurityEngine._DUMMY_HASH is None:
            SecurityEngine._DUMMY_HASH = self.hash_secret(secrets.token_hex(8))
        self.verify_secret("not-the-password", SecurityEngine._DUMMY_HASH)

    # ------------------------------------------------------------ signing
    def _encode(self, payload: Dict[str, Any]) -> str:
        return jwt.encode(
            payload,
            self.signing_keys[self.active_kid],
            algorithm=self.algorithm,
            headers={"kid": self.active_kid, "typ": "JWT"},
        )

    def _decode(
        self, token: str, required: List[str], expected_use: str, audience: Optional[str]
    ) -> Tuple[bool, Optional[Dict[str, Any]], str, str]:
        if not token or not isinstance(token, str):
            return False, None, "TOKEN_MALFORMED", "Token missing or not a string"
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            return False, None, "TOKEN_MALFORMED", f"Malformed token header: {exc}"

        alg = header.get("alg")
        if alg != self.algorithm:
            return False, None, "TOKEN_ALGORITHM_REJECTED", (
                f"Token algorithm '{alg}' rejected: gateway only accepts '{self.algorithm}'"
            )
        kid = header.get("kid")
        if kid not in self.signing_keys:
            return False, None, "TOKEN_UNKNOWN_KEY", f"Token key id '{kid}' is not in the gateway key ring"

        try:
            payload = jwt.decode(
                token,
                self.signing_keys[kid],
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=audience or self.default_audience,
                leeway=self.leeway,
                options={"require": required, "verify_signature": True},
            )
        except jwt.ExpiredSignatureError:
            return False, None, "TOKEN_EXPIRED", "Token has expired"
        except jwt.ImmatureSignatureError:
            return False, None, "TOKEN_NOT_YET_VALID", "Token is not yet valid (nbf/iat in the future)"
        except jwt.InvalidAudienceError:
            return False, None, "TOKEN_AUDIENCE_MISMATCH", "Token audience does not match this gateway"
        except jwt.InvalidIssuerError:
            return False, None, "TOKEN_ISSUER_INVALID", "Invalid token issuer"
        except jwt.MissingRequiredClaimError as exc:
            return False, None, "TOKEN_MISSING_CLAIM", f"Token is missing required claim: {exc.claim}"
        except jwt.InvalidSignatureError:
            return False, None, "TOKEN_SIGNATURE_INVALID", "Signature verification failed / token tampered"
        except jwt.PyJWTError as exc:
            return False, None, "TOKEN_MALFORMED", f"Token rejected: {exc}"

        if payload.get("token_use") != expected_use:
            return False, None, "TOKEN_TYPE_MISMATCH", (
                f"Token type '{payload.get('token_use')}' presented where '{expected_use}' is required"
            )
        return True, payload, "TOKEN_VALID", "Token verified"

    # ------------------------------------------------------ identity tokens
    def create_identity_token(
        self,
        subject: str,
        tenant_id: str,
        role: str,
        principal_type: str = "user",
        agent_id: Optional[str] = None,
        expires_delta: Optional[timedelta] = None,
        audience: Optional[str] = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        exp = now + (expires_delta or timedelta(minutes=settings.DEFAULT_TOKEN_EXPIRY_MINUTES))
        return self._encode({
            "iss": self.issuer,
            "sub": subject,
            "tid": tenant_id,
            "role": role,
            "ptyp": principal_type,
            "aid": agent_id,
            "aud": audience or self.default_audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": self.generate_id("idtok"),
            "token_use": TOKEN_USE_IDENTITY,
        })

    def verify_identity_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]], str, str]:
        """Verifies an identity token against the gateway's own audience."""
        return self._decode(token, _IDENTITY_REQUIRED, TOKEN_USE_IDENTITY, self.default_audience)

    # ------------------------------------------------- delegation credentials
    def create_delegation_credential(
        self,
        delegation_id: str,
        parent_delegation_id: Optional[str],
        original_user_id: str,
        delegating_agent_id: str,
        receiving_agent_id: str,
        tenant_id: str,
        permitted_tools: List[str],
        permitted_actions: List[str],
        resource_restrictions: List[str],
        max_depth: int,
        current_depth: int,
        audience: Optional[str] = None,
        expires_in_minutes: int = 30,
        expires_at: Optional[datetime] = None,
        is_single_use: bool = False,
        custom_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        if expires_at is not None:
            exp = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
        else:
            exp = now + timedelta(minutes=expires_in_minutes)
        return self._encode({
            "iss": self.issuer,
            "sub": receiving_agent_id,
            "aud": audience or self.default_audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": self.generate_id("del_jti"),
            "token_use": TOKEN_USE_DELEGATION,
            "del_id": delegation_id,
            "pdel_id": parent_delegation_id,
            "orig_uid": original_user_id,
            "del_aid": delegating_agent_id,
            "rcv_aid": receiving_agent_id,
            "tid": tenant_id,
            "tools": permitted_tools,
            "actions": permitted_actions,
            "resources": resource_restrictions,
            "max_depth": max_depth,
            "cur_depth": current_depth,
            "single_use": is_single_use,
            "claims": custom_claims or {},
        })

    def verify_delegation_credential(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]], str, str]:
        """Verifies a delegation credential against the gateway's own audience."""
        return self._decode(token, _DELEGATION_REQUIRED, TOKEN_USE_DELEGATION, self.default_audience)

    # --------------------------------------------------------- audit hashing
    @staticmethod
    def canonical_json(data: Dict[str, Any]) -> str:
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

    @classmethod
    def calculate_audit_hash(cls, record: Dict[str, Any]) -> str:
        """SHA-256 over the canonical JSON of *every* hashed audit field."""
        return hashlib.sha256(cls.canonical_json(record).encode("utf-8")).hexdigest()

    @staticmethod
    def calculate_legacy_audit_hash(
        previous_hash: str, request_id: str, timestamp: str, tenant_id: str, user_id: Optional[str],
        agent_id: Optional[str], tool_name: str, requested_action: str, resource_id: Optional[str],
        decision: str, denial_reason: Optional[str],
    ) -> str:
        """v1 (pre-2.0) hash: only 11 pipe-joined fields. Kept to verify archived chains."""
        record_content = (
            f"{previous_hash}|{request_id}|{timestamp}|{tenant_id}|"
            f"{user_id or ''}|{agent_id or ''}|{tool_name}|{requested_action}|"
            f"{resource_id or ''}|{decision}|{denial_reason or ''}"
        )
        return hashlib.sha256(record_content.encode("utf-8")).hexdigest()


security_engine = SecurityEngine()

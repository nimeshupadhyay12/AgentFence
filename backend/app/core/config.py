"""AgentFence configuration.

All settings come from environment variables. Secrets are never hard-coded:

* ``AGENTFENCE_SECRET_KEY`` (or ``AGENTFENCE_SIGNING_KEYS``) must be provided
  when ``AGENTFENCE_ENV=prod``; the gateway refuses to start otherwise.
* In ``dev``/``test`` mode a random signing key is generated on first start
  and persisted to ``<data dir>/.dev_signing_key`` (gitignored) so that
  delegation credentials survive a restart of the demo server.
"""
import os
import secrets
from pathlib import Path
from typing import Dict, List, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_DIR = Path(os.getenv("AGENTFENCE_DATA_DIR", str(BASE_DIR / "data")))
DB_DIR.mkdir(parents=True, exist_ok=True)
SQLITE_PATH = DB_DIR / "agentfence.db"

# The secret that shipped in early versions of this repository. It is public,
# so it must never be accepted as a signing key.
_LEGACY_PUBLIC_SECRET = "agentfence-dev-secret-key-32bytes-min-change-in-prod-xyz123"
_ALLOWED_ALGORITHMS = {"HS256", "HS384", "HS512"}
_MIN_KEY_BYTES = 32


class ConfigurationError(RuntimeError):
    """Raised when the gateway is started with an unsafe configuration."""


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _env_list(name: str, default: str) -> List[str]:
    return [v.strip() for v in os.getenv(name, default).split(",") if v.strip()]


def load_signing_keys(env: str) -> Tuple[Dict[str, str], str]:
    """Returns ({kid: secret}, active_kid).

    ``AGENTFENCE_SIGNING_KEYS="k2:<secret>,k1:<old secret>"`` enables key
    rotation: the first key (or ``AGENTFENCE_ACTIVE_KID``) signs new tokens,
    the others are still accepted for verification until they are removed.
    """
    keys: Dict[str, str] = {}
    multi = os.getenv("AGENTFENCE_SIGNING_KEYS", "").strip()
    if multi:
        for item in multi.split(","):
            kid, sep, secret = item.strip().partition(":")
            if not sep or not kid.strip() or not secret.strip():
                raise ConfigurationError("AGENTFENCE_SIGNING_KEYS must look like 'kid1:secret1,kid2:secret2'")
            keys[kid.strip()] = secret.strip()
        active = os.getenv("AGENTFENCE_ACTIVE_KID", next(iter(keys)))
    else:
        single = os.getenv("AGENTFENCE_SECRET_KEY", "").strip()
        if single:
            keys["k1"] = single
        elif env == "prod":
            raise ConfigurationError(
                "AGENTFENCE_SECRET_KEY (or AGENTFENCE_SIGNING_KEYS) must be set when AGENTFENCE_ENV=prod"
            )
        else:
            key_file = DB_DIR / ".dev_signing_key"
            if key_file.exists():
                keys["dev"] = key_file.read_text(encoding="utf-8").strip()
            else:
                generated = secrets.token_urlsafe(48)
                key_file.write_text(generated, encoding="utf-8")
                keys["dev"] = generated
        active = next(iter(keys))

    if active not in keys:
        raise ConfigurationError(f"AGENTFENCE_ACTIVE_KID '{active}' is not present in the signing key ring")
    for kid, secret in keys.items():
        if secret == _LEGACY_PUBLIC_SECRET:
            raise ConfigurationError(f"Signing key '{kid}' is the publicly known legacy default; generate a new one")
        if len(secret.encode("utf-8")) < _MIN_KEY_BYTES:
            raise ConfigurationError(f"Signing key '{kid}' is shorter than {_MIN_KEY_BYTES} bytes")
    return keys, active


class Settings:
    PROJECT_NAME: str = "AgentFence"
    VERSION: str = "2.0.0"
    DESCRIPTION: str = "Delegation-Aware AI Agent Security Gateway for Model Context Protocol (MCP)"

    def __init__(self) -> None:
        self.ENV: str = os.getenv("AGENTFENCE_ENV", "dev").strip().lower()
        self.HOST: str = os.getenv("AGENTFENCE_HOST", "127.0.0.1")
        self.PORT: int = int(os.getenv("AGENTFENCE_PORT", "8080"))
        self.DEBUG: bool = _env_bool("AGENTFENCE_DEBUG", False)
        self.CORS_ORIGINS: List[str] = _env_list(
            "AGENTFENCE_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        )

        # --- Tokens -------------------------------------------------------
        self.ALGORITHM: str = os.getenv("AGENTFENCE_ALGORITHM", "HS256")
        self.TOKEN_ISSUER: str = os.getenv("AGENTFENCE_ISSUER", "https://auth.agentfence.internal")
        # The audience this gateway accepts. It is never taken from the client.
        self.DEFAULT_AUDIENCE: str = os.getenv("AGENTFENCE_AUDIENCE", "agentfence-gateway-v1")
        self.DEFAULT_TOKEN_EXPIRY_MINUTES: int = int(os.getenv("AGENTFENCE_TOKEN_EXPIRY", "15"))
        self.CLOCK_SKEW_LEEWAY_SECONDS: int = int(os.getenv("AGENTFENCE_LEEWAY_SECONDS", "30"))

        # --- Delegation ---------------------------------------------------
        self.MAX_DELEGATION_DEPTH: int = int(os.getenv("AGENTFENCE_MAX_DEPTH", "3"))
        self.MAX_DELEGATION_TTL_MINUTES: int = int(os.getenv("AGENTFENCE_MAX_DELEGATION_TTL", "1440"))

        # --- Rate limiting & approvals -----------------------------------
        self.RATE_LIMIT_PER_MINUTE: int = int(os.getenv("AGENTFENCE_RATE_LIMIT_PER_MINUTE", "120"))
        self.LOGIN_ATTEMPTS_PER_MINUTE: int = int(os.getenv("AGENTFENCE_LOGIN_ATTEMPTS_PER_MINUTE", "10"))
        self.APPROVAL_TTL_MINUTES: int = int(os.getenv("AGENTFENCE_APPROVAL_TTL", "30"))

        # --- Storage ------------------------------------------------------
        self.DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{SQLITE_PATH.as_posix()}")
        # Demo tenants/principals are seeded automatically in dev/test only,
        # or in prod when explicitly requested.
        self.SEED_DEMO_DATA: bool = _env_bool("AGENTFENCE_SEED_DEMO", self.ENV != "prod")
        self.DATA_DIR: Path = DB_DIR

        # --- Upstream MCP servers -----------------------------------------
        # Allowed origins for tools whose upstream_endpoint is http(s)://.
        # Anything else is refused (fail closed). mock:// uses the in-process
        # demo upstream.
        self.UPSTREAM_ALLOWLIST: List[str] = _env_list(
            "AGENTFENCE_UPSTREAM_ALLOWLIST", "http://127.0.0.1:8001,http://localhost:8001"
        )
        self.UPSTREAM_TIMEOUT_SECONDS: float = float(os.getenv("AGENTFENCE_UPSTREAM_TIMEOUT", "10"))

        self.AUDIT_GENESIS_HASH: str = "0" * 64

        if self.ENV not in ("dev", "test", "prod"):
            raise ConfigurationError("AGENTFENCE_ENV must be one of dev, test, prod")
        if self.ALGORITHM not in _ALLOWED_ALGORITHMS:
            raise ConfigurationError(f"AGENTFENCE_ALGORITHM must be one of {sorted(_ALLOWED_ALGORITHMS)}")
        if self.ENV == "prod" and self.DEBUG:
            raise ConfigurationError("AGENTFENCE_DEBUG must be false when AGENTFENCE_ENV=prod")
        self.SIGNING_KEYS, self.ACTIVE_KID = load_signing_keys(self.ENV)

    @property
    def is_dev(self) -> bool:
        return self.ENV in ("dev", "test")


settings = Settings()

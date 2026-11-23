"""AgentFence demo data: two tenants, users, agents, tools, resources, policies, delegations.

No credential is hard-coded. Passwords and agent client secrets come from
``AGENTFENCE_DEMO_PASSWORD`` (one value for every demo principal, handy for a
live demo) or are generated randomly. Either way they are written to
``<data dir>/demo_credentials.json`` (``backend/data/`` is gitignored) together
with the one-time delegation credentials of the seeded grants.
"""
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.auth import Principal
from app.core.config import settings
from app.core.ratelimit import gateway_rate_limiter, login_rate_limiter
from app.core.security import security_engine
from app.database.session import engine, get_db, init_db
from app.models.base import Base
from app.models.entities import Agent, MCPTool, Policy, ProtectedResource, Tenant, User

CREDENTIALS_FILE = settings.DATA_DIR / "demo_credentials.json"

TENANTS = [
    ("tenant_platform", "AgentFence Security Operations", "secops",
     "Platform operators: run the attack lab, approve high-risk calls, verify the audit ledger."),
    ("tenant_alpha", "Tenant Alpha - Aerospace & Defense Systems", "alpha",
     "Aerospace engineering, autonomous defense telemetry, and avionics data."),
    ("tenant_beta", "Tenant Beta - Healthcare & Biotech Labs", "beta",
     "Clinical trials, oncology research, genomics, and HIPAA-protected health records."),
]

# (id, tenant, username, email, role, is_admin)
USERS = [
    ("usr_secops_admin", "tenant_platform", "secops_admin", "secops@agentfence.internal", "platform_admin", True),
    ("usr_alpha_admin", "tenant_alpha", "alpha_admin", "admin@alpha-defense.internal", "admin", True),
    ("usr_alpha_analyst", "tenant_alpha", "alpha_analyst", "analyst@alpha-defense.internal", "analyst", False),
    ("usr_alpha_eng", "tenant_alpha", "alpha_engineer", "engineer@alpha-defense.internal", "engineer", False),
    ("usr_beta_admin", "tenant_beta", "beta_admin", "admin@beta-health.internal", "admin", True),
    ("usr_beta_researcher", "tenant_beta", "beta_researcher", "researcher@beta-health.internal", "researcher", False),
]

# (id, tenant, name, type, role, description)
AGENTS = [
    ("agent_alpha_primary", "tenant_alpha", "Alpha Mission Coordinator Agent", "primary", "coordinator",
     "Primary autonomous mission agent for aerospace telemetry & engineering documentation."),
    ("agent_alpha_research", "tenant_alpha", "Alpha Radar Research Sub-Agent", "subagent", "researcher",
     "Sub-agent restricted to research-level radar schematics."),
    ("agent_alpha_untrusted", "tenant_alpha", "Alpha Untrusted 3rd-Party Plugin", "restricted", "plugin",
     "Low-privilege external calculation plugin agent (may only see confidential-or-lower data)."),
    ("agent_beta_primary", "tenant_beta", "Beta Clinical Trial Coordinator", "primary", "coordinator",
     "Primary coordinator agent managing patient cohorts and clinical protocol execution."),
    ("agent_beta_analytics", "tenant_beta", "Beta Genomic Data Analyst Sub-Agent", "subagent", "analyst",
     "Sub-agent delegated to execute statistical calculations over genomic sequences."),
]

TOOLS = [
    dict(id="tool_read_document", name="read_document", action="read", resource_param="resource_id",
         risk_level="medium", requires_approval=False, rate_limit_per_minute=None,
         description="Read content of a protected document within the authenticated tenant boundary.",
         schema={"type": "object", "properties": {
             "resource_id": {"type": "string", "maxLength": 64, "pattern": "^[a-z0-9_]+$",
                             "description": "Unique identifier of the protected document"}},
             "required": ["resource_id"]},
         scopes=["documents:read"]),
    dict(id="tool_search_knowledge_base", name="search_knowledge_base", action="search", resource_param=None,
         risk_level="low", requires_approval=False, rate_limit_per_minute=10,
         description="Perform keyword queries against the tenant document catalog (titles and sensitivity only).",
         schema={"type": "object", "properties": {
             "query": {"type": "string", "maxLength": 200, "description": "Search query terms"},
             "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 5}},
             "required": ["query"]},
         scopes=["knowledge:search"]),
    dict(id="tool_execute_analytics_query", name="execute_analytics_query", action="execute", resource_param=None,
         risk_level="medium", requires_approval=False, rate_limit_per_minute=None,
         description="Execute read-only analytical aggregations over tenant dataset metrics.",
         schema={"type": "object", "properties": {
             "query_type": {"type": "string", "enum": ["aggregate", "variance", "percentile"]},
             "dataset_id": {"type": "string", "maxLength": 64}},
             "required": ["query_type", "dataset_id"]},
         scopes=["analytics:execute"]),
    dict(id="tool_export_tenant_report", name="export_tenant_report", action="export", resource_param=None,
         risk_level="high", requires_approval=True, rate_limit_per_minute=None,
         description="Export regulatory compliance audit pack for the current tenant.",
         schema={"type": "object", "properties": {
             "report_format": {"type": "string", "enum": ["json", "csv"]}},
             "required": ["report_format"]},
         scopes=["reports:export"]),
    dict(id="tool_admin_override", name="admin_override", action="admin", resource_param=None,
         risk_level="critical", requires_approval=True, rate_limit_per_minute=None,
         description="High-privilege gateway maintenance operation (diagnostics, cache flush, key rotation).",
         schema={"type": "object", "properties": {
             "action": {"type": "string", "enum": ["diagnostics", "flush_cache", "rotate_keys"]}},
             "required": ["action"]},
         scopes=["admin:override"]),
]

RESOURCES = [
    ("doc_alpha_falcon", "tenant_alpha", "Project Falcon Autonomous Flight Blueprint", "secret", "usr_alpha_admin",
     "[RESTRICTED ALPHA-DEFENSE]: Project Falcon Mach 4.2 flight trajectory specifications, payload telemetry, "
     "and autonomous guidance coordinates."),
    ("doc_alpha_radar", "tenant_alpha", "Alpha Phased Array Radar Architecture", "confidential", "usr_alpha_eng",
     "[CONFIDENTIAL ALPHA-DEFENSE]: Next-generation GaN active electronically scanned array radar transceiver "
     "schematic."),
    ("doc_beta_trial", "tenant_beta", "Beta-709 Oncology Clinical Trial Results", "confidential", "usr_beta_admin",
     "[PHI/HIPAA PROTECTED BETA-HEALTH]: Double-blind Phase III randomized cohort study on CAR-T immunotherapy "
     "response rates."),
    ("doc_beta_genomics", "tenant_beta", "Beta Synthetic CRISPR Sequence Catalog", "secret", "usr_beta_researcher",
     "[PROPRIETARY BETA-BIOTECH]: Target base-pair sequence vectors for lung adenocarcinoma oncogene editing."),
]

# (id, tenant, name, description, effect, ptype, pid, role, tool, action, resource, conditions, priority)
POLICIES = [
    # --- Tenant Alpha ---
    ("pol_alpha_plugin_high_risk_deny", "tenant_alpha", "Alpha: plugins never use high-risk tools",
     "Deny-overrides example: third-party plugin agents can never call high or critical risk tools.",
     "DENY", "agent", "*", "plugin", "*", "*", "*", {"min_risk_level": "high"}, 5),
    ("pol_alpha_admin_all", "tenant_alpha", "Alpha administrators: all tools in tenant",
     "Tenant administrators may use every tool inside their own tenant (high-risk tools still need approval).",
     "ALLOW", "user", "*", "admin", "*", "*", "*", {}, 10),
    ("pol_alpha_analyst_read", "tenant_alpha", "Alpha analysts: read up to confidential",
     "Analysts may read Alpha documents classified confidential or lower.",
     "ALLOW", "user", "*", "analyst", "read_document", "read", "doc_alpha_*", {"max_sensitivity": "confidential"}, 20),
    ("pol_alpha_analyst_search", "tenant_alpha", "Alpha analysts: search catalog",
     "Analysts may search the Alpha catalog (bounded result size).",
     "ALLOW", "user", "*", "analyst", "search_knowledge_base", "search", "*", {"args": {"limit": {"max": 20}}}, 20),
    ("pol_alpha_agent_read", "tenant_alpha", "Alpha coordinator: delegated document read",
     "The coordinator agent may read Alpha documents, only under a valid delegation.",
     "ALLOW", "agent", "agent_alpha_primary", "coordinator", "read_document", "read", "doc_alpha_*",
     {"requires_delegation": True}, 50),
    ("pol_alpha_agent_search", "tenant_alpha", "Alpha coordinator: delegated catalog search",
     "The coordinator agent may search the catalog under a delegation (max 20 results).",
     "ALLOW", "agent", "agent_alpha_primary", "coordinator", "search_knowledge_base", "search", "*",
     {"requires_delegation": True, "args": {"limit": {"max": 20}}}, 50),
    ("pol_alpha_subagent_read", "tenant_alpha", "Alpha research sub-agent: radar only",
     "The research sub-agent may read the radar schematic, only under a valid delegation.",
     "ALLOW", "agent", "agent_alpha_research", "researcher", "read_document", "read", "doc_alpha_radar",
     {"requires_delegation": True}, 60),
    ("pol_alpha_plugin_read", "tenant_alpha", "Alpha plugin: confidential-or-lower reads",
     "The third-party plugin may read Alpha documents up to 'confidential', only under a delegation.",
     "ALLOW", "agent", "agent_alpha_untrusted", "plugin", "read_document", "read", "doc_alpha_*",
     {"requires_delegation": True, "max_sensitivity": "confidential"}, 70),
    # --- Tenant Beta ---
    ("pol_beta_admin_all", "tenant_beta", "Beta administrators: all tools in tenant",
     "Tenant administrators may use every tool inside their own tenant (high-risk tools still need approval).",
     "ALLOW", "user", "*", "admin", "*", "*", "*", {}, 10),
    ("pol_beta_researcher_read", "tenant_beta", "Beta researchers: own documents",
     "Researchers may read Beta documents they own (resource-ownership ABAC).",
     "ALLOW", "user", "*", "researcher", "read_document", "read", "doc_beta_*", {"resource_owner": "principal"}, 20),
    ("pol_beta_agent_read", "tenant_beta", "Beta coordinator: delegated read",
     "The Beta coordinator agent may read Beta documents under a delegation.",
     "ALLOW", "agent", "agent_beta_primary", "coordinator", "read_document", "read", "doc_beta_*",
     {"requires_delegation": True}, 50),
    ("pol_beta_subagent_analytics", "tenant_beta", "Beta analytics sub-agent",
     "The analytics sub-agent may run aggregate queries under a delegation.",
     "ALLOW", "agent", "agent_beta_analytics", "analyst", "execute_analytics_query", "execute", "*",
     {"requires_delegation": True, "args": {"query_type": {"in": ["aggregate", "variance"]}}}, 55),
]


def _secret_for(env_value: Optional[str]) -> str:
    return env_value or secrets.token_urlsafe(18)


def seed_database(force: bool = False) -> Optional[Dict[str, Any]]:
    """Creates the schema and demo data. Returns the generated credentials, or None if skipped."""
    from app.delegation.engine import delegation_engine  # local import: engine imports this package

    if force:
        engine.dispose()
        Base.metadata.drop_all(bind=engine)
        gateway_rate_limiter.reset()
        login_rate_limiter.reset()
    init_db()
    with get_db() as db:
        if db.query(Tenant).count() > 0:
            return None

        now = datetime.now(timezone.utc)
        shared = os.getenv("AGENTFENCE_DEMO_PASSWORD") or None
        creds: Dict[str, Any] = {"users": {}, "agents": {}, "delegations": {}}

        db.add_all([Tenant(id=i, name=n, slug=s, description=d, status="active", created_at=now)
                    for i, n, s, d in TENANTS])
        db.flush()
        for uid, tid, username, email, role, is_admin in USERS:
            pwd = _secret_for(shared)
            creds["users"][username] = pwd
            db.add(User(id=uid, tenant_id=tid, username=username, email=email, role=role, is_admin=is_admin,
                        is_active=True, password_hash=security_engine.hash_secret(pwd), created_at=now))
        for aid, tid, name, atype, role, desc in AGENTS:
            secret = _secret_for(shared)
            creds["agents"][aid] = secret
            db.add(Agent(id=aid, tenant_id=tid, name=name, agent_type=atype, role=role, description=desc,
                         is_active=True, client_secret_hash=security_engine.hash_secret(secret), created_at=now))
        for t in TOOLS:
            db.add(MCPTool(id=t["id"], name=t["name"], description=t["description"],
                           parameters_schema_json=json.dumps(t["schema"]), required_scopes_json=json.dumps(t["scopes"]),
                           risk_level=t["risk_level"], action=t["action"], resource_param=t["resource_param"],
                           requires_approval=t["requires_approval"], rate_limit_per_minute=t["rate_limit_per_minute"],
                           upstream_endpoint=f"mock://sample-upstream-mcp/tools/{t['name']}", is_enabled=True,
                           is_quarantined=False, registered_by="seed", created_at=now))
        for rid, tid, name, level, owner, content in RESOURCES:
            db.add(ProtectedResource(id=rid, tenant_id=tid, name=name, resource_type="document",
                                     sensitivity_level=level, owner_id=owner, content=content, created_at=now))
        for (pid_, tid, name, desc, effect, ptype, pid, role, tool, action, res, cond, prio) in POLICIES:
            db.add(Policy(id=pid_, tenant_id=tid, name=name, description=desc, effect=effect, principal_type=ptype,
                          principal_id=pid, role=role, tool_pattern=tool, action_pattern=action, resource_pattern=res,
                          conditions_json=json.dumps(cond), priority=prio, is_active=True, source="seed",
                          created_at=now))
        db.commit()

        # Seed delegation chain, issued through the real engine (so it is audited):
        # alpha_admin (user) -> agent_alpha_primary -> agent_alpha_research
        admin = Principal("usr_alpha_admin", "user", "tenant_alpha", "admin", True)
        root = delegation_engine.create_delegation(
            db, admin, "agent_alpha_primary", ["read_document", "search_knowledge_base"],
            ["doc_alpha_falcon", "doc_alpha_radar"], duration_minutes=settings.MAX_DELEGATION_TTL_MINUTES,
            delegation_id="del_alpha_root_001",
        )
        if not root.ok:
            raise RuntimeError(f"Seed delegation failed: {root.code} {root.message}")
        primary = Principal("agent_alpha_primary", "agent", "tenant_alpha", "coordinator")
        child = delegation_engine.create_delegation(
            db, primary, "agent_alpha_research", ["read_document"], ["doc_alpha_radar"],
            parent_delegation_id="del_alpha_root_001", duration_minutes=settings.MAX_DELEGATION_TTL_MINUTES,
            delegation_id="del_alpha_child_002",
        )
        if not child.ok:
            raise RuntimeError(f"Seed delegation failed: {child.code} {child.message}")
        creds["delegations"] = {"del_alpha_root_001": root.token, "del_alpha_child_002": child.token}

    try:
        CREDENTIALS_FILE.write_text(json.dumps(creds, indent=2), encoding="utf-8")
        print(f"AgentFence demo data seeded. Demo credentials: {CREDENTIALS_FILE}")
    except OSError:
        print("AgentFence demo data seeded (could not write the credentials file).")
    return creds


if __name__ == "__main__":
    seed_database()

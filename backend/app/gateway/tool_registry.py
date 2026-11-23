"""Tool registration with supply-chain checks (tool poisoning, upstream allowlist)."""
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session

from app.audit.service import audit_service
from app.core.auth import Principal
from app.core.config import settings
from app.core.security import security_engine
from app.gateway.tool_guard import RISK_LEVELS, TOOL_NAME_RE, scan_tool_definition, upstream_allowed
from app.models.entities import MCPTool


def serialize_tool(t: MCPTool) -> Dict[str, Any]:
    return {
        "id": t.id,
        "name": t.name,
        "description": t.description,
        "parameters_schema": t.get_parameters_schema(),
        "required_scopes": t.get_required_scopes(),
        "risk_level": t.risk_level,
        "action": t.action,
        "resource_param": t.resource_param,
        "requires_approval": t.requires_approval,
        "rate_limit_per_minute": t.rate_limit_per_minute,
        "upstream_endpoint": t.upstream_endpoint,
        "is_enabled": t.is_enabled,
        "is_quarantined": t.is_quarantined,
        "quarantine_reason": t.quarantine_reason,
        "registered_by": t.registered_by,
    }


def register_tool(db: Session, actor: Principal, spec: Dict[str, Any]) -> Tuple[int, str, str, Optional[MCPTool]]:
    """Validates and registers a tool. Poisoned definitions are stored *quarantined*.

    Returns (http_status, code, message, tool).
    """
    name = str(spec.get("name") or "")
    description = str(spec.get("description") or "")
    schema = spec.get("parameters_schema") or {"type": "object", "properties": {}}
    risk = str(spec.get("risk_level") or "medium")
    action = str(spec.get("action") or "read")
    endpoint = str(spec.get("upstream_endpoint") or "")
    resource_param = spec.get("resource_param")
    rate_limit = spec.get("rate_limit_per_minute")

    error = None
    if not TOOL_NAME_RE.match(name):
        error = "name must match ^[a-z][a-z0-9_]{2,63}$"
    elif not isinstance(schema, dict) or schema.get("type", "object") != "object":
        error = "parameters_schema must be a JSON object schema"
    elif risk not in RISK_LEVELS:
        error = f"risk_level must be one of {list(RISK_LEVELS)}"
    elif not action.isidentifier():
        error = "action must be a simple identifier (e.g. read, search, export)"
    elif not upstream_allowed(endpoint, settings.UPSTREAM_ALLOWLIST):
        error = "upstream_endpoint must be mock:// or an allowlisted http(s) origin (AGENTFENCE_UPSTREAM_ALLOWLIST)"
    elif resource_param is not None and resource_param not in schema.get("properties", {}):
        error = "resource_param must name a declared parameter"
    elif rate_limit is not None and (not isinstance(rate_limit, int) or rate_limit < 1):
        error = "rate_limit_per_minute must be a positive integer"
    elif db.query(MCPTool).filter(MCPTool.name == name).first() is not None:
        error = f"tool '{name}' already exists"
    if error:
        audit_service.log_event(db, event_type="tool.register", tenant_id=actor.tenant_id, user_id=actor.id,
                                mcp_tool_name=name or None, decision="DENY", reason_code="TOOL_REGISTRATION_INVALID",
                                denial_reason=error, execution_outcome="rejected")
        return 400, "TOOL_REGISTRATION_INVALID", error, None

    findings = scan_tool_definition(name, description, schema)
    tool = MCPTool(
        id=security_engine.generate_id("tool"),
        name=name,
        description=description,
        parameters_schema_json=json.dumps(schema),
        required_scopes_json=json.dumps(spec.get("required_scopes") or []),
        risk_level=risk,
        action=action,
        resource_param=resource_param,
        requires_approval=bool(spec.get("requires_approval", risk in ("high", "critical"))),
        rate_limit_per_minute=rate_limit,
        upstream_endpoint=endpoint,
        is_enabled=True,
        is_quarantined=bool(findings),
        quarantine_reason=("Tool poisoning indicators: " + ", ".join(findings)) if findings else None,
        registered_by=actor.id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(tool)
    db.commit()
    code = "TOOL_QUARANTINED" if findings else "TOOL_REGISTERED"
    audit_service.log_event(
        db, event_type="tool.register", tenant_id=actor.tenant_id, user_id=actor.id, mcp_tool_name=name,
        decision="DENY" if findings else "ALLOW", reason_code=code,
        denial_reason=tool.quarantine_reason, attack_classification="tool_poisoning" if findings else None,
        execution_outcome="quarantined" if findings else "registered",
        details={"risk_level": risk, "upstream_endpoint": endpoint, "findings": findings},
    )
    message = tool.quarantine_reason if findings else f"Tool '{name}' registered"
    return 201, code, message, tool

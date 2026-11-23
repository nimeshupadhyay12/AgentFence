"""AgentFence REST management API and MCP HTTP endpoints.

Every management endpoint except ``/health`` and ``/auth/login`` requires a
valid identity token (``Authorization: Bearer ...``); the ``@endpoint``
decorator enforces authentication and function-level authorization *before*
the handler runs, and audits every refusal. Object-level authorization
(tenant scoping) is done inside each handler.
"""
import json
from functools import wraps
from typing import Any, Awaitable, Callable, Dict, Optional

from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse

from app.audit.service import audit_service
from app.core.auth import Principal, authorize_management, issue_token_for, login_agent, login_user, revoke_token
from app.core.config import settings
from app.database.session import get_db
from app.delegation.engine import delegation_engine
from app.gateway import approvals
from app.gateway.interceptor import gateway_interceptor
from app.gateway.tool_registry import register_tool, serialize_tool
from app.mcp.server import mcp_protocol_handler
from app.models.entities import (Agent, ApprovalRequest, AttackSimulationResult, AuditEvent, DelegationGrant,
                                 MCPTool, Policy, Tenant, User)
from app.policies.engine import policy_engine
from app.simulations.engine import attack_simulation_lab

MAX_BODY_BYTES = 64 * 1024
Handler = Callable[[Request, Any, Principal], Awaitable[Response]]


def bearer_token(request: Request) -> Optional[str]:
    header = request.headers.get("Authorization", "")
    if header[:7].lower() == "bearer ":
        return header[7:].strip() or None
    return None


async def read_json(request: Request) -> Optional[Dict[str, Any]]:
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        return None
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def error(status: int, code: str, message: str) -> JSONResponse:
    headers = {"WWW-Authenticate": 'Bearer realm="agentfence"'} if status == 401 else None
    return JSONResponse({"error": message, "code": code}, status_code=status, headers=headers)


def endpoint(admin: bool = False, platform_admin: bool = False):
    """Requires an authenticated principal (optionally a tenant/platform admin)."""
    def decorator(handler: Handler):
        @wraps(handler)
        async def wrapper(request: Request) -> Response:
            with get_db() as db:
                principal, status, code, msg = authorize_management(
                    db, bearer_token(request), require_admin=admin, require_platform_admin=platform_admin,
                    endpoint=f"{request.method} {request.url.path}",
                )
                if principal is None:
                    return error(status, code, msg)
                return await handler(request, db, principal)
        return wrapper
    return decorator


def tenant_scope(principal: Principal, requested: Optional[str]) -> Optional[str]:
    """Platform admins may filter by any tenant (or none); everyone else is pinned to their own."""
    if principal.is_platform_admin:
        return requested or None
    return principal.tenant_id


# --------------------------------------------------------------------- public
async def health(request: Request) -> Response:
    return JSONResponse({
        "status": "healthy",
        "service": "AgentFence Security Gateway",
        "version": settings.VERSION,
        "protocol": "MCP 2024-11-05",
        "environment": settings.ENV,
    })


async def login(request: Request) -> Response:
    body = await read_json(request)
    if body is None:
        return error(400, "INVALID_JSON", "Request body must be a JSON object")
    client = request.client.host if request.client else "unknown"
    with get_db() as db:
        if body.get("agent_id"):
            subject = str(body.get("agent_id"))
            principal, code, msg = login_agent(db, subject, str(body.get("client_secret") or ""), client)
        else:
            subject = str(body.get("username") or "")
            principal, code, msg = login_user(db, subject, str(body.get("password") or ""), client)
        audit_service.log_event(
            db, event_type="auth.login", tenant_id=principal.tenant_id if principal else "unauthenticated",
            user_id=principal.id if principal and principal.type == "user" else None,
            agent_id=principal.id if principal and principal.type == "agent" else None,
            decision="ALLOW" if principal else "DENY", reason_code=code,
            denial_reason=None if principal else msg,
            attack_classification="credential_stuffing" if code == "LOGIN_RATE_LIMITED" else None,
            execution_outcome="token_issued" if principal else "rejected",
            details={"subject": subject[:64], "client": client},
        )
        if principal is None:
            return error(429 if code == "LOGIN_RATE_LIMITED" else 401, code, msg)
        return JSONResponse({
            "access_token": issue_token_for(principal),
            "token_type": "bearer",
            "expires_in": settings.DEFAULT_TOKEN_EXPIRY_MINUTES * 60,
            "principal": principal.to_dict(),
        })


# ----------------------------------------------------------------- session
@endpoint()
async def logout(request: Request, db, principal: Principal) -> Response:
    revoke_token(db, principal)
    audit_service.log_event(db, event_type="auth.logout", tenant_id=principal.tenant_id,
                            user_id=principal.id if principal.type == "user" else None,
                            agent_id=principal.id if principal.type == "agent" else None,
                            decision="ALLOW", reason_code="TOKEN_REVOKED", execution_outcome="token_revoked")
    return JSONResponse({"success": True, "message": "Token revoked"})


@endpoint()
async def me(request: Request, db, principal: Principal) -> Response:
    return JSONResponse(principal.to_dict())


# ----------------------------------------------------------------- registry
@endpoint()
async def list_tenants(request: Request, db, principal: Principal) -> Response:
    query = db.query(Tenant)
    if not principal.is_platform_admin:
        query = query.filter(Tenant.id == principal.tenant_id)
    return JSONResponse([
        {"id": t.id, "name": t.name, "slug": t.slug, "description": t.description, "status": t.status,
         "users_count": len(t.users), "agents_count": len(t.agents), "resources_count": len(t.resources),
         "policies_count": len(t.policies)}
        for t in query.order_by(Tenant.id).all()
    ])


@endpoint()
async def get_tenant_details(request: Request, db, principal: Principal) -> Response:
    tenant_id = request.path_params["id"]
    tenant = db.get(Tenant, tenant_id)
    if tenant is None or not (principal.is_platform_admin or principal.tenant_id == tenant_id):
        return error(404, "TENANT_NOT_FOUND", "Tenant not found")
    detailed = principal.can_manage_tenant(tenant_id)
    return JSONResponse({
        "id": tenant.id, "name": tenant.name, "slug": tenant.slug, "description": tenant.description,
        "status": tenant.status,
        "users": [{"id": u.id, "username": u.username, "role": u.role, **({"email": u.email} if detailed else {})}
                  for u in tenant.users],
        "agents": [{"id": a.id, "name": a.name, "type": a.agent_type, "role": a.role, "active": a.is_active}
                   for a in tenant.agents],
        "resources": [{"id": r.id, "name": r.name, "sensitivity": r.sensitivity_level} for r in tenant.resources],
        "policies": [{"id": p.id, "name": p.name, "effect": p.effect, "tool_pattern": p.tool_pattern}
                     for p in tenant.policies] if detailed else [],
    })


@endpoint()
async def list_agents(request: Request, db, principal: Principal) -> Response:
    scope = tenant_scope(principal, request.query_params.get("tenant_id"))
    query = db.query(Agent)
    if scope:
        query = query.filter(Agent.tenant_id == scope)
    return JSONResponse([
        {"id": a.id, "tenant_id": a.tenant_id, "name": a.name, "agent_type": a.agent_type, "role": a.role,
         "description": a.description, "is_active": a.is_active}
        for a in query.order_by(Agent.id).all()
    ])


@endpoint()
async def list_tools(request: Request, db, principal: Principal) -> Response:
    return JSONResponse([serialize_tool(t) for t in db.query(MCPTool).order_by(MCPTool.name).all()])


@endpoint(platform_admin=True)
async def create_tool(request: Request, db, principal: Principal) -> Response:
    body = await read_json(request)
    if body is None:
        return error(400, "INVALID_JSON", "Request body must be a JSON object")
    status, code, message, tool = register_tool(db, principal, body)
    if tool is None:
        return error(status, code, message)
    return JSONResponse({"code": code, "message": message, "tool": serialize_tool(tool)}, status_code=status)


# --------------------------------------------------------------- delegation
@endpoint()
async def create_delegation(request: Request, db, principal: Principal) -> Response:
    body = await read_json(request)
    if body is None:
        return error(400, "INVALID_JSON", "Request body must be a JSON object")
    ignored = sorted(k for k in ("delegating_agent_id", "tenant_id", "permitted_actions", "audience") if k in body)
    max_depth = body.get("max_depth")
    result = delegation_engine.create_delegation(
        db,
        delegator=principal,  # always the authenticated caller
        receiving_agent_id=str(body.get("receiving_agent_id") or ""),
        permitted_tools=body.get("permitted_tools") if isinstance(body.get("permitted_tools"), list) else [],
        resource_restrictions=body.get("resource_restrictions") if isinstance(body.get("resource_restrictions"), list) else [],
        parent_delegation_id=body.get("parent_delegation_id") or None,
        duration_minutes=body.get("duration_minutes", 60),
        is_single_use=bool(body.get("is_single_use", False)),
        max_depth=int(max_depth) if isinstance(max_depth, int) else None,
    )
    if not result.ok:
        return JSONResponse({"success": False, "code": result.code, "error": result.message,
                             "audit_event_id": result.audit_event_id}, status_code=403)
    return JSONResponse({
        "success": True,
        **delegation_engine.serialize(result.grant),
        # Returned exactly once. Only its SHA-256 fingerprint is stored.
        "delegation_token": result.token,
        "ignored_fields": ignored,
        "audit_event_id": result.audit_event_id,
    }, status_code=201)


@endpoint()
async def list_delegations(request: Request, db, principal: Principal) -> Response:
    query = db.query(DelegationGrant)
    if principal.is_platform_admin:
        if request.query_params.get("tenant_id"):
            query = query.filter(DelegationGrant.tenant_id == request.query_params["tenant_id"])
    elif principal.is_tenant_admin:
        query = query.filter(DelegationGrant.tenant_id == principal.tenant_id)
    else:
        query = query.filter(DelegationGrant.tenant_id == principal.tenant_id).filter(
            (DelegationGrant.original_user_id == principal.id)
            | (DelegationGrant.delegating_agent_id == principal.id)
            | (DelegationGrant.receiving_agent_id == principal.id)
        )
    grants = query.order_by(DelegationGrant.created_at.desc()).limit(500).all()
    return JSONResponse([delegation_engine.serialize(g) for g in grants])


@endpoint()
async def revoke_delegation(request: Request, db, principal: Principal) -> Response:
    status, code, message = delegation_engine.revoke(db, principal, request.path_params["id"])
    if status != 200:
        return error(status, code, message)
    return JSONResponse({"success": True, "code": code, "message": message})


# ----------------------------------------------------------------- policies
def _serialize_policy(p: Policy) -> Dict[str, Any]:
    return {"id": p.id, "tenant_id": p.tenant_id, "name": p.name, "description": p.description, "effect": p.effect,
            "principal_type": p.principal_type, "principal_id": p.principal_id, "role": p.role,
            "tool_pattern": p.tool_pattern, "action_pattern": p.action_pattern,
            "resource_pattern": p.resource_pattern, "conditions": p.get_conditions(), "priority": p.priority,
            "is_active": p.is_active}


@endpoint(admin=True)
async def list_policies(request: Request, db, principal: Principal) -> Response:
    scope = tenant_scope(principal, request.query_params.get("tenant_id"))
    query = db.query(Policy)
    if scope:
        query = query.filter(Policy.tenant_id == scope)
    return JSONResponse([_serialize_policy(p) for p in query.order_by(Policy.tenant_id, Policy.priority).all()])


@endpoint(admin=True)
async def toggle_policy(request: Request, db, principal: Principal) -> Response:
    policy = db.get(Policy, request.path_params["id"])
    if policy is None or not principal.can_manage_tenant(policy.tenant_id):
        return error(404, "POLICY_NOT_FOUND", "Policy not found")
    policy.is_active = not policy.is_active
    db.commit()
    audit_service.log_event(db, event_type="policy.toggle", tenant_id=policy.tenant_id, user_id=principal.id,
                            decision="ALLOW", reason_code="POLICY_ENABLED" if policy.is_active else "POLICY_DISABLED",
                            execution_outcome="updated",
                            details={"policy_id": policy.id, "is_active": policy.is_active})
    return JSONResponse({"id": policy.id, "name": policy.name, "is_active": policy.is_active})


@endpoint(admin=True)
async def simulate_policy(request: Request, db, principal: Principal) -> Response:
    """Dry-run of the policy decision point. Role and action are looked up server-side."""
    body = await read_json(request)
    if body is None:
        return error(400, "INVALID_JSON", "Request body must be a JSON object")
    tenant_id = tenant_scope(principal, body.get("tenant_id")) or principal.tenant_id
    subject_id = str(body.get("principal_id") or "")
    subject = db.get(Agent, subject_id) or db.query(User).filter(User.id == subject_id).first()
    if subject is None or subject.tenant_id != tenant_id:
        return error(404, "PRINCIPAL_NOT_FOUND", f"Principal '{subject_id}' not found in tenant '{tenant_id}'")
    tool = db.query(MCPTool).filter(MCPTool.name == str(body.get("tool_name") or "")).first()
    if tool is None:
        return error(404, "TOOL_NOT_FOUND", "Tool not found")
    is_agent = isinstance(subject, Agent)
    decision = policy_engine.evaluate(
        db=db, principal_id=subject.id, principal_type="agent" if is_agent else "user", principal_role=subject.role,
        acting_agent_id=subject.id if is_agent else None, tenant_id=tenant_id, tool_name=tool.name,
        requested_action=tool.action, resource_id=body.get("resource_id") or None,
        delegation_payload={"simulated": True, "cur_depth": 1} if body.get("assume_delegation") else None,
        correlation_id=f"simulate_{principal.id}",
        arguments=body.get("arguments") if isinstance(body.get("arguments"), dict) else {},
    )
    return JSONResponse({**decision.to_dict(), "requires_approval": tool.requires_approval})


# ---------------------------------------------------------------- approvals
@endpoint()
async def list_approvals(request: Request, db, principal: Principal) -> Response:
    query = db.query(ApprovalRequest)
    if principal.is_platform_admin:
        pass
    elif principal.is_tenant_admin:
        query = query.filter(ApprovalRequest.tenant_id == principal.tenant_id)
    else:
        query = query.filter(ApprovalRequest.requester_id == principal.id)
    status = request.query_params.get("status")
    if status:
        query = query.filter(ApprovalRequest.status == status.upper())
    return JSONResponse([approvals.serialize(a) for a in
                         query.order_by(ApprovalRequest.created_at.desc()).limit(200).all()])


@endpoint(admin=True)
async def decide_approval(request: Request, db, principal: Principal) -> Response:
    body = await read_json(request)
    if body is None or body.get("decision") not in ("approve", "deny"):
        return error(400, "INVALID_REQUEST", "Body must be {\"decision\": \"approve\" | \"deny\", \"note\": \"...\"}")
    status, code, message = approvals.decide(db, principal, request.path_params["id"],
                                             body["decision"] == "approve", body.get("note"))
    if status != 200:
        return error(status, code, message)
    return JSONResponse({"success": True, "code": code, "message": message})


# -------------------------------------------------------------------- audit
def _serialize_event(e: AuditEvent) -> Dict[str, Any]:
    data = audit_service.serialize(e)
    data["tool"] = e.mcp_tool_name
    data["action"] = e.requested_action
    return data


@endpoint(admin=True)
async def list_audit_events(request: Request, db, principal: Principal) -> Response:
    try:
        limit = max(1, min(int(request.query_params.get("limit", 100)), 1000))
    except ValueError:
        limit = 100
    query = db.query(AuditEvent)
    scope = tenant_scope(principal, request.query_params.get("tenant_id"))
    if scope:
        query = query.filter(AuditEvent.tenant_id == scope)
    for param, column in (("tool", AuditEvent.mcp_tool_name), ("decision", AuditEvent.decision),
                          ("event_type", AuditEvent.event_type)):
        if request.query_params.get(param):
            query = query.filter(column == request.query_params[param])
    return JSONResponse([_serialize_event(e) for e in query.order_by(AuditEvent.seq.desc()).limit(limit).all()])


@endpoint(admin=True)
async def verify_audit_integrity(request: Request, db, principal: Principal) -> Response:
    valid, count, err = audit_service.verify_audit_chain_integrity(db)
    head = db.query(AuditEvent).order_by(AuditEvent.seq.desc()).first()
    return JSONResponse({
        "is_valid": valid,
        "records_verified": count,
        "chain_head_hash": head.record_hash if head else None,
        "error_details": err,
        "message": "Audit ledger integrity verified." if valid else "Audit tampering detected!",
    })


@endpoint(platform_admin=True)
async def export_audit(request: Request, db, principal: Principal) -> Response:
    lines = list(audit_service.export_jsonl(db, request.query_params.get("tenant_id")))
    return StreamingResponse(iter(lines), media_type="application/x-ndjson",
                             headers={"Content-Disposition": "attachment; filename=agentfence-audit.jsonl"})


@endpoint(admin=True)
async def get_security_metrics(request: Request, db, principal: Principal) -> Response:
    return JSONResponse(audit_service.get_security_metrics(db, tenant_scope(principal, request.query_params.get("tenant_id"))))


# -------------------------------------------------------------- simulations
@endpoint()
async def simulation_catalog(request: Request, db, principal: Principal) -> Response:
    return JSONResponse(attack_simulation_lab.catalog())


@endpoint(platform_admin=True)
async def run_simulations(request: Request, db, principal: Principal) -> Response:
    key = request.query_params.get("scenario")
    if key:
        if not attack_simulation_lab.has(key):
            return error(400, "UNKNOWN_SCENARIO", f"Unknown scenario key '{key}'")
        return JSONResponse([attack_simulation_lab.run(db, key)])
    return JSONResponse(attack_simulation_lab.run_all_simulations(db))


@endpoint(platform_admin=True)
async def list_simulation_results(request: Request, db, principal: Principal) -> Response:
    sims = db.query(AttackSimulationResult).order_by(AttackSimulationResult.executed_at.desc()).limit(100).all()
    return JSONResponse([
        {"id": s.id, "simulation_key": s.simulation_key, "scenario_name": s.scenario_name,
         "expected_result": s.expected_result, "actual_result": s.actual_result, "passed": s.passed,
         "request_details": json.loads(s.request_details_json), "checks_evaluated": json.loads(s.checks_evaluated_json),
         "audit_event_id": s.audit_event_id, "executed_at": s.executed_at.isoformat()}
        for s in sims
    ])


# ---------------------------------------------------------------- MCP (HTTP)
_STATUS_FOR = {"ALLOW": 200, "PENDING": 202}
_AUTHN_CODES = {"AUTHN_MISSING_IDENTITY", "TOKEN_REVOKED", "PRINCIPAL_UNKNOWN", "PRINCIPAL_INACTIVE"}


async def mcp_tool_call(request: Request) -> Response:
    """REST convenience wrapper around the same pipeline as JSON-RPC tools/call."""
    body = await read_json(request)
    if body is None:
        return error(400, "INVALID_JSON", "Request body must be a JSON object")
    with get_db() as db:
        result = gateway_interceptor.process_tool_invocation(
            db=db,
            tool_name=body.get("tool_name"),
            arguments=body.get("arguments", {}),
            identity_token=bearer_token(request),
            delegation_token=request.headers.get("X-Delegation-Token"),
            approval_id=body.get("approval_id"),
        )
    code = result["reason_code"]
    if result["decision"] in _STATUS_FOR:
        status = _STATUS_FOR[result["decision"]]
    elif code in _AUTHN_CODES or code.startswith("TOKEN_"):
        status = 401
    elif code == "RATE_LIMIT_EXCEEDED":
        status = 429
    else:
        status = 403
    return JSONResponse(result, status_code=status)


async def mcp_jsonrpc_endpoint(request: Request) -> Response:
    body = await read_json(request)
    if body is None:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                            status_code=400)
    with get_db() as db:
        response = mcp_protocol_handler.handle_jsonrpc(
            db=db,
            request_data=body,
            identity_token=bearer_token(request),
            delegation_token=request.headers.get("X-Delegation-Token"),
        )
    if response is None:
        return Response(status_code=202)
    status = 401 if response.get("error", {}).get("code") == -32001 else 200
    return JSONResponse(response, status_code=status)

"""AgentFence MCP JSON-RPC 2.0 front end (MCP protocol revision 2024-11-05).

Supported methods: ``initialize``, ``notifications/initialized``, ``ping``,
``tools/list`` (filtered per caller) and ``tools/call`` (full gateway
pipeline). ``initialize``/``ping`` need no credentials; the ``tools/*``
methods require a valid identity token.

Credentials travel in HTTP headers only: ``Authorization: Bearer <identity>``
and ``X-Delegation-Token: <delegation credential>``. An approval for a
high-risk tool is passed as ``params._meta.approvalId``.
"""
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.core.auth import authenticate_token
from app.core.config import settings
from app.core.security import security_engine
from app.gateway.interceptor import gateway_interceptor
from app.models.entities import MCPTool
from app.policies.engine import policy_engine

JSONRPC_UNAUTHORIZED = -32001


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


class MCPProtocolHandler:
    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self) -> None:
        self.interceptor = gateway_interceptor

    def list_tools_for(self, db: Session, identity_token: Optional[str],
                       delegation_token: Optional[str]) -> Optional[list]:
        """Tools the caller could plausibly use; None if unauthenticated."""
        principal, _, _ = authenticate_token(db, identity_token)
        if principal is None:
            return None
        delegated_tools = None
        if delegation_token:
            ok, payload, _, _ = security_engine.verify_delegation_credential(delegation_token)
            if ok and payload and payload.get("rcv_aid") == principal.id and payload.get("tid") == principal.tenant_id:
                delegated_tools = set(payload.get("tools") or [])
            else:
                delegated_tools = set()
        visible = []
        for tool in db.query(MCPTool).filter(MCPTool.is_enabled.is_(True), MCPTool.is_quarantined.is_(False)) \
                .order_by(MCPTool.name).all():
            if delegated_tools is not None and tool.name not in delegated_tools:
                continue
            if not policy_engine.may_discover_tool(db, principal.id, principal.type, principal.role,
                                                   principal.tenant_id, tool):
                continue
            visible.append({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.get_parameters_schema(),
                "annotations": {"riskLevel": tool.risk_level, "requiresApproval": tool.requires_approval},
            })
        return visible

    def handle_jsonrpc(
        self,
        db: Session,
        request_data: Any,
        identity_token: Optional[str] = None,
        delegation_token: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Processes one JSON-RPC 2.0 message. Returns None for notifications."""
        if not isinstance(request_data, dict) or request_data.get("jsonrpc") != "2.0" \
                or not isinstance(request_data.get("method"), str):
            return _error(request_data.get("id") if isinstance(request_data, dict) else None,
                          -32600, "Invalid Request")
        req_id = request_data.get("id")
        method = request_data["method"]
        params = request_data.get("params") or {}
        if not isinstance(params, dict):
            return _error(req_id, -32602, "params must be an object")
        is_notification = "id" not in request_data

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "AgentFence Security Gateway", "version": settings.VERSION},
                },
            }
        if method.startswith("notifications/"):
            return None  # notifications never get a response
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            tools = self.list_tools_for(db, identity_token, delegation_token)
            if tools is None:
                return _error(req_id, JSONRPC_UNAUTHORIZED, "Unauthorized: a valid identity token is required")
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}}

        if method == "tools/call":
            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                return _error(req_id, -32602, "Missing 'name' in tools/call params")
            meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
            result = self.interceptor.process_tool_invocation(
                db=db,
                tool_name=tool_name,
                arguments=params.get("arguments", {}),
                identity_token=identity_token,
                delegation_token=delegation_token,
                approval_id=meta.get("approvalId"),
                correlation_id=meta.get("correlationId"),
            )
            if is_notification:
                return None
            gateway = {
                "decision": result["decision"],
                "reasonCode": result["reason_code"],
                "correlationId": result["correlation_id"],
                "auditEventId": result["audit_event_id"],
            }
            if result.get("approval_id"):
                gateway["approvalId"] = result["approval_id"]
            if not result["authorized"]:
                # MCP convention: tool-level failures are results with isError.
                return {"jsonrpc": "2.0", "id": req_id, "result": {
                    "isError": True, "content": result["content"], "_meta": {"agentfence": gateway}}}
            upstream = result.get("result") or {}
            return {"jsonrpc": "2.0", "id": req_id, "result": {
                "isError": bool(upstream.get("isError", False)),
                "content": upstream.get("content", []),
                "_meta": {"agentfence": gateway},
            }}

        return _error(req_id, -32601, f"Method '{method}' not found")


mcp_protocol_handler = MCPProtocolHandler()

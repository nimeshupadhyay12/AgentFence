"""Upstream routing: where an *authorized* tool call is actually executed.

* ``mock://...``   -> the in-process demo upstream (:mod:`app.mcp.upstream_mock`).
  This is the default for the seeded demo tools.
* ``http(s)://...`` -> forwarded as an MCP JSON-RPC ``tools/call`` to a real
  MCP server, but only if the endpoint's origin is in
  ``AGENTFENCE_UPSTREAM_ALLOWLIST`` (fail closed; prevents the registry from
  being abused for SSRF). The caller's identity and delegation tokens are
  never forwarded upstream: the upstream only sees the gateway.
* Anything else is refused.
"""
import itertools
from typing import Any, Dict, Optional

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.gateway.tool_guard import upstream_allowed
from app.mcp.upstream_mock import upstream_mcp_server
from app.models.entities import MCPTool


def _error(text: str, code: str) -> Dict[str, Any]:
    return {"isError": True, "content": [{"type": "text", "text": text}], "gatewayError": code}


class UpstreamRouter:
    def __init__(self, transport: Optional[httpx.BaseTransport] = None) -> None:
        self.mock = upstream_mcp_server
        self.transport = transport  # injectable for tests
        self._ids = itertools.count(1)

    def execute(self, db: Session, tool: MCPTool, arguments: Dict[str, Any], tenant_id: str,
                principal_id: str, correlation_id: str) -> Dict[str, Any]:
        endpoint = tool.upstream_endpoint or ""
        if endpoint.startswith("mock://"):
            return self.mock.execute_tool(db=db, tool_name=tool.name, arguments=arguments, tenant_id=tenant_id)
        if not upstream_allowed(endpoint, settings.UPSTREAM_ALLOWLIST):
            return _error(f"Upstream '{endpoint}' is not allowlisted", "UPSTREAM_NOT_ALLOWLISTED")

        request = {
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": "tools/call",
            "params": {"name": tool.name, "arguments": arguments},
        }
        headers = {
            # Context for the upstream's own logging; never the caller's credentials.
            "X-AgentFence-Tenant": tenant_id,
            "X-AgentFence-Principal": principal_id,
            "X-AgentFence-Correlation-Id": correlation_id,
        }
        try:
            with httpx.Client(timeout=settings.UPSTREAM_TIMEOUT_SECONDS, transport=self.transport,
                              follow_redirects=False) as client:
                resp = client.post(endpoint, json=request, headers=headers)
        except httpx.HTTPError as exc:
            return _error(f"Upstream unavailable: {exc.__class__.__name__}", "UPSTREAM_UNAVAILABLE")
        if resp.status_code != 200:
            return _error(f"Upstream returned HTTP {resp.status_code}", "UPSTREAM_ERROR")
        try:
            body = resp.json()
        except ValueError:
            return _error("Upstream returned invalid JSON", "UPSTREAM_ERROR")
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or body.get("id") != request["id"]:
            return _error("Upstream returned an invalid JSON-RPC response", "UPSTREAM_ERROR")
        if "error" in body:
            message = str((body.get("error") or {}).get("message", "unknown error"))[:500]
            return _error(f"Upstream error: {message}", "UPSTREAM_ERROR")
        result = body.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("content", []), list):
            return _error("Upstream result is not a valid MCP tool result", "UPSTREAM_ERROR")
        return {"isError": bool(result.get("isError", False)), "content": result.get("content", [])}


upstream_router = UpstreamRouter()

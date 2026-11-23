"""A tiny *real* MCP server (JSON-RPC over HTTP) to demo AgentFence's upstream mode.

    python scripts/sample_upstream_mcp.py          # listens on http://127.0.0.1:8001/mcp

Then, as the platform admin, register a tool that points at it (the origin
must be in AGENTFENCE_UPSTREAM_ALLOWLIST, default http://127.0.0.1:8001):

    POST /api/v1/tools
    {"name": "lookup_cve", "description": "Look up a CVE summary.",
     "parameters_schema": {"type": "object", "properties": {"cve_id": {"type": "string",
                           "pattern": "^CVE-[0-9]{4}-[0-9]{4,7}$"}}, "required": ["cve_id"]},
     "risk_level": "low", "action": "read", "upstream_endpoint": "http://127.0.0.1:8001/mcp"}

Add a policy allowing the tool, and authorized tools/call requests are
forwarded here; denied ones never reach this process.
"""
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

CVES = {
    "CVE-2021-44228": "Log4Shell: JNDI lookup in Apache Log4j 2 allows remote code execution.",
    "CVE-2024-3094": "xz-utils backdoor: malicious code in liblzma 5.6.0/5.6.1 build scripts.",
}

TOOLS = [{
    "name": "lookup_cve",
    "description": "Look up a CVE summary.",
    "inputSchema": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
}]


async def mcp(request: Request):
    msg = await request.json()
    rid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "sample-upstream", "version": "1.0"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call" and params.get("name") == "lookup_cve":
        cve = str((params.get("arguments") or {}).get("cve_id", ""))
        text = CVES.get(cve, f"{cve}: not in the sample dataset")
        # The gateway identifies the caller; this server never sees client tokens.
        text += f" (requested via AgentFence by {request.headers.get('X-AgentFence-Principal', 'unknown')})"
        result = {"content": [{"type": "text", "text": text}], "isError": False}
    else:
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}})
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": result})


app = Starlette(routes=[Route("/mcp", mcp, methods=["POST"])])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)

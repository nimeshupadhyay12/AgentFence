"""AgentFence ASGI application: REST management API, MCP gateway endpoints and dashboard."""
from contextlib import asynccontextmanager
from pathlib import Path

from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, HTMLResponse, FileResponse
from starlette.staticfiles import StaticFiles

from app.core.config import settings
from app.database.session import init_db
from app.database.seed import seed_database
from app.api import routes

# Base paths
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

# (method, path, handler, auth, summary). auth: public | authenticated | tenant_admin | platform_admin | mcp
ROUTE_TABLE = [
    ("GET", "/api/v1/health", routes.health, "public", "Gateway health"),
    ("POST", "/api/v1/auth/login", routes.login, "public", "Exchange user password or agent client secret for a 15-minute identity token"),
    ("POST", "/api/v1/auth/logout", routes.logout, "authenticated", "Revoke the presented identity token (jti denylist)"),
    ("GET", "/api/v1/auth/me", routes.me, "authenticated", "Who am I"),
    ("GET", "/api/v1/tenants", routes.list_tenants, "authenticated", "Tenants visible to the caller"),
    ("GET", "/api/v1/tenants/{id}", routes.get_tenant_details, "authenticated", "Tenant details (own tenant only)"),
    ("GET", "/api/v1/agents", routes.list_agents, "authenticated", "Agents in the caller's tenant"),
    ("GET", "/api/v1/tools", routes.list_tools, "authenticated", "MCP tool registry"),
    ("POST", "/api/v1/tools", routes.create_tool, "platform_admin", "Register a tool (poisoned definitions are quarantined)"),
    ("GET", "/api/v1/delegations", routes.list_delegations, "authenticated", "Delegation grants visible to the caller (no raw tokens)"),
    ("POST", "/api/v1/delegations", routes.create_delegation, "authenticated", "Issue a delegation as the caller (attenuated; token returned once)"),
    ("POST", "/api/v1/delegations/revoke/{id}", routes.revoke_delegation, "authenticated", "Revoke a grant (tenant admin, original user or delegator)"),
    ("GET", "/api/v1/policies", routes.list_policies, "tenant_admin", "Policies of the caller's tenant"),
    ("POST", "/api/v1/policies/{id}/toggle", routes.toggle_policy, "tenant_admin", "Enable/disable a policy (audited)"),
    ("POST", "/api/v1/policies/simulate", routes.simulate_policy, "tenant_admin", "Dry-run the policy decision point"),
    ("GET", "/api/v1/approvals", routes.list_approvals, "authenticated", "Approval requests (admins: tenant; others: own)"),
    ("POST", "/api/v1/approvals/{id}/decision", routes.decide_approval, "tenant_admin", "Approve or deny a high-risk call (not your own)"),
    ("GET", "/api/v1/audit/events", routes.list_audit_events, "tenant_admin", "Hash-chained audit events"),
    ("GET", "/api/v1/audit/verify", routes.verify_audit_integrity, "tenant_admin", "Verify the audit hash chain"),
    ("GET", "/api/v1/audit/export", routes.export_audit, "platform_admin", "Export the ledger as JSON Lines"),
    ("GET", "/api/v1/metrics/overview", routes.get_security_metrics, "tenant_admin", "Security metrics"),
    ("GET", "/api/v1/simulations/catalog", routes.simulation_catalog, "authenticated", "Attack scenario catalog"),
    ("POST", "/api/v1/simulations/run", routes.run_simulations, "platform_admin", "Run all (or ?scenario=key) attack simulations"),
    ("GET", "/api/v1/simulations/results", routes.list_simulation_results, "platform_admin", "Recent simulation results"),
    ("POST", "/mcp/v1/jsonrpc", routes.mcp_jsonrpc_endpoint, "mcp", "MCP JSON-RPC 2.0 (initialize, ping, tools/list, tools/call)"),
    ("POST", "/mcp/v1/call", routes.mcp_tool_call, "mcp", "REST wrapper for a single tool call"),
]


def generate_openapi_spec():
    paths: dict = {}
    for method, path, _handler, auth, summary in ROUTE_TABLE:
        op = {"summary": summary, "x-agentfence-auth": auth, "responses": {"200": {"description": "OK"}}}
        if auth != "public":
            op["security"] = [{"bearerAuth": []}]
            op["responses"]["401"] = {"description": "Missing/invalid identity token"}
        if auth in ("tenant_admin", "platform_admin"):
            op["responses"]["403"] = {"description": f"Requires {auth.replace('_', ' ')}"}
        paths.setdefault(path, {})[method.lower()] = op
    return {
        "openapi": "3.0.3",
        "info": {"title": settings.PROJECT_NAME, "version": settings.VERSION, "description": settings.DESCRIPTION},
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}},
        "paths": paths,
    }


async def openapi_json(request):
    return JSONResponse(generate_openapi_spec())


async def swagger_docs(request):
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{settings.PROJECT_NAME} - Interactive API Docs</title>
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body style="margin: 0; background: #0b1120;">
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.ui = SwaggerUIBundle({{
            url: '/openapi.json',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [SwaggerUIBundle.presets.apis]
        }});
    </script>
</body>
</html>"""
    return HTMLResponse(html)

api_routes = [Route(path, handler, methods=[method]) for method, path, handler, _auth, _summary in ROUTE_TABLE]
api_routes += [
    Route("/openapi.json", openapi_json, methods=["GET"]),
    Route("/docs", swagger_docs, methods=["GET"]),
]

# Static UI serving (if built)
async def serve_spa(request):
    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>AgentFence Security Gateway API Running</h1><p>Visit <a href='/docs'>/docs</a> for interactive OpenAPI documentation.</p>")

if FRONTEND_DIST.exists():
    api_routes.append(Mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets"))
api_routes.append(Route("/", serve_spa, methods=["GET"]))

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response


middleware = [
    Middleware(SecurityHeadersMiddleware),
    Middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,  # explicit list, never "*"
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Delegation-Token"],
        allow_credentials=False,  # bearer tokens, no cookies
    ),
]


@asynccontextmanager
async def lifespan(app):
    init_db()
    if settings.SEED_DEMO_DATA:
        seed_database()
    yield


app = Starlette(debug=settings.DEBUG, routes=api_routes, middleware=middleware, lifespan=lifespan)

if __name__ == "__main__":
    import uvicorn
    print(f"Starting {settings.PROJECT_NAME} Gateway on http://{settings.HOST}:{settings.PORT}")
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)

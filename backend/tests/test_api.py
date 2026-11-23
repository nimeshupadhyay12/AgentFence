"""HTTP-level tests: authentication, function/object-level authorization and the MCP endpoints."""
import pytest
from starlette.testclient import TestClient

from app.main import ROUTE_TABLE, app
from app.models.entities import AuditEvent

client = TestClient(app)


def login(creds, username=None, agent_id=None):
    if agent_id:
        body = {"agent_id": agent_id, "client_secret": creds["agents"][agent_id]}
    else:
        body = {"username": username, "password": creds["users"][username]}
    resp = client.post("/api/v1/auth/login", json=body)
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def fill(path):
    return path.replace("{id}", "x")


@pytest.mark.parametrize("method,path", [(m, p) for m, p, _h, auth, _s in ROUTE_TABLE
                                         if auth not in ("public", "mcp")])
def test_every_management_endpoint_requires_a_token(method, path, db):
    before = db.query(AuditEvent).filter(AuditEvent.event_type == "api.access_denied").count()
    resp = client.request(method, fill(path), json={})
    assert resp.status_code == 401
    assert resp.headers.get("WWW-Authenticate", "").startswith("Bearer")
    db.expire_all()
    assert db.query(AuditEvent).filter(AuditEvent.event_type == "api.access_denied").count() == before + 1


@pytest.mark.parametrize("method,path", [(m, p) for m, p, _h, auth, _s in ROUTE_TABLE
                                         if auth in ("tenant_admin", "platform_admin")])
def test_admin_endpoints_reject_agents(method, path, demo_credentials):
    headers = login(demo_credentials, agent_id="agent_alpha_untrusted")
    assert client.request(method, fill(path), json={}, headers=headers).status_code == 403


def test_login_requires_valid_credentials(demo_credentials):
    assert client.post("/api/v1/auth/login", json={"username": "alpha_admin", "password": "wrong"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"username": "alpha_admin"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"username": "nobody", "password": "x"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"agent_id": "agent_alpha_primary"}).status_code == 401
    me = client.get("/api/v1/auth/me", headers=login(demo_credentials, "alpha_admin")).json()
    assert me["id"] == "usr_alpha_admin" and me["is_admin"] is True and me["is_platform_admin"] is False


def test_login_is_rate_limited(demo_credentials):
    codes = [client.post("/api/v1/auth/login", json={"username": "alpha_analyst", "password": "bad"}).status_code
             for _ in range(12)]
    assert codes[:10] == [401] * 10 and codes[-1] == 429


def test_logout_revokes_the_token(demo_credentials):
    headers = login(demo_credentials, "alpha_analyst")
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 401 and resp.json()["code"] == "TOKEN_REVOKED"


def test_delegator_is_the_authenticated_caller(demo_credentials):
    headers = login(demo_credentials, "alpha_admin")
    resp = client.post("/api/v1/delegations", headers=headers, json={
        "delegating_agent_id": "nobody_checked", "tenant_id": "tenant_beta", "receiving_agent_id": "agent_alpha_primary",
        "permitted_tools": ["read_document"], "resource_restrictions": ["doc_alpha_radar"], "duration_minutes": 5})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["delegating_agent_id"] == "usr_alpha_admin" and body["tenant_id"] == "tenant_alpha"
    assert body["delegation_token"] and set(body["ignored_fields"]) == {"delegating_agent_id", "tenant_id"}
    listed = client.get("/api/v1/delegations", headers=headers).json()
    assert listed and all("delegation_token" not in g and "signature" not in g for g in listed)
    assert body["delegation_token"] not in str(listed)


def test_delegation_listing_is_scoped(demo_credentials):
    beta = client.get("/api/v1/delegations", headers=login(demo_credentials, "beta_admin")).json()
    assert all(g["tenant_id"] == "tenant_beta" for g in beta)
    research = client.get("/api/v1/delegations", headers=login(demo_credentials, agent_id="agent_alpha_research")).json()
    assert research and all("agent_alpha_research" in (g["receiving_agent_id"], g["delegating_agent_id"])
                            for g in research)


def test_revocation_and_policy_toggle_are_tenant_scoped(demo_credentials):
    beta = login(demo_credentials, "beta_admin")
    assert client.post("/api/v1/delegations/revoke/del_alpha_root_001", headers=beta).status_code == 404
    assert client.post("/api/v1/policies/pol_alpha_admin_all/toggle", headers=beta).status_code == 404
    alpha = login(demo_credentials, "alpha_admin")
    on = client.post("/api/v1/policies/pol_alpha_analyst_search/toggle", headers=alpha).json()
    off = client.post("/api/v1/policies/pol_alpha_analyst_search/toggle", headers=alpha).json()
    assert on["is_active"] is False and off["is_active"] is True
    events = client.get("/api/v1/audit/events?event_type=policy.toggle", headers=alpha).json()
    assert len(events) >= 2 and all(e["tenant_id"] == "tenant_alpha" for e in events)


def test_tenant_admin_sees_only_own_tenant(demo_credentials):
    headers = login(demo_credentials, "alpha_admin")
    assert [t["id"] for t in client.get("/api/v1/tenants", headers=headers).json()] == ["tenant_alpha"]
    assert client.get("/api/v1/tenants/tenant_beta", headers=headers).status_code == 404
    assert {a["tenant_id"] for a in client.get("/api/v1/agents?tenant_id=tenant_beta", headers=headers).json()} \
        == {"tenant_alpha"}
    secops = login(demo_credentials, "secops_admin")
    assert len(client.get("/api/v1/tenants", headers=secops).json()) == 3


def test_admin_override_allow_path_with_independent_approval(demo_credentials):
    admin = login(demo_credentials, "alpha_admin")
    body = {"tool_name": "admin_override", "arguments": {"action": "diagnostics"}}
    first = client.post("/mcp/v1/call", headers=admin, json=body)
    assert first.status_code == 202 and first.json()["decision"] == "PENDING"
    approval_id = first.json()["approval_id"]
    selfie = client.post(f"/api/v1/approvals/{approval_id}/decision", headers=admin, json={"decision": "approve"})
    assert selfie.status_code == 403
    secops = login(demo_credentials, "secops_admin")
    ok = client.post(f"/api/v1/approvals/{approval_id}/decision", headers=secops, json={"decision": "approve"})
    assert ok.status_code == 200
    done = client.post("/mcp/v1/call", headers=admin, json={**body, "approval_id": approval_id})
    assert done.status_code == 200 and done.json()["decision"] == "ALLOW"
    assert "ADMIN OVERRIDE EXECUTED" in done.json()["result"]["content"][0]["text"]
    again = client.post("/mcp/v1/call", headers=admin, json={**body, "approval_id": approval_id})
    assert again.status_code == 403 and again.json()["reason_code"] == "APPROVAL_ALREADY_USED"


def test_jsonrpc_mcp_flow(demo_credentials):
    init = client.post("/mcp/v1/jsonrpc", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init.json()["result"]["protocolVersion"] == "2024-11-05"
    note = client.post("/mcp/v1/jsonrpc", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert note.status_code == 202 and note.content == b""
    anon = client.post("/mcp/v1/jsonrpc", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert anon.status_code == 401 and anon.json()["error"]["code"] == -32001
    bad = client.post("/mcp/v1/jsonrpc", json={"id": 3, "method": "tools/list"})
    assert bad.json()["error"]["code"] == -32600


def test_tools_list_is_filtered_per_caller(demo_credentials):
    def names(headers, delegation=None):
        h = dict(headers, **({"X-Delegation-Token": delegation} if delegation else {}))
        resp = client.post("/mcp/v1/jsonrpc", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        return {t["name"] for t in resp.json()["result"]["tools"]}

    admin = names(login(demo_credentials, "alpha_admin"))
    plugin = names(login(demo_credentials, agent_id="agent_alpha_untrusted"))
    research = login(demo_credentials, agent_id="agent_alpha_research")
    assert {"admin_override", "export_tenant_report", "read_document"} <= admin
    assert plugin == {"read_document"}
    assert names(research, demo_credentials["delegations"]["del_alpha_child_002"]) == {"read_document"}
    assert names(research, "not-a-token") == set()


def test_jsonrpc_tool_call_with_seeded_delegation(demo_credentials):
    headers = login(demo_credentials, agent_id="agent_alpha_research")
    headers["X-Delegation-Token"] = demo_credentials["delegations"]["del_alpha_child_002"]
    req = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
           "params": {"name": "read_document", "arguments": {"resource_id": "doc_alpha_radar"}}}
    ok = client.post("/mcp/v1/jsonrpc", headers=headers, json=req).json()
    assert ok["result"]["isError"] is False and ok["result"]["_meta"]["agentfence"]["decision"] == "ALLOW"
    req["params"]["arguments"] = {"resource_id": "doc_alpha_falcon"}
    denied = client.post("/mcp/v1/jsonrpc", headers=headers, json=req).json()
    assert denied["result"]["isError"] is True
    assert denied["result"]["_meta"]["agentfence"]["reasonCode"] == "RESOURCE_ACCESS_RESTRICTED"


def test_simulations_endpoint_runs_every_scenario(demo_credentials):
    secops = login(demo_credentials, "secops_admin")
    catalog = client.get("/api/v1/simulations/catalog", headers=secops).json()
    results = client.post("/api/v1/simulations/run", headers=secops).json()
    assert len(results) == len(catalog) >= 18
    failed = [r["scenario_name"] + ": " + r["actual_result"] for r in results if not r["passed"]]
    assert failed == []
    assert all(r["audit_event_id"] for r in results)
    single = client.post("/api/v1/simulations/run?scenario=attack_10", headers=secops).json()
    assert single[0]["key"] == "attack_10_missing_identity" and single[0]["passed"]
    verify = client.get("/api/v1/audit/verify", headers=secops).json()
    assert verify["is_valid"] is True


def test_security_headers_and_cors(demo_credentials):
    resp = client.get("/api/v1/health", headers={"Origin": "https://evil.example"})
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "access-control-allow-origin" not in resp.headers
    ok = client.get("/api/v1/health", headers={"Origin": "http://localhost:5173"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"

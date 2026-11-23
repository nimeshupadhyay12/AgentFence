"""Core security tests: delegation, replay, tenant isolation, policy, audit integrity."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from app.audit.service import audit_service
from app.core.auth import Principal, issue_token_for
from app.core.security import security_engine
from app.database.session import SessionLocal
from app.delegation.engine import delegation_engine
from app.gateway.interceptor import gateway_interceptor
from app.models.entities import AuditEvent, DelegationGrant, ProtectedResource, ReplayIdentifier

ADMIN = Principal("usr_alpha_admin", "user", "tenant_alpha", "admin", True)
ANALYST = Principal("usr_alpha_analyst", "user", "tenant_alpha", "analyst", False)
PRIMARY = Principal("agent_alpha_primary", "agent", "tenant_alpha", "coordinator")
RESEARCH = Principal("agent_alpha_research", "agent", "tenant_alpha", "researcher")
PLUGIN = Principal("agent_alpha_untrusted", "agent", "tenant_alpha", "plugin")


def root(db, receiver="agent_alpha_primary", tools=("read_document",), resources=("doc_alpha_falcon",), **kw):
    res = delegation_engine.create_delegation(db, ADMIN, receiver, list(tools), list(resources),
                                              duration_minutes=kw.pop("duration_minutes", 30), **kw)
    assert res.ok, res.message
    return res


def verify(db, token, agent="agent_alpha_primary", tool="read_document", action="read", resource=None):
    return delegation_engine.verify_active_delegation(db, token, agent, "tenant_alpha", tool, action, resource)


def call(db, principal, tool, args, delegation=None, approval=None):
    return gateway_interceptor.process_tool_invocation(db, tool, args, identity_token=issue_token_for(principal),
                                                       delegation_token=delegation, approval_id=approval)


# 1. Valid delegation succeeds and is usable
def test_valid_delegation_succeeds(db: Session):
    res = root(db)
    assert res.code == "DELEGATION_CREATED" and res.token
    assert verify(db, res.token, resource="doc_alpha_falcon").ok
    out = call(db, PRIMARY, "read_document", {"resource_id": "doc_alpha_falcon"}, res.token)
    assert out["decision"] == "ALLOW" and "Project Falcon" in out["result"]["content"][0]["text"]


# 2. Invalid signature is rejected
def test_invalid_signature_rejected(db: Session):
    res = root(db)
    tampered = res.token[:-6] + ("AAAAAA" if not res.token.endswith("AAAAAA") else "BBBBBB")
    v = verify(db, tampered)
    assert not v.ok and v.code == "DELEGATION_TAMPERING_DETECTED"


# 3. Expired delegation is rejected
def test_expired_delegation_rejected(db: Session):
    token = security_engine.create_delegation_credential(
        delegation_id="del_exp_test", parent_delegation_id=None, original_user_id="usr_alpha_admin",
        delegating_agent_id="usr_alpha_admin", receiving_agent_id="agent_alpha_primary", tenant_id="tenant_alpha",
        permitted_tools=["read_document"], permitted_actions=["read"], resource_restrictions=[], max_depth=3,
        current_depth=1, expires_in_minutes=-5)
    v = verify(db, token)
    assert not v.ok and v.code == "DELEGATION_EXPIRED"


# 4. Audience mismatch is rejected (audience is fixed by config, not by the caller)
def test_audience_mismatch_rejected(db: Session):
    token = security_engine.create_delegation_credential(
        delegation_id="del_aud_test", parent_delegation_id=None, original_user_id="usr_alpha_admin",
        delegating_agent_id="usr_alpha_admin", receiving_agent_id="agent_alpha_primary", tenant_id="tenant_alpha",
        permitted_tools=["read_document"], permitted_actions=["read"], resource_restrictions=[], max_depth=3,
        current_depth=1, audience="other-audience-gateway")
    v = verify(db, token)
    assert not v.ok and v.code == "DELEGATION_AUDIENCE_MISMATCH"


# 5. Delegation scope escalation is rejected
def test_delegation_scope_escalation_rejected(db: Session):
    parent = root(db, resources=["doc_alpha_radar"])
    pid = parent.grant.delegation_id
    res = delegation_engine.create_delegation(db, PRIMARY, "agent_alpha_research", ["read_document", "admin_override"],
                                              ["doc_alpha_radar"], parent_delegation_id=pid)
    assert not res.ok and res.code == "DELEGATION_ATTENUATION_ESCALATION"
    res = delegation_engine.create_delegation(db, PRIMARY, "agent_alpha_research", ["read_document"],
                                              ["doc_alpha_radar", "doc_alpha_falcon"], parent_delegation_id=pid)
    assert not res.ok and res.code == "DELEGATION_ATTENUATION_ESCALATION"
    res = delegation_engine.create_delegation(db, PRIMARY, "agent_alpha_research", ["read_document"], [],
                                              parent_delegation_id=pid)
    assert not res.ok and res.code == "DELEGATION_ATTENUATION_ESCALATION"  # "unrestricted" is wider


# 6. Delegation depth violation is rejected (per-grant cap and global MAX_DELEGATION_DEPTH)
def test_delegation_depth_violation_rejected(db: Session):
    r1 = root(db, resources=["doc_alpha_radar"])
    r2 = delegation_engine.create_delegation(db, PRIMARY, "agent_alpha_research", ["read_document"], ["doc_alpha_radar"],
                                             parent_delegation_id=r1.grant.delegation_id)
    r3 = delegation_engine.create_delegation(db, RESEARCH, "agent_alpha_untrusted", ["read_document"],
                                             ["doc_alpha_radar"], parent_delegation_id=r2.grant.delegation_id)
    assert r2.ok and r3.ok and r3.grant.current_depth == 3
    r4 = delegation_engine.create_delegation(db, PLUGIN, "agent_alpha_primary", ["read_document"], ["doc_alpha_radar"],
                                             parent_delegation_id=r3.grant.delegation_id)
    assert not r4.ok and r4.code == "DELEGATION_DEPTH_EXCEEDED"
    over = delegation_engine.create_delegation(db, ADMIN, "agent_alpha_primary", ["read_document"],
                                               ["doc_alpha_radar"], max_depth=10)
    assert not over.ok and over.code == "DELEGATION_DEPTH_EXCEEDED"


# 7. Cross-tenant access is rejected by the hard isolation rule
def test_cross_tenant_access_rejected(db: Session):
    grant = root(db, resources=[])
    out = call(db, PRIMARY, "read_document", {"resource_id": "doc_beta_trial"}, grant.token)
    assert out["decision"] == "DENY" and out["reason_code"] == "AUTHZ_CROSS_TENANT_VIOLATION"


# 8. A tool outside the delegated scope is rejected by the delegation scope check
def test_unauthorized_tool_invocation_rejected(db: Session):
    grant = root(db, receiver="agent_alpha_research", resources=["doc_alpha_radar"])
    out = call(db, RESEARCH, "export_tenant_report", {"report_format": "csv"}, grant.token)
    assert out["decision"] == "DENY" and out["reason_code"] == "UNAUTHORIZED_TOOL_EXECUTION"
    out = call(db, RESEARCH, "export_tenant_report", {"report_format": "csv"})  # no delegation at all
    assert out["decision"] == "DENY" and out["reason_code"] == "AUTHZ_NO_MATCHING_ALLOW_POLICY"


# 9. Missing identity is rejected
def test_missing_identity_rejected(db: Session):
    out = gateway_interceptor.process_tool_invocation(db, "read_document", {"resource_id": "doc_alpha_falcon"})
    assert out["authorized"] is False and out["reason_code"] == "AUTHN_MISSING_IDENTITY"


# 10. Replay protection holds under concurrent requests (DB-enforced, durable)
def test_replay_protection_concurrent(db: Session):
    grant = root(db, is_single_use=True)
    token = issue_token_for(PRIMARY)

    def invoke():
        session = SessionLocal()
        try:
            return gateway_interceptor.process_tool_invocation(
                session, "read_document", {"resource_id": "doc_alpha_falcon"}, identity_token=token,
                delegation_token=grant.token)
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=5) as ex:
        results = [f.result() for f in [ex.submit(invoke) for _ in range(5)]]
    assert sum(r["decision"] == "ALLOW" for r in results) == 1
    assert sum(r["reason_code"] == "REPLAY_ATTACK_DETECTED" for r in results) == 4
    db.expire_all()
    assert db.query(ReplayIdentifier).filter(ReplayIdentifier.jti == grant.grant.jti).count() == 1


# 11. Revoked delegation is rejected, and revoking a parent kills its descendants
def test_revoked_delegation_rejected(db: Session):
    parent = root(db, resources=["doc_alpha_radar"])
    child = delegation_engine.create_delegation(db, PRIMARY, "agent_alpha_research", ["read_document"],
                                                ["doc_alpha_radar"], parent_delegation_id=parent.grant.delegation_id)
    status, code, _ = delegation_engine.revoke(db, ADMIN, parent.grant.delegation_id)
    assert status == 200 and code == "DELEGATION_REVOKED"
    assert verify(db, parent.token).code == "DELEGATION_REVOKED"
    v = verify(db, child.token, agent="agent_alpha_research", resource="doc_alpha_radar")
    assert not v.ok and v.code == "PARENT_DELEGATION_REVOKED"


# 12. Upstream is never reached after a denial
def test_upstream_never_reached_on_denial(db: Session, monkeypatch):
    calls = []
    monkeypatch.setattr(gateway_interceptor.upstream, "execute", lambda *a, **k: calls.append(1) or {})
    grant = root(db, resources=[])
    out = call(db, PRIMARY, "read_document", {"resource_id": "doc_beta_trial"}, grant.token)
    assert out["authorized"] is False and "result" not in out and calls == []


# 13. Audit events are generated for allowed and denied requests
def test_audit_events_generated(db: Session):
    before = db.query(AuditEvent).filter(AuditEvent.event_type == "tool_call").count()
    grant = root(db)
    allowed = call(db, PRIMARY, "read_document", {"resource_id": "doc_alpha_falcon"}, grant.token)
    denied = gateway_interceptor.process_tool_invocation(db, "read_document", {"resource_id": "doc_alpha_falcon"})
    assert db.query(AuditEvent).filter(AuditEvent.event_type == "tool_call").count() == before + 2
    ids = {allowed["audit_event_id"], denied["audit_event_id"]}
    assert {e.decision for e in db.query(AuditEvent).filter(AuditEvent.id.in_(ids))} == {"ALLOW", "DENY"}


# 14. Audit verification detects modification of ANY stored field
@pytest.mark.parametrize("field", [f for f in AuditEvent.HASHED_FIELDS if f != "previous_record_hash"])
def test_audit_integrity_detects_tampering_of_every_field(db: Session, field):
    assert audit_service.verify_audit_chain_integrity(db)[0] is True
    event = db.query(AuditEvent).order_by(AuditEvent.seq.desc()).offset(1).first()
    original = getattr(event, field)
    tampered = 99 if field == "hash_version" else ('{"x":1}' if field == "details_json" else f"{original}-tampered")
    setattr(event, field, tampered)
    db.commit()
    valid, _, err = audit_service.verify_audit_chain_integrity(db)
    setattr(event, field, original)
    db.commit()
    assert valid is False and err is not None
    assert audit_service.verify_audit_chain_integrity(db)[0] is True


def test_audit_integrity_detects_deleted_record(db: Session):
    event = db.query(AuditEvent).order_by(AuditEvent.seq.asc()).offset(2).first()
    snapshot = {c.name: getattr(event, c.name) for c in AuditEvent.__table__.columns}
    db.delete(event)
    db.commit()
    valid, _, err = audit_service.verify_audit_chain_integrity(db)
    db.add(AuditEvent(**snapshot))
    db.commit()
    assert valid is False and "Broken previous-hash pointer" in err["error"]
    assert audit_service.verify_audit_chain_integrity(db)[0] is True


# 15. Tenant isolation holds across resource queries
def test_tenant_isolation_queries(db: Session):
    alpha = {d.id for d in db.query(ProtectedResource).filter(ProtectedResource.tenant_id == "tenant_alpha")}
    beta = {d.id for d in db.query(ProtectedResource).filter(ProtectedResource.tenant_id == "tenant_beta")}
    assert len(alpha) >= 2 and len(beta) >= 2 and alpha.isdisjoint(beta)


# 16. Only the parent grant's recipient may delegate its authority onward
def test_child_grant_requires_parent_recipient(db: Session):
    parent = root(db)
    res = delegation_engine.create_delegation(db, RESEARCH, "agent_alpha_untrusted", ["read_document"],
                                              ["doc_alpha_falcon"], parent_delegation_id=parent.grant.delegation_id)
    assert not res.ok and res.code == "DELEGATION_CHAIN_MISMATCH"


# 17. Child expiry cannot outlive the parent grant
def test_child_expiry_capped_by_parent(db: Session):
    parent = root(db, duration_minutes=10)
    child = delegation_engine.create_delegation(db, PRIMARY, "agent_alpha_research", ["read_document"],
                                                ["doc_alpha_falcon"], parent_delegation_id=parent.grant.delegation_id,
                                                duration_minutes=600)
    assert child.ok
    parent_exp = parent.grant.expires_at.replace(tzinfo=timezone.utc)
    assert child.grant.expires_at.replace(tzinfo=timezone.utc) <= parent_exp
    ok, payload, _, _ = security_engine.verify_delegation_credential(child.token)
    assert ok and payload["exp"] <= int(parent_exp.timestamp())


# 18. Stored grant expiry is enforced even if the token is still valid
def test_grant_expiry_enforced_even_with_valid_token(db: Session):
    grant = root(db)
    row = db.get(DelegationGrant, grant.grant.id)
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    v = verify(db, grant.token)
    assert not v.ok and v.code == "DELEGATION_EXPIRED"


# 19. An expired parent invalidates its descendants
def test_expired_parent_invalidates_child(db: Session):
    parent = root(db)
    child = delegation_engine.create_delegation(db, PRIMARY, "agent_alpha_research", ["read_document"],
                                                ["doc_alpha_falcon"], parent_delegation_id=parent.grant.delegation_id,
                                                duration_minutes=5)
    row = db.get(DelegationGrant, parent.grant.id)
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    v = verify(db, child.token, agent="agent_alpha_research", resource="doc_alpha_falcon")
    assert not v.ok and v.code == "PARENT_DELEGATION_EXPIRED"


# 20. A rejected scope check must not burn a single-use delegation
def test_single_use_not_consumed_on_scope_failure(db: Session):
    grant = root(db, is_single_use=True)
    out = call(db, PRIMARY, "export_tenant_report", {"report_format": "json"}, grant.token)
    assert out["reason_code"] == "UNAUTHORIZED_TOOL_EXECUTION"
    out = call(db, PRIMARY, "read_document", {"resource_id": "doc_alpha_falcon"}, grant.token)
    assert out["decision"] == "ALLOW"


# 21. Root delegation: only users, only what they hold
def test_root_delegation_requires_delegator_authority(db: Session):
    agent_root = delegation_engine.create_delegation(db, PLUGIN, "agent_alpha_primary", ["read_document"],
                                                     ["doc_alpha_radar"])
    assert not agent_root.ok and agent_root.code == "DELEGATOR_HAS_NO_AUTHORITY"
    secret = delegation_engine.create_delegation(db, ANALYST, "agent_alpha_primary", ["read_document"],
                                                 ["doc_alpha_falcon"])
    assert not secret.ok and secret.code == "DELEGATION_EXCEEDS_DELEGATOR_AUTHORITY"
    confidential = delegation_engine.create_delegation(db, ANALYST, "agent_alpha_primary", ["read_document"],
                                                       ["doc_alpha_radar"])
    assert confidential.ok
    cross = delegation_engine.create_delegation(db, ADMIN, "agent_beta_primary", ["read_document"], [])
    assert not cross.ok and cross.code == "INVALID_RECEIVING_AGENT"


# 22. Delegation creation and rejection are audited
def test_delegation_events_are_audited(db: Session):
    bad = delegation_engine.create_delegation(db, PLUGIN, "agent_alpha_primary", ["read_document"], [])
    ev = db.query(AuditEvent).filter(AuditEvent.id == bad.audit_event_id).one()
    assert ev.event_type == "delegation.create" and ev.decision == "DENY"
    assert ev.reason_code == "DELEGATOR_HAS_NO_AUTHORITY" and ev.attack_classification == "privilege_escalation"


# 23. Confused deputy: a privileged agent cannot exercise authority a low-privilege delegator lacks
def test_confused_deputy_blocked(db: Session):
    plugin_grant = root(db, receiver="agent_alpha_untrusted", resources=["doc_alpha_falcon", "doc_alpha_radar"])
    hop = delegation_engine.create_delegation(db, PLUGIN, "agent_alpha_primary", ["read_document"],
                                              ["doc_alpha_falcon", "doc_alpha_radar"],
                                              parent_delegation_id=plugin_grant.grant.delegation_id)
    assert hop.ok
    secret = call(db, PRIMARY, "read_document", {"resource_id": "doc_alpha_falcon"}, hop.token)
    assert secret["reason_code"] == "AUTHZ_CONFUSED_DEPUTY_BLOCKED"
    confidential = call(db, PRIMARY, "read_document", {"resource_id": "doc_alpha_radar"}, hop.token)
    assert confidential["decision"] == "ALLOW"  # the plugin may read this one, so the deputy may too


# 24. A delegation is bound to its receiving agent
def test_stolen_delegation_rejected(db: Session):
    grant = root(db)
    out = call(db, PLUGIN, "read_document", {"resource_id": "doc_alpha_falcon"}, grant.token)
    assert out["reason_code"] == "AGENT_IDENTITY_MISMATCH"


# 25. Action and resource are derived server-side; smuggled arguments are rejected
def test_action_is_derived_server_side(db: Session):
    grant = root(db)
    out = call(db, PRIMARY, "read_document", {"resource_id": "doc_alpha_falcon", "action": "read"}, grant.token)
    assert out["reason_code"] == "ARGUMENT_VALIDATION_FAILED"
    ev = db.query(AuditEvent).filter(AuditEvent.id == out["audit_event_id"]).one()
    assert ev.requested_action == "read" and ev.attack_classification == "argument_smuggling"

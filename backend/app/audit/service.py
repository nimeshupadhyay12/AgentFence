"""AgentFence audit service: hash-chained, tamper-evident security event ledger.

* Every security-relevant action is recorded (tool calls, logins, delegation
  issuance/rejection/revocation, policy changes, approvals, tool registration).
* ``record_hash = SHA-256(canonical JSON of every field + previous hash)``;
  editing *any* stored field, deleting or reordering a record breaks the chain.
* Appends are serialised in-process by a lock and across processes by the
  UNIQUE constraint on ``previous_record_hash`` (a writer that lost the race
  retries on the new head), so the chain cannot fork.
"""
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import security_engine
from app.models.entities import AuditEvent

HASH_VERSION = 2
_MAX_APPEND_ATTEMPTS = 8


class AuditService:
    def __init__(self) -> None:
        self.genesis_hash = settings.AUDIT_GENESIS_HASH
        self._lock = threading.Lock()

    # ----------------------------------------------------------------- write
    def log_event(
        self,
        db: Session,
        *,
        tenant_id: str,
        decision: str,
        event_type: str = "tool_call",
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        parent_delegation_id: Optional[str] = None,
        delegation_id: Optional[str] = None,
        mcp_tool_name: Optional[str] = None,
        requested_action: Optional[str] = None,
        resource_id: Optional[str] = None,
        reason_code: Optional[str] = None,
        denial_reason: Optional[str] = None,
        attack_classification: Optional[str] = None,
        execution_outcome: str = "not_executed",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Appends a hash-chained event. Commits any pending work in ``db`` first."""
        request_id = request_id or security_engine.generate_id("req")
        details_json = security_engine.canonical_json(details or {})
        with self._lock:
            db.commit()
            last_error: Optional[Exception] = None
            for _ in range(_MAX_APPEND_ATTEMPTS):
                head = db.query(AuditEvent.record_hash).order_by(AuditEvent.seq.desc()).first()
                event = AuditEvent(
                    id=security_engine.generate_id("aud"),
                    event_type=event_type,
                    request_id=request_id,
                    correlation_id=correlation_id or request_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tenant_id=tenant_id or "unknown",
                    user_id=user_id,
                    agent_id=agent_id,
                    parent_delegation_id=parent_delegation_id,
                    delegation_id=delegation_id,
                    mcp_tool_name=mcp_tool_name,
                    requested_action=requested_action,
                    resource_id=resource_id,
                    decision=decision,
                    reason_code=reason_code,
                    denial_reason=denial_reason,
                    attack_classification=attack_classification,
                    execution_outcome=execution_outcome,
                    details_json=details_json,
                    hash_version=HASH_VERSION,
                    previous_record_hash=head[0] if head else self.genesis_hash,
                )
                event.record_hash = security_engine.calculate_audit_hash(event.hash_payload())
                db.add(event)
                try:
                    db.commit()
                    return event
                except IntegrityError as exc:  # another writer appended first
                    db.rollback()
                    last_error = exc
            raise RuntimeError(f"Could not append audit event after {_MAX_APPEND_ATTEMPTS} attempts") from last_error

    # ---------------------------------------------------------------- verify
    def verify_audit_chain_integrity(self, db: Session) -> Tuple[bool, int, Optional[Dict[str, Any]]]:
        """Walks the ledger in sequence order and re-computes every link."""
        expected_prev = self.genesis_hash
        count = 0
        for ev in db.query(AuditEvent).order_by(AuditEvent.seq.asc()).yield_per(500):
            if ev.hash_version != HASH_VERSION:
                return False, count, {"event_id": ev.id, "seq": ev.seq, "error": f"Unsupported hash version {ev.hash_version}"}
            if ev.previous_record_hash != expected_prev:
                return False, count, {
                    "event_id": ev.id,
                    "seq": ev.seq,
                    "error": "Broken previous-hash pointer (record deleted, inserted or reordered)",
                    "stored_previous_hash": ev.previous_record_hash,
                    "expected_previous_hash": expected_prev,
                }
            calculated = security_engine.calculate_audit_hash(ev.hash_payload())
            if calculated != ev.record_hash:
                return False, count, {
                    "event_id": ev.id,
                    "seq": ev.seq,
                    "error": "Record content hash mismatch / data tampering detected",
                    "stored_hash": ev.record_hash,
                    "calculated_hash": calculated,
                }
            expected_prev = ev.record_hash
            count += 1
        return True, count, None

    @staticmethod
    def verify_legacy_sqlite_chain(db_path: str) -> Tuple[bool, int, Optional[Dict[str, Any]]]:
        """Verifies an archived v1 database (11-field pipe hash) with raw SQL."""
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT id, request_id, timestamp, tenant_id, user_id, agent_id, mcp_tool_name, requested_action, "
                "resource_id, decision, denial_reason, previous_record_hash, record_hash FROM audit_events ORDER BY seq"
            ).fetchall()
        finally:
            conn.close()
        expected_prev = settings.AUDIT_GENESIS_HASH
        for idx, r in enumerate(rows):
            if r[11] != expected_prev:
                return False, idx, {"event_id": r[0], "error": "Broken previous-hash pointer"}
            calc = security_engine.calculate_legacy_audit_hash(r[11], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10])
            if calc != r[12]:
                return False, idx, {"event_id": r[0], "error": "Record content hash mismatch"}
            expected_prev = r[12]
        return True, len(rows), None

    # ---------------------------------------------------------------- export
    @staticmethod
    def serialize(ev: AuditEvent) -> Dict[str, Any]:
        return {
            "seq": ev.seq,
            **{k: v for k, v in ev.hash_payload().items() if k != "details_json"},
            "details": ev.get_details(),
            "record_hash": ev.record_hash,
        }

    def export_jsonl(self, db: Session, tenant_id: Optional[str] = None) -> Iterator[str]:
        query = db.query(AuditEvent).order_by(AuditEvent.seq.asc())
        if tenant_id:
            query = query.filter(AuditEvent.tenant_id == tenant_id)
        for ev in query.yield_per(500):
            yield json.dumps(self.serialize(ev), sort_keys=True) + "\n"

    # --------------------------------------------------------------- metrics
    def get_security_metrics(self, db: Session, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        base = db.query(AuditEvent).filter(AuditEvent.event_type == "tool_call")
        if tenant_id:
            base = base.filter(AuditEvent.tenant_id == tenant_id)

        def count_class(*classes: str) -> int:
            q = db.query(AuditEvent).filter(AuditEvent.attack_classification.in_(classes))
            if tenant_id:
                q = q.filter(AuditEvent.tenant_id == tenant_id)
            return q.count()

        tool_counts = (
            base.with_entities(AuditEvent.mcp_tool_name, func.count(AuditEvent.seq))
            .group_by(AuditEvent.mcp_tool_name)
            .all()
        )
        recent_q = db.query(AuditEvent)
        if tenant_id:
            recent_q = recent_q.filter(AuditEvent.tenant_id == tenant_id)
        recent = recent_q.order_by(AuditEvent.seq.desc()).limit(10).all()

        return {
            "total_requests": base.count(),
            "allowed_requests": base.filter(AuditEvent.decision == "ALLOW").count(),
            "denied_requests": base.filter(AuditEvent.decision == "DENY").count(),
            "pending_approvals": base.filter(AuditEvent.decision == "PENDING").count(),
            "security_incidents": {
                "cross_tenant_attempts": count_class("cross_tenant"),
                "confused_deputy_attempts": count_class("confused_deputy", "stolen_delegation"),
                "privilege_escalation_attempts": count_class(
                    "privilege_escalation", "excessive_depth", "unauthorized_tool", "broken_function_authz"
                ),
                "replay_attempts": count_class("replay_attack", "token_replay"),
                "token_forgery_attempts": count_class("token_forgery", "invalid_identity", "expired_delegation",
                                                      "delegation_tampering", "audience_mismatch",
                                                      "forged_delegation", "missing_identity", "unauthenticated_api"),
                "prompt_injection_events": count_class("tool_poisoning", "argument_smuggling"),
                "rate_limited": count_class("rate_limit_abuse", "credential_stuffing"),
                "approval_bypass_attempts": count_class("approval_bypass"),
            },
            "tool_distribution": [{"tool": t or "-", "count": c} for t, c in tool_counts],
            "recent_events": [
                {
                    "id": e.id,
                    "event_type": e.event_type,
                    "timestamp": e.timestamp,
                    "tenant_id": e.tenant_id,
                    "agent_id": e.agent_id,
                    "user_id": e.user_id,
                    "tool": e.mcp_tool_name,
                    "action": e.requested_action,
                    "resource_id": e.resource_id,
                    "decision": e.decision,
                    "reason_code": e.reason_code,
                    "reason": e.denial_reason,
                    "attack_classification": e.attack_classification,
                }
                for e in recent
            ],
        }

    @staticmethod
    def list_recent(db: Session, limit: int = 100) -> List[AuditEvent]:
        return db.query(AuditEvent).order_by(AuditEvent.seq.desc()).limit(limit).all()


audit_service = AuditService()

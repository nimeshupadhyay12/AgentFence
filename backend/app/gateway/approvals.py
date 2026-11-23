"""Human-in-the-loop approval for high-risk tools (``MCPTool.requires_approval``).

Flow: the first call returns ``PENDING`` with an ``approval_id``. A tenant
administrator (or platform administrator) who is *not* the requester approves
or denies it. The requester then repeats the identical call with the
``approval_id``. An approval is bound to requester, tenant, tool and the exact
arguments (SHA-256), expires after ``AGENTFENCE_APPROVAL_TTL`` minutes and can
be used once (atomic ``APPROVED -> USED`` transition).
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session

from app.audit.service import audit_service
from app.core.auth import Principal
from app.core.config import settings
from app.core.security import security_engine
from app.models.entities import ApprovalRequest, as_utc


def arguments_hash(arguments: Dict[str, Any]) -> str:
    return hashlib.sha256(security_engine.canonical_json(arguments).encode("utf-8")).hexdigest()


def create_request(db: Session, principal: Principal, tool_name: str, arguments: Dict[str, Any],
                   delegation_id: Optional[str]) -> ApprovalRequest:
    now = datetime.now(timezone.utc)
    req = ApprovalRequest(
        id=security_engine.generate_id("apr"),
        tenant_id=principal.tenant_id,
        requester_id=principal.id,
        requester_type=principal.type,
        tool_name=tool_name,
        arguments_json=security_engine.canonical_json(arguments),
        arguments_hash=arguments_hash(arguments),
        delegation_id=delegation_id,
        status="PENDING",
        created_at=now,
        expires_at=now + timedelta(minutes=settings.APPROVAL_TTL_MINUTES),
    )
    db.add(req)
    db.commit()
    return req


def check_approval(db: Session, approval_id: str, principal: Principal, tool_name: str,
                   arguments: Dict[str, Any]) -> Tuple[bool, str, str]:
    req = db.get(ApprovalRequest, approval_id)
    if req is None or req.requester_id != principal.id or req.tenant_id != principal.tenant_id \
            or req.tool_name != tool_name:
        return False, "APPROVAL_INVALID", "Approval does not exist or was issued for a different caller/tool"
    if req.arguments_hash != arguments_hash(arguments):
        return False, "APPROVAL_INVALID", "Arguments differ from the approved request"
    if as_utc(req.expires_at) < datetime.now(timezone.utc):
        return False, "APPROVAL_EXPIRED", "Approval has expired"
    if req.status == "PENDING":
        return False, "APPROVAL_PENDING", "Approval is still waiting for an administrator"
    if req.status == "DENIED":
        return False, "APPROVAL_DENIED", "Approval was denied by an administrator"
    if req.status == "USED":
        return False, "APPROVAL_ALREADY_USED", "Approval has already been used"
    return True, "APPROVAL_VALID", "Approved"


def consume_approval(db: Session, approval_id: str) -> bool:
    updated = (
        db.query(ApprovalRequest)
        .filter(ApprovalRequest.id == approval_id, ApprovalRequest.status == "APPROVED")
        .update({ApprovalRequest.status: "USED", ApprovalRequest.used_at: datetime.now(timezone.utc)},
                synchronize_session=False)
    )
    db.commit()
    return updated == 1


def decide(db: Session, approver: Principal, approval_id: str, approve: bool,
           note: Optional[str] = None) -> Tuple[int, str, str]:
    """Returns (http_status, code, message)."""
    req = db.get(ApprovalRequest, approval_id)
    if req is None or not approver.can_manage_tenant(req.tenant_id):
        status, code, msg = 404, "APPROVAL_NOT_FOUND", "Approval request not found"
    elif req.requester_id == approver.id:
        status, code, msg = 403, "APPROVAL_SELF_APPROVAL", "Requesters cannot approve their own requests"
    elif req.status != "PENDING":
        status, code, msg = 409, "APPROVAL_NOT_PENDING", f"Approval is already {req.status}"
    elif as_utc(req.expires_at) < datetime.now(timezone.utc):
        status, code, msg = 409, "APPROVAL_EXPIRED", "Approval has expired"
    else:
        req.status = "APPROVED" if approve else "DENIED"
        req.decided_by = approver.id
        req.decided_at = datetime.now(timezone.utc)
        req.decision_note = (note or "")[:500] or None
        db.commit()
        status, code, msg = 200, f"APPROVAL_{req.status}", f"Request {approval_id} {req.status.lower()}"
    audit_service.log_event(
        db, event_type="approval.decision", tenant_id=req.tenant_id if req else approver.tenant_id,
        user_id=approver.id if approver.type == "user" else None,
        agent_id=req.requester_id if req and req.requester_type == "agent" else None,
        delegation_id=req.delegation_id if req else None,
        mcp_tool_name=req.tool_name if req else None,
        decision="ALLOW" if status == 200 else "DENY", reason_code=code,
        denial_reason=None if status == 200 else msg,
        attack_classification="approval_bypass" if code == "APPROVAL_SELF_APPROVAL" else None,
        execution_outcome="decided" if status == 200 else "rejected",
        details={"approval_id": approval_id, "approve": approve, "approver": approver.id},
    )
    return status, code, msg


def serialize(req: ApprovalRequest) -> Dict[str, Any]:
    return {
        "id": req.id,
        "tenant_id": req.tenant_id,
        "requester_id": req.requester_id,
        "requester_type": req.requester_type,
        "tool_name": req.tool_name,
        "arguments": json.loads(req.arguments_json),
        "delegation_id": req.delegation_id,
        "status": req.status,
        "created_at": as_utc(req.created_at).isoformat(),
        "expires_at": as_utc(req.expires_at).isoformat(),
        "decided_by": req.decided_by,
        "decision_note": req.decision_note,
    }

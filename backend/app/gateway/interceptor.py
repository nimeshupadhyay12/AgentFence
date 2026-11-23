"""AgentFence gateway interceptor: the enforcement point for every MCP tool call.

Decision pipeline (first failing step denies; every outcome is audited):

 1. Authenticate the identity token (alg pinned, kid, iss, aud = this gateway,
    exp/nbf, token_use, jti not revoked) and re-load the principal from the
    database (must exist, be active, and match the token's tenant).
 2. Resolve the tool from the registry (exists, enabled, not quarantined,
    upstream allowlisted).
 3. Validate the arguments against the tool's JSON schema (no undeclared
    parameters). The action and the resource are derived *here*, from the
    tool definition - never taken from the caller.
 4. Per-principal, per-tool rate limit.
 5. Delegation (if a credential is presented): signature/claims, bound to the
    calling agent and tenant, registry record + fingerprint, not revoked or
    expired, single-use not yet consumed, depth limit, tool/action/resource
    scope, and every ancestor in the chain.
 6. Policy decision (hard tenant isolation, then RBAC/ABAC, deny-overrides,
    default deny).
 7. Chain-wide authorization (confused-deputy defence): every delegator in
    the chain must itself be allowed to make this call.
 8. Human approval for tools that require it.
 9. Atomically consume single-use credentials / approvals (DB constraints).
10. Forward to the upstream MCP server and audit the outcome.
"""
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.audit.service import audit_service
from app.core.auth import Principal, authenticate_token
from app.core.config import settings
from app.core.ratelimit import gateway_rate_limiter
from app.core.security import security_engine
from app.delegation.engine import delegation_engine
from app.gateway import approvals
from app.gateway.tool_guard import upstream_allowed, validate_arguments
from app.mcp.upstream import upstream_router
from app.models.entities import MCPTool
from app.policies.engine import policy_engine

ATTACK_CLASSIFICATION = {
    "AUTHN_MISSING_IDENTITY": "missing_identity",
    "TOKEN_ALGORITHM_REJECTED": "token_forgery",
    "TOKEN_SIGNATURE_INVALID": "token_forgery",
    "TOKEN_UNKNOWN_KEY": "token_forgery",
    "TOKEN_MALFORMED": "invalid_identity",
    "TOKEN_EXPIRED": "invalid_identity",
    "TOKEN_AUDIENCE_MISMATCH": "audience_mismatch",
    "TOKEN_TYPE_MISMATCH": "token_forgery",
    "TOKEN_REVOKED": "token_replay",
    "PRINCIPAL_UNKNOWN": "invalid_identity",
    "TOOL_QUARANTINED": "tool_poisoning",
    "ARGUMENT_VALIDATION_FAILED": "argument_smuggling",
    "RATE_LIMIT_EXCEEDED": "rate_limit_abuse",
    "REPLAY_ATTACK_DETECTED": "replay_attack",
    "DELEGATION_EXPIRED": "expired_delegation",
    "DELEGATION_AUDIENCE_MISMATCH": "audience_mismatch",
    "DELEGATION_TAMPERING_DETECTED": "delegation_tampering",
    "DELEGATION_TOKEN_MISMATCH": "delegation_tampering",
    "DELEGATION_NOT_FOUND": "forged_delegation",
    "EXCESSIVE_DELEGATION_DEPTH": "excessive_depth",
    "UNAUTHORIZED_TOOL_EXECUTION": "unauthorized_tool",
    "UNAUTHORIZED_ACTION": "unauthorized_tool",
    "RESOURCE_ACCESS_RESTRICTED": "privilege_escalation",
    "AGENT_IDENTITY_MISMATCH": "stolen_delegation",
    "DELEGATION_TENANT_MISMATCH": "cross_tenant",
    "AUTHZ_CROSS_TENANT_VIOLATION": "cross_tenant",
    "AUTHZ_CONFUSED_DEPUTY_BLOCKED": "confused_deputy",
    "APPROVAL_INVALID": "approval_bypass",
    "APPROVAL_ALREADY_USED": "approval_bypass",
}


class GatewayInterceptor:
    def __init__(self) -> None:
        self.rate_limiter = gateway_rate_limiter
        self.upstream = upstream_router

    def _respond(self, db: Session, *, decision: str, code: str, message: str, corr_id: str, request_id: str,
                 tool_name: Optional[str], action: Optional[str], resource_id: Optional[str],
                 principal: Optional[Principal] = None, tenant_id: Optional[str] = None,
                 delegation: Optional[Dict[str, Any]] = None, outcome: str = "blocked",
                 matched_policy: Optional[str] = None, extra: Optional[Dict[str, Any]] = None,
                 result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        delegation = delegation or {}
        user_id = None
        agent_id = None
        if principal is not None:
            if principal.type == "user":
                user_id = principal.id
            else:
                agent_id = principal.id
                user_id = delegation.get("orig_uid")
        event = audit_service.log_event(
            db,
            event_type="tool_call",
            request_id=request_id,
            correlation_id=corr_id,
            tenant_id=tenant_id or (principal.tenant_id if principal else "unauthenticated"),
            user_id=user_id,
            agent_id=agent_id,
            parent_delegation_id=delegation.get("pdel_id"),
            delegation_id=delegation.get("del_id"),
            mcp_tool_name=tool_name,
            requested_action=action,
            resource_id=resource_id,
            decision=decision,
            reason_code=code,
            denial_reason=None if decision == "ALLOW" else message,
            attack_classification=ATTACK_CLASSIFICATION.get(code) if decision == "DENY" else None,
            execution_outcome=outcome,
            details={k: v for k, v in (extra or {}).items() if k != "content"},
        )
        response: Dict[str, Any] = {
            "authorized": decision == "ALLOW",
            "decision": decision,
            "reason_code": code,
            "message": message,
            "matched_policy": matched_policy,
            "correlation_id": corr_id,
            "audit_event_id": event.id,
        }
        if extra:
            response.update({k: v for k, v in extra.items() if k in ("approval_id", "retry_after")})
        if decision == "ALLOW":
            response["result"] = result
        else:
            label = "Approval Required" if decision == "PENDING" else "Access Denied"
            response["content"] = [{"type": "text", "text": f"AgentFence {label} [{code}]: {message}"}]
        return response

    def process_tool_invocation(
        self,
        db: Session,
        tool_name: Optional[str],
        arguments: Any,
        identity_token: Optional[str] = None,
        delegation_token: Optional[str] = None,
        approval_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        request_id = security_engine.generate_id("req")
        corr_id = str(correlation_id)[:64] if correlation_id else security_engine.generate_id("corr")
        tool_label = str(tool_name)[:128] if tool_name else None
        ctx: Dict[str, Any] = {"corr_id": corr_id, "request_id": request_id, "tool_name": tool_label,
                               "action": None, "resource_id": None}

        # 1. Authentication ---------------------------------------------------
        principal, code, msg = authenticate_token(db, identity_token)
        if principal is None:
            return self._respond(db, decision="DENY", code=code, message=msg,
                                 tenant_id="unauthenticated", **ctx)
        ctx["principal"] = principal

        # 2. Tool resolution --------------------------------------------------
        tool = db.query(MCPTool).filter(MCPTool.name == tool_label).first() if tool_label else None
        if tool is None:
            return self._respond(db, decision="DENY", code="TOOL_NOT_FOUND",
                                 message=f"Tool '{tool_label}' is not registered", **ctx)
        if tool.is_quarantined:
            return self._respond(db, decision="DENY", code="TOOL_QUARANTINED",
                                 message=f"Tool '{tool.name}' is quarantined: {tool.quarantine_reason}", **ctx)
        if not tool.is_enabled:
            return self._respond(db, decision="DENY", code="TOOL_DISABLED",
                                 message=f"Tool '{tool.name}' is disabled", **ctx)
        if not upstream_allowed(tool.upstream_endpoint, settings.UPSTREAM_ALLOWLIST):
            return self._respond(db, decision="DENY", code="UPSTREAM_NOT_ALLOWLISTED",
                                 message=f"Upstream for '{tool.name}' is not on the allowlist", **ctx)

        # 3. Argument validation; action/resource derived from the tool --------
        ctx["action"] = tool.action
        violation = validate_arguments(tool.get_parameters_schema(), arguments)
        if violation:
            return self._respond(db, decision="DENY", code="ARGUMENT_VALIDATION_FAILED", message=violation, **ctx)
        resource_id = None
        if tool.resource_param and arguments.get(tool.resource_param) is not None:
            resource_id = str(arguments[tool.resource_param])
        ctx["resource_id"] = resource_id

        # 4. Rate limit --------------------------------------------------------
        limit = tool.rate_limit_per_minute or settings.RATE_LIMIT_PER_MINUTE
        allowed, retry_after = self.rate_limiter.hit(f"{principal.id}:{tool.name}", limit)
        if not allowed:
            return self._respond(db, decision="DENY", code="RATE_LIMIT_EXCEEDED",
                                 message=f"Rate limit of {limit}/min for '{tool.name}' exceeded; "
                                         f"retry in {retry_after}s",
                                 extra={"retry_after": retry_after}, **ctx)

        # 5. Delegation --------------------------------------------------------
        payload: Optional[Dict[str, Any]] = None
        grant = None
        if delegation_token:
            ver = delegation_engine.verify_active_delegation(
                db, delegation_token, acting_agent_id=principal.id, acting_tenant_id=principal.tenant_id,
                tool_name=tool.name, action=tool.action, resource_id=resource_id,
            )
            if not ver.ok:
                return self._respond(db, decision="DENY", code=ver.code, message=ver.message,
                                     delegation=ver.payload, **ctx)
            payload, grant = ver.payload, ver.grant
        ctx["delegation"] = payload

        # 6. Policy decision -----------------------------------------------------
        decision = policy_engine.evaluate(
            db=db, principal_id=principal.id, principal_type=principal.type, principal_role=principal.role,
            acting_agent_id=principal.id if principal.type == "agent" else None, tenant_id=principal.tenant_id,
            tool_name=tool.name, requested_action=tool.action, resource_id=resource_id,
            delegation_payload=payload, correlation_id=corr_id, arguments=arguments,
        )
        if decision.decision != "ALLOW":
            return self._respond(db, decision="DENY", code=decision.reason_code, message=decision.explanation,
                                 matched_policy=decision.matched_policy, **ctx)

        # 7. Chain-wide authorization (confused deputy) --------------------------
        if grant is not None:
            links = [grant] + delegation_engine.chain_of(db, grant)[0]
            for link in links:
                delegator = delegation_engine.load_principal(db, link.delegating_agent_id, link.delegator_type)
                if delegator is None:
                    return self._respond(db, decision="DENY", code="AUTHZ_CONFUSED_DEPUTY_BLOCKED",
                                         message=f"Delegator '{link.delegating_agent_id}' in the chain is no "
                                                 f"longer an active principal", **ctx)
                link_decision = policy_engine.evaluate(
                    db=db, principal_id=delegator.id, principal_type=delegator.type,
                    principal_role=delegator.role,
                    acting_agent_id=delegator.id if delegator.type == "agent" else None,
                    tenant_id=principal.tenant_id, tool_name=tool.name, requested_action=tool.action,
                    resource_id=resource_id, delegation_payload=payload if delegator.type == "agent" else None,
                    correlation_id=corr_id, arguments=arguments,
                )
                if link_decision.decision != "ALLOW":
                    return self._respond(
                        db, decision="DENY", code="AUTHZ_CONFUSED_DEPUTY_BLOCKED",
                        message=(f"Confused deputy blocked: '{principal.id}' is acting on authority delegated by "
                                 f"'{delegator.id}' ({delegator.type}, role '{delegator.role}'), who is not itself "
                                 f"allowed to '{tool.action}' with '{tool.name}' on "
                                 f"'{resource_id or 'n/a'}' ({link_decision.reason_code})"),
                        matched_policy=link_decision.matched_policy, **ctx)

        # 8. Human approval ---------------------------------------------------------
        if tool.requires_approval:
            if not approval_id:
                req = approvals.create_request(db, principal, tool.name, arguments, (payload or {}).get("del_id"))
                return self._respond(db, decision="PENDING", code="APPROVAL_REQUIRED",
                                     message=f"'{tool.name}' is a {tool.risk_level}-risk tool and needs approval "
                                             f"by an administrator other than the requester",
                                     outcome="awaiting_approval", extra={"approval_id": req.id}, **ctx)
            ok, a_code, a_msg = approvals.check_approval(db, str(approval_id), principal, tool.name, arguments)
            if not ok:
                return self._respond(db, decision="DENY", code=a_code, message=a_msg,
                                     extra={"approval_id": str(approval_id)}, **ctx)

        # 9. Atomic consumption (single-use delegation, approval) ------------------
        if grant is not None and grant.is_single_use:
            ok, r_code, r_msg = delegation_engine.consume_single_use(db, grant, payload["jti"], principal.id)
            if not ok:
                return self._respond(db, decision="DENY", code=r_code, message=r_msg, **ctx)
        if tool.requires_approval and not approvals.consume_approval(db, str(approval_id)):
            return self._respond(db, decision="DENY", code="APPROVAL_ALREADY_USED",
                                 message="Approval has already been used", **ctx)

        # 10. Forward to upstream ----------------------------------------------------
        result = self.upstream.execute(db, tool, arguments, principal.tenant_id, principal.id, corr_id)
        outcome = "error" if result.get("isError") else "success"
        return self._respond(db, decision="ALLOW", code=decision.reason_code, message=decision.explanation,
                             matched_policy=decision.matched_policy, outcome=outcome, result=result,
                             extra={"upstream_error": result.get("gatewayError")} if result.get("gatewayError")
                             else None, **ctx)


gateway_interceptor = GatewayInterceptor()

"""AgentFence Policy Decision Point (RBAC + ABAC).

Semantics
---------
1. Missing principal/tenant -> DENY.
2. Hard tenant isolation: a resource owned by another tenant -> DENY, before
   any policy is consulted (no policy can override it).
3. Tenant policies are matched on principal type/id, role, tool, action and
   resource (case-sensitive glob). A policy with a resource pattern other
   than ``*`` only matches calls that actually name a resource.
4. ABAC conditions must *all* hold for a policy to match. Unknown or malformed
   conditions fail closed: an ALLOW with an unknown condition never matches,
   a DENY with an unknown condition always matches.
5. Deny-overrides: any matching DENY wins over every ALLOW (priority only
   orders which policy is reported). No matching ALLOW -> default DENY.
"""
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, time, timezone
from fnmatch import fnmatchcase
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.entities import MCPTool, Policy, ProtectedResource

SENSITIVITY_ORDER = ["public", "internal", "confidential", "secret"]
RISK_ORDER = ["low", "medium", "high", "critical"]

KNOWN_CONDITIONS = {
    "requires_delegation", "tenant_mismatch", "role_in", "role_not_in", "resource_owner",
    "max_sensitivity", "max_risk_level", "min_risk_level", "time_window", "args", "delegation_max_depth",
}
KNOWN_ARG_CONSTRAINTS = {"max", "min", "in", "not_in", "pattern", "max_length", "path_prefix"}


@dataclass
class PolicyDecision:
    decision: str  # ALLOW | DENY
    reason_code: str
    explanation: str
    matched_policy: Optional[str]
    principal: str
    tenant: str
    tool: str
    action: str
    resource: Optional[str]
    correlation_id: str
    evaluated_policies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def check_arg_constraints(arguments: Dict[str, Any], constraints: Dict[str, Any]) -> Optional[str]:
    """Returns None if every constraint holds, else a human-readable violation."""
    for param, rule in constraints.items():
        if not isinstance(rule, dict) or set(rule) - KNOWN_ARG_CONSTRAINTS:
            return f"invalid constraint for '{param}'"
        if param not in arguments:
            continue  # presence is enforced by the tool schema ('required')
        value = arguments[param]
        if "in" in rule and value not in rule["in"]:
            return f"'{param}'={value!r} not in allowed values {rule['in']}"
        if "not_in" in rule and value in rule["not_in"]:
            return f"'{param}'={value!r} is a forbidden value"
        if "max" in rule or "min" in rule:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return f"'{param}' must be numeric"
            if "max" in rule and value > rule["max"]:
                return f"'{param}'={value} exceeds maximum {rule['max']}"
            if "min" in rule and value < rule["min"]:
                return f"'{param}'={value} below minimum {rule['min']}"
        if "max_length" in rule and isinstance(value, str) and len(value) > rule["max_length"]:
            return f"'{param}' longer than {rule['max_length']} characters"
        if "pattern" in rule and (not isinstance(value, str) or not re.fullmatch(rule["pattern"], value)):
            return f"'{param}' does not match required pattern"
        if "path_prefix" in rule:
            if not isinstance(value, str) or ".." in value.replace("\\", "/").split("/") or "\x00" in value:
                return f"'{param}' contains path traversal"
            normalized = value.replace("\\", "/")
            if not any(normalized.startswith(p) for p in rule["path_prefix"]):
                return f"'{param}' outside allowed paths {rule['path_prefix']}"
    return None


class PolicyEngine:
    def __init__(self, clock=lambda: datetime.now(timezone.utc)):
        self.clock = clock

    # ------------------------------------------------------------ conditions
    def _conditions_hold(
        self,
        conditions: Dict[str, Any],
        *,
        db: Session,
        tenant_id: str,
        principal_id: str,
        principal_role: str,
        resource: Optional[ProtectedResource],
        tool: Optional[MCPTool],
        arguments: Dict[str, Any],
        delegation_payload: Optional[Dict[str, Any]],
    ) -> Optional[bool]:
        """True/False, or None when a condition is unknown/malformed."""
        if set(conditions) - KNOWN_CONDITIONS:
            return None
        try:
            if conditions.get("requires_delegation") and not delegation_payload:
                return False
            if conditions.get("tenant_mismatch"):
                if resource is None or resource.tenant_id == tenant_id:
                    return False
            if "role_in" in conditions and principal_role not in conditions["role_in"]:
                return False
            if "role_not_in" in conditions and principal_role in conditions["role_not_in"]:
                return False
            if "resource_owner" in conditions:
                if resource is None:
                    return False
                mode = conditions["resource_owner"]
                if mode == "principal":
                    owner = principal_id
                elif mode == "original_user":
                    owner = (delegation_payload or {}).get("orig_uid")
                else:
                    return None
                if resource.owner_id != owner:
                    return False
            if "max_sensitivity" in conditions:
                if resource is None:
                    return False
                if SENSITIVITY_ORDER.index(resource.sensitivity_level) > SENSITIVITY_ORDER.index(conditions["max_sensitivity"]):
                    return False
            if "max_risk_level" in conditions:
                if tool is None or RISK_ORDER.index(tool.risk_level) > RISK_ORDER.index(conditions["max_risk_level"]):
                    return False
            if "min_risk_level" in conditions:
                if tool is None or RISK_ORDER.index(tool.risk_level) < RISK_ORDER.index(conditions["min_risk_level"]):
                    return False
            if "time_window" in conditions:
                tw = conditions["time_window"]
                start, end = time.fromisoformat(tw["start"]), time.fromisoformat(tw["end"])
                now = self.clock().astimezone(timezone.utc).time()
                inside = start <= now <= end if start <= end else (now >= start or now <= end)
                if not inside:
                    return False
            if "delegation_max_depth" in conditions:
                if not delegation_payload or int(delegation_payload.get("cur_depth", 99)) > int(conditions["delegation_max_depth"]):
                    return False
            if "args" in conditions:
                if not isinstance(conditions["args"], dict):
                    return None
                violation = check_arg_constraints(arguments, conditions["args"])
                if violation and violation.startswith("invalid constraint"):
                    return None
                if violation:
                    return False
        except (KeyError, ValueError, TypeError):
            return None
        return True

    # -------------------------------------------------------------- evaluate
    def evaluate(
        self,
        db: Session,
        principal_id: str,
        principal_type: str,
        principal_role: str,
        acting_agent_id: Optional[str],
        tenant_id: str,
        tool_name: str,
        requested_action: str,
        resource_id: Optional[str] = None,
        delegation_payload: Optional[Dict[str, Any]] = None,
        correlation_id: str = "corr_default",
        arguments: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        def decide(decision: str, code: str, explanation: str, matched: Optional[str] = None,
                   evaluated: Optional[List[str]] = None) -> PolicyDecision:
            return PolicyDecision(decision, code, explanation, matched, principal_id or "anonymous",
                                  tenant_id or "unknown", tool_name, requested_action, resource_id,
                                  correlation_id, evaluated or [])

        if not principal_id or not tenant_id:
            return decide("DENY", "AUTHZ_MISSING_IDENTITY", "Request lacks authenticated principal or tenant context")

        arguments = arguments or {}
        resource = db.get(ProtectedResource, resource_id) if resource_id else None
        tool = db.query(MCPTool).filter(MCPTool.name == tool_name).first()

        # Hard tenant isolation (not overridable by policy).
        if resource is not None and resource.tenant_id != tenant_id:
            return decide(
                "DENY", "AUTHZ_CROSS_TENANT_VIOLATION",
                f"Cross-tenant access blocked: principal '{principal_id}' belongs to tenant '{tenant_id}', "
                f"but resource '{resource_id}' belongs to tenant '{resource.tenant_id}'.",
                "builtin:strict_tenant_isolation",
            )

        policies = (
            db.query(Policy)
            .filter(Policy.tenant_id == tenant_id, Policy.is_active.is_(True))
            .order_by(Policy.priority.asc(), Policy.id.asc())
            .all()
        )
        denials: List[Policy] = []
        allows: List[Policy] = []
        evaluated: List[str] = []

        for pol in policies:
            if pol.principal_type not in ("*", principal_type):
                continue
            if pol.principal_id not in ("*", principal_id):
                continue
            if pol.role not in ("*", principal_role):
                continue
            if not fnmatchcase(tool_name, pol.tool_pattern):
                continue
            if not fnmatchcase(requested_action, pol.action_pattern):
                continue
            if pol.resource_pattern != "*":
                if not resource_id or not fnmatchcase(resource_id, pol.resource_pattern):
                    continue
            evaluated.append(pol.id)
            holds = self._conditions_hold(
                pol.get_conditions(), db=db, tenant_id=tenant_id, principal_id=principal_id,
                principal_role=principal_role, resource=resource, tool=tool, arguments=arguments,
                delegation_payload=delegation_payload,
            )
            if pol.effect == "DENY":
                if holds is None or holds:  # unknown condition on a DENY -> fail closed (applies)
                    denials.append(pol)
            elif pol.effect == "ALLOW":
                if holds:  # unknown condition on an ALLOW -> fail closed (does not apply)
                    allows.append(pol)

        if denials:
            d = denials[0]
            return decide("DENY", "AUTHZ_EXPLICIT_DENY_POLICY",
                          f"Denied by explicit policy '{d.name}' ({d.id}): {d.description or 'no description'}",
                          d.id, evaluated)
        if allows:
            a = allows[0]
            return decide("ALLOW", "AUTHZ_PERMITTED_BY_POLICY", f"Authorized by policy '{a.name}' ({a.id})",
                          a.id, evaluated)
        return decide(
            "DENY", "AUTHZ_NO_MATCHING_ALLOW_POLICY",
            f"Default deny: no active policy allows '{principal_id}' ({principal_role}) to perform "
            f"'{requested_action}' with '{tool_name}' on resource '{resource_id or 'none'}'",
            None, evaluated,
        )

    # ------------------------------------------------------------- discovery
    def may_discover_tool(self, db: Session, principal_id: str, principal_type: str, principal_role: str,
                          tenant_id: str, tool: MCPTool) -> bool:
        """Used to filter ``tools/list``: could *some* call to this tool be allowed?

        Resource patterns and argument/resource conditions are ignored (they are
        call-specific); an unconditional DENY hides the tool.
        """
        call_specific = {"args", "resource_owner", "max_sensitivity", "tenant_mismatch",
                         "requires_delegation", "delegation_max_depth", "time_window"}
        allowed = False
        for pol in db.query(Policy).filter(Policy.tenant_id == tenant_id, Policy.is_active.is_(True)).all():
            if pol.principal_type not in ("*", principal_type) or pol.principal_id not in ("*", principal_id):
                continue
            if pol.role not in ("*", principal_role):
                continue
            if not fnmatchcase(tool.name, pol.tool_pattern) or not fnmatchcase(tool.action, pol.action_pattern):
                continue
            conds = pol.get_conditions()
            static = {k: v for k, v in conds.items() if k not in call_specific}
            holds = self._conditions_hold(static, db=db, tenant_id=tenant_id, principal_id=principal_id,
                                          principal_role=principal_role, resource=None, tool=tool,
                                          arguments={}, delegation_payload=None)
            if pol.effect == "DENY" and pol.resource_pattern == "*" and not (set(conds) & call_specific) \
                    and holds is not False:
                return False
            if pol.effect == "ALLOW" and holds:
                allowed = True
        return allowed


policy_engine = PolicyEngine()

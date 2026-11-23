/**
 * AgentFence dashboard API client.
 *
 * Every management call carries the operator's identity token
 * (`Authorization: Bearer ...`). The token is short-lived (15 minutes) and is
 * kept in sessionStorage so it disappears when the tab is closed; a 401 from
 * the gateway clears it and returns the user to the login screen.
 */

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://127.0.0.1:8080'
  : '';

const TOKEN_KEY = 'agentfence.token';
const PRINCIPAL_KEY = 'agentfence.principal';

export interface Principal {
  id: string;
  type: 'user' | 'agent';
  tenant_id: string;
  role: string;
  is_admin: boolean;
  is_platform_admin: boolean;
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

let unauthorizedHandler: (() => void) | null = null;

export const session = {
  token(): string | null {
    try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
  },
  principal(): Principal | null {
    try {
      const raw = sessionStorage.getItem(PRINCIPAL_KEY);
      return raw ? (JSON.parse(raw) as Principal) : null;
    } catch { return null; }
  },
  save(token: string, principal: Principal) {
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
      sessionStorage.setItem(PRINCIPAL_KEY, JSON.stringify(principal));
    } catch { /* storage unavailable: session lasts until reload */ }
  },
  clear() {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(PRINCIPAL_KEY);
    } catch { /* ignore */ }
  },
  onUnauthorized(handler: () => void) {
    unauthorizedHandler = handler;
  },
};

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = session.token();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body) headers.set('Content-Type', 'application/json');
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  let body: any = null;
  try { body = await res.json(); } catch { body = null; }
  if (res.status === 401 && token) {
    session.clear();
    unauthorizedHandler?.();
  }
  // A rejected delegation (403 with {success:false}) is a normal, displayable result.
  const displayable = res.status === 403 && body && typeof body === 'object' && 'success' in body;
  if (!res.ok && !displayable) {
    throw new ApiError(res.status, body?.code ?? 'HTTP_ERROR', body?.error ?? body?.message ?? res.statusText);
  }
  return body as T;
}

const post = <T>(path: string, data?: unknown) =>
  request<T>(path, { method: 'POST', body: data === undefined ? undefined : JSON.stringify(data) });

export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  protocol: string;
  environment: string;
}

export interface SecurityMetrics {
  total_requests: number;
  allowed_requests: number;
  denied_requests: number;
  pending_approvals: number;
  security_incidents: Record<string, number>;
  tool_distribution: Array<{ tool: string; count: number }>;
  recent_events: Array<{
    id: string;
    event_type: string;
    timestamp: string;
    tenant_id: string;
    agent_id?: string;
    user_id?: string;
    tool?: string;
    action?: string;
    resource_id?: string;
    decision: string;
    reason_code?: string;
    reason?: string;
    attack_classification?: string;
  }>;
}

export interface TenantInfo {
  id: string;
  name: string;
  slug: string;
  description: string;
  status: string;
  users_count: number;
  agents_count: number;
  resources_count: number;
  policies_count: number;
}

export interface AgentInfo {
  id: string;
  tenant_id: string;
  name: string;
  agent_type: string;
  role: string;
  description: string;
  is_active: boolean;
}

export interface MCPToolInfo {
  id: string;
  name: string;
  description: string;
  parameters_schema: any;
  required_scopes: string[];
  risk_level: string;
  action: string;
  resource_param?: string | null;
  requires_approval: boolean;
  rate_limit_per_minute?: number | null;
  upstream_endpoint: string;
  is_enabled: boolean;
  is_quarantined: boolean;
  quarantine_reason?: string | null;
}

export interface DelegationGrantInfo {
  id: string;
  delegation_id: string;
  parent_delegation_id?: string;
  tenant_id: string;
  original_user_id: string;
  delegating_agent_id: string;
  delegator_type: string;
  receiving_agent_id: string;
  permitted_tools: string[];
  permitted_actions: string[];
  resource_restrictions: string[];
  current_depth: number;
  max_depth: number;
  is_single_use: boolean;
  is_consumed: boolean;
  is_revoked: boolean;
  expires_at: string;
  jti: string;
  token_fingerprint: string;
}

export interface PolicyInfo {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  effect: 'ALLOW' | 'DENY';
  principal_type: string;
  principal_id: string;
  role: string;
  tool_pattern: string;
  action_pattern: string;
  resource_pattern: string;
  conditions: any;
  priority: number;
  is_active: boolean;
}

export interface AuditEventInfo {
  id: string;
  seq: number;
  event_type: string;
  request_id: string;
  correlation_id: string;
  timestamp: string;
  tenant_id: string;
  user_id?: string;
  agent_id?: string;
  delegation_id?: string;
  tool?: string;
  action?: string;
  resource_id?: string;
  decision: 'ALLOW' | 'DENY' | 'PENDING';
  reason_code?: string;
  denial_reason?: string;
  attack_classification?: string;
  execution_outcome: string;
  previous_record_hash: string;
  record_hash: string;
}

export interface ApprovalInfo {
  id: string;
  tenant_id: string;
  requester_id: string;
  requester_type: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  delegation_id?: string;
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'USED';
  created_at: string;
  expires_at: string;
  decided_by?: string;
  decision_note?: string;
}

export interface ScenarioInfo {
  key: string;
  name: string;
  description: string;
  owasp: string;
  expected_result: string;
}

export interface AttackSimulationResult extends ScenarioInfo {
  scenario_name: string;
  actual_result: string;
  passed: boolean;
  request_details: any;
  checks_evaluated: Array<{ check: string; status: string }>;
  audit_event_id?: string;
}

export const api = {
  async login(username: string, password: string): Promise<Principal> {
    const res = await post<{ access_token: string; principal: Principal }>('/api/v1/auth/login', { username, password });
    session.save(res.access_token, res.principal);
    return res.principal;
  },

  async logout(): Promise<void> {
    try { await post('/api/v1/auth/logout'); } finally { session.clear(); }
  },

  getHealth: () => request<HealthStatus>('/api/v1/health'),
  getMetrics: () => request<SecurityMetrics>('/api/v1/metrics/overview'),
  getTenants: () => request<TenantInfo[]>('/api/v1/tenants'),
  getTenantDetails: (id: string) => request<any>(`/api/v1/tenants/${encodeURIComponent(id)}`),
  getAgents: () => request<AgentInfo[]>('/api/v1/agents'),
  getTools: () => request<MCPToolInfo[]>('/api/v1/tools'),
  getDelegations: () => request<DelegationGrantInfo[]>('/api/v1/delegations'),
  createDelegation: (data: {
    receiving_agent_id: string;
    parent_delegation_id?: string | null;
    permitted_tools: string[];
    resource_restrictions: string[];
    duration_minutes: number;
    is_single_use?: boolean;
  }) => post<any>('/api/v1/delegations', data),
  revokeDelegation: (id: string) => post<any>(`/api/v1/delegations/revoke/${encodeURIComponent(id)}`),
  getPolicies: () => request<PolicyInfo[]>('/api/v1/policies'),
  togglePolicy: (id: string) => post<any>(`/api/v1/policies/${encodeURIComponent(id)}/toggle`),
  simulatePolicy: (params: {
    tenant_id?: string;
    principal_id: string;
    tool_name: string;
    resource_id?: string;
    assume_delegation?: boolean;
  }) => post<any>('/api/v1/policies/simulate', params),
  getApprovals: () => request<ApprovalInfo[]>('/api/v1/approvals'),
  decideApproval: (id: string, decision: 'approve' | 'deny', note?: string) =>
    post<any>(`/api/v1/approvals/${encodeURIComponent(id)}/decision`, { decision, note }),

  getAuditEvents(filters?: { tenant_id?: string; tool?: string; decision?: string; event_type?: string }) {
    const params = new URLSearchParams();
    Object.entries(filters ?? {}).forEach(([k, v]) => {
      if (v && v !== 'ALL') params.append(k, v);
    });
    return request<AuditEventInfo[]>(`/api/v1/audit/events?${params.toString()}`);
  },
  verifyAuditIntegrity: () => request<any>('/api/v1/audit/verify'),

  getSimulationCatalog: () => request<ScenarioInfo[]>('/api/v1/simulations/catalog'),
  runAttackSimulations: (scenarioKey?: string) =>
    post<AttackSimulationResult[]>(
      scenarioKey ? `/api/v1/simulations/run?scenario=${encodeURIComponent(scenarioKey)}` : '/api/v1/simulations/run',
    ),
};

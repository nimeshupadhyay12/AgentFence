import React, { useEffect, useState } from 'react';
import { api, ApiError, PolicyInfo, Principal } from '../services/api';

interface PolicyManagementPageProps {
  principal: Principal;
}

export default function PolicyManagementPage({ principal: operator }: PolicyManagementPageProps) {
  const [policies, setPolicies] = useState<PolicyInfo[]>([]);
  const [tenant, setTenant] = useState(operator.is_platform_admin ? 'tenant_alpha' : operator.tenant_id);
  const [principal, setPrincipal] = useState('agent_alpha_primary');
  const [assumeDelegation, setAssumeDelegation] = useState(true);
  const [tool, setTool] = useState('read_document');
  const [resource, setResource] = useState('doc_alpha_falcon');
  const [simResult, setSimResult] = useState<any>(null);

  const fetchPolicies = async () => {
    try {
      const data = await api.getPolicies();
      setPolicies(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleToggle = async (id: string) => {
    try {
      await api.togglePolicy(id);
    } catch (e) {
      alert(e instanceof ApiError ? e.message : 'Toggle failed');
    }
    fetchPolicies();
  };

  const handleSimulate = async () => {
    try {
      const res = await api.simulatePolicy({
        tenant_id: tenant,
        principal_id: principal,
        tool_name: tool,
        resource_id: resource || undefined,
        assume_delegation: assumeDelegation,
      });
      setSimResult(res);
    } catch (e) {
      setSimResult({ decision: 'ERROR', reason_code: e instanceof ApiError ? e.code : 'ERROR',
                     explanation: e instanceof ApiError ? e.message : 'Request failed' });
    }
  };

  return (
    <div>
      <div className="card-panel" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
        <h3 className="card-title">Policy Decision Simulator</h3>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '14px' }}>
          Dry-run the live Policy Decision Point. The principal's role and the tool's action are looked up on the
          server, exactly as the gateway does for a real call.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '14px' }}>
          <div className="form-group">
            <label className="form-label">Tenant Context</label>
            <select className="form-select" value={tenant} onChange={(e) => setTenant(e.target.value)}
                    disabled={!operator.is_platform_admin}>
              <option value="tenant_alpha">Tenant Alpha</option>
              <option value="tenant_beta">Tenant Beta</option>
              {!['tenant_alpha', 'tenant_beta'].includes(operator.tenant_id) && (
                <option value={operator.tenant_id}>{operator.tenant_id}</option>
              )}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Principal ID</label>
            <input className="form-input" value={principal} onChange={(e) => setPrincipal(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Delegation context</label>
            <label style={{ fontSize: '12.5px' }}>
              <input type="checkbox" checked={assumeDelegation} onChange={(e) => setAssumeDelegation(e.target.checked)} />
              {' '}Assume a valid delegation is presented
            </label>
          </div>
          <div className="form-group">
            <label className="form-label">MCP Tool</label>
            <select className="form-select" value={tool} onChange={(e) => setTool(e.target.value)}>
              <option value="read_document">read_document</option>
              <option value="search_knowledge_base">search_knowledge_base</option>
              <option value="execute_analytics_query">execute_analytics_query</option>
              <option value="export_tenant_report">export_tenant_report</option>
              <option value="admin_override">admin_override</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Resource ID</label>
            <input className="form-input" value={resource} onChange={(e) => setResource(e.target.value)} />
          </div>
        </div>
        <button className="btn btn-primary" onClick={handleSimulate}>Evaluate Policy Decision</button>

        {simResult && (
          <div style={{ marginTop: '16px', padding: '14px', borderRadius: '8px', background: '#0f172a', border: `1px solid ${simResult.decision === 'ALLOW' ? 'var(--status-allow)' : 'var(--status-deny)'}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 700, color: simResult.decision === 'ALLOW' ? 'var(--status-allow)' : 'var(--status-deny)' }}>
                DECISION: {simResult.decision}
              </span>
              <span className="code-pill">{simResult.reason_code}</span>
            </div>
            <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', marginTop: '6px' }}>
              {simResult.explanation} {simResult.matched_policy && `[Matched: ${simResult.matched_policy}]`}
              {simResult.requires_approval && ' This tool additionally requires human approval at call time.'}
            </p>
          </div>
        )}
      </div>

      <div className="card-panel">
        <h3 className="card-title">Configured Policies</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Priority</th>
              <th>Policy Name</th>
              <th>Tenant</th>
              <th>Effect</th>
              <th>Principal Match</th>
              <th>Tool Pattern</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {policies.map((p) => (
              <tr key={p.id}>
                <td><strong>{p.priority}</strong></td>
                <td><strong>{p.name}</strong></td>
                <td><span className="code-pill">{p.tenant_id}</span></td>
                <td><span className={`badge ${p.effect === 'ALLOW' ? 'badge-allow' : 'badge-deny'}`}>{p.effect}</span></td>
                <td>{p.principal_id} ({p.role})</td>
                <td><span className="code-pill">{p.tool_pattern}</span></td>
                <td>{p.action_pattern}</td>
                <td><span className="code-pill">{p.resource_pattern}</span></td>
                <td><span className={`badge ${p.is_active ? 'badge-allow' : 'badge-warn'}`}>{p.is_active ? 'ACTIVE' : 'DISABLED'}</span></td>
                <td>
                  <button className="btn btn-secondary" style={{ padding: '3px 8px', fontSize: '11px' }} onClick={() => handleToggle(p.id)}>
                    {p.is_active ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

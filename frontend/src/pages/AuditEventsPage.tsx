import React, { useEffect, useState } from 'react';
import { api, AuditEventInfo } from '../services/api';

export default function AuditEventsPage() {
  const [events, setEvents] = useState<AuditEventInfo[]>([]);
  const [tenantFilter, setTenantFilter] = useState('ALL');
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const [toolFilter, setToolFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');

  const fetchEvents = async () => {
    try {
      const data = await api.getAuditEvents({
        tenant_id: tenantFilter,
        decision: decisionFilter,
        tool: toolFilter,
        event_type: typeFilter,
      });
      setEvents(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [tenantFilter, decisionFilter, toolFilter, typeFilter]);

  const handleVerify = async () => {
    const res = await api.verifyAuditIntegrity().catch(() => null);
    if (!res) return;
    if (res.is_valid) {
      alert(`Audit Ledger Integrity Verified!\n\nStatus: VALID\nTotal Records: ${res.records_verified}\nChain Head: ${res.chain_head_hash}`);
    } else {
      alert(`Tampering detected at record: ${res.error_details?.event_id}`);
    }
  };

  return (
    <div className="card-panel">
      <div style={{ display: 'flex', gap: '12px', marginBottom: '20px', flexWrap: 'wrap', alignItems: 'center' }}>
        <select className="form-select" style={{ width: '180px' }} value={tenantFilter} onChange={(e) => setTenantFilter(e.target.value)}>
          <option value="ALL">All Tenants</option>
          <option value="tenant_alpha">Tenant Alpha</option>
          <option value="tenant_beta">Tenant Beta</option>
          <option value="tenant_platform">Platform (SecOps)</option>
          <option value="unauthenticated">Unauthenticated</option>
        </select>
        <select className="form-select" style={{ width: '190px' }} value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
          <option value="ALL">All Event Types</option>
          <option value="tool_call">tool_call</option>
          <option value="auth.login">auth.login</option>
          <option value="auth.logout">auth.logout</option>
          <option value="delegation.create">delegation.create</option>
          <option value="delegation.revoke">delegation.revoke</option>
          <option value="policy.toggle">policy.toggle</option>
          <option value="approval.decision">approval.decision</option>
          <option value="tool.register">tool.register</option>
          <option value="api.access_denied">api.access_denied</option>
        </select>
        <select className="form-select" style={{ width: '160px' }} value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)}>
          <option value="ALL">All Decisions</option>
          <option value="ALLOW">ALLOW Only</option>
          <option value="DENY">DENY Only</option>
          <option value="PENDING">PENDING Only</option>
        </select>
        <select className="form-select" style={{ width: '220px' }} value={toolFilter} onChange={(e) => setToolFilter(e.target.value)}>
          <option value="ALL">All Tools</option>
          <option value="read_document">read_document</option>
          <option value="search_knowledge_base">search_knowledge_base</option>
          <option value="execute_analytics_query">execute_analytics_query</option>
          <option value="export_tenant_report">export_tenant_report</option>
          <option value="admin_override">admin_override</option>
        </select>
        <button className="btn btn-secondary" onClick={fetchEvents}>Refresh</button>
        <button className="btn btn-primary" style={{ marginLeft: 'auto' }} onClick={handleVerify}>Verify Hash Chain</button>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Seq</th>
            <th>Timestamp</th>
            <th>Event</th>
            <th>Tenant</th>
            <th>Agent / Principal</th>
            <th>Tool</th>
            <th>Action</th>
            <th>Resource</th>
            <th>Decision</th>
            <th>Reason & Classification</th>
            <th>Hash Pointer</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td><strong>#{e.seq}</strong></td>
              <td style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{e.timestamp.replace('T', ' ').substring(0, 19)}</td>
              <td style={{ fontSize: '11px' }}>{e.event_type}</td>
              <td><span className="code-pill">{e.tenant_id}</span></td>
              <td>{e.agent_id || e.user_id || 'system'}</td>
              <td>{e.tool ? <span className="code-pill">{e.tool}</span> : '-'}</td>
              <td>{e.action || '-'}</td>
              <td>{e.resource_id ? <span className="code-pill">{e.resource_id}</span> : '-'}</td>
              <td>
                <span className={`badge ${e.decision === 'ALLOW' ? 'badge-allow' : e.decision === 'PENDING' ? 'badge-warn' : 'badge-deny'}`}>
                  {e.decision}
                </span>
              </td>
              <td style={{ fontSize: '11.5px' }}>
                {e.reason_code && <span className="code-pill">{e.reason_code}</span>} {e.denial_reason || ''}{' '}
                {e.attack_classification && <span className="badge badge-warn">{e.attack_classification}</span>}
              </td>
              <td><span className="code-pill" title={`Hash: ${e.record_hash}`}>{e.record_hash.substring(0, 10)}...</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

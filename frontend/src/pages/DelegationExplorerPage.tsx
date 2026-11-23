import React, { useEffect, useState } from 'react';
import { api, ApiError, DelegationGrantInfo, Principal } from '../services/api';

interface DelegationExplorerPageProps {
  principal: Principal;
}

export default function DelegationExplorerPage({ principal }: DelegationExplorerPageProps) {
  const [grants, setGrants] = useState<DelegationGrantInfo[]>([]);
  const [showModal, setShowModal] = useState(false);
  const [receiver, setReceiver] = useState('agent_alpha_primary');
  const [parent, setParent] = useState('');
  const [tools, setTools] = useState('read_document');
  const [resources, setResources] = useState('doc_alpha_radar');
  const [duration, setDuration] = useState(30);
  const [singleUse, setSingleUse] = useState(false);
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const fetchGrants = async () => {
    try {
      setGrants(await api.getDelegations());
    } catch (e) {
      setMessage(e instanceof ApiError ? e.message : 'Failed to load delegations');
    }
  };

  useEffect(() => {
    fetchGrants();
  }, []);

  const handleRevoke = async (id: string) => {
    if (!confirm(`Revoke delegation ${id}? Every delegation derived from it stops working too.`)) return;
    try {
      const res = await api.revokeDelegation(id);
      setMessage(res.message);
    } catch (e) {
      setMessage(e instanceof ApiError ? `${e.message} (${e.code})` : 'Revocation failed');
    }
    fetchGrants();
  };

  const handleCreate = async () => {
    try {
      const res = await api.createDelegation({
        receiving_agent_id: receiver.trim(),
        parent_delegation_id: parent.trim() || null,
        permitted_tools: tools.split(',').map((s) => s.trim()).filter(Boolean),
        resource_restrictions: resources.split(',').map((s) => s.trim()).filter(Boolean),
        duration_minutes: duration,
        is_single_use: singleUse,
      });
      if (res.success) {
        setIssuedToken(res.delegation_token);
        setMessage(`Delegation ${res.delegation_id} issued (depth ${res.current_depth}/${res.max_depth}).`);
        setShowModal(false);
        fetchGrants();
      } else {
        setMessage(`DELEGATION REJECTED [${res.code}]: ${res.error}`);
      }
    } catch (e) {
      setMessage(e instanceof ApiError ? `${e.message} (${e.code})` : 'Request failed');
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontSize: '16px', fontWeight: 700 }}>Hierarchical Delegation Chains</h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Signed, attenuated delegation chains. You always delegate as yourself ({principal.id}); users issue root
            grants for permissions they hold, agents can only narrow a grant issued to them.
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>Issue New Delegation</button>
      </div>

      {message && <div className="card-panel" style={{ fontSize: '12.5px' }}>{message}</div>}
      {issuedToken && (
        <div className="card-panel" style={{ borderLeft: '4px solid var(--status-warn)' }}>
          <h3 className="card-title">Delegation credential (shown once)</h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
            Give this to the receiving agent; it sends it as the <code>X-Delegation-Token</code> header together with
            its own identity token. AgentFence stores only its SHA-256 fingerprint.
          </p>
          <textarea className="form-input" readOnly rows={3} value={issuedToken} style={{ fontFamily: 'monospace', fontSize: '11px' }} />
          <button className="btn btn-secondary" style={{ marginTop: '8px' }} onClick={() => setIssuedToken(null)}>Dismiss</button>
        </div>
      )}

      <div className="card-panel">
        <h3 className="card-title">Delegation Grants</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Delegation ID</th>
              <th>Parent ID</th>
              <th>Tenant</th>
              <th>Delegator</th>
              <th>Receiver</th>
              <th>Tools / Resources</th>
              <th>Depth</th>
              <th>Fingerprint</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.id}>
                <td><span className="code-pill">{g.delegation_id}</span></td>
                <td>{g.parent_delegation_id ? <span className="code-pill">{g.parent_delegation_id}</span> : '- (Root)'}</td>
                <td><span className="code-pill">{g.tenant_id}</span></td>
                <td>{g.delegating_agent_id} <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>({g.delegator_type})</span></td>
                <td><strong>{g.receiving_agent_id}</strong></td>
                <td>
                  {g.permitted_tools.map((t) => <span key={t} className="code-pill">{t}</span>)}
                  <div style={{ fontSize: '10.5px', color: 'var(--text-dim)' }}>
                    {g.resource_restrictions.length ? g.resource_restrictions.join(', ') : 'any resource'}
                  </div>
                </td>
                <td><span className="badge badge-info">{g.current_depth} / {g.max_depth}</span></td>
                <td><span className="code-pill" title={g.token_fingerprint}>{g.token_fingerprint.substring(0, 10)}…</span></td>
                <td>
                  <span className={`badge ${g.is_revoked ? 'badge-deny' : g.is_consumed ? 'badge-warn' : 'badge-allow'}`}>
                    {g.is_revoked ? 'Revoked' : g.is_consumed ? 'Consumed' : g.is_single_use ? 'Single-use' : 'Active'}
                  </span>
                </td>
                <td>
                  {!g.is_revoked && (
                    <button className="btn btn-danger" style={{ padding: '3px 8px', fontSize: '11px' }} onClick={() => handleRevoke(g.delegation_id)}>
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '16px' }}>Issue Attenuated Delegation</h3>
            <div className="form-group">
              <label className="form-label">Delegator</label>
              <input type="text" className="form-input" value={`${principal.id} (you, tenant ${principal.tenant_id})`} disabled />
            </div>
            <div className="form-group">
              <label className="form-label">Receiving Agent</label>
              <input type="text" className="form-input" value={receiver} onChange={(e) => setReceiver(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Parent Delegation ID (agents only; empty for a root grant)</label>
              <input type="text" className="form-input" value={parent} onChange={(e) => setParent(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Permitted Tools (comma separated)</label>
              <input type="text" className="form-input" value={tools} onChange={(e) => setTools(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Resource Restrictions (comma separated, empty = any)</label>
              <input type="text" className="form-input" value={resources} onChange={(e) => setResources(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Duration (minutes)</label>
              <input type="number" className="form-input" value={duration} min={1}
                     onChange={(e) => setDuration(parseInt(e.target.value, 10) || 1)} />
            </div>
            <div className="form-group">
              <label className="form-label">
                <input type="checkbox" checked={singleUse} onChange={(e) => setSingleUse(e.target.checked)} /> Single-use
              </label>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
              <button className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleCreate}>Create Signed Delegation</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

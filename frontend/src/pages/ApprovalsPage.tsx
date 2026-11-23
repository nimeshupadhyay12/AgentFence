import React, { useEffect, useState } from 'react';
import { api, ApiError, ApprovalInfo, Principal } from '../services/api';

interface ApprovalsPageProps {
  principal: Principal;
}

export default function ApprovalsPage({ principal }: ApprovalsPageProps) {
  const [items, setItems] = useState<ApprovalInfo[]>([]);
  const [message, setMessage] = useState<string | null>(null);

  const load = async () => {
    try {
      setItems(await api.getApprovals());
    } catch (e) {
      setMessage(e instanceof ApiError ? e.message : 'Failed to load approvals');
    }
  };

  useEffect(() => {
    load();
  }, []);

  const decide = async (id: string, decision: 'approve' | 'deny') => {
    try {
      const res = await api.decideApproval(id, decision);
      setMessage(res.message);
    } catch (e) {
      setMessage(e instanceof ApiError ? `${e.message} (${e.code})` : 'Request failed');
    }
    load();
  };

  return (
    <div className="card-panel">
      <div className="card-title">
        <span>Human-in-the-Loop Approvals</span>
        <button className="btn btn-secondary" onClick={load}>Refresh</button>
      </div>
      <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '14px' }}>
        High-risk tools (export_tenant_report, admin_override) return PENDING until an administrator other than the
        requester approves. The requester then repeats the identical call with the approval id; an approval is bound
        to the caller, tool and exact arguments, expires, and works once.
      </p>
      {message && <p style={{ fontSize: '12.5px', marginBottom: '10px' }}>{message}</p>}
      <table className="data-table">
        <thead>
          <tr>
            <th>Approval ID</th>
            <th>Tenant</th>
            <th>Requester</th>
            <th>Tool</th>
            <th>Arguments</th>
            <th>Status</th>
            <th>Decided by</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {items.map((a) => (
            <tr key={a.id}>
              <td><span className="code-pill">{a.id}</span></td>
              <td><span className="code-pill">{a.tenant_id}</span></td>
              <td>{a.requester_id}</td>
              <td><span className="code-pill">{a.tool_name}</span></td>
              <td style={{ fontSize: '11px' }}><code>{JSON.stringify(a.arguments)}</code></td>
              <td>
                <span className={`badge ${a.status === 'APPROVED' || a.status === 'USED' ? 'badge-allow'
                  : a.status === 'DENIED' ? 'badge-deny' : 'badge-warn'}`}>{a.status}</span>
              </td>
              <td>{a.decided_by ?? '-'}</td>
              <td>
                {a.status === 'PENDING' && principal.is_admin && a.requester_id !== principal.id ? (
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <button className="btn btn-primary" style={{ padding: '3px 8px', fontSize: '11px' }}
                            onClick={() => decide(a.id, 'approve')}>Approve</button>
                    <button className="btn btn-danger" style={{ padding: '3px 8px', fontSize: '11px' }}
                            onClick={() => decide(a.id, 'deny')}>Deny</button>
                  </div>
                ) : a.status === 'PENDING' && a.requester_id === principal.id ? (
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Needs another admin</span>
                ) : '-'}
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr><td colSpan={8} style={{ color: 'var(--text-dim)' }}>No approval requests yet.</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

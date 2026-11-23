import React, { useState } from 'react';
import { api, ApiError, Principal } from '../services/api';

interface LoginPageProps {
  onLogin: (principal: Principal) => void;
}

export default function LoginPage({ onLogin }: LoginPageProps) {
  const [username, setUsername] = useState('secops_admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await api.login(username, password));
    } catch (err) {
      setError(err instanceof ApiError ? `${err.message} (${err.code})` : 'Gateway unreachable');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '16px' }}>
      <form className="card-panel" style={{ width: '100%', maxWidth: '380px' }} onSubmit={submit}>
        <div className="brand-header" style={{ marginBottom: '18px' }}>
          <div className="brand-icon">AF</div>
          <div>
            <div className="brand-title">AgentFence</div>
            <div className="brand-subtitle">Operator sign-in</div>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="username">Username</label>
          <input id="username" className="form-input" autoComplete="username" value={username}
                 onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="password">Password</label>
          <input id="password" type="password" className="form-input" autoComplete="current-password"
                 value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        {error && <p style={{ color: 'var(--status-deny)', fontSize: '12.5px', marginBottom: '10px' }}>{error}</p>}
        <button className="btn btn-primary" style={{ width: '100%' }} disabled={busy || !password}>
          {busy ? 'Signing in...' : 'Sign in'}
        </button>
        <p style={{ fontSize: '11.5px', color: 'var(--text-dim)', marginTop: '14px' }}>
          Demo credentials are generated on first start and written to <code>backend/data/demo_credentials.json</code>
          {' '}(or set <code>AGENTFENCE_DEMO_PASSWORD</code>). Use <strong>secops_admin</strong> for the full view,
          or a tenant admin such as <strong>alpha_admin</strong> to see tenant scoping.
        </p>
      </form>
    </div>
  );
}

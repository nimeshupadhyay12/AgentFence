import React, { useEffect, useState } from 'react';
import { api, ApiError, AttackSimulationResult, ScenarioInfo } from '../services/api';

export default function AttackLabPage() {
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [results, setResults] = useState<Record<string, AttackSimulationResult>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getSimulationCatalog().then(setScenarios).catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, []);

  // Results are keyed by the exact scenario key returned by the backend.
  const store = (data: AttackSimulationResult[]) =>
    setResults((prev) => ({ ...prev, ...Object.fromEntries(data.map((r) => [r.key, r])) }));

  const runAll = async () => {
    setLoading(true);
    setError(null);
    try {
      store(await api.runAttackSimulations());
    } catch (e) {
      setError(e instanceof ApiError ? `${e.message} (${e.code})` : 'Run failed');
    } finally {
      setLoading(false);
    }
  };

  const runSingle = async (key: string) => {
    try {
      store(await api.runAttackSimulations(key));
    } catch (e) {
      setError(e instanceof ApiError ? `${e.message} (${e.code})` : 'Run failed');
    }
  };

  const passed = Object.values(results).filter((r) => r.passed).length;

  return (
    <div>
      <div className="card-panel" style={{ borderLeft: '4px solid var(--status-deny)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '4px' }}>
            Attack Simulation Lab ({scenarios.length} live scenarios)
          </h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Each scenario sends real requests through the gateway and passes only if the attack is stopped by the
            specific control it targets (checked via the reason code). Mapped to the OWASP Top 10 for LLM Applications
            (2025) and the OWASP API Security Top 10.
          </p>
          {Object.keys(results).length > 0 && (
            <p style={{ fontSize: '12.5px', marginTop: '6px' }}><strong>{passed}/{Object.keys(results).length}</strong> passed</p>
          )}
        </div>
        <button className="btn btn-primary" style={{ background: 'linear-gradient(135deg, #b91c1c, #ef4444)' }} onClick={runAll} disabled={loading}>
          {loading ? 'Executing Scenarios...' : `Execute All ${scenarios.length} Attacks`}
        </button>
      </div>
      {error && <div className="card-panel" style={{ color: 'var(--status-deny)', fontSize: '12.5px' }}>{error}</div>}

      <div className="card-panel">
        <h3 className="card-title">Attack Execution Matrix</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Scenario</th>
              <th>OWASP</th>
              <th>Expected</th>
              <th>Actual</th>
              <th>Status</th>
              <th>Checks</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {scenarios.map((s, idx) => {
              const res = results[s.key];
              return (
                <tr key={s.key}>
                  <td><strong>{idx + 1}</strong></td>
                  <td>
                    <strong>{s.name}</strong>
                    <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{s.description}</div>
                  </td>
                  <td style={{ fontSize: '11px' }}>{s.owasp}</td>
                  <td style={{ fontSize: '11px' }}>{s.expected_result}</td>
                  <td>{res ? <span className="code-pill">{res.actual_result}</span> : <span style={{ color: 'var(--text-dim)' }}>Ready</span>}</td>
                  <td>
                    {res ? (
                      <span className={`badge ${res.passed ? 'badge-allow' : 'badge-deny'}`}>
                        {res.passed ? 'PASSED' : 'FAILED'}
                      </span>
                    ) : (
                      <span className="badge badge-info">PENDING</span>
                    )}
                  </td>
                  <td style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                    {res ? res.checks_evaluated.map((c, i) => (
                      <div key={i}>• {c.check}: <strong>{c.status}</strong></div>
                    )) : '-'}
                    {res?.audit_event_id && <div>audit: <span className="code-pill">{res.audit_event_id}</span></div>}
                  </td>
                  <td>
                    <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: '11.5px' }} onClick={() => runSingle(s.key)}>
                      Run
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

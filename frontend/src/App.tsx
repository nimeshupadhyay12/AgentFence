import React, { useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import OverviewPage from './pages/OverviewPage';
import AuditEventsPage from './pages/AuditEventsPage';
import DelegationExplorerPage from './pages/DelegationExplorerPage';
import PolicyManagementPage from './pages/PolicyManagementPage';
import RegistryPage from './pages/RegistryPage';
import AttackLabPage from './pages/AttackLabPage';
import TenantManagementPage from './pages/TenantManagementPage';
import ApprovalsPage from './pages/ApprovalsPage';
import LoginPage from './pages/LoginPage';
import { api, Principal, session } from './services/api';

export type TabType =
  | 'overview' | 'audit' | 'delegation' | 'policy' | 'approvals' | 'registry' | 'attack-lab' | 'tenants';

export function tabsFor(principal: Principal): TabType[] {
  const tabs: TabType[] = [];
  if (principal.is_admin) tabs.push('overview', 'audit');
  tabs.push('delegation');
  if (principal.is_admin) tabs.push('policy');
  tabs.push('approvals', 'registry');
  if (principal.is_platform_admin) tabs.push('attack-lab');
  tabs.push('tenants');
  return tabs;
}

export default function App() {
  const [principal, setPrincipal] = useState<Principal | null>(session.principal());
  const [activeTab, setActiveTab] = useState<TabType>('overview');

  useEffect(() => {
    session.onUnauthorized(() => setPrincipal(null));
  }, []);

  useEffect(() => {
    if (principal) {
      const allowed = tabsFor(principal);
      if (!allowed.includes(activeTab)) setActiveTab(allowed[0]);
    }
  }, [principal]);

  if (!principal) {
    return <LoginPage onLogin={setPrincipal} />;
  }

  const logout = async () => {
    await api.logout().catch(() => undefined);
    setPrincipal(null);
  };

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} onSelectTab={setActiveTab} tabs={tabsFor(principal)} />
      <main className="main-content">
        <header className="top-bar">
          <div className="page-title">
            <span style={{ color: 'var(--accent-cyan)' }}>AgentFence</span> — AI Agent Security Gateway
          </div>
          <div className="top-bar-right">
            <span className="badge badge-info">MCP 2024-11-05</span>
            <span className="badge badge-allow" title={principal.tenant_id}>
              {principal.id} ({principal.is_platform_admin ? 'platform admin' : principal.role})
            </span>
            <a href="/docs" target="_blank" rel="noreferrer" className="btn btn-secondary" style={{ textDecoration: 'none' }}>
              API Docs
            </a>
            <button className="btn btn-secondary" onClick={logout}>Sign out</button>
          </div>
        </header>

        <div className="content-body">
          {activeTab === 'overview' && <OverviewPage onNavigate={setActiveTab} />}
          {activeTab === 'audit' && <AuditEventsPage />}
          {activeTab === 'delegation' && <DelegationExplorerPage principal={principal} />}
          {activeTab === 'policy' && <PolicyManagementPage principal={principal} />}
          {activeTab === 'approvals' && <ApprovalsPage principal={principal} />}
          {activeTab === 'registry' && <RegistryPage />}
          {activeTab === 'attack-lab' && <AttackLabPage />}
          {activeTab === 'tenants' && <TenantManagementPage />}
        </div>
      </main>
    </div>
  );
}

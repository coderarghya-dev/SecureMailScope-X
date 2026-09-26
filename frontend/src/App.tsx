import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import AppShell from './components/layout/AppShell';
import DashboardPage from './pages/DashboardPage';
import AnalyzePage from './pages/AnalyzePage';
import SessionsPage from './pages/SessionsPage';
import SessionDetailPage from './pages/SessionDetailPage';
import FindingsPage from './pages/FindingsPage';
import CryptoPosturePage from './pages/CryptoPosturePage';
import PQCReadinessPage from './pages/PQCReadinessPage';
import PacketExplorerPage from './pages/PacketExplorerPage';
import ChainOfCustodyPage from './pages/ChainOfCustodyPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';
import PostureMonitoringPage from './pages/PostureMonitoringPage';
import RemediationPage from './pages/RemediationPage';
import PQCMigrationPage from './pages/PQCMigrationPage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="analyze" element={<AnalyzePage />} />
          <Route path="sessions" element={<SessionsPage />} />
          <Route path="sessions/:id" element={<SessionDetailPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="crypto" element={<CryptoPosturePage />} />
          <Route path="pqc" element={<PQCReadinessPage />} />
          <Route path="pqc-migration" element={<PQCMigrationPage />} />
          <Route path="packets" element={<PacketExplorerPage />} />
          <Route path="custody" element={<ChainOfCustodyPage />} />
          <Route path="monitoring" element={<PostureMonitoringPage />} />
          <Route path="remediation" element={<RemediationPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

export default App;

import React, { useEffect } from 'react';
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
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import ProtectedRoute from './components/auth/ProtectedRoute';
import { useAuthStore } from './store/useAuthStore';

export const App: React.FC = () => {
  const { checkAuth } = useAuthStore();

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  return (
    <BrowserRouter>
      <Routes>
        {/* Public Authentication Routes */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />

        {/* Protected Application Routes */}
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <AppShell />
            </ProtectedRoute>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="analyze" element={<AnalyzePage />} />
          <Route path="sessions" element={<SessionsPage />} />
          <Route path="sessions/:id" element={<SessionDetailPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="crypto" element={<CryptoPosturePage />} />
          <Route path="pqc" element={<PQCReadinessPage />} />
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

import React, { useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import { useHealthStore } from '../../store/useHealthStore';
import { useAnalysisStore } from '../../store/useAnalysisStore';

export const AppShell: React.FC = () => {
  const { checkHealth } = useHealthStore();
  const { loadAnalyses } = useAnalysisStore();

  useEffect(() => {
    checkHealth();
    loadAnalyses();
    const interval = setInterval(() => {
      checkHealth();
    }, 15000);
    return () => clearInterval(interval);
  }, [checkHealth, loadAnalyses]);

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main-viewport">
        <Header />
        <main className="main-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default AppShell;

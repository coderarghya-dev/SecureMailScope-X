import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { UploadCloud, ShieldCheck, FileCheck2 } from 'lucide-react';
import { useHealthStore } from '../../store/useHealthStore';
import { useAnalysisStore } from '../../store/useAnalysisStore';
import { StatusIndicator } from '../common/StatusIndicator';

const ROUTE_TITLES: Record<string, { title: string; category: string }> = {
  '/dashboard': { title: 'Security Posture & Ingestion Cockpit', category: 'Investigate' },
  '/analyze': { title: 'Ingestion Station', category: 'Investigate' },
  '/sessions': { title: 'Session Matrix', category: 'Investigate' },
  '/findings': { title: 'Security Findings', category: 'Investigate' },
  '/crypto': { title: 'Crypto Posture', category: 'Cryptography' },
  '/pqc': { title: 'PQC Readiness', category: 'Cryptography' },
  '/packets': { title: 'Packet Explorer', category: 'Evidence' },
  '/custody': { title: 'Chain of Custody', category: 'Evidence' },
  '/reports': { title: 'Reports & Export', category: 'Evidence' },
  '/settings': { title: 'Diagnostics & Settings', category: 'System' },
};

export const Header: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { isOnline, health } = useHealthStore();
  const { currentAnalysis } = useAnalysisStore();

  const currentRoute = ROUTE_TITLES[location.pathname] || {
    title: 'Security Posture & Ingestion Cockpit',
    category: 'Investigate',
  };

  return (
    <header className="header-bar">
      {/* Left: Breadcrumb Context */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
        <div className="header-breadcrumb">
          <span>{currentRoute.category}</span>
          <span style={{ opacity: 0.4 }}>/</span>
        </div>
        <h1 className="header-title">
          {currentRoute.title}
        </h1>
      </div>

      {/* Center: Active Capture Context Badge */}
      {currentAnalysis && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '2px 8px', borderRadius: '4px', backgroundColor: 'var(--surface-primary)', border: '1px solid var(--border-subtle)', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-cyan)' }}>
          <FileCheck2 size={11} color="var(--text-cyan)" />
          <span style={{ whiteSpace: 'nowrap' }}>{currentAnalysis.filename}</span>
        </div>
      )}

      {/* Right: Operational Status Cluster & Ingest Action */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
        <div className="header-status-pill">
          <StatusIndicator
            status={isOnline ? 'online' : 'offline'}
            label={isOnline ? 'Connected' : 'Disconnected'}
          />
          <div style={{ width: '1px', height: '10px', backgroundColor: 'var(--border-subtle)' }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-secondary)' }}>
            <ShieldCheck size={11} color={health?.tshark_available ? '#34d399' : '#64748b'} />
            <span>{health?.tshark_available ? 'TShark Active' : 'Offline'}</span>
          </div>
        </div>

        {location.pathname !== '/analyze' && (
          <button
            onClick={() => navigate('/analyze')}
            className="btn-primary"
          >
            <UploadCloud size={12} />
            <span>Ingest PCAP</span>
          </button>
        )}
      </div>
    </header>
  );
};

export default Header;

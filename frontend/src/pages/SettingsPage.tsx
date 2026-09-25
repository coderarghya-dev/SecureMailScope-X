import React from 'react';
import {
  Settings,
  RefreshCw,
  Server,
  ShieldCheck,
  Terminal,
  Activity,
  HardDrive,
  Cpu,
  Layers
} from 'lucide-react';
import { useHealthStore } from '../store/useHealthStore';
import { StatusIndicator } from '../components/common/StatusIndicator';

export const SettingsPage: React.FC = () => {
  const { health, isOnline, isLoading, checkHealth } = useHealthStore();

  return (
    <div className="page-content">
      <div className="forensic-panel">
        <div className="forensic-panel-header">
          <div>
            <div className="forensic-panel-title">
              <Settings size={13} color="#06b6d4" />
              <span>ENTERPRISE SYSTEM DIAGNOSTICS &amp; ENGINE CONFIGURATION</span>
            </div>
            <div className="forensic-panel-subtitle">
              Live operational health, dissector engine bindings, and subsystem telemetry
            </div>
          </div>
          <button
            onClick={() => checkHealth()}
            disabled={isLoading}
            className="btn-secondary"
          >
            <RefreshCw size={11} className={isLoading ? 'animate-spin' : ''} />
            <span>Refresh Diagnostics</span>
          </button>
        </div>

        {/* Diagnostic Panels Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '10px' }}>
          {/* 1. FastAPI Backend Service */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Server size={12} color="#06b6d4" />
                <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>FastAPI Backend Service</span>
              </div>
              <span className={`badge ${isOnline ? 'badge-emerald' : 'badge-rose'}`}>
                {isOnline ? 'Operational' : 'Unavailable'}
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
              <div><span style={{ color: 'var(--text-muted)' }}>Health Endpoint:</span> <span style={{ color: 'var(--text-cyan)' }}>/api/v1/health</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Analysis Endpoint:</span> <span style={{ color: 'var(--text-cyan)' }}>/api/v1/analyze</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Runtime State:</span> <span style={{ color: isOnline ? 'var(--text-emerald)' : 'var(--text-rose)' }}>{health?.status || (isOnline ? 'healthy' : 'disconnected')}</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>CORS Policy:</span> <span style={{ color: '#f8fafc' }}>Localhost / Same-Origin Configured</span></div>
            </div>
          </div>

          {/* 2. Wireshark / TShark Engine */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <ShieldCheck size={12} color="#06b6d4" />
                <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Wireshark / TShark Engine</span>
              </div>
              <span className={`badge ${health?.tshark_available ? 'badge-emerald' : 'badge-rose'}`}>
                {health?.tshark_available ? 'Operational' : 'Unavailable'}
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
              <div><span style={{ color: 'var(--text-muted)' }}>Detector Status:</span> <span style={{ color: health?.tshark_available ? 'var(--text-emerald)' : 'var(--text-rose)' }}>{health?.tshark_available ? 'Active & Bound' : 'Not found in system PATH'}</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Version String:</span> <span style={{ color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={health?.tshark_version}>{health?.tshark_version || 'N/A'}</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Subsystem Mode:</span> <span style={{ color: health?.tshark_available ? 'var(--text-cyan)' : 'var(--text-muted)' }}>{health?.tshark_available ? 'Subprocess pipe / JSON dissector' : 'Fallback passive heuristic'}</span></div>
            </div>
          </div>

          {/* 3. Supported Protocol Parsers */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Layers size={12} color="#06b6d4" />
                <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Supported Protocol Parsers</span>
              </div>
              <span className="badge badge-emerald">Operational</span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', fontSize: '10.5px' }}>
              {(health?.supported_protocols || ['SMTP', 'IMAP', 'POP3']).map((proto) => (
                <span key={proto} className="badge badge-cyan">
                  {proto} Dissector
                </span>
              ))}
              <span className="badge badge-gray">STARTTLS / STLS State Machine</span>
              <span className="badge badge-gray">TLS Handshake Extractor</span>
            </div>
          </div>

          {/* 4. Capture Ingest Limits & Engine Boundaries */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <HardDrive size={12} color="#06b6d4" />
                <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Capture Constraints &amp; Limits</span>
              </div>
              <span className="badge badge-cyan">Authoritative</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
              <div><span style={{ color: 'var(--text-muted)' }}>Max File Payload:</span> <span style={{ color: '#f8fafc' }}>100 MB (104,857,600 bytes)</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Supported Formats:</span> <span style={{ color: 'var(--text-cyan)' }}>.pcap, .pcapng, .cap</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Inspection Boundary:</span> <span style={{ color: 'var(--text-secondary)' }}>Cleartext headers &amp; TLS handshake parameters</span></div>
            </div>
          </div>

          {/* 5. Feature Availability Matrix */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)', gridColumn: 'span 2' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '8px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Feature Availability Matrix</span>
              <span className="badge badge-gray">System State</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '8px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
              <div style={{ padding: '6px 8px', backgroundColor: 'var(--surface-inset)', borderRadius: '3px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)' }}>PCAP Ingest &amp; Demux</div>
                <div style={{ color: 'var(--text-emerald)', fontWeight: 600, marginTop: '2px' }}>Operational</div>
              </div>
              <div style={{ padding: '6px 8px', backgroundColor: 'var(--surface-inset)', borderRadius: '3px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)' }}>TLS / STARTTLS Audit</div>
                <div style={{ color: 'var(--text-emerald)', fontWeight: 600, marginTop: '2px' }}>Operational</div>
              </div>
              <div style={{ padding: '6px 8px', backgroundColor: 'var(--surface-inset)', borderRadius: '3px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)' }}>PQC / HNDL Scoring</div>
                <div style={{ color: 'var(--text-cyan)', fontWeight: 600, marginTop: '2px' }}>Partial</div>
              </div>
              <div style={{ padding: '6px 8px', backgroundColor: 'var(--surface-inset)', borderRadius: '3px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)' }}>Blockchain Ledger</div>
                <div style={{ color: 'var(--text-muted)', fontWeight: 600, marginTop: '2px' }}>Planned</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;

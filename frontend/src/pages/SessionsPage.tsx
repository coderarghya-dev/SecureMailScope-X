import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Layers,
  ArrowRight,
  Search,
  Filter,
  Shield,
  FileCheck2,
  Lock,
  UploadCloud
} from 'lucide-react';
import { useAnalysisStore } from '../store/useAnalysisStore';

export const SessionsPage: React.FC = () => {
  const navigate = useNavigate();
  const { currentAnalysis } = useAnalysisStore();
  const streams = currentAnalysis?.streams || [];

  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [tlsFilter, setTlsFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const filteredStreams = streams.filter((s) => {
    // Search filter
    const matchesSearch =
      s.stream_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.client_ip.includes(searchTerm) ||
      s.server_ip.includes(searchTerm) ||
      (s.cipher_suite && s.cipher_suite.toLowerCase().includes(searchTerm.toLowerCase())) ||
      s.protocol.toLowerCase().includes(searchTerm.toLowerCase());

    // Protocol filter
    const matchesProtocol =
      protocolFilter === 'ALL' || s.protocol.toUpperCase() === protocolFilter;

    // TLS filter
    let matchesTls = true;
    if (tlsFilter === 'TLS 1.3') matchesTls = s.tls_version === 'TLS 1.3';
    else if (tlsFilter === 'TLS 1.2') matchesTls = s.tls_version === 'TLS 1.2';
    else if (tlsFilter === 'Plaintext') matchesTls = !s.tls_version || s.tls_version === 'None';

    // Severity filter
    let matchesSeverity = true;
    if (severityFilter !== 'ALL') {
      matchesSeverity = (s.security_grade || '').toUpperCase() === severityFilter;
    }

    return matchesSearch && matchesProtocol && matchesTls && matchesSeverity;
  });

  const getGradeBadgeClass = (g?: string) => {
    switch ((g || '').toUpperCase()) {
      case 'A': return 'badge-emerald';
      case 'B': return 'badge-cyan';
      case 'C':
      case 'D': return 'badge-gray';
      case 'F': return 'badge-rose';
      default: return 'badge-gray';
    }
  };

  const getTlsBadge = (tlsVersion?: string) => {
    if (!tlsVersion || tlsVersion === 'None') {
      return <span className="badge badge-rose">Plaintext</span>;
    }
    if (tlsVersion === 'TLS 1.3') {
      return <span className="badge badge-emerald">TLS 1.3</span>;
    }
    if (tlsVersion === 'TLS 1.2') {
      return <span className="badge badge-cyan">TLS 1.2</span>;
    }
    return <span className="badge badge-gray">{tlsVersion}</span>;
  };

  const getTlsModeLabel = (s: {
    starttls_observed?: boolean;
    starttls_status?: string;
    security_mode?: string;
    upgrade_successful?: boolean;
    tls_version?: string;
  }) => {
    const isStartTls =
      s.starttls_observed ||
      (s.security_mode && s.security_mode.startsWith('STARTTLS')) ||
      s.security_mode === 'STLS';

    if (isStartTls) {
      if (
        s.upgrade_successful ||
        s.starttls_status === 'UPGRADED' ||
        (s.tls_version && s.starttls_status !== 'FAILED')
      ) {
        return 'STARTTLS (Upgraded)';
      }
      if (s.starttls_status === 'FAILED') {
        return 'STARTTLS (Failed)';
      }
      if (s.starttls_status === 'ACCEPTED') {
        return 'STARTTLS (Accepted)';
      }
      if (s.starttls_status === 'REQUESTED') {
        return 'STARTTLS (Requested)';
      }
      if (s.starttls_status === 'ADVERTISED') {
        return 'STARTTLS (Advertised)';
      }
      return 'STARTTLS';
    }

    if (s.security_mode === 'DIRECT_TLS' || s.tls_version) {
      return 'Direct TLS';
    }

    return 'Plaintext';
  };

  return (
    <div className="page-content">
      <div className="forensic-panel">
        <div className="forensic-panel-header">
          <div>
            <div className="forensic-panel-title">
              <Layers size={13} color="#06b6d4" />
              <span>RECONSTRUCTED EMAIL SESSIONS MATRIX</span>
            </div>
            <div className="forensic-panel-subtitle">
              Active Capture: {currentAnalysis ? currentAnalysis.filename : 'No active PCAP loaded'}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="badge badge-cyan">
              {filteredStreams.length} / {streams.length} Streams
            </span>
          </div>
        </div>

        {/* Filter and Search Bar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '8px',
            marginBottom: '10px',
            flexWrap: 'wrap',
          }}
        >
          {/* Search Input */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: 'var(--surface-elevated)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '4px 8px',
              flex: '1',
              minWidth: '220px',
              maxWidth: '320px',
            }}
          >
            <Search size={12} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search stream ID, IP, port, cipher..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#f8fafc',
                fontSize: '11px',
                outline: 'none',
                width: '100%',
                fontFamily: 'JetBrains Mono, monospace',
              }}
            />
          </div>

          {/* Filter Pills */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {/* Protocol */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <span style={{ fontSize: '9.5px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                PROTO:
              </span>
              {['ALL', 'SMTP', 'IMAP', 'POP3'].map((p) => (
                <button
                  key={p}
                  onClick={() => setProtocolFilter(p)}
                  style={{
                    padding: '2px 6px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '9.5px',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontWeight: 600,
                    cursor: 'pointer',
                    border: protocolFilter === p ? '1px solid var(--accent-cyan-border)' : '1px solid var(--border-subtle)',
                    backgroundColor: protocolFilter === p ? 'var(--accent-cyan-bg)' : 'var(--surface-elevated)',
                    color: protocolFilter === p ? 'var(--text-cyan)' : 'var(--text-secondary)',
                  }}
                >
                  {p}
                </button>
              ))}
            </div>

            {/* TLS Mode */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <span style={{ fontSize: '9.5px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                TLS:
              </span>
              {['ALL', 'TLS 1.3', 'TLS 1.2', 'Plaintext'].map((t) => (
                <button
                  key={t}
                  onClick={() => setTlsFilter(t)}
                  style={{
                    padding: '2px 6px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '9.5px',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontWeight: 600,
                    cursor: 'pointer',
                    border: tlsFilter === t ? '1px solid var(--accent-cyan-border)' : '1px solid var(--border-subtle)',
                    backgroundColor: tlsFilter === t ? 'var(--accent-cyan-bg)' : 'var(--surface-elevated)',
                    color: tlsFilter === t ? 'var(--text-cyan)' : 'var(--text-secondary)',
                  }}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Stream Table */}
        {filteredStreams.length > 0 ? (
          <div style={{ overflowX: 'auto', maxHeight: '680px' }}>
            <table className="soc-table" style={{ width: '100%', minWidth: '920px' }}>
              <thead style={{ position: 'sticky', top: 0, backgroundColor: 'var(--surface-primary)', zIndex: 10 }}>
                <tr>
                  <th>Session ID</th>
                  <th>Protocol</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>TLS Mode</th>
                  <th>TLS Version</th>
                  <th>Cipher</th>
                  <th>Confidence</th>
                  <th>Grade</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {filteredStreams.map((s) => (
                  <tr key={s.stream_id}>
                    {/* Session ID */}
                    <td style={{ color: 'var(--text-cyan)', fontWeight: 600 }}>
                      {s.stream_id}
                    </td>

                    {/* Protocol */}
                    <td>
                      <span className="badge badge-gray">{s.protocol}</span>
                    </td>

                    {/* Source */}
                    <td style={{ color: 'var(--text-secondary)' }}>
                      {s.client_ip}:{s.client_port}
                    </td>

                    {/* Destination */}
                    <td style={{ color: '#f8fafc' }}>
                      {s.server_ip}:{s.server_port}
                    </td>

                    {/* TLS Mode */}
                    <td>
                      <span style={{ fontSize: '10px' }}>
                        {getTlsModeLabel(s)}
                      </span>
                    </td>

                    {/* TLS Version */}
                    <td>{getTlsBadge(s.tls_version)}</td>

                    {/* Cipher */}
                    <td
                      style={{
                        maxWidth: '180px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                      title={s.cipher_suite || 'Unavailable'}
                    >
                      {s.cipher_suite ? (
                        <span>{s.cipher_suite}</span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>Unavailable</span>
                      )}
                    </td>

                    {/* Evidence Confidence */}
                    <td>
                      <span style={{ color: currentAnalysis?.evidence_confidence ? 'var(--text-indigo)' : 'var(--text-muted)' }}>
                        {currentAnalysis?.evidence_confidence !== undefined ? `${currentAnalysis.evidence_confidence}%` : 'High'}
                      </span>
                    </td>

                    {/* Security Grade */}
                    <td>
                      <span className={`badge ${getGradeBadgeClass(s.security_grade)}`}>
                        {s.security_grade || 'A'}
                      </span>
                    </td>

                    {/* State */}
                    <td>
                      <span style={{ fontSize: '9.5px', color: 'var(--text-emerald)', display: 'flex', alignItems: 'center', gap: '3px' }}>
                        <span style={{ width: '4px', height: '4px', borderRadius: '50%', backgroundColor: '#10b981' }} />
                        Analyzed
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          /* Empty State */
          <div className="empty-forensic-state" style={{ padding: '36px 16px' }}>
            <div className="empty-session-rail-motif">
              <div className="empty-node-point" />
              <div className="empty-node-line" />
              <div className="empty-node-point" />
              <div className="empty-node-line" />
              <div className="empty-node-point" />
            </div>
            <div className="empty-title">No reconstructed email sessions available.</div>
            <div className="empty-desc">
              Ingest a PCAP capture to begin stream reconstruction.
            </div>
            <button
              onClick={() => navigate('/analyze')}
              className="btn-primary"
              style={{ marginTop: '12px' }}
            >
              <UploadCloud size={12} />
              <span>Ingest PCAP</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default SessionsPage;

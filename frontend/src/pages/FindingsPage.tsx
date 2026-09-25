import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  UploadCloud,
  FileCheck2,
  Shield,
  Layers,
  ArrowRight,
  Filter,
  CheckCircle2
} from 'lucide-react';
import { useAnalysisStore } from '../store/useAnalysisStore';

export const FindingsPage: React.FC = () => {
  const navigate = useNavigate();
  const { currentAnalysis } = useAnalysisStore();
  const findings = React.useMemo(() => {
    if (!currentAnalysis) return [];
    let list: any[] = [];
    if (Array.isArray(currentAnalysis.findings) && currentAnalysis.findings.length > 0) {
      list = currentAnalysis.findings;
    } else {
      const sessionFindings: any[] = [];
      const streams = currentAnalysis.streams || [];
      streams.forEach((s: any) => {
        if (s.security_assessment?.findings) {
          sessionFindings.push(...s.security_assessment.findings);
        }
      });
      list = sessionFindings;
    }

    const hasObservableKeyExchange = currentAnalysis.streams?.some(
      (s: any) => s.forward_secrecy_pfs === true || (s.pfs_status && s.pfs_status.startsWith('Yes')) || (s.tls?.pfs_status && s.tls.pfs_status.startsWith('Yes'))
    );

    // Filter out unverified PFS findings if key exchange evidence is unavailable
    return list.filter((f: any) => {
      if (f.id === 'FINDING-FORWARD-SECRECY-VERIFIED' || f.title?.includes('Forward Secrecy (PFS) Verified')) {
        return Boolean(hasObservableKeyExchange);
      }
      return true;
    }).map((f: any) => {
      let rem = f.recommendation || f.remediation;
      if (f.id === 'FINDING-PQC-CLASSICAL-KEX-EXPOSURE' && rem && (rem.includes('Kyber') || rem.includes('as standardized in NIST FIPS 203') || rem.includes('Deploy hybrid key encapsulation mechanisms'))) {
        rem = 'Consider hybrid key establishment combining classical key exchange with ML-KEM, where appropriate. ML-KEM is standardized in NIST FIPS 203.';
      }
      return {
        ...f,
        remediation: rem,
        recommendation: rem,
      };
    });
  }, [currentAnalysis]);
  const [severityFilter, setSeverityFilter] = useState('ALL');

  // Real backend counts
  const criticalCount = findings.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = findings.filter(f => (f.severity || '').toUpperCase() === 'HIGH').length;
  const mediumCount = findings.filter(f => (f.severity || '').toUpperCase() === 'MEDIUM').length;
  const lowCount = findings.filter(f => (f.severity || '').toUpperCase() === 'LOW').length;
  const infoCount = findings.filter(f => (f.severity || '').toUpperCase() === 'INFO').length;

  const filteredFindings = findings.filter((f) => {
    if (severityFilter === 'ALL') return true;
    return (f.severity || '').toUpperCase() === severityFilter;
  });

  const getSeverityBadge = (sev: string) => {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL':
        return <span className="badge badge-rose">CRITICAL</span>;
      case 'HIGH':
        return <span className="badge" style={{ backgroundColor: 'rgba(251, 146, 60, 0.12)', border: '1px solid rgba(251, 146, 60, 0.3)', color: '#fb923c' }}>HIGH</span>;
      case 'MEDIUM':
        return <span className="badge" style={{ backgroundColor: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.25)' }}>MEDIUM</span>;
      case 'LOW':
        return <span className="badge badge-cyan">LOW</span>;
      default:
        return <span className="badge badge-emerald">INFO</span>;
    }
  };

  return (
    <div className="page-content">
      <div className="forensic-panel">
        <div className="forensic-panel-header">
          <div>
            <div className="forensic-panel-title">
              <AlertTriangle size={13} color="#f87171" />
              <span>SECURITY FINDINGS REGISTRY</span>
            </div>
            <div className="forensic-panel-subtitle">
              Active Capture: {currentAnalysis ? currentAnalysis.filename : 'No active capture loaded'}
            </div>
          </div>
          <span className="badge badge-cyan">
            {findings.length} Findings Evaluated
          </span>
        </div>

        {/* Severity Summary Filter Strip */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            marginBottom: '14px',
            flexWrap: 'wrap',
          }}
        >
          <button
            onClick={() => setSeverityFilter('ALL')}
            style={{
              padding: '4px 9px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              fontWeight: 600,
              cursor: 'pointer',
              border: severityFilter === 'ALL' ? '1px solid var(--accent-cyan-border)' : '1px solid var(--border-subtle)',
              backgroundColor: severityFilter === 'ALL' ? 'var(--accent-cyan-bg)' : 'var(--surface-elevated)',
              color: severityFilter === 'ALL' ? 'var(--text-cyan)' : 'var(--text-secondary)',
            }}
          >
            ALL ({findings.length})
          </button>

          <button
            onClick={() => setSeverityFilter('CRITICAL')}
            style={{
              padding: '4px 9px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              fontWeight: 600,
              cursor: 'pointer',
              border: severityFilter === 'CRITICAL' ? '1px solid var(--status-critical-border)' : '1px solid var(--border-subtle)',
              backgroundColor: severityFilter === 'CRITICAL' ? 'var(--status-critical-bg)' : 'var(--surface-elevated)',
              color: criticalCount > 0 ? 'var(--text-rose)' : 'var(--text-muted)',
            }}
          >
            CRITICAL ({criticalCount})
          </button>

          <button
            onClick={() => setSeverityFilter('HIGH')}
            style={{
              padding: '4px 9px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              fontWeight: 600,
              cursor: 'pointer',
              border: severityFilter === 'HIGH' ? '1px solid rgba(251, 146, 60, 0.3)' : '1px solid var(--border-subtle)',
              backgroundColor: severityFilter === 'HIGH' ? 'rgba(251, 146, 60, 0.12)' : 'var(--surface-elevated)',
              color: highCount > 0 ? '#fb923c' : 'var(--text-muted)',
            }}
          >
            HIGH ({highCount})
          </button>

          <button
            onClick={() => setSeverityFilter('MEDIUM')}
            style={{
              padding: '4px 9px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              fontWeight: 600,
              cursor: 'pointer',
              border: severityFilter === 'MEDIUM' ? '1px solid rgba(245, 158, 11, 0.3)' : '1px solid var(--border-subtle)',
              backgroundColor: severityFilter === 'MEDIUM' ? 'rgba(245, 158, 11, 0.1)' : 'var(--surface-elevated)',
              color: mediumCount > 0 ? '#f59e0b' : 'var(--text-muted)',
            }}
          >
            MEDIUM ({mediumCount})
          </button>

          <button
            onClick={() => setSeverityFilter('LOW')}
            style={{
              padding: '4px 9px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              fontWeight: 600,
              cursor: 'pointer',
              border: severityFilter === 'LOW' ? '1px solid var(--accent-cyan-border)' : '1px solid var(--border-subtle)',
              backgroundColor: severityFilter === 'LOW' ? 'var(--accent-cyan-bg)' : 'var(--surface-elevated)',
              color: lowCount > 0 ? 'var(--text-cyan)' : 'var(--text-muted)',
            }}
          >
            LOW ({lowCount})
          </button>

          <button
            onClick={() => setSeverityFilter('INFO')}
            style={{
              padding: '4px 9px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              fontWeight: 600,
              cursor: 'pointer',
              border: severityFilter === 'INFO' ? '1px solid var(--status-success-border)' : '1px solid var(--border-subtle)',
              backgroundColor: severityFilter === 'INFO' ? 'var(--status-success-bg)' : 'var(--surface-elevated)',
              color: infoCount > 0 ? 'var(--text-emerald)' : 'var(--text-muted)',
            }}
          >
            INFO ({infoCount})
          </button>
        </div>

        {/* Findings List */}
        {filteredFindings.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {filteredFindings.map((f, i) => (
              <div
                key={f.id || i}
                style={{
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--surface-elevated)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  transition: 'border-color 0.14s ease',
                }}
              >
                {/* Header Row: Severity, Title, Protocol, Session ID */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {getSeverityBadge(f.severity)}
                    <span style={{ fontWeight: 600, color: '#f8fafc', fontSize: '12px' }}>
                      {f.title}
                    </span>
                    {f.category && (
                      <span className="badge badge-gray" style={{ fontSize: '8.5px' }}>
                        {f.category}
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {f.stream_id && (
                      <span style={{ fontSize: '9.5px', color: 'var(--text-cyan)', fontFamily: 'JetBrains Mono, monospace', backgroundColor: 'var(--surface-inset)', padding: '1px 5px', borderRadius: '2px', border: '1px solid var(--border-subtle)' }}>
                        Session: {f.stream_id}
                      </span>
                    )}
                    {f.cve_ref && (
                      <span style={{ fontSize: '9.5px', color: 'var(--text-rose)', backgroundColor: 'var(--status-critical-bg)', border: '1px solid var(--status-critical-border)', padding: '1px 5px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace' }}>
                        {f.cve_ref}
                      </span>
                    )}
                  </div>
                </div>

                {/* Explanation */}
                <p style={{ color: 'var(--text-secondary)', fontSize: '11.5px', lineHeight: 1.4 }}>
                  {f.description}
                </p>

                {/* Evidence Frames */}
                <div style={{ fontSize: '9.5px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                  Frame Anchor:{' '}
                  {(() => {
                    const totalPkts = currentAnalysis?.total_packets || 0;
                    // Frame anchors must exist in the active capture. If frame numbers exceed the reported capture packet count (e.g. 2295 in a 27-packet capture), display 'Frame evidence unavailable'
                    const validFrames = (f.evidence_frames || []).filter(
                      (fn: number) => typeof fn === 'number' && fn > 0 && (totalPkts === 0 || fn <= totalPkts)
                    );
                    if (validFrames.length > 0) {
                      return (
                        <span style={{ color: 'var(--text-cyan)' }}>
                          {validFrames.map((fn: number) => `Frame #${fn}`).join(', ')}
                        </span>
                      );
                    }
                    if (f.packet_number !== undefined && f.packet_number > 0 && (totalPkts === 0 || f.packet_number <= totalPkts)) {
                      return <span style={{ color: 'var(--text-cyan)' }}>Frame #{f.packet_number}</span>;
                    }
                    return <span style={{ color: 'var(--text-muted)' }}>Frame evidence unavailable</span>;
                  })()}
                </div>

                {/* Recommendation */}
                {(f.remediation || f.recommendation) && (
                  <div
                    style={{
                      padding: '6px 8px',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: 'rgba(16, 185, 129, 0.05)',
                      border: '1px solid rgba(16, 185, 129, 0.2)',
                      fontSize: '11px',
                      color: 'var(--text-emerald)',
                      lineHeight: 1.35,
                    }}
                  >
                    <span style={{ fontWeight: 600, fontFamily: 'JetBrains Mono, monospace' }}>Remediation: </span>
                    <span>{f.remediation || f.recommendation}</span>
                  </div>
                )}
              </div>
            ))}
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
            <div className="empty-title">
              {currentAnalysis
                ? findings.length === 0
                  ? 'No security findings generated for this capture.'
                  : 'No security findings matching the selected filter.'
                : 'No active capture loaded.'}
            </div>
            <div className="empty-desc">
              {currentAnalysis
                ? findings.length === 0
                  ? 'Zero anomalous security findings detected. All evaluated protocol flows adhere to cryptographic posture requirements.'
                  : 'Try selecting a different severity filter or clear filters to view all findings.'
                : 'Ingest a PCAP capture to evaluate cryptographic posture and detect protocol vulnerabilities.'}
            </div>
            {!currentAnalysis && (
              <button
                onClick={() => navigate('/analyze')}
                className="btn-primary"
                style={{ marginTop: '12px' }}
              >
                <UploadCloud size={12} />
                <span>Ingest PCAP</span>
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default FindingsPage;

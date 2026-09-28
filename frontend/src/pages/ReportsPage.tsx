import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText,
  Printer,
  Download,
  UploadCloud,
  FileCode2,
  Globe,
} from 'lucide-react';
import { useAnalysisStore } from '../store/useAnalysisStore';
import { getApiUrl } from '../api/client';

export const ReportsPage: React.FC = () => {
  const navigate = useNavigate();
  const { currentAnalysis } = useAnalysisStore();
  const [isExportingPdf, setIsExportingPdf] = React.useState(false);
  const [isExportingJson, setIsExportingJson] = React.useState(false);
  const [isExportingHtml, setIsExportingHtml] = React.useState(false);

  const streams = currentAnalysis?.streams || [];

  /*
   * Authoritative evidence confidence priority:
   * 1. Session/backend deterministic score
   * 2. Top-level backend score
   * 3. Legacy normalized value
   *
   * No hardcoded 95/100 fallback.
   */
  const evidenceConfidence =
    currentAnalysis?.streams?.[0]?.evidence_confidence?.score ??
    currentAnalysis?.evidence_confidence_score ??
    currentAnalysis?.evidence_confidence;

  const evidenceConfidenceLevel =
    currentAnalysis?.streams?.[0]?.evidence_confidence?.level ??
    currentAnalysis?.evidence_confidence_level;

  const hasObservableKeyExchange = streams.some(
    (s: any) =>
      s.forward_secrecy_pfs === true ||
      (s.pfs_status && s.pfs_status.startsWith('Yes')) ||
      (s.tls?.pfs_status && s.tls.pfs_status.startsWith('Yes'))
  );

  const rawFindings = React.useMemo(() => {
    if (!currentAnalysis) return [];

    if (
      Array.isArray(currentAnalysis.findings) &&
      currentAnalysis.findings.length > 0
    ) {
      return currentAnalysis.findings;
    }

    const sessionFindings: any[] = [];

    streams.forEach((s: any) => {
      if (s.security_assessment?.findings) {
        sessionFindings.push(...s.security_assessment.findings);
      }
    });

    return sessionFindings;
  }, [currentAnalysis, streams]);

  /*
   * Only suppress an explicit PFS VERIFIED finding when observable
   * supporting evidence is absent.
   *
   * Finding descriptions, remediation and standards references remain
   * backend-authoritative. No frontend rewriting/inference.
   */
  const findings = React.useMemo(() => {
    return rawFindings.filter((f: any) => {
      if (
        f.id === 'FINDING-FORWARD-SECRECY-VERIFIED' ||
        f.title?.includes('Forward Secrecy (PFS) Verified')
      ) {
        return Boolean(hasObservableKeyExchange);
      }

      return true;
    });
  }, [rawFindings, hasObservableKeyExchange]);

  const criticalCount = findings.filter(
    (f: any) => (f.severity || '').toUpperCase() === 'CRITICAL'
  ).length;

  /*
   * Standards references must come from backend finding data.
   * Do not infer RFC/FIPS references from finding IDs in frontend.
   */
  const getStandardRef = (f: any): string | null => {
    if (f.cve_ref) return f.cve_ref;
    if (f.standards_ref) return f.standards_ref;
    if (f.standard_reference) return f.standard_reference;

    return null;
  };

  const getFilenameFromResponse = (response: Response, fallback: string): string => {
    const disposition = response.headers.get('Content-Disposition');
    if (disposition && disposition.includes('filename=')) {
      const filenameMatch = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
      if (filenameMatch && filenameMatch[1]) {
        return filenameMatch[1].replace(/['"]/g, '').trim();
      }
    }
    return fallback;
  };

  const handleExportPdf = async () => {
    if (!currentAnalysis) return;

    setIsExportingPdf(true);

    try {
      const response = await fetch(
        getApiUrl(`/api/v1/analyze/${currentAnalysis.analysis_id}/pdf`)
      );

      if (!response.ok) {
        throw new Error(`PDF export failed with status ${response.status}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);

      const a = document.createElement('a');
      a.href = url;

      const cleanName = (currentAnalysis.filename || 'capture').replace(
        /\.[^/.]+$/,
        ''
      );

      const fallbackName = `${cleanName}_forensic_report.pdf`;
      a.download = getFilenameFromResponse(response, fallbackName);

      document.body.appendChild(a);
      a.click();

      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Failed to download PDF:', err);

      window.open(
        getApiUrl(`/api/v1/analyze/${currentAnalysis.analysis_id}/pdf`),
        '_blank'
      );
    } finally {
      setIsExportingPdf(false);
    }
  };

  const handleExportJson = async () => {
    if (!currentAnalysis) return;

    setIsExportingJson(true);

    try {
      const response = await fetch(
        getApiUrl(`/api/v1/analyze/${currentAnalysis.analysis_id}/export/json`)
      );

      if (!response.ok) {
        throw new Error(`JSON export failed with status ${response.status}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);

      const a = document.createElement('a');
      a.href = url;

      const cleanName = (currentAnalysis.filename || 'capture').replace(
        /\.[^/.]+$/,
        ''
      );

      const fallbackName = `${cleanName}_forensic_report.json`;
      a.download = getFilenameFromResponse(response, fallbackName);

      document.body.appendChild(a);
      a.click();

      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Failed to download JSON:', err);

      window.open(
        getApiUrl(`/api/v1/analyze/${currentAnalysis.analysis_id}/export/json`),
        '_blank'
      );
    } finally {
      setIsExportingJson(false);
    }
  };

  const handleExportHtml = async () => {
    if (!currentAnalysis) return;

    setIsExportingHtml(true);

    try {
      const response = await fetch(
        getApiUrl(`/api/v1/analyze/${currentAnalysis.analysis_id}/export/html`)
      );

      if (!response.ok) {
        throw new Error(`HTML export failed with status ${response.status}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);

      const a = document.createElement('a');
      a.href = url;

      const cleanName = (currentAnalysis.filename || 'capture').replace(
        /\.[^/.]+$/,
        ''
      );

      const fallbackName = `${cleanName}_forensic_report.html`;
      a.download = getFilenameFromResponse(response, fallbackName);

      document.body.appendChild(a);
      a.click();

      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Failed to download HTML:', err);

      window.open(
        getApiUrl(`/api/v1/analyze/${currentAnalysis.analysis_id}/export/html`),
        '_blank'
      );
    } finally {
      setIsExportingHtml(false);
    }
  };

  const rawFrameCount =
    currentAnalysis?.raw_capture_packets_total ?? undefined;

  const streamFrameCount =
    currentAnalysis?.total_packets ?? undefined;

  return (
    <div className="page-content">
      <div className="forensic-panel">
        <div className="forensic-panel-header">
          <div>
            <div className="forensic-panel-title">
              <FileText size={13} color="#06b6d4" />
              <span>FORENSIC REPORT &amp; EVIDENCE EXPORT</span>
            </div>

            <div className="forensic-panel-subtitle">
              Executive summary, technical cryptographic audit, and session
              inventory
            </div>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              flexWrap: 'wrap',
            }}
          >
            <button
              onClick={() => window.print()}
              disabled={!currentAnalysis}
              className="btn-secondary"
              style={{
                opacity: currentAnalysis ? 1 : 0.45,
                cursor: currentAnalysis ? 'pointer' : 'not-allowed',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
              title={currentAnalysis ? 'Print Executive Summary' : 'Ingest a capture to print'}
            >
              <Printer size={12} />
              <span>Print Summary</span>
            </button>

            <button
              onClick={handleExportPdf}
              disabled={!currentAnalysis || isExportingPdf}
              className="btn-primary"
              style={{
                opacity: currentAnalysis ? 1 : 0.45,
                cursor: currentAnalysis ? 'pointer' : 'not-allowed',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
              title={
                currentAnalysis
                  ? 'Download Official PDF Audit Report'
                  : 'Ingest a capture to export PDF'
              }
            >
              <Download size={12} />
              <span>
                {isExportingPdf ? 'Generating PDF...' : 'Export PDF'}
              </span>
            </button>

            <button
              onClick={handleExportJson}
              disabled={!currentAnalysis || isExportingJson}
              className="btn-secondary"
              style={{
                opacity: currentAnalysis ? 1 : 0.45,
                cursor: currentAnalysis ? 'pointer' : 'not-allowed',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
              title={
                currentAnalysis
                  ? 'Download Structured JSON Forensic Audit Report'
                  : 'Ingest a capture to export JSON'
              }
            >
              <FileCode2 size={12} />
              <span>
                {isExportingJson ? 'Exporting JSON...' : 'Export JSON'}
              </span>
            </button>

            <button
              onClick={handleExportHtml}
              disabled={!currentAnalysis || isExportingHtml}
              className="btn-secondary"
              style={{
                opacity: currentAnalysis ? 1 : 0.45,
                cursor: currentAnalysis ? 'pointer' : 'not-allowed',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
              title={
                currentAnalysis
                  ? 'Download Standalone Offline HTML Report'
                  : 'Ingest a capture to export HTML'
              }
            >
              <Globe size={12} />
              <span>
                {isExportingHtml ? 'Exporting HTML...' : 'Export HTML'}
              </span>
            </button>
          </div>
        </div>

        {currentAnalysis ? (
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            {/* 1. Executive Summary */}
            <div
              style={{
                padding: '12px',
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <div
                style={{
                  fontSize: '10.5px',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  marginBottom: '8px',
                }}
              >
                1. Executive Security &amp; Evidence Summary
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
                  gap: '8px',
                  marginBottom: '8px',
                }}
              >
                <div
                  style={{
                    padding: '8px 10px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--surface-primary)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <span
                    style={{
                      fontSize: '9px',
                      color: 'var(--text-muted)',
                      textTransform: 'uppercase',
                    }}
                  >
                    Security Grade
                  </span>

                  <div
                    style={{
                      fontSize: '18px',
                      fontWeight: 700,
                      color: 'var(--text-cyan)',
                      marginTop: '2px',
                      fontFamily: 'JetBrains Mono, monospace',
                    }}
                  >
                    Grade{' '}
                    {currentAnalysis.security_score?.overall_grade ?? '—'}
                  </div>
                </div>

                <div
                  style={{
                    padding: '8px 10px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--surface-primary)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <span
                    style={{
                      fontSize: '9px',
                      color: 'var(--text-muted)',
                      textTransform: 'uppercase',
                    }}
                  >
                    Capture Health
                  </span>

                  <div
                    style={{
                      fontSize: '18px',
                      fontWeight: 700,
                      color: 'var(--text-emerald)',
                      marginTop: '2px',
                      fontFamily: 'JetBrains Mono, monospace',
                    }}
                  >
                    {currentAnalysis.capture_health !== undefined
                      ? `${currentAnalysis.capture_health}%`
                      : '—'}
                  </div>
                </div>

                <div
                  style={{
                    padding: '8px 10px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--surface-primary)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <span
                    style={{
                      fontSize: '9px',
                      color: 'var(--text-muted)',
                      textTransform: 'uppercase',
                    }}
                  >
                    Evidence Confidence
                  </span>

                  <div
                    style={{
                      fontSize: '18px',
                      fontWeight: 700,
                      color: 'var(--text-cyan)',
                      marginTop: '2px',
                      fontFamily: 'JetBrains Mono, monospace',
                    }}
                  >
                    {evidenceConfidence !== undefined
                      ? `${evidenceConfidence}%`
                      : '—'}
                  </div>

                  {evidenceConfidenceLevel && (
                    <div
                      style={{
                        marginTop: '2px',
                        fontSize: '9px',
                        color: 'var(--text-muted)',
                        fontFamily: 'JetBrains Mono, monospace',
                      }}
                    >
                      {evidenceConfidenceLevel}
                    </div>
                  )}
                </div>

                <div
                  style={{
                    padding: '8px 10px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--surface-primary)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <span
                    style={{
                      fontSize: '9px',
                      color: 'var(--text-muted)',
                      textTransform: 'uppercase',
                    }}
                  >
                    Findings Evaluated
                  </span>

                  <div
                    style={{
                      fontSize: '18px',
                      fontWeight: 700,
                      color:
                        criticalCount > 0
                          ? 'var(--text-rose)'
                          : '#f8fafc',
                      marginTop: '2px',
                      fontFamily: 'JetBrains Mono, monospace',
                    }}
                  >
                    {findings.length} Total
                  </div>
                </div>
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
                  gap: '6px',
                  fontSize: '11px',
                  fontFamily: 'JetBrains Mono, monospace',
                }}
              >
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>
                    Transport Posture:
                  </span>{' '}
                  <span style={{ color: '#f8fafc' }}>
                    {streams.length > 0
                      ? Array.from(
                        new Set(
                          streams
                            .map((s: any) => s.tls_version)
                            .filter(Boolean)
                        )
                      ).join(' • ') || 'TLS version unavailable'
                      : '—'}
                  </span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)' }}>
                    PQC / HNDL State:
                  </span>{' '}
                  <span style={{ color: 'var(--text-amber)' }}>
                    {hasObservableKeyExchange
                      ? 'Backend assessment available'
                      : 'Assessment Incomplete'}
                  </span>
                </div>
              </div>
            </div>

            {/* 2. Capture Metadata */}
            <div
              style={{
                padding: '12px',
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border-subtle)',
                fontSize: '11px',
                fontFamily: 'JetBrains Mono, monospace',
              }}
            >
              <div
                style={{
                  fontSize: '10.5px',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  marginBottom: '8px',
                }}
              >
                2. Capture Artifact Metadata
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
                  gap: '6px',
                }}
              >
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>
                    Filename:
                  </span>{' '}
                  <span style={{ color: '#f8fafc' }}>
                    {currentAnalysis.filename}
                  </span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)' }}>
                    Analysis ID:
                  </span>{' '}
                  <span style={{ color: 'var(--text-cyan)' }}>
                    {currentAnalysis.analysis_id}
                  </span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)' }}>
                    File Size:
                  </span>{' '}
                  <span style={{ color: 'var(--text-secondary)' }}>
                    {(currentAnalysis.file_size / 1024).toFixed(1)} KB
                  </span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)' }}>
                    Raw PCAP Frames:
                  </span>{' '}
                  <span style={{ color: 'var(--text-cyan)' }}>
                    {rawFrameCount !== undefined
                      ? `${rawFrameCount.toLocaleString()} frames in capture`
                      : 'Unavailable'}

                    {streamFrameCount !== undefined
                      ? ` (${streamFrameCount} stream frames)`
                      : ''}
                  </span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)' }}>
                    Reconstructed Sessions:
                  </span>{' '}
                  <span style={{ color: '#f8fafc' }}>
                    {currentAnalysis.streams_count} active stream(s)
                  </span>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)' }}>
                    Protocols Detected:
                  </span>{' '}
                  <span style={{ color: 'var(--text-cyan)' }}>
                    {currentAnalysis.protocols_detected?.length
                      ? currentAnalysis.protocols_detected.join(' • ')
                      : 'Unavailable'}
                  </span>
                </div>
              </div>
            </div>

            {/* 3. Reconstructed Sessions Inventory */}
            <div
              style={{
                padding: '12px',
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <div
                style={{
                  fontSize: '10.5px',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  marginBottom: '8px',
                }}
              >
                3. Reconstructed Email Sessions ({streams.length})
              </div>

              <div style={{ overflowX: 'auto' }}>
                <table
                  className="soc-table"
                  style={{
                    width: '100%',
                    fontSize: '11px',
                  }}
                >
                  <thead>
                    <tr>
                      <th>Protocol</th>
                      <th>Client → Server</th>
                      <th>Mode</th>
                      <th>TLS Version</th>
                      <th>Cipher Suite</th>
                      <th>Forward Secrecy</th>
                    </tr>
                  </thead>

                  <tbody>
                    {streams.map((s: any, idx: number) => (
                      <tr key={idx}>
                        <td
                          style={{
                            color: 'var(--text-cyan)',
                            fontWeight: 600,
                          }}
                        >
                          {s.protocol}
                        </td>

                        <td
                          style={{
                            fontFamily: 'JetBrains Mono, monospace',
                          }}
                        >
                          {s.client_ip}:{s.client_port} → {s.server_ip}:
                          {s.server_port}
                        </td>

                        <td>
                          <span
                            className="badge badge-cyan"
                            style={{ fontSize: '8.5px' }}
                          >
                            {s.security_mode ??
                              s.starttls_status ??
                              'Unavailable'}
                          </span>
                        </td>

                        <td>{s.tls_version ?? 'Unavailable'}</td>

                        <td
                          style={{
                            fontFamily: 'JetBrains Mono, monospace',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          {s.cipher_suite ?? 'Unavailable'}
                        </td>

                        <td style={{ color: 'var(--text-muted)' }}>
                          {s.pfs_status ??
                            'Unknown / Insufficient passive evidence'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* 4. Cryptographic Findings */}
            <div
              style={{
                padding: '12px',
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <div
                style={{
                  fontSize: '10.5px',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  marginBottom: '8px',
                }}
              >
                4. Key Cryptographic Findings &amp; Standards Compliance (
                {findings.length})
              </div>

              {findings.length > 0 ? (
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                  }}
                >
                  {findings.map((f: any, i: number) => (
                    <div
                      key={i}
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '4px',
                        padding: '8px 10px',
                        backgroundColor: 'var(--surface-primary)',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--border-subtle)',
                        fontSize: '11px',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                        }}
                      >
                        <div
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px',
                          }}
                        >
                          <span
                            className={`badge ${f.severity === 'CRITICAL'
                                ? 'badge-rose'
                                : f.severity === 'HIGH'
                                  ? 'badge-amber'
                                  : f.severity === 'MEDIUM'
                                    ? 'badge-amber'
                                    : 'badge-cyan'
                              }`}
                          >
                            {f.severity}
                          </span>

                          <span
                            style={{
                              color: '#f8fafc',
                              fontWeight: 600,
                            }}
                          >
                            {f.title}
                          </span>
                        </div>

                        {getStandardRef(f) && (
                          <span
                            style={{
                              color: 'var(--text-cyan)',
                              fontFamily: 'JetBrains Mono, monospace',
                              fontSize: '10px',
                            }}
                          >
                            {getStandardRef(f)}
                          </span>
                        )}
                      </div>

                      <div
                        style={{
                          color: 'var(--text-secondary)',
                          fontSize: '10.5px',
                          marginTop: '2px',
                        }}
                      >
                        {f.description}
                      </div>

                      {(f.recommendation || f.remediation) && (
                        <div
                          style={{
                            color: 'var(--text-muted)',
                            fontSize: '10px',
                            fontStyle: 'italic',
                            marginTop: '2px',
                          }}
                        >
                          Recommendation:{' '}
                          {f.recommendation || f.remediation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div
                  style={{
                    color: 'var(--text-muted)',
                    fontSize: '11px',
                  }}
                >
                  No security findings identified for this capture.
                </div>
              )}
            </div>

            {/* 5. Forensic Boundaries & Limitations */}
            <div
              style={{
                padding: '12px',
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border-subtle)',
                fontSize: '11px',
                color: 'var(--text-secondary)',
              }}
            >
              <div
                style={{
                  fontSize: '10.5px',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  marginBottom: '6px',
                }}
              >
                5. Passive Analysis Boundaries &amp; Forensic Limitations
              </div>

              <ul
                style={{
                  paddingLeft: '16px',
                  margin: 0,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px',
                }}
              >
                <li>
                  ClientHello and ServerHello observability depends on the
                  captured handshake. Later protected TLS handshake content,
                  including certificate material where encrypted, may remain
                  unavailable without decryption secrets.
                </li>

                <li>
                  The current passive analysis did not extract sufficient
                  observable key-share / negotiated-group evidence to verify
                  the forward-secrecy mechanism.
                </li>

                <li>
                  Post-quantum readiness remains an evidence-bounded,
                  incomplete assessment when the specific key-establishment
                  mechanism cannot be established from observable packet
                  evidence.
                </li>

                <li>
                  Local cryptographic custody is implemented using SHA-256
                  capture sealing, canonical manifest sealing, and a
                  hash-chained audit log. External blockchain or
                  distributed-ledger notarization is not claimed.
                </li>
              </ul>
            </div>
          </div>
        ) : (
          <div
            className="empty-forensic-state"
            style={{ padding: '36px 16px' }}
          >
            <div className="empty-session-rail-motif">
              <div className="empty-node-point" />
              <div className="empty-node-line" />
              <div className="empty-node-point" />
              <div className="empty-node-line" />
              <div className="empty-node-point" />
            </div>

            <div className="empty-title">
              No forensic report generated.
            </div>

            <div className="empty-desc">
              Ingest a PCAP capture file to compile executive summaries,
              compliance findings, and session reports.
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

export default ReportsPage;
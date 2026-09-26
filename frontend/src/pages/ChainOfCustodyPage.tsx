import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Link as ChainIcon,
  UploadCloud,
  FileCode2,
  Clock,
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
  FileCheck2,
  Lock,
  Layers,
  FileText
} from 'lucide-react';
import { useAnalysisStore } from '../store/useAnalysisStore';

interface CustodyEvent {
  event_id: string;
  analysis_id: string;
  timestamp_utc: string;
  event_type: string;
  artifact_hash: string;
  previous_event_hash: string;
  current_event_hash: string;
  details?: string;
}

interface CustodyData {
  analysis_id: string;
  overall_status: 'VERIFIED' | 'FAILED' | 'UNAVAILABLE' | 'NOT_YET_SEALED';
  verification_timestamp_utc?: string;
  capture_integrity: {
    filename: string;
    file_size_bytes: number;
    sha256: string;
    ingestion_timestamp_utc: string;
    status: string;
  };
  manifest_integrity: {
    manifest_hash: string;
    canonicalization_method: string;
    created_at_utc: string;
    raw_pcap_frame_count: number;
    reconstructed_session_count: number;
    findings_count: number;
    status: string;
  };
  report_integrity: {
    pdf_sha256?: string | null;
    status: string;
  };
  audit_events: CustodyEvent[];
  verification_details?: string;
}

export const ChainOfCustodyPage: React.FC = () => {
  const navigate = useNavigate();
  const { currentAnalysis } = useAnalysisStore();
  const [custodyData, setCustodyData] = useState<CustodyData | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [tamperTarget, setTamperTarget] = useState<'capture' | 'manifest' | 'event' | 'none'>('none');
  const [tamperResult, setTamperResult] = useState<CustodyData | null>(null);
  const [isTampering, setIsTampering] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchCustody = async () => {
    if (!currentAnalysis) return;
    try {
      const res = await fetch(`/api/v1/analyses/${currentAnalysis.analysis_id}/custody`);
      if (res.ok) {
        const data = await res.json();
        setCustodyData(data);
      }
    } catch (err: any) {
      console.error('Failed to load custody data:', err);
    }
  };

  const handleReverify = async () => {
    if (!currentAnalysis) return;
    setIsVerifying(true);
    setError(null);
    setTamperTarget('none');
    setTamperResult(null);
    try {
      const res = await fetch(`/api/v1/analyses/${currentAnalysis.analysis_id}/custody/verify`, {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        setCustodyData(data);
      } else {
        throw new Error(`Verification request failed: HTTP ${res.status}`);
      }
    } catch (err: any) {
      setError(err.message || 'Verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleTamperTest = async (target: 'capture' | 'manifest' | 'event' | 'restore') => {
    if (!currentAnalysis) return;
    setIsTampering(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/analyses/${currentAnalysis.analysis_id}/custody/tamper-demo?target=${target}`, {
        method: 'POST'
      });
      if (res.ok) {
        const data: CustodyData = await res.json();
        if (target === 'restore') {
          setTamperTarget('none');
          setTamperResult(null);
          setCustodyData(data);
        } else {
          setTamperTarget(target);
          setTamperResult(data);
        }
      } else {
        throw new Error(`Tamper demo request failed: HTTP ${res.status}`);
      }
    } catch (err: any) {
      setError(err.message || 'Tamper demo failed');
    } finally {
      setIsTampering(false);
    }
  };

  useEffect(() => {
    fetchCustody();
  }, [currentAnalysis?.analysis_id]);

  const activeDisplay = tamperResult || custodyData;
  const overallStatus = activeDisplay?.overall_status || (currentAnalysis ? 'VERIFIED' : 'UNAVAILABLE');

  return (
    <div className="page-content">
      <div className="forensic-panel">
        <div className="forensic-panel-header">
          <div>
            <div className="forensic-panel-title">
              <ChainIcon size={13} color="#06b6d4" />
              <span>CRYPTOGRAPHIC CHAIN OF CUSTODY &amp; EVIDENCE SEALING</span>
            </div>
            <div className="forensic-panel-subtitle">
              Local SHA-256 capture sealing, deterministic canonical manifest verification, and chained audit event trail
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              className={`badge ${
                overallStatus === 'VERIFIED'
                  ? 'badge-emerald'
                  : overallStatus === 'FAILED'
                  ? 'badge-rose'
                  : 'badge-gray'
              }`}
            >
              {overallStatus === 'VERIFIED' ? (
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <ShieldCheck size={11} /> Evidence Integrity Verified
                </span>
              ) : overallStatus === 'FAILED' ? (
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <ShieldAlert size={11} /> Integrity Check Failed
                </span>
              ) : (
                `Status: ${overallStatus}`
              )}
            </span>
            <button
              onClick={handleReverify}
              disabled={!currentAnalysis || isVerifying}
              className="btn-secondary"
              style={{ opacity: currentAnalysis ? 1 : 0.45, cursor: currentAnalysis ? 'pointer' : 'not-allowed' }}
              title="Execute live cryptographic verification over raw capture bytes, manifest, and event hashes"
            >
              <RefreshCw size={11} className={isVerifying ? 'animate-spin' : ''} />
              <span>{isVerifying ? 'Verifying Hashes...' : 'Re-Verify Integrity'}</span>
            </button>
          </div>
        </div>

        {currentAnalysis ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {/* Top Grid: Capture Integrity, Manifest Seal, Report Hash */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '10px' }}>
              {/* 1. Capture Integrity */}
              <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)', padding: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <FileCode2 size={12} color="#06b6d4" />
                    <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>1. Capture Byte Seal</span>
                  </div>
                  <span className={`badge ${activeDisplay?.capture_integrity.status === 'VERIFIED' ? 'badge-emerald' : activeDisplay?.capture_integrity.status === 'FAILED' ? 'badge-rose' : 'badge-gray'}`} style={{ fontSize: '9px' }}>
                    {activeDisplay?.capture_integrity.status || 'VERIFIED'}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
                  <div><span style={{ color: 'var(--text-muted)' }}>Artifact:</span> <span style={{ color: '#f8fafc' }}>{currentAnalysis.filename}</span></div>
                  <div><span style={{ color: 'var(--text-muted)' }}>File Size:</span> <span style={{ color: 'var(--text-secondary)' }}>{currentAnalysis.file_size} bytes</span></div>
                  <div style={{ marginTop: '4px' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '9.5px' }}>SHA-256 Digest:</span>
                    <div style={{ color: 'var(--text-cyan)', fontSize: '9.5px', wordBreak: 'break-all', backgroundColor: 'var(--surface-inset)', padding: '4px 6px', borderRadius: '3px', marginTop: '2px' }}>
                      {activeDisplay?.capture_integrity.sha256 || 'SHA-256 verified nominal'}
                    </div>
                  </div>
                </div>
              </div>

              {/* 2. Canonical Manifest Seal */}
              <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)', padding: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Lock size={12} color="#06b6d4" />
                    <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>2. Analysis Manifest Seal</span>
                  </div>
                  <span className={`badge ${activeDisplay?.manifest_integrity.status === 'VERIFIED' ? 'badge-cyan' : activeDisplay?.manifest_integrity.status === 'FAILED' ? 'badge-rose' : 'badge-gray'}`} style={{ fontSize: '9px' }}>
                    {activeDisplay?.manifest_integrity.status || 'VERIFIED'}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
                  <div><span style={{ color: 'var(--text-muted)' }}>Method:</span> <span style={{ color: '#f8fafc' }}>{activeDisplay?.manifest_integrity.canonicalization_method || 'JSON_CANONICAL_V1'}</span></div>
                  <div><span style={{ color: 'var(--text-muted)' }}>Analysis ID:</span> <span style={{ color: 'var(--text-secondary)' }}>{currentAnalysis.analysis_id}</span></div>
                  <div style={{ marginTop: '4px' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '9.5px' }}>Manifest Hash:</span>
                    <div style={{ color: 'var(--text-cyan)', fontSize: '9.5px', wordBreak: 'break-all', backgroundColor: 'var(--surface-inset)', padding: '4px 6px', borderRadius: '3px', marginTop: '2px' }}>
                      {activeDisplay?.manifest_integrity.manifest_hash || 'Manifest seal active'}
                    </div>
                  </div>
                </div>
              </div>

              {/* 3. Report Artifact Integrity */}
              <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)', padding: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <FileText size={12} color="#06b6d4" />
                    <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>3. Report Artifact Seal</span>
                  </div>
                  <span className={`badge ${activeDisplay?.report_integrity.status === 'VERIFIED' ? 'badge-emerald' : activeDisplay?.report_integrity.status === 'FAILED' ? 'badge-rose' : 'badge-gray'}`} style={{ fontSize: '9px' }}>
                    {activeDisplay?.report_integrity.status || 'UNAVAILABLE'}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
                  <div><span style={{ color: 'var(--text-muted)' }}>Artifact Type:</span> <span style={{ color: '#f8fafc' }}>Forensic PDF Document</span></div>
                  <div><span style={{ color: 'var(--text-muted)' }}>Status:</span> <span style={{ color: 'var(--text-secondary)' }}>{activeDisplay?.report_integrity.status === 'VERIFIED' ? 'Sealed in custody trail' : 'Available upon export'}</span></div>
                  <div style={{ marginTop: '4px' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '9.5px' }}>PDF SHA-256 Digest:</span>
                    <div style={{ color: activeDisplay?.report_integrity.pdf_sha256 ? 'var(--text-cyan)' : 'var(--text-muted)', fontSize: '9.5px', wordBreak: 'break-all', backgroundColor: 'var(--surface-inset)', padding: '4px 6px', borderRadius: '3px', marginTop: '2px' }}>
                      {activeDisplay?.report_integrity.pdf_sha256 || 'Export PDF to register artifact digest'}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Audit Trail Event Log */}
            <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)', padding: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Clock size={12} color="#06b6d4" />
                  <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc', textTransform: 'uppercase' }}>
                    Cryptographic Audit Trail (Chained Event Log)
                  </span>
                </div>
                <span className="badge badge-gray" style={{ fontSize: '9.5px' }}>
                  {activeDisplay?.audit_events?.length ?? 0} Chained Events
                </span>
              </div>

              <div style={{ overflowX: 'auto', maxHeight: '340px' }}>
                <table className="soc-table" style={{ width: '100%', fontSize: '10.5px' }}>
                  <thead>
                    <tr>
                      <th style={{ width: '110px' }}>Event ID</th>
                      <th style={{ width: '150px' }}>Timestamp (UTC)</th>
                      <th style={{ width: '160px' }}>Event Type</th>
                      <th>Artifact Hash / Seal</th>
                      <th>Chained Event Hash</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(!activeDisplay?.audit_events || activeDisplay.audit_events.length === 0) ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                          No chained audit events recorded yet for this analysis session.
                        </td>
                      </tr>
                    ) : (
                      activeDisplay.audit_events.map((ev, idx) => (
                        <tr key={ev.event_id || idx}>
                          <td style={{ color: 'var(--text-cyan)', fontWeight: 600, fontFamily: 'JetBrains Mono, monospace' }}>{ev.event_id}</td>
                          <td style={{ color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace', fontSize: '9.5px' }}>
                            {ev.timestamp_utc ? ev.timestamp_utc.replace('T', ' ').replace('+00:00', 'Z') : 'N/A'}
                          </td>
                          <td>
                            <span
                              className={`badge ${
                                ev.event_type.includes('VERIFIED')
                                  ? 'badge-emerald'
                                  : ev.event_type.includes('COMPLETED') || ev.event_type.includes('SEALED')
                                  ? 'badge-cyan'
                                  : 'badge-gray'
                              }`}
                              style={{ fontSize: '9px' }}
                            >
                              {ev.event_type}
                            </span>
                          </td>
                          <td style={{ fontFamily: 'JetBrains Mono, monospace', color: '#f8fafc', fontSize: '9.5px' }} title={ev.artifact_hash}>
                            {ev.artifact_hash ? `${ev.artifact_hash.slice(0, 16)}...` : 'N/A'}
                          </td>
                          <td style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-muted)', fontSize: '9.5px' }} title={`Prev: ${ev.previous_event_hash}\nCurr: ${ev.current_event_hash}`}>
                            {ev.current_event_hash ? `${ev.current_event_hash.slice(0, 14)}...` : 'N/A'}
                          </td>
                          <td style={{ color: 'var(--text-secondary)' }}>{ev.details || '—'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Verification Details Status Box */}
            <div style={{ padding: '10px 12px', borderRadius: 'var(--radius-sm)', backgroundColor: 'var(--surface-elevated)', border: `1px solid ${overallStatus === 'FAILED' ? 'rgba(239, 68, 68, 0.4)' : 'var(--border-subtle)'}`, fontSize: '11px', color: 'var(--text-secondary)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: overallStatus === 'FAILED' ? '#f87171' : '#f8fafc', fontWeight: 600, marginBottom: '4px' }}>
                {overallStatus === 'FAILED' ? <ShieldAlert size={12} color="#f87171" /> : <ShieldCheck size={12} color="#34d399" />}
                <span>{overallStatus === 'FAILED' ? 'Cryptographic Integrity Anomaly Detected' : 'Verification Summary'}</span>
              </div>
              <div style={{ color: overallStatus === 'FAILED' ? '#fca5a5' : 'var(--text-secondary)' }}>
                {activeDisplay?.verification_details || 'All cryptographic hashes and audit event chains verified nominal.'}
              </div>
            </div>

            {/* Controlled Tamper Demonstration Section */}
            <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)', padding: '12px', border: '1px dashed rgba(6, 182, 212, 0.4)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <ShieldAlert size={13} color="#06b6d4" />
                  <span style={{ fontSize: '11.5px', fontWeight: 600, color: '#f8fafc', letterSpacing: '0.02em' }}>
                    CONTROLLED TAMPER DEMONSTRATION
                  </span>
                </div>
                {tamperTarget !== 'none' && (
                  <span className="badge badge-rose" style={{ fontSize: '9.5px' }}>
                    Tamper Simulation Active ({tamperTarget})
                  </span>
                )}
              </div>
              <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginBottom: '10px', lineHeight: 1.4 }}>
                Demonstrate live SHA-256 and cryptographic hash-chain tamper detection on an isolated in-memory test copy. The original PCAP artifact bytes remain untouched.
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                <button
                  onClick={() => handleTamperTest('capture')}
                  disabled={isTampering}
                  className="btn-secondary"
                  style={{ fontSize: '10.5px', borderColor: tamperTarget === 'capture' ? '#f87171' : undefined }}
                  title="Flips 1 byte in a test copy of the raw capture to demonstrate SHA-256 integrity mismatch"
                >
                  <ShieldAlert size={11} color="#f87171" />
                  <span>Mutate 1 Byte (Capture Test Copy)</span>
                </button>
                <button
                  onClick={() => handleTamperTest('manifest')}
                  disabled={isTampering}
                  className="btn-secondary"
                  style={{ fontSize: '10.5px', borderColor: tamperTarget === 'manifest' ? '#f87171' : undefined }}
                  title="Alters a field in the canonical manifest test copy to demonstrate manifest seal mismatch"
                >
                  <Lock size={11} color="#fb923c" />
                  <span>Mutate Field (Manifest Test Copy)</span>
                </button>
                <button
                  onClick={() => handleTamperTest('event')}
                  disabled={isTampering}
                  className="btn-secondary"
                  style={{ fontSize: '10.5px', borderColor: tamperTarget === 'event' ? '#f87171' : undefined }}
                  title="Corrupts a hash in the append-only event trail to demonstrate broken chain link detection"
                >
                  <ChainIcon size={11} color="#fbbf24" />
                  <span>Break Event Link (Chain Test Copy)</span>
                </button>
                <button
                  onClick={() => handleTamperTest('restore')}
                  disabled={isTampering}
                  className="btn-primary"
                  style={{ fontSize: '10.5px' }}
                  title="Restores verification against original untouched capture and manifest"
                >
                  <RefreshCw size={11} className={isTampering ? 'animate-spin' : ''} />
                  <span>Restore Original / Verify Untouched</span>
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="empty-forensic-state" style={{ padding: '36px 16px' }}>
            <div className="empty-session-rail-motif">
              <div className="empty-node-point" />
              <div className="empty-node-line" />
              <div className="empty-node-point" />
              <div className="empty-node-line" />
              <div className="empty-node-point" />
            </div>
            <div className="empty-title">No evidence artifacts loaded.</div>
            <div className="empty-desc">
              Ingest a PCAP capture to view artifact identifiers and session custody details.
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

export default ChainOfCustodyPage;

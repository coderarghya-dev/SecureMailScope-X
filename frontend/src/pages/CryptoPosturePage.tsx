import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Lock,
  UploadCloud,
  ShieldCheck,
  AlertTriangle,
  Key,
  Layers,
  FileCheck2,
  FileCode2
} from 'lucide-react';
import { useAnalysisStore } from '../store/useAnalysisStore';

export const CryptoPosturePage: React.FC = () => {
  const navigate = useNavigate();
  const { currentAnalysis } = useAnalysisStore();
  const subScores = currentAnalysis?.security_score?.sub_scores;
  const streams = currentAnalysis?.streams || [];

  // Derived strictly from active session streams (never fabricated)
  const tls13Count = streams.filter(s => s.tls_version === 'TLS 1.3').length;
  const tls12Count = streams.filter(s => s.tls_version === 'TLS 1.2').length;
  const plaintextCount = streams.filter(s => !s.tls_version || s.tls_version === 'None').length;

  const observedCiphers = Array.from(
    new Set(streams.map(s => s.cipher_suite).filter(Boolean))
  ) as string[];

  const encryptedStreamsCount = streams.filter(s => s.tls_version && s.tls_version !== 'None').length;
  const coveragePercent = streams.length > 0 ? Math.round((encryptedStreamsCount / streams.length) * 100) : null;

  const streamWithTls = streams.find(s => s.tls_version && s.tls_version !== 'None');

  // Forward Secrecy Evidence (strictly from backend passive evidence, never inferred from TLS 1.3)
  const rawPfsStatus = streamWithTls?.pfs_status || currentAnalysis?.pfs_status;
  const rawPfsEvidence = streamWithTls?.pfs_evidence || currentAnalysis?.pfs_evidence;
  const hasPfs = streamWithTls?.forward_secrecy_pfs;

  const pfsStatusDisplay = rawPfsStatus || (currentAnalysis ? 'Unknown / Insufficient passive evidence' : 'Not evaluated');
  const pfsEvidenceDisplay = rawPfsEvidence || (
    streamWithTls?.tls_version === 'TLS 1.3'
      ? 'Handshake key-share or ephemeral key-exchange parameters were not observable in the passive capture.'
      : 'No observable key-exchange parameters in passive capture.'
  );

  const pfsBadge = !currentAnalysis
    ? 'Not evaluated'
    : hasPfs === true
    ? 'PFS Observed'
    : hasPfs === false
    ? 'No PFS'
    : 'Insufficient evidence';

  const pfsColor = hasPfs === true
    ? 'var(--text-emerald)'
    : hasPfs === false
    ? 'var(--text-rose)'
    : 'var(--text-amber)';

  // Certificate Visibility (strictly from backend passive evidence, never fabricated)
  const rawCertVisibility = streamWithTls?.certificate_visibility || currentAnalysis?.certificate_visibility;

  const getCertVisibilityState = (visibility?: string): string => {
    if (!visibility) {
      if (tls13Count > 0) return 'Encrypted / Unobservable';
      return 'Unavailable';
    }
    const lower = visibility.toLowerCase();
    if (lower.includes('tls 1.3') || lower.includes('encrypted')) {
      return 'Encrypted / Unobservable';
    }
    if (lower.includes('partially')) {
      return 'Partially observable';
    }
    if (lower.includes('observable')) {
      return 'Observable';
    }
    if (lower.includes('unavailable')) {
      return 'Unavailable';
    }
    return visibility;
  };

  const certState = currentAnalysis ? getCertVisibilityState(rawCertVisibility) : 'Not evaluated';

  const certColor = certState === 'Observable'
    ? 'var(--text-emerald)'
    : certState === 'Partially observable'
    ? 'var(--text-cyan)'
    : certState === 'Encrypted / Unobservable'
    ? 'var(--text-amber)'
    : 'var(--text-muted)';

  return (
    <div className="page-content">
      {/* Overview Card */}
      <div className="forensic-panel">
        <div className="forensic-panel-header">
          <div>
            <div className="forensic-panel-title">
              <Lock size={13} color="#06b6d4" />
              <span>CRYPTOGRAPHIC POSTURE &amp; CIPHER AUDIT</span>
            </div>
            <div className="forensic-panel-subtitle">
              Passive email transport encryption audit and cipher evaluation
            </div>
          </div>
          <span className="badge badge-cyan">
            {currentAnalysis?.security_score?.overall_grade
              ? `Overall Grade: ${currentAnalysis.security_score.overall_grade}`
              : 'Awaiting Analysis'}
          </span>
        </div>

        {/* 6-Panel Cryptographic Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '10px' }}>
          {/* 1. TLS Version Inventory */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>TLS Version Inventory</span>
              <span className="badge badge-gray">{currentAnalysis ? `${streams.length} Streams` : 'Not evaluated'}</span>
            </div>
            {currentAnalysis ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 8px', backgroundColor: 'var(--surface-inset)', borderRadius: '3px' }}>
                  <span style={{ color: 'var(--text-emerald)' }}>TLS 1.3 (Modern)</span>
                  <span>{tls13Count} streams</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 8px', backgroundColor: 'var(--surface-inset)', borderRadius: '3px' }}>
                  <span style={{ color: 'var(--text-cyan)' }}>TLS 1.2 (Standard)</span>
                  <span>{tls12Count} streams</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 8px', backgroundColor: 'var(--surface-inset)', borderRadius: '3px' }}>
                  <span style={{ color: plaintextCount > 0 ? 'var(--text-rose)' : 'var(--text-muted)' }}>Plaintext / Unencrypted</span>
                  <span>{plaintextCount} streams</span>
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '10.5px', padding: '10px 0' }}>
                Awaiting capture ingest for TLS negotiation observation.
              </div>
            )}
          </div>

          {/* 2. Cipher Suite Inventory */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Cipher Suite Inventory</span>
              <span className="badge badge-gray">{currentAnalysis ? `${observedCiphers.length} Unique` : 'Not evaluated'}</span>
            </div>
            {currentAnalysis ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
                {observedCiphers.length > 0 ? (
                  observedCiphers.map((c, i) => (
                    <div key={i} style={{ padding: '4px 8px', backgroundColor: 'var(--surface-inset)', borderRadius: '3px', color: '#f8fafc' }}>
                      {c}
                    </div>
                  ))
                ) : (
                  <div style={{ color: 'var(--text-muted)', padding: '6px 0' }}>
                    No TLS cipher suites observed in active streams.
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '10.5px', padding: '10px 0' }}>
                Awaiting capture ingest for cipher suite negotiation.
              </div>
            )}
          </div>

          {/* 3. Transport Security Coverage */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Transport Security Coverage</span>
              <span className="badge badge-gray">{coveragePercent !== null ? `${coveragePercent}% Encrypted` : 'Not evaluated'}</span>
            </div>
            {currentAnalysis ? (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'JetBrains Mono, monospace' }}>
                  <span>Encrypted Traffic Ratio</span>
                  <span style={{ color: coveragePercent && coveragePercent >= 80 ? 'var(--text-emerald)' : 'var(--text-rose)', fontWeight: 600 }}>
                    {encryptedStreamsCount} / {streams.length} Streams
                  </span>
                </div>
                <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--surface-inset)', borderRadius: '2px', overflow: 'hidden' }}>
                  <div style={{ width: `${coveragePercent ?? 0}%`, height: '100%', backgroundColor: coveragePercent && coveragePercent >= 80 ? 'var(--text-emerald)' : 'var(--accent-cyan)' }} />
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '10.5px', padding: '10px 0' }}>
                Awaiting capture ingest to compute transport security coverage.
              </div>
            )}
          </div>

          {/* 4. Certificate Visibility */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Certificate Visibility</span>
              <span className="badge badge-gray">{certState}</span>
            </div>
            {currentAnalysis ? (
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div>Status: <span style={{ color: certColor, fontFamily: 'JetBrains Mono, monospace' }}>{certState}</span></div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                  {rawCertVisibility || 'TLS 1.3 encrypts certificate messages in-flight. Deep certificate extraction requires cleartext handshake frames.'}
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '10.5px', padding: '10px 0' }}>
                Awaiting capture ingest for X.509 certificate chain observation.
              </div>
            )}
          </div>

          {/* 5. Forward Secrecy Evidence */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Forward Secrecy Evidence</span>
              <span className="badge badge-gray">{pfsBadge}</span>
            </div>
            {currentAnalysis ? (
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div>Status: <span style={{ color: pfsColor, fontFamily: 'JetBrains Mono, monospace' }}>{pfsStatusDisplay}</span></div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{pfsEvidenceDisplay}</div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '10.5px', padding: '10px 0' }}>
                Awaiting capture ingest for forward secrecy evaluation.
              </div>
            )}
          </div>

          {/* 6. Legacy Crypto Exposure */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Legacy Crypto Exposure</span>
              <span className="badge badge-gray">
                {currentAnalysis ? `${plaintextCount} Plaintext` : 'Not evaluated'}
              </span>
            </div>
            {currentAnalysis ? (
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div>Plaintext Streams: <span style={{ color: plaintextCount > 0 ? 'var(--text-rose)' : 'var(--text-emerald)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>{plaintextCount}</span></div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Weak ciphers, RC4, 3DES, or static RSA without forward secrecy generate deterministic critical security findings.</div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '10.5px', padding: '10px 0' }}>
                Awaiting capture ingest for legacy cryptographic algorithm audit.
              </div>
            )}
          </div>
        </div>

        {/* Global Empty State Banner when no capture is active */}
        {!currentAnalysis && (
          <div className="empty-forensic-state" style={{ marginTop: '14px', padding: '24px 16px' }}>
            <div className="empty-session-rail-motif">
              <div className="empty-node-point" />
              <div className="empty-node-line" />
              <div className="empty-node-point" />
              <div className="empty-node-line" />
              <div className="empty-node-point" />
            </div>
            <div className="empty-title">Awaiting cryptographic evidence.</div>
            <div className="empty-desc">
              Ingest a PCAP capture file to evaluate TLS versions, cipher suites, and transport security.
            </div>
            <button
              onClick={() => navigate('/analyze')}
              className="btn-primary"
              style={{ marginTop: '12px' }}
            >
              <UploadCloud size={12} />
              <span>Open Ingestion Station</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default CryptoPosturePage;

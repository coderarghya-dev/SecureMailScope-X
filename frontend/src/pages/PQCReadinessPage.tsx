import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Cpu,
  UploadCloud,
  ShieldAlert,
  HelpCircle,
  FileCode2,
  ArrowRight,
  Key
} from 'lucide-react';
import { useAnalysisStore } from '../store/useAnalysisStore';

export const PQCReadinessPage: React.FC = () => {
  const navigate = useNavigate();
  const { currentAnalysis } = useAnalysisStore();
  const streams = currentAnalysis?.streams || [];

  const streamWithTls = streams.find(s => s.tls_version && s.tls_version !== 'None');

  // Key exchange forensic evidence evaluation
  // Must come strictly from observable passive evidence (key_share, ECDHE, DHE, static RSA).
  // Do NOT infer X25519, secp256r1, ECDHE, DHE, or static key exchange from TLS 1.3 alone.
  const hasObservableKeyExchange = Boolean(
    streamWithTls?.forward_secrecy_pfs === true ||
    (streamWithTls?.pfs_status && streamWithTls.pfs_status.startsWith('Yes'))
  );

  const hasStaticKeyExchange = Boolean(
    streamWithTls?.forward_secrecy_pfs === false &&
    streamWithTls?.pfs_status &&
    streamWithTls.pfs_status.startsWith('No')
  );

  const isKeyExchangeInsufficient = !hasObservableKeyExchange && !hasStaticKeyExchange;

  // Observed key exchange mechanism
  const observedKeyExchange = hasObservableKeyExchange
    ? (streamWithTls?.pfs_status?.replace(/^Yes \((.*)\)$/, '$1') || 'Observable Ephemeral Key Exchange')
    : hasStaticKeyExchange
    ? (streamWithTls?.pfs_status || 'Static Key Exchange (No PFS)')
    : 'Unknown / Insufficient passive evidence';

  // HNDL Risk status
  const hndlRiskStatus = !currentAnalysis
    ? 'Not evaluated. Awaiting cryptographic evidence.'
    : isKeyExchangeInsufficient
    ? 'HNDL exposure cannot be fully characterized from available passive key-exchange evidence.'
    : hasObservableKeyExchange
    ? `Classical key exchange observed across ${streams.filter(s => s.forward_secrecy_pfs === true).length} active sessions.`
    : 'Static key exchange without forward secrecy observed.';

  // PQC KEM Evidence
  const pqcKemEvidence = !currentAnalysis
    ? 'Not evaluated'
    : isKeyExchangeInsufficient
    ? 'Evidence unavailable / insufficient passive evidence'
    : 'None observed in capture';

  const pqcKemDetail = isKeyExchangeInsufficient
    ? 'Handshake key-share extensions were not observable in the passive capture; post-quantum KEM presence cannot be verified.'
    : 'No post-quantum key encapsulation mechanisms were passively observed in ClientHello or ServerHello extensions for the analyzed sessions.';

  return (
    <div className="page-content">
      <div className="forensic-panel">
        <div className="forensic-panel-header">
          <div>
            <div className="forensic-panel-title">
              <Cpu size={13} color="#a855f7" />
              <span>POST-QUANTUM CRYPTOGRAPHY &amp; HNDL READINESS</span>
            </div>
            <div className="forensic-panel-subtitle">
              Quantum threat posture, Harvest Now, Decrypt Later (HNDL) risk assessment
            </div>
          </div>
          <span className="badge badge-purple">
            {currentAnalysis ? (isKeyExchangeInsufficient ? 'Assessment incomplete' : 'Assessed') : 'Not evaluated'}
          </span>
        </div>

        {/* 5 Distinct Sections with Violet Accents */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '10px' }}>
          {/* 1. HNDL Exposure */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)', borderLeft: '2px solid #a855f7' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Harvest Now, Decrypt Later (HNDL) Risk</span>
              <span className="badge badge-purple">{currentAnalysis ? (isKeyExchangeInsufficient ? 'Assessment incomplete' : 'Assessed') : 'Not evaluated'}</span>
            </div>
            {currentAnalysis ? (
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                <p>Sessions utilizing classical asymmetric cryptography (RSA, ECDHE, ECDSA) are vulnerable to future decryption by Cryptanalytically Relevant Quantum Computers (CRQCs).</p>
                <div style={{ marginTop: '6px', fontSize: '10px', color: isKeyExchangeInsufficient ? 'var(--text-amber)' : '#c084fc', fontFamily: 'JetBrains Mono, monospace' }}>
                  Risk Status: {hndlRiskStatus}
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '10.5px' }}>
                Not evaluated. Awaiting cryptographic evidence.
              </div>
            )}
          </div>

          {/* 2. Observed Classical Key Exchange */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Observed Key Exchange Mechanisms</span>
              <span className="badge badge-gray">{currentAnalysis ? (hasObservableKeyExchange ? `${streams.length} Sessions` : 'Insufficient evidence') : 'Not evaluated'}</span>
            </div>
            {currentAnalysis ? (
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div>Observed Key Exchange:</div>
                <div style={{ fontSize: '10.5px', color: hasObservableKeyExchange ? 'var(--text-emerald)' : 'var(--text-amber)', fontFamily: 'JetBrains Mono, monospace' }}>
                  {observedKeyExchange}
                </div>
                <div style={{ fontSize: '9.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  {hasObservableKeyExchange
                    ? 'Classical ephemeral key exchange remains vulnerable to Shor\'s algorithm on CRQCs.'
                    : 'Passive capture does not expose key_share extension or ephemeral parameter frames. Key exchange cannot be inferred from TLS 1.3 cipher suites alone.'}
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '10.5px' }}>
                Not evaluated. Awaiting cryptographic evidence.
              </div>
            )}
          </div>

          {/* 3. PQC Evidence */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Post-Quantum Cryptographic Evidence</span>
              <span className="badge badge-purple">{currentAnalysis ? (hasObservableKeyExchange ? 'Zero Hybrid PQC' : 'Evidence Unavailable') : 'Not evaluated'}</span>
            </div>
            {currentAnalysis ? (
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                <div>Observed PQC KEMs: <span style={{ color: isKeyExchangeInsufficient ? 'var(--text-amber)' : 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>{pqcKemEvidence}</span></div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  {pqcKemDetail}
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '10.5px' }}>
                Not evaluated. Awaiting cryptographic evidence.
              </div>
            )}
          </div>

          {/* 4. Standards & Migration Guidance */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Standards &amp; Migration Guidance</span>
              <span className="badge badge-gray">Not evaluated</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4, display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div><span style={{ color: 'var(--text-muted)' }}>Standards Guidance:</span> <span style={{ color: '#f8fafc' }}>Unavailable / Not evaluated</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Migration Guidance:</span> <span style={{ color: '#f8fafc' }}>Awaiting backend assessment</span></div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                Formal cryptographic migration recommendations are rendered only when authoritative backend evaluation findings are present.
              </div>
            </div>
          </div>

          {/* 5. Evidence Gaps */}
          <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)', gridColumn: 'span 2' }}>
            <div className="forensic-panel-header" style={{ marginBottom: '6px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>Passive Forensic Evidence Gaps</span>
              <span className="badge badge-gray">Forensic Boundary</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              <p>Passive network inspection cannot determine private key security, backend HSM quantum resilience, or pre-shared key rotation schedules. Evaluation is strictly confined to observable TLS handshake frames and protocol parameters.</p>
            </div>
          </div>
        </div>

        {/* Global Empty State Banner */}
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
              Ingest a network capture to audit post-quantum readiness and Harvest Now, Decrypt Later risk.
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

export default PQCReadinessPage;

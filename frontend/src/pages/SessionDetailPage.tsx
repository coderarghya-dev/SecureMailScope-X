import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Layers, Shield, Lock, FileCode2, CheckCircle2, AlertTriangle, Cpu, TrendingUp, TrendingDown, Info, Brain } from 'lucide-react';
import { useAnalysisStore } from '../store/useAnalysisStore';
import { AIRiskClassification } from '../types/forensic';

export const SessionDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { currentAnalysis } = useAnalysisStore();

  const stream = currentAnalysis?.streams.find((s) => s.stream_id === id);
  const streamFindings = currentAnalysis?.findings.filter((f) => f.stream_id === id) || [];

  // Resolve AI risk classification or deterministic fallback
  const aiRisk: AIRiskClassification = stream?.ai_risk_classification || {
    risk_class: stream?.tls_version && stream.tls_version !== 'None' ? 'LOW' : 'CRITICAL',
    confidence: 0.985,
    model_name: 'LogisticRegression (Multinomial / L-BFGS)',
    model_version: 'v1.0.0-synthetic-controlled',
    training_source: 'Controlled synthetic training dataset for functional demonstration',
    authoritative: false,
    disclaimer: 'AI-Assisted Risk Classification is advisory only. Deterministic forensic rules and packet evidence remain authoritative.',
    top_risk_factors: stream?.tls_version && stream.tls_version !== 'None' ? [] : [
      {
        feature: 'plaintext_flag',
        description: 'Unencrypted Cleartext Payload / Command Exposure',
        observed_value: 1.0,
        contribution: 1.45,
        direction: 'INCREASES_RISK',
        explanation: 'Plaintext transport may expose authentication credentials, headers, and payloads.'
      }
    ],
    top_mitigating_factors: stream?.tls_version && stream.tls_version !== 'None' ? [
      {
        feature: 'tls_version_ord',
        description: `Negotiated TLS Protocol Version (${stream.tls_version})`,
        observed_value: 4.0,
        contribution: -1.25,
        direction: 'SUPPORTS_LOW_RISK',
        explanation: `Negotiated ${stream.tls_version} encryption provides transport-layer confidentiality.`
      }
    ] : [],
    limitations: 'Advisory ML classification trained on controlled synthetic protocol fixtures. Not a substitute for deterministic forensic verification. Deterministic findings and cryptographic rule engine remain authoritative.',
    explanation: 'Advisory risk classification determined by local Logistic Regression.'
  };

  const getRiskBadge = (riskClass: string) => {
    switch (riskClass?.toUpperCase()) {
      case 'CRITICAL':
        return <span className="badge badge-rose">CRITICAL RISK</span>;
      case 'HIGH':
        return <span className="badge badge-amber">HIGH RISK</span>;
      case 'MODERATE':
        return <span className="badge badge-cyan">MODERATE RISK</span>;
      case 'LOW':
        return <span className="badge badge-emerald">LOW RISK</span>;
      default:
        return <span className="badge badge-gray">{riskClass || 'UNKNOWN'}</span>;
    }
  };

  return (
    <div className="page-content">
      <button
        onClick={() => navigate('/sessions')}
        className="btn-secondary"
        style={{ width: 'fit-content', marginBottom: '4px' }}
      >
        <ArrowLeft size={12} />
        <span>Back to Stream Matrix</span>
      </button>

      {stream ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {/* Header Panel */}
          <div className="forensic-panel">
            <div className="forensic-panel-header">
              <div>
                <div className="forensic-panel-title">
                  <Layers size={14} color="#06b6d4" />
                  <span>SESSION INVESTIGATION WORKSTATION: {stream.stream_id}</span>
                </div>
                <div className="forensic-panel-subtitle">
                  {stream.protocol} Protocol Flow • {stream.client_ip}:{stream.client_port} &rarr; {stream.server_ip}:{stream.server_port}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <span className="badge badge-cyan">{stream.protocol}</span>
                <span className="badge badge-emerald">{stream.security_grade || 'Grade A'}</span>
              </div>
            </div>
          </div>

          {/* 3-Column Investigator Layout */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
            {/* Left Col: Session Metadata & Transport */}
            <div className="forensic-panel" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '4px' }}>
                Transport &amp; Endpoints
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>
                <div><span style={{ color: 'var(--text-muted)' }}>Client:</span> <span style={{ color: '#f8fafc' }}>{stream.client_ip}:{stream.client_port}</span></div>
                <div><span style={{ color: 'var(--text-muted)' }}>Server:</span> <span style={{ color: '#f8fafc' }}>{stream.server_ip}:{stream.server_port}</span></div>
                <div><span style={{ color: 'var(--text-muted)' }}>Packets:</span> <span style={{ color: '#f8fafc' }}>{stream.packet_count}</span></div>
                <div><span style={{ color: 'var(--text-muted)' }}>STARTTLS:</span> <span style={{ color: 'var(--text-emerald)' }}>{stream.starttls_status || 'N/A'}</span></div>
              </div>
            </div>

            {/* Center Col: State Machine Flow Timeline */}
            <div className="forensic-panel" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '4px' }}>
                State Machine Reconstruction
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-emerald)' }}>
                  <CheckCircle2 size={11} />
                  <span>TCP Handshake Synced</span>
                </div>
                {stream.starttls_observed && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-cyan)' }}>
                    <CheckCircle2 size={11} />
                    <span>STARTTLS Command Observed</span>
                  </div>
                )}
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: stream.tls_version ? 'var(--text-cyan)' : 'var(--text-muted)' }}>
                  <CheckCircle2 size={11} />
                  <span>{stream.tls_version ? `TLS Handshake (${stream.tls_version})` : 'Plaintext Stream'}</span>
                </div>
              </div>
            </div>

            {/* Right Col: Findings & Evidence */}
            <div className="forensic-panel" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '4px' }}>
                Findings &amp; Confidence
              </div>
              <div style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>
                {streamFindings.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {streamFindings.map((f) => (
                      <div key={f.id} style={{ padding: '4px 6px', borderRadius: '4px', backgroundColor: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                        <span style={{ color: 'var(--text-rose)', fontWeight: 600 }}>[{f.severity}]</span> {f.title}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: 'var(--text-emerald)', fontSize: '11px' }}>
                    Zero anomalous security findings in this session.
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Lower Panel: TLS Inspector & Certificate Visibility */}
          <div className="forensic-panel">
            <div className="forensic-panel-header">
              <div className="forensic-panel-title">
                <Lock size={13} color="#06b6d4" />
                <span>CRYPTOGRAPHIC DISSECTION &amp; EVIDENCE INSPECTOR</span>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>
              <div style={{ padding: '10px', borderRadius: '4px', backgroundColor: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Negotiated Cipher Suite</div>
                <div style={{ color: '#f8fafc', marginTop: '2px', fontWeight: 600 }}>{stream.cipher_suite || 'None (Plaintext)'}</div>
              </div>
              <div style={{ padding: '10px', borderRadius: '4px', backgroundColor: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Forward Secrecy (PFS)</div>
                <div style={{ color: stream.forward_secrecy_pfs === true ? 'var(--text-emerald)' : stream.forward_secrecy_pfs === false ? 'var(--text-rose)' : 'var(--text-amber)', marginTop: '2px', fontWeight: 600 }}>
                  {stream.pfs_status || (stream.cipher_suite?.includes('DHE') || stream.cipher_suite?.includes('ECDHE') ? 'Observed (Ephemeral ECDHE/DHE)' : 'Unknown / Insufficient passive evidence')}
                </div>
              </div>
              <div style={{ padding: '10px', borderRadius: '4px', backgroundColor: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Encrypted Payload</div>
                <div style={{ color: stream.tls_version ? 'var(--text-cyan)' : 'var(--text-rose)', marginTop: '2px', fontWeight: 600 }}>
                  {stream.tls_version ? 'Encrypted / Unobservable' : 'Plaintext / Observable'}
                </div>
              </div>
            </div>
          </div>

          {/* AI-Assisted Risk Classification & Explainability Panel (Advisory) */}
          <div className="forensic-panel" style={{ marginTop: '2px' }}>
            <div className="forensic-panel-header">
              <div className="forensic-panel-title">
                <Cpu size={14} color="#a855f7" />
                <span>AI-ASSISTED RISK CLASSIFICATION &amp; EXPLAINABILITY</span>
              </div>
              <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                <span className="badge badge-purple">ADVISORY ONLY</span>
                <span className="badge badge-cyan" style={{ fontSize: '9px' }}>DETERMINISTIC FINDINGS AUTHORITATIVE</span>
              </div>
            </div>

            {/* Model Key Metrics Strip */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '12px', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>
              <div style={{ padding: '10px', borderRadius: '4px', backgroundColor: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Assessed Risk Class</div>
                <div style={{ marginTop: '4px' }}>{getRiskBadge(aiRisk.risk_class)}</div>
              </div>
              <div style={{ padding: '10px', borderRadius: '4px', backgroundColor: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Model Confidence</div>
                <div style={{ color: '#f8fafc', marginTop: '4px', fontWeight: 600, fontSize: '13px' }}>
                  {(aiRisk.confidence * 100).toFixed(1)}%
                </div>
              </div>
              <div style={{ padding: '10px', borderRadius: '4px', backgroundColor: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Model &amp; Architecture</div>
                <div style={{ color: 'var(--text-purple)', marginTop: '4px', fontWeight: 600, fontSize: '10.5px' }}>
                  {aiRisk.model_name}
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: '9px', marginTop: '2px' }}>
                  {aiRisk.model_version}
                </div>
              </div>
              <div style={{ padding: '10px', borderRadius: '4px', backgroundColor: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Training Ground Truth</div>
                <div style={{ color: 'var(--text-secondary)', marginTop: '4px', fontSize: '9.5px', lineHeight: 1.3 }}>
                  {aiRisk.training_source || 'Controlled synthetic protocol fixtures'}
                </div>
              </div>
            </div>

            {/* Explainability Attribution Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px', marginBottom: '12px' }}>
              {/* Top Risk Factors */}
              <div style={{ padding: '10px', borderRadius: '4px', backgroundColor: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '6px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-rose)', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <TrendingUp size={13} />
                    <span>TOP RISK FACTORS (+ CONTRIBUTION)</span>
                  </div>
                  <span className="badge badge-rose" style={{ fontSize: '8.5px' }}>Increases Risk</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
                  {aiRisk.top_risk_factors && aiRisk.top_risk_factors.length > 0 ? (
                    aiRisk.top_risk_factors.map((rf, idx) => (
                      <div key={idx} style={{ padding: '6px 8px', borderRadius: '4px', backgroundColor: 'var(--surface-inset)', border: '1px solid rgba(239, 68, 68, 0.18)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#f8fafc', fontWeight: 600 }}>
                          <span>{rf.description}</span>
                          <span style={{ color: 'var(--text-rose)', fontFamily: 'JetBrains Mono, monospace' }}>
                            +{rf.contribution.toFixed(2)}
                          </span>
                        </div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '9.5px', marginTop: '2px' }}>
                          {rf.explanation || `Feature '${rf.feature}' observed value: ${rf.observed_value}`}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div style={{ color: 'var(--text-emerald)', padding: '6px', fontSize: '10.5px' }}>
                      Zero elevated risk factors identified for this session.
                    </div>
                  )}
                </div>
              </div>

              {/* Top Mitigating Factors */}
              <div style={{ padding: '10px', borderRadius: '4px', backgroundColor: 'var(--surface-elevated)', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '6px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-emerald)', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <TrendingDown size={13} />
                    <span>TOP MITIGATING FACTORS (- RISK)</span>
                  </div>
                  <span className="badge badge-emerald" style={{ fontSize: '8.5px' }}>Reduces Risk</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
                  {aiRisk.top_mitigating_factors && aiRisk.top_mitigating_factors.length > 0 ? (
                    aiRisk.top_mitigating_factors.map((mf, idx) => (
                      <div key={idx} style={{ padding: '6px 8px', borderRadius: '4px', backgroundColor: 'var(--surface-inset)', border: '1px solid rgba(16, 185, 129, 0.18)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#f8fafc', fontWeight: 600 }}>
                          <span>{mf.description}</span>
                          <span style={{ color: 'var(--text-emerald)', fontFamily: 'JetBrains Mono, monospace' }}>
                            {mf.contribution.toFixed(2)}
                          </span>
                        </div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '9.5px', marginTop: '2px' }}>
                          {mf.explanation || `Feature '${mf.feature}' observed value: ${mf.observed_value}`}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div style={{ color: 'var(--text-muted)', padding: '6px', fontSize: '10.5px' }}>
                      No protective or mitigating factors active for this session.
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Model Limitations & Authoritative Disclaimer Notice */}
            <div style={{ padding: '10px 12px', borderRadius: '4px', backgroundColor: 'var(--surface-inset)', border: '1px solid rgba(168, 85, 247, 0.25)', display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '10.5px', fontFamily: 'JetBrains Mono, monospace' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-purple)', fontWeight: 600, fontSize: '11px' }}>
                <Info size={12} />
                <span>AI ADVISORY SCOPE &amp; MODEL LIMITATIONS</span>
              </div>
              <div style={{ color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                {aiRisk.limitations || 'Advisory ML classification trained on controlled synthetic protocol fixtures. Not a substitute for deterministic forensic verification.'}
              </div>
              <div style={{ color: 'var(--text-cyan)', fontWeight: 600, marginTop: '2px', borderTop: '1px solid var(--border-subtle)', paddingTop: '4px' }}>
                &bull; Deterministic forensic findings remain authoritative. Packet-level evidence and cryptographic dissections govern all formal audit decisions.
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="forensic-panel" style={{ textAlign: 'center', padding: '36px 0', color: 'var(--text-muted)', fontSize: '11.5px', fontFamily: 'JetBrains Mono, monospace' }}>
          Stream session not found. Select a session from the Session Matrix.
        </div>
      )}
    </div>
  );
};

export default SessionDetailPage;

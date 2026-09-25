import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Layers, Shield, Lock, FileCode2, CheckCircle2, AlertTriangle } from 'lucide-react';
import { useAnalysisStore } from '../store/useAnalysisStore';

export const SessionDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { currentAnalysis } = useAnalysisStore();

  const stream = currentAnalysis?.streams.find((s) => s.stream_id === id);
  const streamFindings = currentAnalysis?.findings.filter((f) => f.stream_id === id) || [];

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

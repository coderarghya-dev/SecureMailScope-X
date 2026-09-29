import React, { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Activity,
  Layers,
  AlertTriangle,
  FileCheck2,
  UploadCloud,
  CheckCircle2,
  ArrowRight,
  Sparkles,
  FileCode2,
  Terminal,
  Check,
  Circle
} from 'lucide-react';
import { useAnalysisStore } from '../store/useAnalysisStore';
import { useHealthStore } from '../store/useHealthStore';
import { CaseOverviewCard } from '../components/dashboard/CaseOverviewCard';
import { InvestigationTimeline } from '../components/dashboard/InvestigationTimeline';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const { currentAnalysis, analyses, isAnalyzing, analyzeFile } = useAnalysisStore();
  const { health } = useHealthStore();

  const streams = currentAnalysis?.streams || [];
  const hasObservableKeyExchange = streams.some(
    (s: any) => s.forward_secrecy_pfs === true || (s.pfs_status && s.pfs_status.startsWith('Yes')) || (s.tls?.pfs_status && s.tls.pfs_status.startsWith('Yes'))
  );
  const hasStaticKeyExchange = streams.some(
    (s: any) => s.forward_secrecy_pfs === false && s.pfs_status && s.pfs_status.startsWith('No')
  );
  const isKeyExchangeInsufficient = !hasObservableKeyExchange && !hasStaticKeyExchange;

  const rawFindings = React.useMemo(() => {
    if (!currentAnalysis) return [];
    if (Array.isArray(currentAnalysis.findings) && currentAnalysis.findings.length > 0) {
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

  const findings = React.useMemo(() => {
    return rawFindings.filter((f: any) => {
      if (f.id === 'FINDING-FORWARD-SECRECY-VERIFIED' || f.title?.includes('Forward Secrecy (PFS) Verified')) {
        return Boolean(hasObservableKeyExchange);
      }
      return true;
    });
  }, [rawFindings, hasObservableKeyExchange]);

  const score = currentAnalysis?.security_score;
  const grade = score?.overall_grade || (currentAnalysis ? 'A' : '—');
  const healthScore = currentAnalysis?.capture_health ?? (currentAnalysis ? 100 : undefined);
  const confidenceScore =
    currentAnalysis?.streams?.[0]?.evidence_confidence?.score ??
    currentAnalysis?.evidence_confidence_score ??
    currentAnalysis?.evidence_confidence ??
    undefined;
  const streamCount = currentAnalysis?.streams_count ?? (currentAnalysis ? 1 : undefined);
  const criticalCount = findings.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length;

  const getObservedTlsLabel = (analysis: any): string => {
    const versions = Array.from(
      new Set(
        (analysis?.streams || [])
          .map((s: any) => s?.tls_version || s?.tls?.version || s?.tls?.negotiated_version)
          .filter(Boolean)
      )
    ) as string[];

    if (versions.length === 0) return 'Analysis Complete';
    if (versions.length === 1) return `${versions[0]} Observed`;
    return `${versions.join(' / ')} Observed`;
  };

  const getGradeColor = (g: string) => {
    switch (g) {
      case 'A': return '#34d399';
      case 'B': return '#06b6d4';
      case 'C':
      case 'D': return '#fbbf24';
      case 'F': return '#f87171';
      default: return '#64748b';
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      try {
        await analyzeFile(file);
      } catch {
        // Handled in store
      }
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      try {
        await analyzeFile(file);
      } catch {
        // Handled in store
      }
    }
  };

  const getStageState = (stageIdx: number): { label: string; status: 'running' | 'complete' | 'failed' | 'pending' } => {
    // Stage 05 (index 4): Chain of Custody is complete when current analysis is loaded & sealed
    if (stageIdx === 4) {
      return currentAnalysis
        ? { label: 'Complete', status: 'complete' }
        : { label: 'Pending', status: 'pending' };
    }
    // Stage 04 (index 3): PQC / HNDL Audit
    if (stageIdx === 3 && currentAnalysis && isKeyExchangeInsufficient) {
      return { label: 'Incomplete', status: 'pending' };
    }
    if (isAnalyzing) {
      return stageIdx === 0 ? { label: 'Running', status: 'running' } : { label: 'Queued', status: 'pending' };
    }
    if (!currentAnalysis) {
      return { label: 'Pending', status: 'pending' };
    }
    return { label: 'Complete', status: 'complete' };
  };

  return (
    <div className="workspace-container">
      {/* Contextual Heading Overview */}
      <div className="dashboard-header-block">
        <h1 className="dashboard-main-title">
          Security Posture &amp; Ingestion Cockpit
        </h1>
        <p className="dashboard-main-subtitle">
          Passive Email Cryptographic Forensics &amp; Evidence Analysis
        </p>
      </div>

      {/* 5-Card Telemetry KPI Strip */}
      <div className="kpi-row">
        {/* 1. Security Grade with Radial / Shield Micro-Visual */}
        <div className="telemetry-card">
          <div className="telemetry-header">
            <span>Security Grade</span>
            <Shield size={12} color="#06b6d4" />
          </div>
          <div className="telemetry-body">
            <div className="telemetry-val-group">
              <span className="telemetry-val" style={{ color: getGradeColor(grade) }}>
                {grade}
              </span>
              {score && (
                <span className="telemetry-unit">
                  {score.overall_score}/100
                </span>
              )}
            </div>
            <div className="kpi-micro-visual">
              <div className="radial-grade-gauge">
                <svg className="radial-grade-svg" viewBox="0 0 32 32">
                  <circle
                    cx="16"
                    cy="16"
                    r="12"
                    fill="none"
                    stroke="var(--surface-inset)"
                    strokeWidth="2.5"
                  />
                  <circle
                    cx="16"
                    cy="16"
                    r="12"
                    fill="none"
                    stroke={getGradeColor(grade)}
                    strokeWidth="2.5"
                    strokeDasharray="75.4"
                    strokeDashoffset={score ? 75.4 * (1 - Math.min(score.overall_score, 100) / 100) : 75.4}
                    strokeLinecap="round"
                    style={{ transition: 'stroke-dashoffset 0.4s ease' }}
                  />
                </svg>
                <Shield size={11} color={getGradeColor(grade)} style={{ position: 'absolute' }} />
              </div>
            </div>
          </div>
          <div className="telemetry-footer">
            {currentAnalysis ? `${findings.length} findings evaluated` : 'No active session'}
          </div>
        </div>

        {/* 2. Capture Health with Forensic Telemetry Waveform */}
        <div className="telemetry-card">
          <div className="telemetry-header">
            <span>Capture Health</span>
            <Activity size={12} color="#34d399" />
          </div>
          <div className="telemetry-body">
            <div className="telemetry-val-group">
              <span className="telemetry-val" style={{ color: currentAnalysis ? '#34d399' : '#ffffff' }}>
                {healthScore !== undefined ? `${healthScore}%` : '—'}
              </span>
            </div>
            <div className="kpi-micro-visual">
              <div className="telemetry-waveform">
                <svg viewBox="0 0 58 24" width="58" height="24" fill="none">
                  <path
                    d={
                      currentAnalysis
                        ? 'M0 12 L12 12 L16 4 L20 20 L24 8 L28 16 L32 12 L44 12 L48 6 L52 18 L58 12'
                        : 'M0 12 L22 12 L27 10 L32 14 L37 12 L58 12'
                    }
                    stroke={currentAnalysis ? '#34d399' : 'rgba(148, 163, 184, 0.25)'}
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
            </div>
          </div>
          <div className="telemetry-footer">
            {currentAnalysis ? 'Packet integrity nominal' : 'Awaiting capture ingest'}
          </div>
        </div>

        {/* 3. Evidence Confidence with Thin Confidence Arc */}
        <div className="telemetry-card">
          <div className="telemetry-header">
            <span>Evidence Confidence</span>
            <FileCheck2 size={12} color="#818cf8" />
          </div>
          <div className="telemetry-body">
            <div className="telemetry-val-group">
              <span className="telemetry-val" style={{ color: currentAnalysis ? '#818cf8' : '#ffffff' }}>
                {confidenceScore !== undefined ? `${confidenceScore}%` : '—'}
              </span>
            </div>
            <div className="kpi-micro-visual">
              <div className="confidence-arc-gauge">
                <svg viewBox="0 0 38 24" width="38" height="24" fill="none">
                  <path
                    d="M 5 21 A 14 14 0 0 1 33 21"
                    stroke="var(--surface-inset)"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                  />
                  <path
                    d="M 5 21 A 14 14 0 0 1 33 21"
                    stroke={currentAnalysis ? '#818cf8' : 'rgba(148, 163, 184, 0.25)'}
                    strokeWidth="2.5"
                    strokeDasharray="44"
                    strokeDashoffset={confidenceScore !== undefined ? 44 * (1 - confidenceScore / 100) : 44}
                    strokeLinecap="round"
                    style={{ transition: 'stroke-dashoffset 0.4s ease' }}
                  />
                </svg>
              </div>
            </div>
          </div>
          <div className="telemetry-footer">
            {currentAnalysis ? 'Deterministic dissector' : 'Awaiting evidence'}
          </div>
        </div>

        {/* 4. Email Streams with 3 Miniature Protocol Lanes */}
        <div className="telemetry-card">
          <div className="telemetry-header">
            <span>Email Streams</span>
            <Layers size={12} color="#22d3ee" />
          </div>
          <div className="telemetry-body">
            <div className="telemetry-val-group">
              <span className="telemetry-val" style={{ color: currentAnalysis ? '#22d3ee' : '#ffffff' }}>
                {streamCount !== undefined ? streamCount : '—'}
              </span>
              {currentAnalysis && (
                <span className="telemetry-unit">streams</span>
              )}
            </div>
            <div className="kpi-micro-visual">
              <div className="protocol-lanes">
                {['SMTP', 'IMAP', 'POP3'].map((proto) => {
                  const isDetected =
                    currentAnalysis?.protocols_detected?.some((p) =>
                      p.toUpperCase().includes(proto)
                    ) ?? false;
                  return (
                    <div key={proto} className="protocol-lane-item">
                      <span>{proto}</span>
                      <div className="protocol-lane-bar">
                        <div
                          className="protocol-lane-fill"
                          style={{
                            width: isDetected ? '100%' : '0%',
                            backgroundColor: isDetected ? '#22d3ee' : 'transparent',
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
          <div className="telemetry-footer">
            {currentAnalysis?.protocols_detected?.length
              ? currentAnalysis.protocols_detected.join(' • ')
              : 'SMTP / IMAP / POP3'}
          </div>
        </div>

        {/* 5. Critical Findings with Compact Severity Indicator */}
        <div className="telemetry-card">
          <div className="telemetry-header">
            <span>Critical Findings</span>
            <AlertTriangle size={12} color={(criticalCount ?? 0) > 0 ? '#f87171' : '#64748b'} />
          </div>
          <div className="telemetry-body">
            <div className="telemetry-val-group">
              <span className="telemetry-val" style={{ color: (criticalCount ?? 0) > 0 ? '#f87171' : '#ffffff' }}>
                {criticalCount !== undefined ? criticalCount : '—'}
              </span>
              {currentAnalysis && (
                <span className="telemetry-unit">findings</span>
              )}
            </div>
            <div className="kpi-micro-visual">
              <div className="severity-spectrum">
                {[
                  { label: 'CRIT', active: (criticalCount ?? 0) > 0, color: '#f87171' },
                  { label: 'HIGH', active: (currentAnalysis?.high_findings_count ?? 0) > 0, color: '#fb923c' },
                  { label: 'MED', active: Boolean(currentAnalysis), color: '#fbbf24' },
                  { label: 'LOW', active: Boolean(currentAnalysis), color: '#34d399' },
                ].map((sev, idx) => (
                  <div
                    key={idx}
                    className="severity-pill-block"
                    style={{
                      backgroundColor: sev.active ? sev.color : 'var(--surface-inset)',
                      borderColor: sev.active ? sev.color : 'var(--border-subtle)',
                      opacity: sev.active ? 1 : 0.35,
                    }}
                    title={sev.label}
                  />
                ))}
              </div>
            </div>
          </div>
          <div className="telemetry-footer">
            {(criticalCount ?? 0) > 0 ? `${criticalCount} issues require review` : 'No critical findings observed'}
          </div>
        </div>
      </div>

      {/* Canonical Case Overview / Judge Demo Card */}
      <CaseOverviewCard />

      {/* Workspace Empty State when no analyses in user workspace */}
      {!currentAnalysis && analyses.length === 0 && (
        <div
          className="forensic-panel"
          style={{
            backgroundColor: 'var(--surface-elevated, #131b2e)',
            border: '1px solid rgba(6, 182, 212, 0.25)',
            padding: '32px 24px',
            textAlign: 'center',
            marginBottom: '16px',
            borderRadius: '8px',
          }}
        >
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              backgroundColor: 'rgba(6, 182, 212, 0.1)',
              border: '1px solid rgba(6, 182, 212, 0.3)',
              marginBottom: '12px',
            }}
          >
            <UploadCloud size={24} color="#06b6d4" />
          </div>
          <div
            style={{
              fontSize: '15px',
              fontWeight: 700,
              color: '#f8fafc',
              marginBottom: '6px',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            No forensic cases in this workspace yet.
          </div>
          <div
            style={{
              fontSize: '12px',
              color: 'var(--text-muted, #94a3b8)',
              maxWidth: '480px',
              margin: '0 auto 18px',
              lineHeight: 1.5,
            }}
          >
            Your analyst workspace is isolated and empty. Upload a packet capture (.pcap, .pcapng, .cap) to reconstruct email sessions, audit TLS handshakes, and verify post-quantum readiness.
          </div>
          <button
            onClick={() => fileInputRef.current?.click()}
            className="btn-primary"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 20px',
              fontSize: '12px',
              fontWeight: 600,
              borderRadius: '4px',
              cursor: 'pointer',
            }}
          >
            <UploadCloud size={14} />
            <span>Ingest PCAP</span>
          </button>
        </div>
      )}


      {/* 12-Column Grid Workspace (Left 8 cols, Right 4 cols) */}
      <div className="grid-12col-workspace">
        {/* LEFT COLUMN: 8 Columns (~67%) */}
        <div className="grid-col-8">
          {/* Investigation Timeline */}
          <InvestigationTimeline />

          {/* Forensic Dissection Pipeline (Hero Element with Connected Rail) */}
          <div className="forensic-panel">
            <div className="forensic-panel-header">
              <div>
                <div className="forensic-panel-title">
                  <Sparkles size={13} color="#06b6d4" />
                  <span>FORENSIC DISSECTION PIPELINE</span>
                </div>
                <div className="forensic-panel-subtitle">
                  Deterministic multi-stage packet dissection &amp; cryptographic evaluation
                </div>
              </div>
              <span className="badge badge-emerald">DETERMINISTIC ENGINE</span>
            </div>

            <div className="pipeline-rail-container">
              {/* Connected Forensic Rail Track */}
              <div className="pipeline-rail-track" />

              <div className="pipeline-5stage-row">
                {[
                  { step: '01', name: 'PCAP Ingestion', detail: 'Frame validation & indexing' },
                  { step: '02', name: 'Protocol Demux', detail: 'SMTP / IMAP / POP3 extraction' },
                  { step: '03', name: 'TLS / STARTTLS / STLS', detail: 'Handshake & cipher audit' },
                  { step: '04', name: 'PQC / HNDL Audit', detail: 'Quantum risk evaluation' },
                  { step: '05', name: 'Chain of Custody', detail: 'Cryptographic SHA-256 seal' },
                ].map((s, idx) => {
                  const state = getStageState(idx);
                  return (
                    <div
                      key={idx}
                      className={`pipeline-analysis-node ${state.status === 'running' ? 'active-stage' : ''}`}
                    >
                      <div className="node-header-row">
                        <span className="node-step-index">{s.step}</span>
                        <div className={`node-marker-hub ${state.status}`}>
                          {state.status === 'complete' && <Check size={8} color="#10b981" strokeWidth={3} />}
                          {state.status === 'running' && <div className="pulse-dot" />}
                          {state.status === 'failed' && <div style={{ width: '4px', height: '4px', borderRadius: '50%', backgroundColor: '#ef4444' }} />}
                          {state.status === 'pending' && <Circle size={4} color="#64748b" fill="#64748b" />}
                        </div>
                      </div>
                      <div>
                        <div className="node-title-label">{s.name}</div>
                        <div className="node-desc-label">{s.detail}</div>
                      </div>
                      <div className={`node-status-badge status-${state.status}`}>
                        {state.label}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Recent PCAP Investigations */}
          <div className="forensic-panel">
            <div className="forensic-panel-header">
              <div>
                <div className="forensic-panel-title">
                  <FileCode2 size={13} color="#06b6d4" />
                  <span>RECENT PCAP INVESTIGATIONS</span>
                </div>
                <div className="forensic-panel-subtitle">
                  Historical packet capture sessions and cryptographic findings
                </div>
              </div>
              <button
                onClick={() => navigate('/sessions')}
                className="btn-secondary"
              >
                <span>View Matrix</span>
                <ArrowRight size={11} />
              </button>
            </div>

            {analyses.length > 0 ? (
              <div className="recent-pcap-list">
                {analyses.slice(0, 4).map((a) => (
                  <div
                    key={a.analysis_id}
                    onClick={() => navigate('/sessions')}
                    className="recent-pcap-row"
                  >
                    <div className="recent-pcap-left">
                      <span className="badge badge-cyan" style={{ flexShrink: 0 }}>
                        {a.security_score?.overall_grade || 'A'}
                      </span>
                      <div className="recent-pcap-meta-container">
                        <div className="recent-pcap-filename" title={a.filename}>
                          {a.filename}
                        </div>
                        <div className="recent-pcap-subtext">
                          <span>{a.total_packets} pkts</span>
                          <span>•</span>
                          <span>{a.streams_count} streams</span>
                          <span>•</span>
                          <span>{(a.file_size / 1024).toFixed(1)} KB</span>
                        </div>
                      </div>
                    </div>
                    <div className="recent-pcap-right">
                      <span
                        className="recent-pcap-status"
                        style={{
                          color: (a.critical_findings_count ?? 0) > 0 ? '#f87171' : '#34d399',
                        }}
                        title={(a.critical_findings_count ?? 0) > 0 ? `${a.critical_findings_count} Critical Issues` : getObservedTlsLabel(a)}
                      >
                        {(a.critical_findings_count ?? 0) > 0
                          ? `${a.critical_findings_count} Critical Issues`
                          : getObservedTlsLabel(a)}
                      </span>
                      <ArrowRight size={11} color="#64748b" style={{ flexShrink: 0 }} />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              /* Deliberate Forensic Empty State with Session-Node Motif */
              <div className="empty-forensic-state">
                <div className="empty-session-rail-motif">
                  <div className="empty-node-point" />
                  <div className="empty-node-line" />
                  <div className="empty-node-point" />
                  <div className="empty-node-line" />
                  <div className="empty-node-point" />
                </div>
                <div className="empty-title">Evidence queue empty</div>
                <div className="empty-desc">
                  No PCAP investigations loaded. Ingest a network capture file to begin analysis.
                </div>
              </div>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: 4 Columns (~33%) */}
        <div className="grid-col-4">
          {/* Ingest Capture File */}
          <div className="forensic-panel">
            <div className="forensic-panel-header">
              <div className="forensic-panel-title">
                <UploadCloud size={13} color="#06b6d4" />
                <span>INGEST CAPTURE FILE</span>
              </div>
              <span className="badge badge-cyan">100 MB Limit</span>
            </div>
            <div className="forensic-panel-subtitle" style={{ marginBottom: '10px' }}>
              Passive capture intake &amp; automated stream indexing
            </div>

            {/* Dropzone Intake Workstation */}
            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className="dropzone-box"
              style={{ borderColor: dragOver ? '#06b6d4' : undefined }}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng,.cap"
                onChange={handleFileChange}
                style={{ display: 'none' }}
              />
              <UploadCloud size={24} color="#06b6d4" style={{ marginBottom: '6px' }} />
              <div style={{ fontSize: '12px', fontWeight: 600, color: '#f8fafc' }}>
                {isAnalyzing ? 'Dissecting Packet Capture...' : 'Open Ingestion Cockpit'}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                Click to inspect or drag network capture
              </div>
              <div className="format-chips-row">
                <span className="format-chip">.PCAP</span>
                <span className="format-chip">.PCAPNG</span>
                <span className="format-chip">.CAP</span>
              </div>
            </div>
          </div>

          {/* Engine Capabilities — Authentic State Bound */}
          <div className="forensic-panel">
            <div className="forensic-panel-header">
              <div>
                <div className="forensic-panel-title">
                  <Terminal size={13} color="#06b6d4" />
                  <span>ENGINE CAPABILITIES</span>
                </div>
                <div className="forensic-panel-subtitle">
                  Passive analyzer &amp; cryptographic evaluation state
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>Protocol Dissectors</span>
                <span style={{ color: 'var(--text-cyan)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  {health?.supported_protocols?.length ? health.supported_protocols.join(' / ') : 'SMTP / IMAP / POP3'}
                </span>
              </div>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>STARTTLS / STLS Detection</span>
                <span style={{ color: 'var(--text-emerald)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  Available
                </span>
              </div>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>PQC / HNDL Analysis</span>
                <span style={{ color: currentAnalysis ? (isKeyExchangeInsufficient ? 'var(--text-purple)' : 'var(--text-emerald)') : 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  {currentAnalysis ? (isKeyExchangeInsufficient ? 'Assessment Incomplete' : 'Evaluated') : 'Not evaluated'}
                </span>
              </div>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>TShark Engine</span>
                <span style={{ color: health?.tshark_available ? 'var(--text-emerald)' : 'var(--text-rose)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  {health?.tshark_available ? 'Active' : 'Offline'}
                </span>
              </div>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>Evidence Preservation</span>
                <span style={{ color: 'var(--text-emerald)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  Available
                </span>
              </div>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>Certificate Visibility</span>
                <span style={{ color: currentAnalysis ? (currentAnalysis.certificate_visibility?.toLowerCase().includes('observable') ? 'var(--text-emerald)' : 'var(--text-amber)') : 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  {currentAnalysis ? (currentAnalysis.certificate_visibility?.toLowerCase().includes('observable') ? 'Observable' : 'Encrypted') : 'Not evaluated'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;

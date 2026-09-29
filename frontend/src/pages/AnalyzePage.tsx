import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  CheckCircle2,
  AlertCircle,
  ArrowRight,
  Clock,
  FileCheck2,
  ShieldCheck,
  Terminal,
  X,
  Check,
  Activity,
  Loader2,
  Lock,
} from 'lucide-react';
import { useAnalysisStore } from '../store/useAnalysisStore';
import { useHealthStore } from '../store/useHealthStore';

const FORENSIC_PROCESSING_STAGES = [
  { label: 'Uploading packet capture...', code: 'INTAKE' },
  { label: 'Validating evidence integrity...', code: 'INTEGRITY' },
  { label: 'Reconstructing SMTP / IMAP / POP3 streams...', code: 'RECONSTRUCTION' },
  { label: 'Inspecting TLS / STARTTLS / STLS handshakes...', code: 'DISSECTION' },
  { label: 'Running cryptographic posture analysis...', code: 'POSTURE' },
  { label: 'Evaluating PQC / HNDL readiness...', code: 'PQC_ASSESS' },
  { label: 'Sealing chain-of-custody evidence...', code: 'CUSTODY' },
  { label: 'Finalizing forensic results...', code: 'FINALIZE' },
];

export const AnalyzePage: React.FC = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [stageIndex, setStageIndex] = useState(0);
  const [isSuccessComplete, setIsSuccessComplete] = useState(false);

  const { analyzeFile, isAnalyzing, error, analyses, clearError } = useAnalysisStore();
  const { isOnline, health } = useHealthStore();

  useEffect(() => {
    // Clear any stale errors on component mount
    clearError();
  }, [clearError]);

  // Rotate through processing stages while isAnalyzing is true
  useEffect(() => {
    let timer: any = null;
    if (isAnalyzing) {
      setStageIndex(0);
      setIsSuccessComplete(false);
      timer = setInterval(() => {
        setStageIndex((prev) => {
          if (prev < FORENSIC_PROCESSING_STAGES.length - 1) {
            return prev + 1;
          }
          return prev;
        });
      }, 1300);
    } else {
      setStageIndex(0);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isAnalyzing]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (isAnalyzing) return;
    clearError();
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (isAnalyzing) return;
    clearError();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleClearFile = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (isAnalyzing) return;
    setSelectedFile(null);
    clearError();
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleStartAnalysis = async () => {
    if (!selectedFile || isAnalyzing) return;
    try {
      await analyzeFile(selectedFile);
      setIsSuccessComplete(true);
      // Brief completion confirmation before smooth transition to dashboard
      setTimeout(() => {
        navigate('/dashboard');
      }, 700);
    } catch {
      setIsSuccessComplete(false);
      // Errors handled cleanly in store
    }
  };

  // Real validation states
  const fileExtension = selectedFile
    ? selectedFile.name.substring(selectedFile.name.lastIndexOf('.')).toLowerCase()
    : '';
  const isValidFormat = ['.pcap', '.pcapng', '.cap'].includes(fileExtension);
  const isSizeValid = selectedFile ? selectedFile.size <= 100 * 1024 * 1024 : false;
  const canStartAnalysis = Boolean(selectedFile && isValidFormat && isSizeValid && !isAnalyzing && isOnline);

  const getFormatName = (ext: string) => {
    switch (ext) {
      case '.pcapng': return 'PCAP Next Generation (pcapng)';
      case '.pcap': return 'Standard libpcap (pcap)';
      case '.cap': return 'Raw Packet Capture (cap)';
      default: return 'Unknown Format';
    }
  };

  const currentStage = FORENSIC_PROCESSING_STAGES[stageIndex];

  return (
    <div className="page-content">
      <style>{`
        @keyframes forensicRingRotate {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes forensicRingCounterRotate {
          0% { transform: rotate(360deg); }
          100% { transform: rotate(0deg); }
        }
        @keyframes forensicRadarPulse {
          0% { transform: scale(0.95); opacity: 0.75; box-shadow: 0 0 0 0 rgba(6, 182, 212, 0.4); }
          50% { transform: scale(1.05); opacity: 1; box-shadow: 0 0 24px 8px rgba(6, 182, 212, 0.25); }
          100% { transform: scale(0.95); opacity: 0.75; box-shadow: 0 0 0 0 rgba(6, 182, 212, 0.4); }
        }
        @keyframes dotPulse1 {
          0%, 80%, 100% { opacity: 0.25; transform: scale(0.75); }
          40% { opacity: 1; transform: scale(1.2); }
        }
        @keyframes dotPulse2 {
          0%, 20%, 100% { opacity: 0.25; transform: scale(0.75); }
          50% { opacity: 1; transform: scale(1.2); }
        }
        @keyframes dotPulse3 {
          0%, 40%, 100% { opacity: 0.25; transform: scale(0.75); }
          70% { opacity: 1; transform: scale(1.2); }
        }
      `}</style>

      {/* 1. Page Header Block */}
      <div className="dashboard-header-block">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <h1 className="dashboard-main-title">
              Ingest Network Packet Capture
            </h1>
            <p className="dashboard-main-subtitle">
              Upload raw .pcap, .pcapng, or .cap network captures for deterministic SMTP, IMAP, and POP3 cryptographic analysis.
            </p>
          </div>

          {/* Operational Status Chips */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className={`badge ${isOnline ? 'badge-emerald' : 'badge-rose'}`}>
              <span style={{ width: '5px', height: '5px', borderRadius: '50%', backgroundColor: isOnline ? '#10b981' : '#ef4444' }} />
              API {isOnline ? 'Connected' : 'Disconnected'}
            </span>
            <span className={`badge ${health?.tshark_available ? 'badge-emerald' : 'badge-rose'}`}>
              <ShieldCheck size={10} />
              TShark {health?.tshark_available ? 'Active' : 'Offline'}
            </span>
            <span className="badge badge-cyan">
              100 MB Limit
            </span>
          </div>
        </div>
      </div>

      {/* 2. Analysis Flow Strip (Workflow Guide) */}
      <div className="evidence-flow-strip">
        <div className={`evidence-flow-step ${isAnalyzing && stageIndex <= 1 ? 'active' : ''}`}>
          <span className="evidence-flow-num">01</span>
          <span style={{ fontWeight: isAnalyzing && stageIndex <= 1 ? 600 : 500, color: isAnalyzing && stageIndex <= 1 ? 'var(--text-cyan)' : '#f1f5f9' }}>Capture Intake</span>
        </div>
        <span className="evidence-flow-arrow">→</span>
        <div className={`evidence-flow-step ${isAnalyzing && stageIndex > 1 && stageIndex <= 3 ? 'active' : ''}`}>
          <span className="evidence-flow-num">02</span>
          <span style={{ fontWeight: isAnalyzing && stageIndex > 1 && stageIndex <= 3 ? 600 : 500, color: isAnalyzing && stageIndex > 1 && stageIndex <= 3 ? 'var(--text-cyan)' : undefined }}>Integrity &amp; Stream Demux</span>
        </div>
        <span className="evidence-flow-arrow">→</span>
        <div className={`evidence-flow-step ${isAnalyzing && stageIndex > 3 && stageIndex <= 5 ? 'active' : ''}`}>
          <span className="evidence-flow-num">03</span>
          <span style={{ fontWeight: isAnalyzing && stageIndex > 3 && stageIndex <= 5 ? 600 : 500, color: isAnalyzing && stageIndex > 3 && stageIndex <= 5 ? 'var(--text-cyan)' : undefined }}>Crypto &amp; PQC Analysis</span>
        </div>
        <span className="evidence-flow-arrow">→</span>
        <div className={`evidence-flow-step ${isAnalyzing && stageIndex > 5 ? 'active' : ''}`}>
          <span className="evidence-flow-num">04</span>
          <span style={{ fontWeight: isAnalyzing && stageIndex > 5 ? 600 : 500, color: isAnalyzing && stageIndex > 5 ? 'var(--text-cyan)' : undefined }}>Custody &amp; Results Sealing</span>
        </div>
      </div>

      {/* 3. Main Two-Column Layout (Left 65% / Right 35%) */}
      <div className="grid-12col-workspace">
        {/* LEFT COLUMN: Evidence Intake & Forensic Animation Station */}
        <div className="grid-col-8">
          <div className="forensic-panel">
            <div className="forensic-panel-header">
              <div>
                <div className="forensic-panel-title">
                  <UploadCloud size={13} color="#06b6d4" />
                  <span>EVIDENCE INTAKE WORKSTATION</span>
                </div>
                <div className="forensic-panel-subtitle">
                  Passive capture stream indexing &amp; raw frame demuxing
                </div>
              </div>
              <span className={`badge ${isAnalyzing ? 'badge-cyan' : isSuccessComplete ? 'badge-emerald' : 'badge-cyan'}`}>
                {isAnalyzing ? 'DISSECTING' : isSuccessComplete ? 'COMPLETED' : 'PASSIVE INGEST'}
              </span>
            </div>

            {/* Drop Zone with Animated Loading State */}
            <div
              onDragOver={(e) => { e.preventDefault(); if (!isAnalyzing) setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => { if (!isAnalyzing) fileInputRef.current?.click(); }}
              className="dropzone-box"
              style={{
                borderColor: isAnalyzing ? 'var(--accent-cyan-border)' : dragOver ? '#06b6d4' : undefined,
                background: isAnalyzing ? 'radial-gradient(ellipse at center, rgba(6, 182, 212, 0.08) 0%, rgba(15, 23, 42, 0.6) 80%)' : undefined,
                padding: '24px 16px',
                minHeight: '160px',
                cursor: isAnalyzing ? 'wait' : 'pointer',
                position: 'relative',
                overflow: 'hidden',
              }}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng,.cap"
                onChange={handleFileChange}
                disabled={isAnalyzing}
                style={{ display: 'none' }}
              />

              {isAnalyzing ? (
                /* Active Forensic Processing Animation */
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '14px',
                    padding: '8px 0',
                    width: '100%',
                  }}
                  aria-live="polite"
                  aria-busy="true"
                >
                  {/* Dual-Rotating Forensic Ring with Pulsing Radar Hub */}
                  <div
                    style={{
                      position: 'relative',
                      width: '84px',
                      height: '84px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    {/* Outer Rotating Ring */}
                    <div
                      style={{
                        position: 'absolute',
                        inset: 0,
                        borderRadius: '50%',
                        border: '2px dashed rgba(6, 182, 212, 0.65)',
                        borderTopColor: '#06b6d4',
                        borderRightColor: 'transparent',
                        animation: 'forensicRingRotate 3.2s linear infinite',
                      }}
                    />
                    {/* Inner Counter-Rotating Ring */}
                    <div
                      style={{
                        position: 'absolute',
                        inset: '8px',
                        borderRadius: '50%',
                        border: '2px solid rgba(6, 182, 212, 0.3)',
                        borderBottomColor: '#22d3ee',
                        borderLeftColor: 'transparent',
                        animation: 'forensicRingCounterRotate 2.1s linear infinite',
                      }}
                    />
                    {/* Pulsing Central Hub */}
                    <div
                      style={{
                        width: '42px',
                        height: '42px',
                        borderRadius: '50%',
                        background: 'rgba(6, 182, 212, 0.18)',
                        border: '1px solid var(--accent-cyan-border)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        animation: 'forensicRadarPulse 2s ease-in-out infinite',
                      }}
                    >
                      <Activity size={20} color="#22d3ee" />
                    </div>
                  </div>

                  {/* Stage Text & Pulsing Status */}
                  <div style={{ textAlign: 'center', maxWidth: '420px' }}>
                    <div
                      style={{
                        fontSize: '13px',
                        fontWeight: 600,
                        color: '#f8fafc',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '6px',
                        fontFamily: 'JetBrains Mono, monospace',
                      }}
                    >
                      <span>{currentStage.label}</span>
                      <span style={{ display: 'inline-flex', gap: '3px', marginLeft: '2px' }}>
                        <span style={{ width: '4px', height: '4px', borderRadius: '50%', background: '#06b6d4', animation: 'dotPulse1 1.4s infinite' }} />
                        <span style={{ width: '4px', height: '4px', borderRadius: '50%', background: '#06b6d4', animation: 'dotPulse2 1.4s infinite' }} />
                        <span style={{ width: '4px', height: '4px', borderRadius: '50%', background: '#06b6d4', animation: 'dotPulse3 1.4s infinite' }} />
                      </span>
                    </div>

                    <div
                      style={{
                        fontSize: '10px',
                        color: 'var(--text-cyan)',
                        fontFamily: 'JetBrains Mono, monospace',
                        marginTop: '4px',
                        letterSpacing: '0.04em',
                      }}
                    >
                      STAGE {String(stageIndex + 1).padStart(2, '0')} / 08 • {currentStage.code}
                    </div>

                    {/* Stage Step Indicator Dots */}
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'center',
                        alignItems: 'center',
                        gap: '6px',
                        marginTop: '10px',
                      }}
                    >
                      {FORENSIC_PROCESSING_STAGES.map((stg, idx) => (
                        <div
                          key={stg.code}
                          title={stg.label}
                          style={{
                            width: idx === stageIndex ? '16px' : '6px',
                            height: '5px',
                            borderRadius: '3px',
                            background:
                              idx === stageIndex
                                ? '#06b6d4'
                                : idx < stageIndex
                                ? 'rgba(6, 182, 212, 0.45)'
                                : 'rgba(148, 163, 184, 0.2)',
                            transition: 'all 0.3s ease',
                          }}
                        />
                      ))}
                    </div>

                    {selectedFile && (
                      <div
                        style={{
                          fontSize: '9.5px',
                          color: 'var(--text-muted)',
                          fontFamily: 'JetBrains Mono, monospace',
                          marginTop: '8px',
                        }}
                      >
                        Target: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
                      </div>
                    )}
                  </div>
                </div>
              ) : !selectedFile ? (
                <>
                  <UploadCloud size={28} color="#06b6d4" style={{ marginBottom: '6px' }} />
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc' }}>
                    Drop PCAP evidence here
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    or click to browse from workstation
                  </div>
                  <div className="format-chips-row" style={{ marginTop: '10px' }}>
                    <span className="format-chip">.PCAP</span>
                    <span className="format-chip">.PCAPNG</span>
                    <span className="format-chip">.CAP</span>
                    <span style={{ fontSize: '9px', color: 'var(--text-muted)', marginLeft: '4px' }}>
                      (Max 100 MB backend authoritative)
                    </span>
                  </div>
                </>
              ) : (
                <div className="selected-file-card" onClick={(e) => e.stopPropagation()}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: '32px', height: '32px', borderRadius: '4px', backgroundColor: 'var(--accent-cyan-bg)', border: '1px solid var(--accent-cyan-border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <FileCheck2 size={16} color="#06b6d4" />
                    </div>
                    <div>
                      <div style={{ fontSize: '12.5px', fontWeight: 600, color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>
                        {selectedFile.name}
                      </div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', display: 'flex', gap: '8px', fontFamily: 'JetBrains Mono, monospace', marginTop: '1px' }}>
                        <span>{(selectedFile.size / 1024).toFixed(1)} KB</span>
                        <span>•</span>
                        <span style={{ color: isValidFormat ? 'var(--text-emerald)' : 'var(--text-rose)' }}>
                          {getFormatName(fileExtension)}
                        </span>
                      </div>
                    </div>
                  </div>

                  <button
                    onClick={handleClearFile}
                    className="btn-secondary"
                    style={{ padding: '3px 8px', fontSize: '10px' }}
                    title="Remove selected file"
                  >
                    <X size={11} />
                    <span>Clear</span>
                  </button>
                </div>
              )}
            </div>

            {/* Pre-Analysis Checklist (Real States Only) */}
            <div className="checklist-container">
              <div className="checklist-title">Pre-Analysis Readiness Checklist</div>

              {/* 1. File Selected */}
              <div className="checklist-item">
                <div className="checklist-label">
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'var(--text-muted)' }}>01</span>
                  <span>Evidence File Intake</span>
                </div>
                {selectedFile ? (
                  <span style={{ fontSize: '10px', color: 'var(--text-emerald)', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <Check size={11} strokeWidth={2.5} />
                    <span>Ready</span>
                  </span>
                ) : (
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                    Pending file selection
                  </span>
                )}
              </div>

              {/* 2. Format Valid */}
              <div className="checklist-item">
                <div className="checklist-label">
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'var(--text-muted)' }}>02</span>
                  <span>Supported Capture Format</span>
                </div>
                {selectedFile ? (
                  isValidFormat ? (
                    <span style={{ fontSize: '10px', color: 'var(--text-emerald)', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Check size={11} strokeWidth={2.5} />
                      <span>{fileExtension.toUpperCase()} Valid</span>
                    </span>
                  ) : (
                    <span style={{ fontSize: '10px', color: 'var(--text-rose)', fontFamily: 'JetBrains Mono, monospace' }}>
                      Unsupported format
                    </span>
                  )
                ) : (
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                    .pcap, .pcapng, .cap
                  </span>
                )}
              </div>

              {/* 3. Size Valid */}
              <div className="checklist-item">
                <div className="checklist-label">
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'var(--text-muted)' }}>03</span>
                  <span>Payload Size Constraint</span>
                </div>
                {selectedFile ? (
                  isSizeValid ? (
                    <span style={{ fontSize: '10px', color: 'var(--text-emerald)', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Check size={11} strokeWidth={2.5} />
                      <span>Within 100 MB Limit</span>
                    </span>
                  ) : (
                    <span style={{ fontSize: '10px', color: 'var(--text-rose)', fontFamily: 'JetBrains Mono, monospace' }}>
                      Exceeds 100 MB limit
                    </span>
                  )
                ) : (
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                    &lt;= 100 MB backend limit
                  </span>
                )}
              </div>

              {/* 4. API Reachable */}
              <div className="checklist-item">
                <div className="checklist-label">
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'var(--text-muted)' }}>04</span>
                  <span>FastAPI Analysis Gateway</span>
                </div>
                <span style={{ fontSize: '10px', color: isOnline ? 'var(--text-emerald)' : 'var(--text-rose)', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  {isOnline ? <Check size={11} strokeWidth={2.5} /> : <X size={11} strokeWidth={2.5} />}
                  <span>{isOnline ? 'Online (/api/v1)' : 'Disconnected'}</span>
                </span>
              </div>

              {/* 5. TShark Engine Available */}
              <div className="checklist-item">
                <div className="checklist-label">
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'var(--text-muted)' }}>05</span>
                  <span>TShark Dissector Subsystem</span>
                </div>
                <span style={{ fontSize: '10px', color: health?.tshark_available ? 'var(--text-emerald)' : '#fbbf24', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  {health?.tshark_available ? <Check size={11} strokeWidth={2.5} /> : <AlertCircle size={11} strokeWidth={2.5} />}
                  <span>{health?.tshark_available ? 'Active' : 'Offline (Fallback Mode)'}</span>
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: Analysis Readiness Panel */}
        <div className="grid-col-4">
          <div className="forensic-panel">
            <div className="forensic-panel-header">
              <div>
                <div className="forensic-panel-title">
                  <Terminal size={13} color="#06b6d4" />
                  <span>ANALYSIS READINESS</span>
                </div>
                <div className="forensic-panel-subtitle">
                  Engine parameters &amp; execution trigger
                </div>
              </div>
              <span className={`badge ${isAnalyzing ? 'badge-cyan' : canStartAnalysis ? 'badge-emerald' : 'badge-gray'}`}>
                {isAnalyzing ? 'PROCESSING' : canStartAnalysis ? 'READY' : 'STANDBY'}
              </span>
            </div>

            {/* Specification Rows */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '14px' }}>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>API Gateway</span>
                <span style={{ color: isOnline ? 'var(--text-emerald)' : 'var(--text-rose)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  {isOnline ? 'Operational' : 'Offline'}
                </span>
              </div>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>TShark Subsystem</span>
                <span style={{ color: health?.tshark_available ? 'var(--text-emerald)' : 'var(--text-rose)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  {health?.tshark_available ? 'Active' : 'Offline'}
                </span>
              </div>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>Accepted Formats</span>
                <span style={{ color: 'var(--text-cyan)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  .pcap, .pcapng, .cap
                </span>
              </div>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>Supported Protocols</span>
                <span style={{ color: 'var(--text-cyan)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  SMTP / IMAP / POP3
                </span>
              </div>
              <div className="capability-row">
                <span style={{ color: 'var(--text-secondary)' }}>Evidence Verification</span>
                <span style={{ color: 'var(--text-emerald)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                  SHA-256 Sealed
                </span>
              </div>
            </div>

            {/* Upload Error Alert (Shown only for real failures) */}
            {error && (
              <div style={{ marginBottom: '12px', padding: '8px 10px', borderRadius: '4px', backgroundColor: 'var(--status-critical-bg)', border: '1px solid var(--status-critical-border)', color: 'var(--text-rose)', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'JetBrains Mono, monospace' }}>
                <AlertCircle size={13} style={{ flexShrink: 0 }} />
                <span>{error}</span>
              </div>
            )}

            {/* Start Forensic Analysis Button with Live Status States */}
            <button
              onClick={handleStartAnalysis}
              disabled={!canStartAnalysis || isAnalyzing}
              className="btn-primary"
              style={{
                width: '100%',
                padding: '9px 14px',
                justifyContent: 'center',
                opacity: canStartAnalysis && !isAnalyzing ? 1 : 0.65,
                cursor: canStartAnalysis && !isAnalyzing ? 'pointer' : 'not-allowed',
                background: isSuccessComplete
                  ? 'rgba(34, 197, 94, 0.2)'
                  : isAnalyzing
                  ? 'rgba(6, 182, 212, 0.2)'
                  : undefined,
                borderColor: isSuccessComplete
                  ? 'rgba(34, 197, 94, 0.5)'
                  : isAnalyzing
                  ? 'var(--accent-cyan-border)'
                  : undefined,
                color: isSuccessComplete ? 'var(--text-emerald)' : isAnalyzing ? 'var(--text-cyan)' : undefined,
                transition: 'all 0.2s ease',
              }}
            >
              {isSuccessComplete ? (
                <>
                  <CheckCircle2 size={14} color="#10b981" />
                  <span>Analysis Complete</span>
                </>
              ) : isAnalyzing ? (
                <>
                  <Loader2 size={14} className="animate-spin" style={{ animation: 'forensicRingRotate 1.2s linear infinite' }} />
                  <span>Analyzing Capture...</span>
                </>
              ) : (
                <>
                  <span>Start Forensic Analysis</span>
                  <ArrowRight size={13} />
                </>
              )}
            </button>
            <div style={{ fontSize: '9.5px', color: 'var(--text-muted)', textAlign: 'center', marginTop: '6px' }}>
              {isAnalyzing
                ? 'Passive dissection in progress — please wait'
                : isSuccessComplete
                ? 'Navigating to Forensic Dashboard...'
                : !selectedFile
                ? 'Select a PCAP capture file to enable analysis'
                : !isValidFormat
                ? 'Selected file must be .pcap, .pcapng, or .cap'
                : !isSizeValid
                ? 'Selected file exceeds the 100 MB limit'
                : 'Click to execute passive multi-stage dissection'}
            </div>
          </div>
        </div>
      </div>

      {/* 4. Previous Capture Analyses */}
      <div className="forensic-panel" style={{ marginTop: '2px' }}>
        <div className="forensic-panel-header">
          <div>
            <div className="forensic-panel-title">
              <Clock size={13} color="#06b6d4" />
              <span>PREVIOUS CAPTURE ANALYSES</span>
            </div>
            <div className="forensic-panel-subtitle">
              Locally analyzed capture sessions and cryptographic reports
            </div>
          </div>
          <span className="badge badge-gray">{analyses.length} Records</span>
        </div>

        {analyses.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {analyses.map((a) => (
              <div
                key={a.analysis_id}
                onClick={() => { if (!isAnalyzing) navigate('/dashboard'); }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 12px',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--surface-elevated)',
                  border: '1px solid var(--border-subtle)',
                  cursor: isAnalyzing ? 'not-allowed' : 'pointer',
                  opacity: isAnalyzing ? 0.7 : 1,
                  transition: 'border-color 0.14s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="badge badge-cyan">
                    {a.security_score?.overall_grade || 'A'}
                  </span>
                  <div>
                    <div style={{ fontSize: '11.5px', fontWeight: 600, color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>
                      {a.filename}
                    </div>
                    <div style={{ fontSize: '9.5px', color: 'var(--text-muted)', display: 'flex', gap: '8px', fontFamily: 'JetBrains Mono, monospace' }}>
                      <span>ID: {a.analysis_id}</span>
                      <span>•</span>
                      <span>{a.streams_count} streams</span>
                      <span>•</span>
                      <span>{a.total_packets} pkts</span>
                      <span>•</span>
                      <span>{(a.file_size / 1024).toFixed(1)} KB</span>
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div style={{ display: 'flex', gap: '4px' }}>
                    {a.protocols_detected.map((p) => (
                      <span key={p} className="badge badge-gray" style={{ fontSize: '8px' }}>
                        {p}
                      </span>
                    ))}
                  </div>
                  <span style={{ fontSize: '9.5px', fontFamily: 'JetBrains Mono, monospace', color: a.critical_findings_count > 0 ? 'var(--text-rose)' : 'var(--text-emerald)' }}>
                    {a.critical_findings_count > 0 ? `${a.critical_findings_count} Critical` : 'Secure'}
                  </span>
                  <ArrowRight size={11} color="#64748b" />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-forensic-state">
            <div className="empty-session-rail-motif">
              <div className="empty-node-point" />
              <div className="empty-node-line" />
              <div className="empty-node-point" />
              <div className="empty-node-line" />
              <div className="empty-node-point" />
            </div>
            <div className="empty-title">No previous analyses available.</div>
            <div className="empty-desc">
              Ingest a network packet capture above to initiate cryptographic forensics.
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AnalyzePage;

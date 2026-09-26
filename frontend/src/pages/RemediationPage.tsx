import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Terminal,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  FileCode,
  Copy,
  Check,
  AlertTriangle,
  ArrowRight,
  Layers,
  FileCheck,
  RefreshCw,
  Plus,
  ShieldCheck,
  Sliders,
  ChevronRight,
  Sparkles,
} from 'lucide-react';

interface RemediationGuidanceItem {
  item_id: string;
  finding_code: string;
  platform: string;
  category: string;
  priority: string;
  title: string;
  description: string;
  configuration_snippet: string;
  assumptions: string[];
  security_effect: string;
  validation_steps: string[];
  rollback_snippet: string;
  limitations: string[];
}

interface RemediationPlanItem {
  item_id: string;
  plan_id: string;
  finding_code: string;
  platform: string;
  priority: string;
  title: string;
  configuration_snippet: string;
  status: string;
  created_at: string;
}

interface RemediationPlan {
  plan_id: string;
  title: string;
  case_id?: string;
  target_id?: string;
  platform: string;
  status: string;
  created_by: string;
  created_at: string;
  applied_at?: string;
  applied_by?: string;
  deployment_notes?: string;
  verified_at?: string;
  verified_by?: string;
  verification_status?: string;
  items: RemediationPlanItem[];
}

interface SimulateFixResponse {
  simulation_id: string;
  platform: string;
  baseline_findings: string[];
  resolved_findings: string[];
  remaining_findings: string[];
  projected_posture: Record<string, any>;
  side_by_side_comparison: {
    baseline: Record<string, any>;
    projected: Record<string, any>;
  };
  simulated_at: string;
  disclaimer: string;
}

interface VerificationRecord {
  verification_id: string;
  plan_id: string;
  verification_status: string;
  verification_method: string;
  evidence_reference?: string;
  verified_by: string;
  verified_at: string;
  prior_finding_codes: string[];
  new_finding_codes: string[];
  resolved_finding_codes: string[];
  unresolved_finding_codes: string[];
  details: string;
}

export const RemediationPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'playbooks' | 'simulate' | 'plans' | 'verifications'>('playbooks');
  const [loading, setLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);

  // Playbook generator state
  const [selectedPlatform, setSelectedPlatform] = useState('POSTFIX');
  const [targetHostname, setTargetHostname] = useState('');
  const [selectedFindingCodes, setSelectedFindingCodes] = useState<string[]>([
    'FINDING_CLEAR_TEXT_AUTH',
    'FINDING_LEGACY_TLS_10',
  ]);
  const [playbooks, setPlaybooks] = useState<RemediationGuidanceItem[]>([]);

  // Simulation state
  const [simBaselineFindings, setSimBaselineFindings] = useState<string[]>([
    'FINDING_CLEAR_TEXT_AUTH',
    'FINDING_LEGACY_TLS_10',
    'FINDING_NULL_CIPHER',
  ]);
  const [simFixCodes, setSimFixCodes] = useState<string[]>([
    'FINDING_CLEAR_TEXT_AUTH',
    'FINDING_LEGACY_TLS_10',
  ]);
  const [simResult, setSimResult] = useState<SimulateFixResponse | null>(null);

  // Plans state
  const [plans, setPlans] = useState<RemediationPlan[]>([]);
  const [selectedPlan, setSelectedPlan] = useState<RemediationPlan | null>(null);
  const [newPlanTitle, setNewPlanTitle] = useState('');
  const [newPlanCaseId, setNewPlanCaseId] = useState('');
  const [showCreatePlanModal, setShowCreatePlanModal] = useState(false);

  // Verification modal state
  const [showApplyModal, setShowApplyModal] = useState(false);
  const [applyNotes, setApplyNotes] = useState('');
  const [showVerifyModal, setShowVerifyModal] = useState(false);
  const [verifyEvidenceRef, setVerifyEvidenceRef] = useState('');
  const [verifyNewFindings, setVerifyNewFindings] = useState<string[]>([]);
  const [verifyMethod, setVerifyMethod] = useState('ACTIVE_SCAN');
  const [planVerifications, setPlanVerifications] = useState<VerificationRecord[]>([]);

  const availableFindings = [
    { code: 'FINDING_CLEAR_TEXT_AUTH', name: 'Cleartext Authentication Detected (High)' },
    { code: 'FINDING_LEGACY_TLS_10', name: 'Obsolete TLS 1.0 / 1.1 In Use (High)' },
    { code: 'FINDING_NULL_CIPHER', name: 'Insecure Null / Anonymous Cipher (Critical)' },
    { code: 'FINDING_WEAK_DH_PARAMS', name: 'Weak Diffie-Hellman Parameter (<2048-bit) (Medium)' },
    { code: 'FINDING_EXPIRED_CERT', name: 'Expired X.509 Certificate (High)' },
    { code: 'FINDING_SELF_SIGNED_CERT', name: 'Untrusted Self-Signed Certificate (Medium)' },
    { code: 'FINDING_NO_STARTTLS', name: 'STARTTLS Negotiation Missing / Disabled (High)' },
  ];

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(id);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleGeneratePlaybooks = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/remediation/playbooks/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          platform: selectedPlatform,
          target_hostname: targetHostname || undefined,
          finding_codes: selectedFindingCodes,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setPlaybooks(data.guidance_items || []);
      }
    } catch (e) {
      console.error('Failed to generate playbooks', e);
    } finally {
      setLoading(false);
    }
  };

  const handleRunSimulation = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/remediation/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          platform: selectedPlatform,
          baseline_findings: simBaselineFindings,
          applied_remediation_codes: simFixCodes,
          baseline_posture: {
            tls_version: 'TLS 1.0',
            cipher_suite: 'RC4-MD5',
            pfs_status: 'DISABLED',
            pqc_status: 'CLASSICAL',
            security_mode: 'STARTTLS',
            reachable: true,
          },
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setSimResult(data);
      }
    } catch (e) {
      console.error('Simulation failed', e);
    } finally {
      setLoading(false);
    }
  };

  const fetchPlans = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/remediation/plans');
      if (res.ok) {
        const data = await res.json();
        setPlans(data || []);
      }
    } catch (e) {
      console.error('Failed to fetch plans', e);
    } finally {
      setLoading(false);
    }
  };

  const handleCreatePlanFromPlaybooks = async () => {
    if (!playbooks.length) return;
    setLoading(true);
    try {
      const items = playbooks.map((p) => ({
        finding_code: p.finding_code,
        platform: p.platform,
        priority: p.priority,
        title: p.title,
        configuration_snippet: p.configuration_snippet,
        assumptions: p.assumptions,
        security_effect: p.security_effect,
        validation_steps: p.validation_steps,
        rollback_snippet: p.rollback_snippet,
        limitations: p.limitations,
      }));

      const res = await fetch('/api/v1/remediation/plans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newPlanTitle || `${selectedPlatform} Security Hardening Plan`,
          case_id: newPlanCaseId || undefined,
          platform: selectedPlatform,
          items,
        }),
      });
      if (res.ok) {
        setShowCreatePlanModal(false);
        setNewPlanTitle('');
        setNewPlanCaseId('');
        setActiveTab('plans');
        fetchPlans();
      }
    } catch (e) {
      console.error('Failed to create plan', e);
    } finally {
      setLoading(false);
    }
  };

  const handleMarkApplied = async () => {
    if (!selectedPlan) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/remediation/plans/${selectedPlan.plan_id}/apply`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deployment_notes: applyNotes || 'Applied configuration snippet per change request.',
        }),
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedPlan(updated);
        setShowApplyModal(false);
        setApplyNotes('');
        fetchPlans();
      }
    } catch (e) {
      console.error('Failed to apply plan', e);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyPlan = async () => {
    if (!selectedPlan) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/remediation/plans/${selectedPlan.plan_id}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          verification_method: verifyMethod,
          evidence_reference: verifyEvidenceRef || 'scan-rec-001',
          new_finding_codes: verifyNewFindings,
          details: 'Forensic verification scan completed.',
        }),
      });
      if (res.ok) {
        const record = await res.json();
        setShowVerifyModal(false);
        fetchPlans();
        // Refresh selected plan
        const planRes = await fetch(`/api/v1/remediation/plans/${selectedPlan.plan_id}`);
        if (planRes.ok) {
          setSelectedPlan(await planRes.json());
        }
        fetchVerifications(selectedPlan.plan_id);
      }
    } catch (e) {
      console.error('Failed to verify plan', e);
    } finally {
      setLoading(false);
    }
  };

  const fetchVerifications = async (planId: string) => {
    try {
      const res = await fetch(`/api/v1/remediation/plans/${planId}/verifications`);
      if (res.ok) {
        const data = await res.json();
        setPlanVerifications(data || []);
      }
    } catch (e) {
      console.error('Failed to fetch verifications', e);
    }
  };

  useEffect(() => {
    if (activeTab === 'plans') {
      fetchPlans();
    }
  }, [activeTab]);

  return (
    <div style={{ padding: '24px', maxWidth: '1400px', margin: '0 auto', color: 'var(--text-main)' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <ShieldAlert size={20} color="var(--text-cyan)" />
            <h1 style={{ margin: 0, fontSize: '20px', fontWeight: 600 }}>Evidence-Based Remediation & Simulate-Fix</h1>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'JetBrains Mono, monospace',
                padding: '2px 6px',
                borderRadius: '3px',
                background: 'var(--accent-cyan-bg)',
                color: 'var(--text-cyan)',
                border: '1px solid var(--accent-cyan-border)',
              }}
            >
              PHASE 23 ADVISORY
            </span>
          </div>
          <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-muted)' }}>
            Deterministic platform hardening playbooks, offline simulate-fix modeling, and verified evidence-based remediation tracking.
          </p>
        </div>
      </div>

      {/* Safety Notice Banner */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '10px 14px',
          borderRadius: '6px',
          background: 'rgba(56, 189, 248, 0.05)',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          marginBottom: '20px',
          fontSize: '12px',
        }}
      >
        <Terminal size={16} color="var(--text-cyan)" style={{ flexShrink: 0 }} />
        <span>
          <strong>Strictly Advisory Engine:</strong> Zero commands, scripts, SSH sessions, or configuration files are executed or modified on live servers. All remediation plans require human review and forensic re-verification against newly collected evidence.
        </span>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-subtle)', marginBottom: '20px' }}>
        {[
          { id: 'playbooks', label: 'Playbook Generator', icon: <FileCode size={14} /> },
          { id: 'simulate', label: 'Simulate-Fix Engine', icon: <Sliders size={14} /> },
          { id: 'plans', label: 'Case Remediation Plans', icon: <Layers size={14} /> },
          { id: 'verifications', label: 'Verification Audit Logs', icon: <FileCheck size={14} /> },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid var(--text-cyan)' : '2px solid transparent',
              color: activeTab === tab.id ? 'var(--text-cyan)' : 'var(--text-muted)',
              fontSize: '13px',
              fontWeight: 500,
              cursor: 'pointer',
            }}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* TAB 1: Playbook Generator */}
      {activeTab === 'playbooks' && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
            {/* Left controls */}
            <div
              style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '16px',
              }}
            >
              <h3 style={{ margin: '0 0 14px 0', fontSize: '14px', fontWeight: 600 }}>Playbook Parameters</h3>

              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Target Platform / MTA
                </label>
                <select
                  value={selectedPlatform}
                  onChange={(e) => setSelectedPlatform(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '6px 8px',
                    borderRadius: '4px',
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-main)',
                    fontSize: '12px',
                  }}
                >
                  <option value="POSTFIX">Postfix Mail Transfer Agent</option>
                  <option value="EXIM">Exim Internet Mailer</option>
                  <option value="DOVECOT">Dovecot Secure IMAP/POP3 Server</option>
                  <option value="SENDMAIL">Sendmail MTA</option>
                  <option value="GENERIC">Generic Mail Appliance</option>
                </select>
              </div>

              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Target Hostname (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. mail.corp.example.com"
                  value={targetHostname}
                  onChange={(e) => setTargetHostname(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '6px 8px',
                    borderRadius: '4px',
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-main)',
                    fontSize: '12px',
                  }}
                />
              </div>

              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Select Observed Findings
                </label>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {availableFindings.map((f) => (
                    <label
                      key={f.code}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        fontSize: '11px',
                        cursor: 'pointer',
                        padding: '4px 6px',
                        borderRadius: '4px',
                        background: selectedFindingCodes.includes(f.code)
                          ? 'rgba(56, 189, 248, 0.08)'
                          : 'transparent',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={selectedFindingCodes.includes(f.code)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedFindingCodes([...selectedFindingCodes, f.code]);
                          } else {
                            setSelectedFindingCodes(selectedFindingCodes.filter((c) => c !== f.code));
                          }
                        }}
                      />
                      <span>{f.name}</span>
                    </label>
                  ))}
                </div>
              </div>

              <button
                onClick={handleGeneratePlaybooks}
                disabled={loading || selectedFindingCodes.length === 0}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '6px',
                  padding: '8px 12px',
                  borderRadius: '4px',
                  background: 'var(--accent-cyan-bg)',
                  border: '1px solid var(--accent-cyan-border)',
                  color: 'var(--text-cyan)',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: loading ? 'not-allowed' : 'pointer',
                }}
              >
                <Sparkles size={14} />
                <span>{loading ? 'Generating...' : 'Generate Playbooks'}</span>
              </button>

              {playbooks.length > 0 && (
                <button
                  onClick={() => setShowCreatePlanModal(true)}
                  style={{
                    width: '100%',
                    marginTop: '8px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '6px',
                    padding: '8px 12px',
                    borderRadius: '4px',
                    background: 'var(--accent-pqc-bg)',
                    border: '1px solid var(--accent-pqc-border)',
                    color: 'var(--text-purple)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  <Plus size={14} />
                  <span>Create Case Remediation Plan</span>
                </button>
              )}
            </div>

            {/* Right: Playbook Items */}
            <div>
              {playbooks.length === 0 ? (
                <div
                  style={{
                    padding: '40px',
                    textAlign: 'center',
                    background: 'var(--bg-card)',
                    border: '1px dashed var(--border-subtle)',
                    borderRadius: '8px',
                    color: 'var(--text-muted)',
                  }}
                >
                  <FileCode size={32} style={{ marginBottom: '10px', opacity: 0.5 }} />
                  <p style={{ margin: 0, fontSize: '13px' }}>
                    Select findings and click "Generate Playbooks" to view deterministic hardening guidance.
                  </p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  {playbooks.map((p) => (
                    <div
                      key={p.item_id}
                      style={{
                        background: 'var(--bg-card)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: '8px',
                        padding: '16px',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'flex-start',
                          marginBottom: '10px',
                        }}
                      >
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                            <span
                              style={{
                                fontSize: '10px',
                                fontFamily: 'JetBrains Mono, monospace',
                                padding: '1px 5px',
                                borderRadius: '3px',
                                background:
                                  p.priority === 'CRITICAL'
                                    ? 'rgba(239, 68, 68, 0.1)'
                                    : p.priority === 'HIGH'
                                    ? 'rgba(249, 115, 22, 0.1)'
                                    : 'rgba(56, 189, 248, 0.1)',
                                color:
                                  p.priority === 'CRITICAL'
                                    ? 'var(--text-red)'
                                    : p.priority === 'HIGH'
                                    ? 'var(--text-orange)'
                                    : 'var(--text-cyan)',
                                border: '1px solid var(--border-subtle)',
                              }}
                            >
                              {p.priority}
                            </span>
                            <span
                              style={{
                                fontSize: '10px',
                                fontFamily: 'JetBrains Mono, monospace',
                                color: 'var(--text-muted)',
                              }}
                            >
                              {p.platform} / {p.finding_code}
                            </span>
                          </div>
                          <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>{p.title}</h4>
                        </div>
                      </div>

                      <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '0 0 10px 0' }}>
                        {p.description}
                      </p>

                      {/* Config Snippet */}
                      <div style={{ marginBottom: '12px' }}>
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            fontSize: '11px',
                            color: 'var(--text-muted)',
                            marginBottom: '4px',
                          }}
                        >
                          <span>Recommended Configuration Snippet</span>
                          <button
                            onClick={() => handleCopy(p.configuration_snippet, p.item_id)}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px',
                              background: 'transparent',
                              border: 'none',
                              color: 'var(--text-cyan)',
                              fontSize: '11px',
                              cursor: 'pointer',
                            }}
                          >
                            {copiedIndex === p.item_id ? <Check size={12} /> : <Copy size={12} />}
                            <span>{copiedIndex === p.item_id ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                        <pre
                          style={{
                            margin: 0,
                            padding: '10px',
                            borderRadius: '4px',
                            background: 'var(--bg-surface)',
                            border: '1px solid var(--border-subtle)',
                            fontFamily: 'JetBrains Mono, monospace',
                            fontSize: '11px',
                            overflowX: 'auto',
                            color: '#a5f3fc',
                          }}
                        >
                          {p.configuration_snippet}
                        </pre>
                      </div>

                      {/* Security Effect & Validation */}
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '11px' }}>
                        <div
                          style={{
                            padding: '8px',
                            borderRadius: '4px',
                            background: 'rgba(34, 197, 94, 0.05)',
                            border: '1px solid rgba(34, 197, 94, 0.2)',
                          }}
                        >
                          <strong style={{ color: 'var(--text-green)' }}>Security Effect:</strong>
                          <p style={{ margin: '4px 0 0 0', color: 'var(--text-muted)' }}>{p.security_effect}</p>
                        </div>
                        <div
                          style={{
                            padding: '8px',
                            borderRadius: '4px',
                            background: 'var(--bg-surface)',
                            border: '1px solid var(--border-subtle)',
                          }}
                        >
                          <strong>Validation Steps:</strong>
                          <ul style={{ margin: '4px 0 0 16px', padding: 0, color: 'var(--text-muted)' }}>
                            {p.validation_steps.map((s, idx) => (
                              <li key={idx}>{s}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Simulate-Fix Engine */}
      {activeTab === 'simulate' && (
        <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: '20px' }}>
          {/* Left: Input controls */}
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '16px',
            }}
          >
            <h3 style={{ margin: '0 0 14px 0', fontSize: '14px', fontWeight: 600 }}>Simulate-Fix Parameters</h3>

            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Baseline Finding Codes
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {availableFindings.map((f) => (
                  <label key={f.code} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                    <input
                      type="checkbox"
                      checked={simBaselineFindings.includes(f.code)}
                      onChange={(e) => {
                        if (e.target.checked) setSimBaselineFindings([...simBaselineFindings, f.code]);
                        else setSimBaselineFindings(simBaselineFindings.filter((c) => c !== f.code));
                      }}
                    />
                    <span>{f.name}</span>
                  </label>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Applied Remediation Fixes
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {simBaselineFindings.map((code) => (
                  <label key={code} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                    <input
                      type="checkbox"
                      checked={simFixCodes.includes(code)}
                      onChange={(e) => {
                        if (e.target.checked) setSimFixCodes([...simFixCodes, code]);
                        else setSimFixCodes(simFixCodes.filter((c) => c !== code));
                      }}
                    />
                    <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{code}</span>
                  </label>
                ))}
              </div>
            </div>

            <button
              onClick={handleRunSimulation}
              disabled={loading}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
                padding: '8px 12px',
                borderRadius: '4px',
                background: 'var(--accent-cyan-bg)',
                border: '1px solid var(--accent-cyan-border)',
                color: 'var(--text-cyan)',
                fontSize: '12px',
                fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
              }}
            >
              <Play size={14} />
              <span>{loading ? 'Simulating...' : 'Run Simulation'}</span>
            </button>
          </div>

          {/* Right: Simulation Results */}
          <div>
            {!simResult ? (
              <div
                style={{
                  padding: '40px',
                  textAlign: 'center',
                  background: 'var(--bg-card)',
                  border: '1px dashed var(--border-subtle)',
                  borderRadius: '8px',
                  color: 'var(--text-muted)',
                }}
              >
                <Sliders size={32} style={{ marginBottom: '10px', opacity: 0.5 }} />
                <p style={{ margin: 0, fontSize: '13px' }}>
                  Run simulation to calculate projected posture outcomes side-by-side with baseline evidence.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {/* Status Callout */}
                <div
                  style={{
                    padding: '12px',
                    borderRadius: '6px',
                    background: 'rgba(168, 85, 247, 0.05)',
                    border: '1px solid rgba(168, 85, 247, 0.2)',
                    fontSize: '12px',
                    color: 'var(--text-purple)',
                  }}
                >
                  <strong>{simResult.disclaimer}</strong>
                </div>

                {/* Side-by-Side Comparison */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                  {/* Baseline (Observed) */}
                  <div
                    style={{
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '8px',
                      padding: '16px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                      <AlertTriangle size={16} color="var(--text-orange)" />
                      <h4 style={{ margin: 0, fontSize: '13px', fontWeight: 600 }}>Observed Baseline Posture</h4>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>TLS Version: </span>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                          {simResult.side_by_side_comparison.baseline.tls_version || 'N/A'}
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Cipher Suite: </span>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                          {simResult.side_by_side_comparison.baseline.cipher_suite || 'N/A'}
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Active Findings ({simResult.baseline_findings.length}):</span>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '4px' }}>
                          {simResult.baseline_findings.map((f) => (
                            <span
                              key={f}
                              style={{
                                fontSize: '10px',
                                fontFamily: 'JetBrains Mono, monospace',
                                color: 'var(--text-red)',
                              }}
                            >
                              • {f}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Projected (After Fix) */}
                  <div
                    style={{
                      background: 'var(--bg-card)',
                      border: '1px solid rgba(34, 197, 94, 0.3)',
                      borderRadius: '8px',
                      padding: '16px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                      <ShieldCheck size={16} color="var(--text-green)" />
                      <h4 style={{ margin: 0, fontSize: '13px', fontWeight: 600 }}>Projected After-Fix Posture</h4>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>TLS Version: </span>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-green)' }}>
                          {simResult.side_by_side_comparison.projected.tls_version} (ASSUMED)
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Cipher Suite: </span>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-green)' }}>
                          {simResult.side_by_side_comparison.projected.cipher_suite} (ASSUMED)
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>
                          Resolved Findings ({simResult.resolved_findings.length}):
                        </span>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '4px' }}>
                          {simResult.resolved_findings.map((f) => (
                            <span
                              key={f}
                              style={{
                                fontSize: '10px',
                                fontFamily: 'JetBrains Mono, monospace',
                                color: 'var(--text-green)',
                              }}
                            >
                              ✓ {f}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: Remediation Plans */}
      {activeTab === 'plans' && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
            {/* Plans List */}
            <div
              style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '16px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>Persisted Plans</h3>
                <button
                  onClick={fetchPlans}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                  }}
                >
                  <RefreshCw size={13} />
                </button>
              </div>

              {plans.length === 0 ? (
                <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>No remediation plans recorded.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {plans.map((p) => (
                    <div
                      key={p.plan_id}
                      onClick={() => {
                        setSelectedPlan(p);
                        fetchVerifications(p.plan_id);
                      }}
                      style={{
                        padding: '10px',
                        borderRadius: '6px',
                        border: selectedPlan?.plan_id === p.plan_id ? '1px solid var(--text-cyan)' : '1px solid var(--border-subtle)',
                        background: selectedPlan?.plan_id === p.plan_id ? 'rgba(56, 189, 248, 0.05)' : 'var(--bg-surface)',
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span style={{ fontSize: '12px', fontWeight: 600 }}>{p.title}</span>
                        <span
                          style={{
                            fontSize: '9px',
                            fontFamily: 'JetBrains Mono, monospace',
                            padding: '1px 4px',
                            borderRadius: '2px',
                            background:
                              p.status === 'VERIFIED'
                                ? 'rgba(34, 197, 94, 0.1)'
                                : p.status === 'USER_REPORTED_APPLIED'
                                ? 'rgba(234, 179, 8, 0.1)'
                                : 'rgba(56, 189, 248, 0.1)',
                            color:
                              p.status === 'VERIFIED'
                                ? 'var(--text-green)'
                                : p.status === 'USER_REPORTED_APPLIED'
                                ? 'var(--text-yellow)'
                                : 'var(--text-cyan)',
                          }}
                        >
                          {p.status}
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        {p.platform} • {p.items?.length || 0} items • By {p.created_by}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Plan Details & Actions */}
            <div>
              {!selectedPlan ? (
                <div
                  style={{
                    padding: '40px',
                    textAlign: 'center',
                    background: 'var(--bg-card)',
                    border: '1px dashed var(--border-subtle)',
                    borderRadius: '8px',
                    color: 'var(--text-muted)',
                  }}
                >
                  <Layers size={32} style={{ marginBottom: '10px', opacity: 0.5 }} />
                  <p style={{ margin: 0, fontSize: '13px' }}>Select a plan to view details, mark applied, or verify.</p>
                </div>
              ) : (
                <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '20px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                    <div>
                      <h3 style={{ margin: '0 0 4px 0', fontSize: '16px', fontWeight: 600 }}>{selectedPlan.title}</h3>
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        Plan ID: <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{selectedPlan.plan_id}</span> • Platform: {selectedPlan.platform}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      {selectedPlan.status === 'PROPOSED' && (
                        <button
                          onClick={() => setShowApplyModal(true)}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                            padding: '6px 12px',
                            borderRadius: '4px',
                            background: 'var(--accent-yellow-bg, rgba(234, 179, 8, 0.1))',
                            border: '1px solid var(--accent-yellow-border, rgba(234, 179, 8, 0.3))',
                            color: 'var(--text-yellow, #facc15)',
                            fontSize: '12px',
                            cursor: 'pointer',
                          }}
                        >
                          <CheckCircle2 size={13} />
                          <span>Mark Applied</span>
                        </button>
                      )}
                      {(selectedPlan.status === 'USER_REPORTED_APPLIED' || selectedPlan.status === 'AWAITING_VERIFICATION') && (
                        <button
                          onClick={() => setShowVerifyModal(true)}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                            padding: '6px 12px',
                            borderRadius: '4px',
                            background: 'var(--accent-green-bg, rgba(34, 197, 94, 0.1))',
                            border: '1px solid var(--accent-green-border, rgba(34, 197, 94, 0.3))',
                            color: 'var(--text-green)',
                            fontSize: '12px',
                            cursor: 'pointer',
                          }}
                        >
                          <ShieldCheck size={13} />
                          <span>Verify After Fix</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Plan Items */}
                  <h4 style={{ margin: '0 0 10px 0', fontSize: '13px', fontWeight: 600 }}>Action Items ({selectedPlan.items?.length || 0})</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {selectedPlan.items?.map((item) => (
                      <div
                        key={item.item_id}
                        style={{
                          padding: '12px',
                          borderRadius: '6px',
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border-subtle)',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                          <span style={{ fontSize: '12px', fontWeight: 600 }}>{item.title}</span>
                          <span style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-cyan)' }}>
                            {item.finding_code}
                          </span>
                        </div>
                        <pre
                          style={{
                            margin: 0,
                            padding: '8px',
                            borderRadius: '4px',
                            background: 'var(--bg-main)',
                            fontFamily: 'JetBrains Mono, monospace',
                            fontSize: '10px',
                            overflowX: 'auto',
                            color: '#a5f3fc',
                          }}
                        >
                          {item.configuration_snippet}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: Verification Audit Logs */}
      {activeTab === 'verifications' && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
            <FileCheck size={18} color="var(--text-cyan)" />
            <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 600 }}>Forensic Verification Audit Trail</h3>
          </div>

          <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '0 0 16px 0' }}>
            Permanent non-repudiable audit logs confirming whether remediation plans passed or failed forensic re-verification against fresh evidence.
          </p>

          {planVerifications.length === 0 ? (
            <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
              Select a plan from the "Case Remediation Plans" tab to view its verification audit records.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {planVerifications.map((v) => (
                <div
                  key={v.verification_id}
                  style={{
                    padding: '12px',
                    borderRadius: '6px',
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '12px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {v.verification_status === 'VERIFIED' ? (
                        <CheckCircle2 size={14} color="var(--text-green)" />
                      ) : (
                        <XCircle size={14} color="var(--text-red)" />
                      )}
                      <strong style={{ color: v.verification_status === 'VERIFIED' ? 'var(--text-green)' : 'var(--text-red)' }}>
                        {v.verification_status}
                      </strong>
                      <span style={{ color: 'var(--text-muted)' }}>via {v.verification_method}</span>
                    </div>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{v.verified_at} by {v.verified_by}</span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{v.details}</div>
                  <div style={{ display: 'flex', gap: '16px', marginTop: '6px', fontSize: '11px' }}>
                    <span>Resolved: <strong style={{ color: 'var(--text-green)' }}>{v.resolved_finding_codes?.length || 0}</strong></span>
                    <span>Unresolved: <strong style={{ color: 'var(--text-red)' }}>{v.unresolved_finding_codes?.length || 0}</strong></span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Modal: Create Plan */}
      {showCreatePlanModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
        >
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '24px',
              width: '440px',
            }}
          >
            <h3 style={{ margin: '0 0 14px 0', fontSize: '15px', fontWeight: 600 }}>Create Case Remediation Plan</h3>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Plan Title
              </label>
              <input
                type="text"
                value={newPlanTitle}
                onChange={(e) => setNewPlanTitle(e.target.value)}
                placeholder="e.g. Mail Server Security Hardening Plan"
                style={{
                  width: '100%',
                  padding: '6px 8px',
                  borderRadius: '4px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-main)',
                  fontSize: '12px',
                }}
              />
            </div>
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Case ID (Optional)
              </label>
              <input
                type="text"
                value={newPlanCaseId}
                onChange={(e) => setNewPlanCaseId(e.target.value)}
                placeholder="e.g. CASE-2026-001"
                style={{
                  width: '100%',
                  padding: '6px 8px',
                  borderRadius: '4px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-main)',
                  fontSize: '12px',
                }}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                onClick={() => setShowCreatePlanModal(false)}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  background: 'transparent',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-muted)',
                  fontSize: '12px',
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleCreatePlanFromPlaybooks}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  background: 'var(--accent-cyan-bg)',
                  border: '1px solid var(--accent-cyan-border)',
                  color: 'var(--text-cyan)',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Save Plan
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Mark Applied */}
      {showApplyModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
        >
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '24px',
              width: '440px',
            }}
          >
            <h3 style={{ margin: '0 0 14px 0', fontSize: '15px', fontWeight: 600 }}>Mark Plan as User-Reported Applied</h3>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '0 0 12px 0' }}>
              Confirm that configuration changes were manually applied on the target mail server. This moves the plan to <strong>AWAITING_VERIFICATION</strong>.
            </p>
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Deployment Notes
              </label>
              <textarea
                value={applyNotes}
                onChange={(e) => setApplyNotes(e.target.value)}
                placeholder="e.g. Applied via change ticket CHG-8921 on production MTA."
                rows={3}
                style={{
                  width: '100%',
                  padding: '6px 8px',
                  borderRadius: '4px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-main)',
                  fontSize: '12px',
                }}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                onClick={() => setShowApplyModal(false)}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  background: 'transparent',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-muted)',
                  fontSize: '12px',
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleMarkApplied}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  background: 'var(--accent-yellow-bg, rgba(234, 179, 8, 0.1))',
                  border: '1px solid var(--accent-yellow-border, rgba(234, 179, 8, 0.3))',
                  color: 'var(--text-yellow, #facc15)',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Confirm Applied
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Verify Plan */}
      {showVerifyModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
        >
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '24px',
              width: '460px',
            }}
          >
            <h3 style={{ margin: '0 0 14px 0', fontSize: '15px', fontWeight: 600 }}>Verify Remediation Against Forensic Evidence</h3>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '0 0 12px 0' }}>
              Compare prior findings against newly observed scan or packet evidence.
            </p>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Verification Evidence Reference (Scan ID / PCAP ID)
              </label>
              <input
                type="text"
                value={verifyEvidenceRef}
                onChange={(e) => setVerifyEvidenceRef(e.target.value)}
                placeholder="e.g. scan-target-mail01-20260926"
                style={{
                  width: '100%',
                  padding: '6px 8px',
                  borderRadius: '4px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-main)',
                  fontSize: '12px',
                }}
              />
            </div>
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Newly Observed Findings in Verification Scan (leave empty if all resolved)
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {availableFindings.map((f) => (
                  <label key={f.code} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                    <input
                      type="checkbox"
                      checked={verifyNewFindings.includes(f.code)}
                      onChange={(e) => {
                        if (e.target.checked) setVerifyNewFindings([...verifyNewFindings, f.code]);
                        else setVerifyNewFindings(verifyNewFindings.filter((c) => c !== f.code));
                      }}
                    />
                    <span>{f.name}</span>
                  </label>
                ))}
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                onClick={() => setShowVerifyModal(false)}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  background: 'transparent',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-muted)',
                  fontSize: '12px',
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleVerifyPlan}
                style={{
                  padding: '6px 12px',
                  borderRadius: '4px',
                  background: 'var(--accent-green-bg, rgba(34, 197, 94, 0.1))',
                  border: '1px solid var(--accent-green-border, rgba(34, 197, 94, 0.3))',
                  color: 'var(--text-green)',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Complete Verification
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RemediationPage;

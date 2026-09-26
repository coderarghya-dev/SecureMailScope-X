import React, { useState, useEffect } from 'react';
import {
  Cpu,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Layers,
  ArrowRight,
  Sparkles,
  Key,
  Lock,
  RefreshCw,
  Plus,
  FileCheck,
  Search,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  ShieldCheck,
  Info
} from 'lucide-react';

interface CryptoAsset {
  asset_id: string;
  analysis_id?: string;
  case_id?: string;
  target_id?: string;
  protocol: string;
  endpoint: string;
  crypto_layer: string;
  algorithm_family: string;
  algorithm_name: string;
  key_size?: number;
  pqc_status: string;
  hybrid_status: boolean;
  evidence_reference: string;
  observed_at: string;
}

interface GapFinding {
  gap_id: string;
  roadmap_id?: string;
  asset_id?: string;
  gap_type: string;
  severity: string;
  description: string;
  evidence_reference: string;
  remediation_action: string;
  created_at: string;
}

interface MigrationStep {
  step_id: string;
  roadmap_id: string;
  phase_name: string;
  sequence_order: number;
  objective: string;
  recommended_actions: string[];
  validation_criteria: string[];
  rollback_considerations: string[];
  blocking_issues: string[];
  status: string;
  created_at: string;
}

interface MigrationRoadmap {
  roadmap_id: string;
  case_id?: string;
  target_id?: string;
  analysis_id?: string;
  title: string;
  description: string;
  current_readiness: string;
  target_profile: string;
  exposure_level: string;
  status: string;
  version: number;
  steps: MigrationStep[];
  gaps: GapFinding[];
  approved_by?: string;
  approved_at?: string;
  approval_signature?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export const PQCMigrationPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'inventory' | 'gaps' | 'roadmaps'>('roadmaps');
  const [roadmaps, setRoadmaps] = useState<MigrationRoadmap[]>([]);
  const [selectedRoadmap, setSelectedRoadmap] = useState<MigrationRoadmap | null>(null);
  const [assets, setAssets] = useState<CryptoAsset[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // New Roadmap Form State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [targetArch, setTargetArch] = useState('HYBRID_KEM_TARGET');

  // Sign-off Modal State
  const [showApproveModal, setShowApproveModal] = useState(false);
  const [reviewerId, setReviewerId] = useState('analyst-02');
  const [sigHex, setSigHex] = useState('');
  const [pubKeyHex, setPubKeyHex] = useState('');
  const [sigAlg, setSigAlg] = useState('Ed25519');

  const fetchRoadmaps = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/pqc/roadmaps');
      if (res.ok) {
        const data = await res.json();
        setRoadmaps(data.roadmaps || []);
        if (data.roadmaps?.length > 0 && !selectedRoadmap) {
          setSelectedRoadmap(data.roadmaps[0]);
        }
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchInventory = async () => {
    try {
      const res = await fetch('/api/v1/pqc/inventory');
      if (res.ok) {
        const data = await res.json();
        setAssets(data.assets || []);
      }
    } catch (e: any) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchRoadmaps();
    fetchInventory();
  }, []);

  const handleCreateRoadmap = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle) return;

    try {
      const res = await fetch('/api/v1/pqc/roadmaps', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newTitle,
          description: newDesc,
          target_architecture: targetArch,
        }),
      });
      if (res.ok) {
        const created = await res.json();
        setShowCreateModal(false);
        setNewTitle('');
        setNewDesc('');
        fetchRoadmaps();
        setSelectedRoadmap(created);
      }
    } catch (e: any) {
      alert('Error creating roadmap: ' + e.message);
    }
  };

  const handleApprove = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedRoadmap || !sigHex || !pubKeyHex) return;

    try {
      const res = await fetch(`/api/v1/pqc/roadmaps/${selectedRoadmap.roadmap_id}/approve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Actor-ID': reviewerId,
        },
        body: JSON.stringify({
          roadmap_id: selectedRoadmap.roadmap_id,
          reviewer_analyst_id: reviewerId,
          signature_algorithm: sigAlg,
          signature_hex: sigHex,
          public_key_hex: pubKeyHex,
        }),
      });
      if (res.ok) {
        const updated = await res.json();
        setShowApproveModal(false);
        setSelectedRoadmap(updated);
        fetchRoadmaps();
      } else {
        const errData = await res.json();
        alert('Approval failed: ' + (errData.detail || 'Signature invalid'));
      }
    } catch (e: any) {
      alert('Error approving roadmap: ' + e.message);
    }
  };

  const getExposureBadge = (level: string) => {
    switch (level) {
      case 'LOW':
        return <span style={{ color: '#10b981', background: '#064e3b33', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>LOW EXPOSURE</span>;
      case 'MODERATE':
        return <span style={{ color: '#f59e0b', background: '#78350f33', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>MODERATE</span>;
      case 'HIGH':
        return <span style={{ color: '#f97316', background: '#7c2d1233', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>HIGH (HNDL RISK)</span>;
      case 'CRITICAL':
        return <span style={{ color: '#ef4444', background: '#7f1d1d33', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>CRITICAL</span>;
      default:
        return <span style={{ color: '#94a3b8', background: '#33415533', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>UNKNOWN</span>;
    }
  };

  return (
    <div style={{ padding: '20px', maxWidth: '1400px', margin: '0 auto', color: '#e2e8f0' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h1 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 4px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Cpu size={22} style={{ color: 'var(--text-purple, #c084fc)' }} />
            Post-Quantum Cryptography Migration Planner
          </h1>
          <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8' }}>
            Evidence-backed cryptographic asset cataloging, Harvest-Now-Decrypt-Later (HNDL) quantum exposure modeling, and 7-phase hybrid transition roadmaps.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={() => { fetchRoadmaps(); fetchInventory(); }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 12px',
              background: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '6px',
              color: '#cbd5e1',
              cursor: 'pointer',
              fontSize: '12px',
            }}
          >
            <RefreshCw size={13} /> Refresh
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 14px',
              background: '#9333ea',
              border: 'none',
              borderRadius: '6px',
              color: '#fff',
              cursor: 'pointer',
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            <Plus size={14} /> New Migration Roadmap
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '4px', borderBottom: '1px solid #334155', marginBottom: '20px' }}>
        <button
          onClick={() => setActiveTab('roadmaps')}
          style={{
            padding: '8px 16px',
            background: activeTab === 'roadmaps' ? '#1e293b' : 'transparent',
            border: 'none',
            borderBottom: activeTab === 'roadmaps' ? '2px solid #a855f7' : '2px solid transparent',
            color: activeTab === 'roadmaps' ? '#f1f5f9' : '#94a3b8',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: 600,
          }}
        >
          7-Phase Migration Roadmaps
        </button>
        <button
          onClick={() => setActiveTab('inventory')}
          style={{
            padding: '8px 16px',
            background: activeTab === 'inventory' ? '#1e293b' : 'transparent',
            border: 'none',
            borderBottom: activeTab === 'inventory' ? '2px solid #a855f7' : '2px solid transparent',
            color: activeTab === 'inventory' ? '#f1f5f9' : '#94a3b8',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: 600,
          }}
        >
          Cryptographic Asset Inventory ({assets.length})
        </button>
        <button
          onClick={() => setActiveTab('gaps')}
          style={{
            padding: '8px 16px',
            background: activeTab === 'gaps' ? '#1e293b' : 'transparent',
            border: 'none',
            borderBottom: activeTab === 'gaps' ? '2px solid #a855f7' : '2px solid transparent',
            color: activeTab === 'gaps' ? '#f1f5f9' : '#94a3b8',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: 600,
          }}
        >
          Gap Analysis Matrix
        </button>
      </div>

      {/* Tab 1: Roadmaps View */}
      {activeTab === 'roadmaps' && (
        <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
          {/* Roadmap List Sidebar */}
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '12px' }}>
            <h3 style={{ fontSize: '13px', fontWeight: 600, color: '#94a3b8', margin: '0 0 10px 0', textTransform: 'uppercase' }}>
              Transition Plans ({roadmaps.length})
            </h3>
            {roadmaps.length === 0 ? (
              <div style={{ fontSize: '12px', color: '#64748b', textAlign: 'center', padding: '20px' }}>
                No migration roadmaps created yet.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {roadmaps.map((rm) => (
                  <div
                    key={rm.roadmap_id}
                    onClick={() => setSelectedRoadmap(rm)}
                    style={{
                      padding: '10px',
                      borderRadius: '6px',
                      background: selectedRoadmap?.roadmap_id === rm.roadmap_id ? '#1e293b' : '#090d16',
                      border: `1px solid ${selectedRoadmap?.roadmap_id === rm.roadmap_id ? '#a855f7' : '#1e293b'}`,
                      cursor: 'pointer',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: '#f1f5f9' }}>{rm.title}</span>
                      <span style={{ fontSize: '10px', fontFamily: 'monospace', color: rm.status === 'APPROVED' ? '#10b981' : '#f59e0b' }}>
                        {rm.status}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: '#64748b' }}>
                      <span>Target: {rm.target_profile}</span>
                      {getExposureBadge(rm.exposure_level)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Roadmap Detail View */}
          {selectedRoadmap ? (
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '20px' }}>
              {/* Header Box */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid #1e293b', paddingBottom: '16px', marginBottom: '20px' }}>
                <div>
                  <h2 style={{ fontSize: '18px', fontWeight: 700, margin: '0 0 6px 0', color: '#f8fafc' }}>
                    {selectedRoadmap.title}
                  </h2>
                  <p style={{ margin: '0 0 8px 0', fontSize: '13px', color: '#94a3b8' }}>
                    {selectedRoadmap.description || 'Target hybrid transition roadmap per NIST PQC FIPS 203/204 recommendations.'}
                  </p>
                  <div style={{ display: 'flex', gap: '10px', alignItems: 'center', fontSize: '12px' }}>
                    <span style={{ color: '#64748b' }}>Current Readiness: <strong style={{ color: '#38bdf8' }}>{selectedRoadmap.current_readiness}</strong></span>
                    <span style={{ color: '#64748b' }}>•</span>
                    <span style={{ color: '#64748b' }}>Target Profile: <strong style={{ color: '#c084fc' }}>{selectedRoadmap.target_profile}</strong></span>
                    <span style={{ color: '#64748b' }}>•</span>
                    {getExposureBadge(selectedRoadmap.exposure_level)}
                  </div>
                </div>

                <div>
                  {selectedRoadmap.status === 'APPROVED' ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: '#064e3b33', border: '1px solid #065f46', padding: '6px 12px', borderRadius: '6px', color: '#10b981', fontSize: '12px' }}>
                      <CheckCircle2 size={14} /> Cryptographically Approved by {selectedRoadmap.approved_by}
                    </div>
                  ) : (
                    <button
                      onClick={() => setShowApproveModal(true)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        padding: '6px 14px',
                        background: '#10b981',
                        border: 'none',
                        borderRadius: '6px',
                        color: '#fff',
                        cursor: 'pointer',
                        fontSize: '12px',
                        fontWeight: 600,
                      }}
                    >
                      <Key size={14} /> Peer Sign-Off & Approve
                    </button>
                  )}
                </div>
              </div>

              {/* 7-Phase Steps List */}
              <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#94a3b8', marginBottom: '14px', textTransform: 'uppercase' }}>
                7-Phase Hybrid Transition Roadmap Steps
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {selectedRoadmap.steps.map((step) => (
                  <div
                    key={step.step_id}
                    style={{
                      background: '#090d16',
                      border: '1px solid #1e293b',
                      borderRadius: '6px',
                      padding: '14px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ background: '#3b82f6', color: '#fff', padding: '2px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 700 }}>
                          PHASE {step.sequence_order}
                        </span>
                        <span style={{ fontSize: '13px', fontWeight: 600, color: '#f1f5f9' }}>
                          {step.objective}
                        </span>
                        {step.phase_name === 'PHASE_F_PQC_PRIMARY_TRANSITION' && (
                          <span style={{ background: '#7c3aed33', color: '#c084fc', border: '1px solid #7c3aed', padding: '1px 5px', borderRadius: '3px', fontSize: '9px', fontWeight: 600 }}>
                            TARGET / ADVISORY
                          </span>
                        )}
                      </div>
                      <span style={{ fontSize: '11px', fontFamily: 'monospace', color: '#94a3b8' }}>
                        {step.status}
                      </span>
                    </div>

                    <div style={{ fontSize: '12px', color: '#cbd5e1', marginBottom: '8px' }}>
                      <strong>Recommended Actions:</strong>
                      <ul style={{ margin: '4px 0 0 16px', padding: 0 }}>
                        {step.recommended_actions.map((act, i) => (
                          <li key={i} style={{ marginBottom: '2px' }}>{act}</li>
                        ))}
                      </ul>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '11px', color: '#94a3b8', background: '#0f172a', padding: '8px', borderRadius: '4px' }}>
                      <div>
                        <strong style={{ color: '#38bdf8' }}>Validation Criteria:</strong>
                        <ul style={{ margin: '2px 0 0 12px', padding: 0 }}>
                          {step.validation_criteria.map((vc, i) => (
                            <li key={i}>{vc}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <strong style={{ color: '#f59e0b' }}>Rollback Guidance:</strong>
                        <ul style={{ margin: '2px 0 0 12px', padding: 0 }}>
                          {step.rollback_considerations.map((rc, i) => (
                            <li key={i}>{rc}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '40px', textAlign: 'center', color: '#64748b' }}>
              Select a migration roadmap to inspect details and 7-phase transition steps.
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Inventory View */}
      {activeTab === 'inventory' && (
        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px' }}>
          <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#94a3b8', marginBottom: '12px', textTransform: 'uppercase' }}>
            Observed Cryptographic Assets ({assets.length})
          </h3>
          {assets.length === 0 ? (
            <div style={{ padding: '30px', textAlign: 'center', color: '#64748b', fontSize: '13px' }}>
              No cryptographic assets extracted yet. Ingest an email PCAP capture or execute an active posture scan to catalogue endpoints.
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                    <th style={{ padding: '8px' }}>Endpoint</th>
                    <th style={{ padding: '8px' }}>Layer</th>
                    <th style={{ padding: '8px' }}>Algorithm</th>
                    <th style={{ padding: '8px' }}>PQC Classification</th>
                    <th style={{ padding: '8px' }}>Hybrid Status</th>
                    <th style={{ padding: '8px' }}>Evidence Reference</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((a) => (
                    <tr key={a.asset_id} style={{ borderBottom: '1px solid #1e293b' }}>
                      <td style={{ padding: '8px', fontFamily: 'monospace' }}>{a.endpoint}</td>
                      <td style={{ padding: '8px' }}><span style={{ background: '#1e293b', padding: '2px 6px', borderRadius: '4px' }}>{a.crypto_layer}</span></td>
                      <td style={{ padding: '8px', fontWeight: 600, color: '#f8fafc' }}>{a.algorithm_name}</td>
                      <td style={{ padding: '8px' }}>
                        <span style={{
                          color: a.pqc_status === 'HYBRID_READY' || a.pqc_status === 'PQC_READY' ? '#10b981' : '#f59e0b',
                          background: a.pqc_status === 'HYBRID_READY' || a.pqc_status === 'PQC_READY' ? '#064e3b33' : '#78350f33',
                          padding: '2px 6px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: 600,
                        }}>
                          {a.pqc_status}
                        </span>
                      </td>
                      <td style={{ padding: '8px' }}>{a.hybrid_status ? 'Dual ML-KEM' : 'Classical Only'}</td>
                      <td style={{ padding: '8px', fontFamily: 'monospace', color: '#64748b' }}>{a.evidence_reference}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Gap Analysis View */}
      {activeTab === 'gaps' && selectedRoadmap && (
        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '20px' }}>
          <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#94a3b8', marginBottom: '12px', textTransform: 'uppercase' }}>
            Detected Cryptographic Transition Gaps ({selectedRoadmap.gaps.length})
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {selectedRoadmap.gaps.map((gap) => (
              <div key={gap.gap_id} style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '6px', padding: '14px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc' }}>{gap.gap_type}</span>
                  <span style={{
                    color: gap.severity === 'HIGH' || gap.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b',
                    background: gap.severity === 'HIGH' || gap.severity === 'CRITICAL' ? '#7f1d1d33' : '#78350f33',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontWeight: 600,
                  }}>
                    {gap.severity}
                  </span>
                </div>
                <p style={{ margin: '0 0 6px 0', fontSize: '12px', color: '#cbd5e1' }}>{gap.description}</p>
                <div style={{ fontSize: '11px', color: '#38bdf8' }}>
                  <strong>Remediation:</strong> {gap.remediation_action}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '8px', padding: '20px', width: '480px', maxWidth: '90%' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 700, margin: '0 0 14px 0', color: '#f8fafc' }}>
              Create PQC Migration Roadmap
            </h3>
            <form onSubmit={handleCreateRoadmap}>
              <div style={{ marginBottom: '12px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>Roadmap Title</label>
                <input
                  type="text"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Enterprise Mail Gateway PQC Transition Plan"
                  style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#fff', fontSize: '13px' }}
                  required
                />
              </div>
              <div style={{ marginBottom: '12px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>Description</label>
                <textarea
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Target migration objectives and transition scope..."
                  style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#fff', fontSize: '13px', height: '60px' }}
                />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>Target Architecture</label>
                <select
                  value={targetArch}
                  onChange={(e) => setTargetArch(e.target.value)}
                  style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#fff', fontSize: '13px' }}
                >
                  <option value="HYBRID_KEM_TARGET">HYBRID_KEM_TARGET (Dual Classical + ML-KEM KEX)</option>
                  <option value="HYBRID_SIGNATURE_TARGET">HYBRID_SIGNATURE_TARGET (Dual ML-DSA / Falcon)</option>
                  <option value="PQC_CERTIFICATE_TARGET">PQC_CERTIFICATE_TARGET (Composite X.509)</option>
                  <option value="PQC_CAPABLE_MAIL_GATEWAY">PQC_CAPABLE_MAIL_GATEWAY (Full Gateway Hybrid)</option>
                  <option value="PQC_AWARE_TLS_TERMINATOR">PQC_AWARE_TLS_TERMINATOR (Edge Reverse Proxy)</option>
                </select>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  style={{ padding: '6px 12px', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#cbd5e1', cursor: 'pointer', fontSize: '12px' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ padding: '6px 14px', background: '#9333ea', border: 'none', borderRadius: '4px', color: '#fff', cursor: 'pointer', fontSize: '12px', fontWeight: 600 }}
                >
                  Generate Roadmap
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Approval Modal */}
      {showApproveModal && selectedRoadmap && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '8px', padding: '20px', width: '520px', maxWidth: '90%' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 700, margin: '0 0 14px 0', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Key size={18} style={{ color: '#10b981' }} />
              Cryptographic Peer Sign-Off
            </h3>
            <form onSubmit={handleApprove}>
              <div style={{ marginBottom: '10px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>Reviewer Analyst ID</label>
                <input
                  type="text"
                  value={reviewerId}
                  onChange={(e) => setReviewerId(e.target.value)}
                  style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#fff', fontSize: '12px' }}
                  required
                />
              </div>
              <div style={{ marginBottom: '10px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>Public Key Hex</label>
                <input
                  type="text"
                  value={pubKeyHex}
                  onChange={(e) => setPubKeyHex(e.target.value)}
                  placeholder="32-byte Ed25519 hex or SubjectPublicKeyInfo PEM"
                  style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#fff', fontSize: '12px', fontFamily: 'monospace' }}
                  required
                />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>Digital Signature Hex</label>
                <input
                  type="text"
                  value={sigHex}
                  onChange={(e) => setSigHex(e.target.value)}
                  placeholder="64-byte Ed25519 signature hex"
                  style={{ width: '100%', padding: '8px', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#fff', fontSize: '12px', fontFamily: 'monospace' }}
                  required
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => setShowApproveModal(false)}
                  style={{ padding: '6px 12px', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#cbd5e1', cursor: 'pointer', fontSize: '12px' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ padding: '6px 14px', background: '#10b981', border: 'none', borderRadius: '4px', color: '#fff', cursor: 'pointer', fontSize: '12px', fontWeight: 600 }}
                >
                  Sign & Approve
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default PQCMigrationPage;

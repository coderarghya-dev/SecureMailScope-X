import React, { useState, useEffect } from 'react';
import {
  Activity,
  Shield,
  Clock,
  RefreshCw,
  Plus,
  Play,
  Bookmark,
  AlertTriangle,
  CheckCircle,
  Hash,
  Server,
  Lock,
  ArrowRight,
  TrendingDown,
  TrendingUp,
  MinusCircle
} from 'lucide-react';

interface MonitoredTarget {
  target_id: string;
  display_name: string;
  hostname: string;
  port: number;
  protocol: string;
  security_mode: string;
  enabled: boolean;
  schedule_type: string;
  schedule_value?: string;
  baseline_snapshot_id?: string;
  baseline_pinned_by?: string;
  baseline_pinned_at?: string;
  last_scanned_at?: string;
  next_scan_due_at?: string;
  created_at: string;
}

interface PostureSnapshot {
  snapshot_id: string;
  target_id: string;
  scanned_at: string;
  reachable: boolean;
  protocol: string;
  security_mode: string;
  starttls_supported?: boolean;
  starttls_accepted?: boolean;
  tls_version?: string;
  cipher_suite?: string;
  certificate_fingerprint?: string;
  certificate_subject?: string;
  certificate_issuer?: string;
  certificate_valid?: boolean;
  pfs_status?: string;
  pqc_status?: string;
  scan_result_sha256: string;
  canonical_snapshot_sha256: string;
}

interface PostureDriftEvent {
  event_id: string;
  target_id: string;
  prior_snapshot_id?: string;
  current_snapshot_id: string;
  drift_type: string;
  classification: 'IMPROVEMENT' | 'REGRESSION' | 'NEUTRAL' | 'UNKNOWN';
  old_value?: string;
  new_value?: string;
  details: string;
  detected_at: string;
  compared_against_baseline: boolean;
}

interface SummaryData {
  total_targets: number;
  enabled_targets: number;
  total_snapshots: number;
  total_drift_events: number;
  regressions_count: number;
  improvements_count: number;
  neutral_count: number;
  last_scan_timestamp?: string;
}

export const PostureMonitoringPage: React.FC = () => {
  const [targets, setTargets] = useState<MonitoredTarget[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<PostureSnapshot[]>([]);
  const [driftEvents, setDriftEvents] = useState<PostureDriftEvent[]>([]);
  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [scanningTargetId, setScanningTargetId] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'targets' | 'snapshots' | 'drift'>('targets');

  // Form State
  const [formData, setFormData] = useState({
    display_name: '',
    hostname: '',
    port: 587,
    protocol: 'SMTP',
    security_mode: 'PLAIN_WITH_STARTTLS',
    schedule_type: 'MANUAL',
    enabled: true,
  });

  const fetchData = async () => {
    setLoading(true);
    try {
      const [targetsRes, summaryRes, driftRes] = await Promise.all([
        fetch('/api/v1/monitoring/targets'),
        fetch('/api/v1/monitoring/summary'),
        fetch('/api/v1/monitoring/drift?limit=50'),
      ]);

      if (targetsRes.ok) {
        const data = await targetsRes.json();
        setTargets(data);
        if (data.length > 0 && !selectedTargetId) {
          setSelectedTargetId(data[0].target_id);
        }
      }
      if (summaryRes.ok) {
        setSummary(await summaryRes.json());
      }
      if (driftRes.ok) {
        setDriftEvents(await driftRes.json());
      }
    } catch (e) {
      console.error('Failed to load monitoring data:', e);
    } finally {
      setLoading(false);
    }
  };

  const fetchSnapshots = async (targetId: string) => {
    try {
      const res = await fetch(`/api/v1/monitoring/targets/${targetId}/snapshots?limit=25`);
      if (res.ok) {
        setSnapshots(await res.json());
      }
    } catch (e) {
      console.error('Failed to load snapshots:', e);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    if (selectedTargetId) {
      fetchSnapshots(selectedTargetId);
    }
  }, [selectedTargetId]);

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/v1/monitoring/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      if (res.ok) {
        setShowAddModal(false);
        setFormData({
          display_name: '',
          hostname: '',
          port: 587,
          protocol: 'SMTP',
          security_mode: 'PLAIN_WITH_STARTTLS',
          schedule_type: 'MANUAL',
          enabled: true,
        });
        fetchData();
      }
    } catch (err) {
      console.error('Target creation failed:', err);
    }
  };

  const handleScanTarget = async (targetId: string) => {
    setScanningTargetId(targetId);
    try {
      const res = await fetch(`/api/v1/monitoring/targets/${targetId}/scan?allow_local_testing=true`, {
        method: 'POST',
      });
      if (res.ok) {
        await fetchData();
        if (selectedTargetId === targetId) {
          await fetchSnapshots(targetId);
        }
      }
    } catch (err) {
      console.error('Scan execution error:', err);
    } finally {
      setScanningTargetId(null);
    }
  };

  const handlePinBaseline = async (targetId: string, snapshotId: string) => {
    try {
      const res = await fetch(`/api/v1/monitoring/targets/${targetId}/baseline/${snapshotId}`, {
        method: 'POST',
      });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error('Baseline pin failed:', err);
    }
  };

  const handleRunDueScans = async () => {
    setLoading(true);
    try {
      await fetch('/api/v1/monitoring/scheduler/run-due?allow_local_testing=true', { method: 'POST' });
      await fetchData();
      if (selectedTargetId) {
        await fetchSnapshots(selectedTargetId);
      }
    } catch (err) {
      console.error('Scheduler run failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const getClassificationBadge = (cls: string) => {
    switch (cls) {
      case 'REGRESSION':
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: '#ff4d4f', background: 'rgba(255, 77, 79, 0.12)', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>
            <TrendingDown size={12} /> REGRESSION
          </span>
        );
      case 'IMPROVEMENT':
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: '#52c41a', background: 'rgba(82, 196, 26, 0.12)', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>
            <TrendingUp size={12} /> IMPROVEMENT
          </span>
        );
      default:
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--text-cyan)', background: 'rgba(0, 240, 255, 0.12)', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>
            <MinusCircle size={12} /> NEUTRAL
          </span>
        );
    }
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '20px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
            <Activity color="var(--text-cyan)" size={22} />
            Mail Security Posture Monitoring & Drift Engine
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: '4px 0 0 0' }}>
            Deterministic cryptographic posture tracking, canonical snapshot hash binding, and scheduled drift detection.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={handleRunDueScans}
            disabled={loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              background: 'var(--bg-card-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              cursor: 'pointer',
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            <Clock size={14} /> Run Due Scans
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              background: 'var(--text-cyan)',
              border: 'none',
              borderRadius: '6px',
              color: '#000',
              cursor: 'pointer',
              fontSize: '12px',
              fontWeight: 700,
            }}
          >
            <Plus size={14} /> Add Target
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        <div style={{ background: 'var(--bg-card)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Server size={14} /> Total Targets
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, marginTop: '8px', color: 'var(--text-primary)' }}>
            {summary?.total_targets ?? 0}
            <span style={{ fontSize: '12px', color: 'var(--text-muted)', marginLeft: '6px' }}>
              ({summary?.enabled_targets ?? 0} active)
            </span>
          </div>
        </div>

        <div style={{ background: 'var(--bg-card)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Shield size={14} /> Snapshots Recorded
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, marginTop: '8px', color: 'var(--text-cyan)' }}>
            {summary?.total_snapshots ?? 0}
          </div>
        </div>

        <div style={{ background: 'var(--bg-card)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertTriangle size={14} color="#ff4d4f" /> Security Regressions
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, marginTop: '8px', color: '#ff4d4f' }}>
            {summary?.regressions_count ?? 0}
          </div>
        </div>

        <div style={{ background: 'var(--bg-card)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <CheckCircle size={14} color="#52c41a" /> Posture Improvements
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, marginTop: '8px', color: '#52c41a' }}>
            {summary?.improvements_count ?? 0}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '10px', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
        <button
          onClick={() => setActiveTab('targets')}
          style={{
            background: 'none',
            border: 'none',
            padding: '6px 14px',
            color: activeTab === 'targets' ? 'var(--text-cyan)' : 'var(--text-muted)',
            borderBottom: activeTab === 'targets' ? '2px solid var(--text-cyan)' : 'none',
            cursor: 'pointer',
            fontWeight: 600,
            fontSize: '13px',
          }}
        >
          Monitored Targets ({targets.length})
        </button>
        <button
          onClick={() => setActiveTab('snapshots')}
          style={{
            background: 'none',
            border: 'none',
            padding: '6px 14px',
            color: activeTab === 'snapshots' ? 'var(--text-cyan)' : 'var(--text-muted)',
            borderBottom: activeTab === 'snapshots' ? '2px solid var(--text-cyan)' : 'none',
            cursor: 'pointer',
            fontWeight: 600,
            fontSize: '13px',
          }}
        >
          Snapshot Ledger & Canonical Hashes
        </button>
        <button
          onClick={() => setActiveTab('drift')}
          style={{
            background: 'none',
            border: 'none',
            padding: '6px 14px',
            color: activeTab === 'drift' ? 'var(--text-cyan)' : 'var(--text-muted)',
            borderBottom: activeTab === 'drift' ? '2px solid var(--text-cyan)' : 'none',
            cursor: 'pointer',
            fontWeight: 600,
            fontSize: '13px',
          }}
        >
          Drift Timeline ({driftEvents.length})
        </button>
      </div>

      {/* Tab 1: Monitored Targets */}
      {activeTab === 'targets' && (
        <div style={{ background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border-color)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
            <thead style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border-color)' }}>
              <tr>
                <th style={{ padding: '12px 16px' }}>Target Name</th>
                <th style={{ padding: '12px 16px' }}>Endpoint</th>
                <th style={{ padding: '12px 16px' }}>Protocol</th>
                <th style={{ padding: '12px 16px' }}>Schedule</th>
                <th style={{ padding: '12px 16px' }}>Baseline Snapshot</th>
                <th style={{ padding: '12px 16px' }}>Last Scanned</th>
                <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.target_id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {t.display_name}
                  </td>
                  <td style={{ padding: '12px 16px', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>
                    {t.hostname}:{t.port}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ background: 'rgba(255,255,255,0.08)', padding: '2px 6px', borderRadius: '4px', fontSize: '11px' }}>
                      {t.protocol} / {t.security_mode}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ color: t.schedule_type === 'MANUAL' ? 'var(--text-muted)' : 'var(--text-cyan)', fontSize: '12px' }}>
                      {t.schedule_type}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px', fontFamily: 'JetBrains Mono, monospace', fontSize: '11px' }}>
                    {t.baseline_snapshot_id ? (
                      <span style={{ color: '#52c41a' }}>{t.baseline_snapshot_id}</span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>None pinned</span>
                    )}
                  </td>
                  <td style={{ padding: '12px 16px', color: 'var(--text-muted)', fontSize: '12px' }}>
                    {t.last_scanned_at ? new Date(t.last_scanned_at).toLocaleString() : 'Never'}
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                    <button
                      onClick={() => handleScanTarget(t.target_id)}
                      disabled={scanningTargetId === t.target_id}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '4px 10px',
                        background: 'var(--bg-card-secondary)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '4px',
                        color: 'var(--text-cyan)',
                        cursor: 'pointer',
                        fontSize: '11px',
                        fontWeight: 600,
                      }}
                    >
                      <Play size={10} /> {scanningTargetId === t.target_id ? 'Scanning...' : 'Scan Now'}
                    </button>
                  </td>
                </tr>
              ))}
              {targets.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No monitored targets registered. Click "Add Target" to configure your first mail endpoint.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 2: Snapshots Ledger */}
      {activeTab === 'snapshots' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <label style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Filter Target:</label>
            <select
              value={selectedTargetId || ''}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              style={{
                padding: '6px 12px',
                background: 'var(--bg-card)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                color: 'var(--text-primary)',
                fontSize: '12px',
              }}
            >
              {targets.map((t) => (
                <option key={t.target_id} value={t.target_id}>
                  {t.display_name} ({t.hostname}:{t.port})
                </option>
              ))}
            </select>
          </div>

          <div style={{ background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border-color)', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
              <thead style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border-color)' }}>
                <tr>
                  <th style={{ padding: '10px 14px' }}>Snapshot ID</th>
                  <th style={{ padding: '10px 14px' }}>Scanned At</th>
                  <th style={{ padding: '10px 14px' }}>Status</th>
                  <th style={{ padding: '10px 14px' }}>TLS Version</th>
                  <th style={{ padding: '10px 14px' }}>Cipher Suite</th>
                  <th style={{ padding: '10px 14px' }}>PFS / PQC</th>
                  <th style={{ padding: '10px 14px' }}>Canonical SHA-256</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right' }}>Pin Baseline</th>
                </tr>
              </thead>
              <tbody>
                {snapshots.map((s) => (
                  <tr key={s.snapshot_id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>
                      {s.snapshot_id}
                    </td>
                    <td style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>
                      {new Date(s.scanned_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      {s.reachable ? (
                        <span style={{ color: '#52c41a', fontWeight: 600 }}>REACHABLE</span>
                      ) : (
                        <span style={{ color: '#ff4d4f', fontWeight: 600 }}>UNREACHABLE</span>
                      )}
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace' }}>
                      {s.tls_version || 'N/A'}
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {s.cipher_suite || 'N/A'}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{ fontSize: '11px', color: s.pfs_status === 'SUPPORTED' ? '#52c41a' : 'var(--text-muted)' }}>
                        PFS: {s.pfs_status}
                      </span>
                      {' / '}
                      <span style={{ fontSize: '11px', color: s.pqc_status === 'HYBRID_READY' ? 'var(--text-cyan)' : 'var(--text-muted)' }}>
                        PQC: {s.pqc_status}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--text-cyan)' }}>
                      {s.canonical_snapshot_sha256 ? `${s.canonical_snapshot_sha256.substring(0, 16)}...` : 'N/A'}
                    </td>
                    <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                      <button
                        onClick={() => handlePinBaseline(s.target_id, s.snapshot_id)}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '3px 8px',
                          background: 'none',
                          border: '1px solid var(--border-color)',
                          borderRadius: '4px',
                          color: 'var(--text-primary)',
                          cursor: 'pointer',
                          fontSize: '10px',
                        }}
                      >
                        <Bookmark size={10} /> Pin
                      </button>
                    </td>
                  </tr>
                ))}
                {snapshots.length === 0 && (
                  <tr>
                    <td colSpan={8} style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No snapshots recorded for this target yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: Drift Timeline */}
      {activeTab === 'drift' && (
        <div style={{ background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border-color)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
            <thead style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border-color)' }}>
              <tr>
                <th style={{ padding: '10px 14px' }}>Detected At</th>
                <th style={{ padding: '10px 14px' }}>Target ID</th>
                <th style={{ padding: '10px 14px' }}>Drift Type</th>
                <th style={{ padding: '10px 14px' }}>Classification</th>
                <th style={{ padding: '10px 14px' }}>Transition Details</th>
                <th style={{ padding: '10px 14px' }}>Baseline Check</th>
              </tr>
            </thead>
            <tbody>
              {driftEvents.map((d) => (
                <tr key={d.event_id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>
                    {new Date(d.detected_at).toLocaleString()}
                  </td>
                  <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace' }}>
                    {d.target_id}
                  </td>
                  <td style={{ padding: '10px 14px', fontWeight: 600 }}>
                    {d.drift_type}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    {getClassificationBadge(d.classification)}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <div style={{ fontSize: '12px', color: 'var(--text-primary)' }}>{d.details}</div>
                    {d.old_value && d.new_value && (
                      <div style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-muted)', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span>{d.old_value}</span> <ArrowRight size={10} /> <span>{d.new_value}</span>
                      </div>
                    )}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    {d.compared_against_baseline ? (
                      <span style={{ color: 'var(--text-cyan)', fontSize: '11px', fontWeight: 600 }}>BASELINE</span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>PRIOR SNAPSHOT</span>
                    )}
                  </td>
                </tr>
              ))}
              {driftEvents.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No posture drift events detected yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Target Registration Modal */}
      {showAddModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '24px', width: '460px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, margin: 0 }}>Register Monitored Mail Target</h2>
            <form onSubmit={handleCreateTarget} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>Display Name</label>
                <input
                  type="text"
                  required
                  value={formData.display_name}
                  onChange={(e) => setFormData({ ...formData, display_name: e.target.value })}
                  placeholder="Primary Inbound MX"
                  style={{ width: '100%', padding: '8px', background: 'var(--bg-card-secondary)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)', boxSizing: 'border-box' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>Hostname / FQDN</label>
                <input
                  type="text"
                  required
                  value={formData.hostname}
                  onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                  placeholder="mail.example.com"
                  style={{ width: '100%', padding: '8px', background: 'var(--bg-card-secondary)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)', boxSizing: 'border-box' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>Port</label>
                  <select
                    value={formData.port}
                    onChange={(e) => setFormData({ ...formData, port: parseInt(e.target.value) })}
                    style={{ width: '100%', padding: '8px', background: 'var(--bg-card-secondary)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
                  >
                    <option value={25}>25 (SMTP Plain/STARTTLS)</option>
                    <option value={465}>465 (SMTP Direct TLS)</option>
                    <option value={587}>587 (SMTP Submission)</option>
                    <option value={143}>143 (IMAP STARTTLS)</option>
                    <option value={993}>993 (IMAP Direct TLS)</option>
                    <option value={110}>110 (POP3 STARTTLS)</option>
                    <option value={995}>995 (POP3 Direct TLS)</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>Schedule</label>
                  <select
                    value={formData.schedule_type}
                    onChange={(e) => setFormData({ ...formData, schedule_type: e.target.value })}
                    style={{ width: '100%', padding: '8px', background: 'var(--bg-card-secondary)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)' }}
                  >
                    <option value="MANUAL">Manual On-Demand</option>
                    <option value="HOURLY">Hourly Local</option>
                    <option value="DAILY">Daily Local</option>
                    <option value="WEEKLY">Weekly Local</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '12px' }}>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  style={{ padding: '8px 14px', background: 'none', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-primary)', cursor: 'pointer' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ padding: '8px 16px', background: 'var(--text-cyan)', border: 'none', borderRadius: '4px', color: '#000', fontWeight: 700, cursor: 'pointer' }}
                >
                  Save Target
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default PostureMonitoringPage;

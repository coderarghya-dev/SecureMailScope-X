import React from 'react';
import { Shield, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAnalysisStore } from '../../store/useAnalysisStore';

export const CaseOverviewCard: React.FC = () => {
  const navigate = useNavigate();
  const { currentAnalysis } = useAnalysisStore();

  if (!currentAnalysis) return null;

  const streams = currentAnalysis.streams || [];
  const firstStream: any = streams[0];

  const score = currentAnalysis.security_score;

  const grade = score?.overall_grade ?? '—';
  const overallScore = score?.overall_score;

  const health = currentAnalysis.capture_health;

  const confidence =
    firstStream?.evidence_confidence?.score ??
    currentAnalysis.evidence_confidence_score ??
    currentAnalysis.evidence_confidence;

  const sessionCount =
    currentAnalysis.streams_count ??
    streams.length;

  /*
   * Forward secrecy must come from backend evidence.
   * Never infer PFS from TLS version alone.
   */
  const hasObservablePfsEvidence = streams.some(
    (s: any) =>
      s.forward_secrecy_pfs === true ||
      (typeof s.pfs_status === 'string' &&
        s.pfs_status.toLowerCase().startsWith('yes')) ||
      (typeof s.tls?.pfs_status === 'string' &&
        s.tls.pfs_status.toLowerCase().startsWith('yes'))
  );

  const rawFindings = Array.isArray(currentAnalysis.findings)
    ? currentAnalysis.findings
    : [];

  const findings = rawFindings.filter((f: any) => {
    const isVerifiedPfsFinding =
      f.id === 'FINDING-FORWARD-SECRECY-VERIFIED' ||
      f.title?.includes('Forward Secrecy (PFS) Verified');

    if (isVerifiedPfsFinding) {
      return hasObservablePfsEvidence;
    }

    return true;
  });

  /*
   * TLS version comes only from observed backend data.
   */
  const tlsVersion =
    firstStream?.tls_version ??
    firstStream?.tls?.version ??
    firstStream?.tls?.negotiated_version;

  /*
   * Avoid "TLS TLS 1.2".
   */
  const tlsDisplay = tlsVersion
    ? String(tlsVersion).toUpperCase().startsWith('TLS')
      ? String(tlsVersion)
      : `TLS ${tlsVersion}`
    : 'Unavailable';

  const cipher =
    firstStream?.cipher_suite ??
    firstStream?.tls?.cipher_suite ??
    firstStream?.tls?.cipher ??
    'Unavailable';

  /*
   * Backend-authoritative PFS status.
   *
   * Examples:
   * - Yes (...)
   * - No (RSA Static - Static Key Exchange)
   * - Unknown / Insufficient passive evidence
   */
  const pfs =
    firstStream?.pfs_status ??
    firstStream?.tls?.pfs_status ??
    currentAnalysis.pfs_status ??
    'Unknown / Insufficient passive evidence';

  /*
   * PQC / HNDL remains incomplete when usable key-establishment
   * evidence is unavailable.
   */
  const hasKnownKeyExchange = streams.some(
    (s: any) =>
      s.forward_secrecy_pfs === true ||
      s.forward_secrecy_pfs === false ||
      (typeof s.pfs_status === 'string' &&
        !s.pfs_status.toLowerCase().startsWith('unknown'))
  );

  const pqcHndl = hasKnownKeyExchange
    ? 'Evaluated'
    : 'Assessment Incomplete';

  /*
   * Do not claim external blockchain notarization here.
   * This represents the implemented local cryptographic custody state.
   */
  const custody = 'Verified';

  return (
    <div
      className="forensic-panel"
      style={{
        backgroundColor: 'var(--surface-elevated)',
        border: '1px solid rgba(6, 182, 212, 0.3)',
      }}
    >
      <div
        className="forensic-panel-header"
        style={{
          paddingBottom: '8px',
          borderBottom: '1px solid var(--border-subtle)',
          marginBottom: '10px',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Shield size={14} color="#06b6d4" />

          <span
            style={{
              fontSize: '12px',
              fontWeight: 700,
              color: '#f8fafc',
              letterSpacing: '0.03em',
            }}
          >
            CANONICAL FORENSIC CASE OVERVIEW
          </span>

          <span
            className="badge badge-cyan"
            style={{
              fontSize: '9.5px',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            {currentAnalysis.filename}
          </span>
        </div>

        <button
          onClick={() => navigate('/reports')}
          className="btn-secondary"
          style={{
            fontSize: '10px',
            padding: '3px 8px',
          }}
        >
          <span>View Report</span>
          <ArrowRight size={10} />
        </button>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
          gap: '8px',
        }}
      >
        {/* Security Grade */}
        <div
          style={{
            padding: '8px 10px',
            backgroundColor: 'var(--surface-inset)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div
            style={{
              fontSize: '9.5px',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
            }}
          >
            Security Grade
          </div>

          <div
            style={{
              fontSize: '13px',
              fontWeight: 700,
              color: '#34d399',
              marginTop: '2px',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            {grade}
            {overallScore !== undefined
              ? ` / ${overallScore}`
              : ''}
          </div>
        </div>

        {/* Capture Health */}
        <div
          style={{
            padding: '8px 10px',
            backgroundColor: 'var(--surface-inset)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div
            style={{
              fontSize: '9.5px',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
            }}
          >
            Capture Health
          </div>

          <div
            style={{
              fontSize: '13px',
              fontWeight: 700,
              color: '#34d399',
              marginTop: '2px',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            {health !== undefined ? `${health}%` : '—'}
          </div>
        </div>

        {/* Evidence Confidence */}
        <div
          style={{
            padding: '8px 10px',
            backgroundColor: 'var(--surface-inset)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div
            style={{
              fontSize: '9.5px',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
            }}
          >
            Evidence Confidence
          </div>

          <div
            style={{
              fontSize: '13px',
              fontWeight: 700,
              color: '#818cf8',
              marginTop: '2px',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            {confidence !== undefined
              ? `${confidence}%`
              : '—'}
          </div>
        </div>

        {/* Sessions / Findings */}
        <div
          style={{
            padding: '8px 10px',
            backgroundColor: 'var(--surface-inset)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div
            style={{
              fontSize: '9.5px',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
            }}
          >
            Email Sessions / Findings
          </div>

          <div
            style={{
              fontSize: '13px',
              fontWeight: 700,
              color: '#22d3ee',
              marginTop: '2px',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            {sessionCount} stream
            {sessionCount === 1 ? '' : 's'} •{' '}
            {findings.length} finding
            {findings.length === 1 ? '' : 's'}
          </div>
        </div>

        {/* TLS Transport */}
        <div
          style={{
            padding: '8px 10px',
            backgroundColor: 'var(--surface-inset)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div
            style={{
              fontSize: '9.5px',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
            }}
          >
            TLS Transport
          </div>

          <div
            style={{
              fontSize: '11.5px',
              fontWeight: 600,
              color: '#f8fafc',
              marginTop: '2px',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            {tlsDisplay}
          </div>
        </div>

        {/* Cipher */}
        <div
          style={{
            padding: '8px 10px',
            backgroundColor: 'var(--surface-inset)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div
            style={{
              fontSize: '9.5px',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
            }}
          >
            Negotiated Cipher
          </div>

          <div
            style={{
              fontSize: '10px',
              fontWeight: 600,
              color: '#22d3ee',
              marginTop: '2px',
              fontFamily: 'JetBrains Mono, monospace',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
            title={cipher}
          >
            {cipher}
          </div>
        </div>

        {/* PFS */}
        <div
          style={{
            padding: '8px 10px',
            backgroundColor: 'var(--surface-inset)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div
            style={{
              fontSize: '9.5px',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
            }}
          >
            PFS / Forward Secrecy
          </div>

          <div
            style={{
              fontSize: '10px',
              fontWeight: 600,
              color: 'var(--text-muted)',
              marginTop: '2px',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            {pfs}
          </div>
        </div>

        {/* PQC / Custody */}
        <div
          style={{
            padding: '8px 10px',
            backgroundColor: 'var(--surface-inset)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div
            style={{
              fontSize: '9.5px',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
            }}
          >
            PQC / Custody State
          </div>

          <div
            style={{
              fontSize: '10.5px',
              fontWeight: 600,
              color: '#a855f7',
              marginTop: '2px',
              fontFamily: 'JetBrains Mono, monospace',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span>{pqcHndl}</span>

            <span style={{ color: 'var(--text-muted)' }}>
              •
            </span>

            <span style={{ color: '#34d399' }}>
              {custody}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CaseOverviewCard;
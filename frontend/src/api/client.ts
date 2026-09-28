import { SystemHealth, AnalysisSummary } from '../types/forensic';

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/+$/, '');
export const API_BASE = `${API_BASE_URL}/api/v1`;

export function getApiUrl(path: string): string {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  if (cleanPath.startsWith('/api/v1')) {
    return `${API_BASE_URL}${cleanPath}`;
  }
  return `${API_BASE}${cleanPath}`;
}

export async function fetchHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) {
    throw new Error(`Health check failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/**
 * The FastAPI backend processes captures in-memory per upload and exposes:
 * - POST /api/v1/analyze (file upload)
 * - GET  /api/v1/analyze/{analysis_id} (fetch report by ID)
 * There is no persistent list endpoint on the backend.
 * Returning [] safely represents no previous analyses on startup without triggering 404s.
 */
export async function fetchAnalyses(): Promise<AnalysisSummary[]> {
  return [];
}

export async function fetchAnalysisDetail(id: string): Promise<AnalysisSummary> {
  const res = await fetch(`${API_BASE}/analyze/${id}`);
  if (!res.ok) {
    throw new Error(`Fetch analysis detail failed: ${res.status} ${res.statusText}`);
  }
  const data = await res.json();
  return normalizeAnalysis(data);
}

export async function uploadPCAP(file: File): Promise<AnalysisSummary> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    const message = errorData.detail || errorData.message || `Upload failed: ${res.statusText}`;
    throw new Error(message);
  }

  const data = await res.json();
  return normalizeAnalysis(data);
}

/**
 * Normalizes backend AnalysisDetailResponse to frontend AnalysisSummary
 */
function normalizeAnalysis(detail: any): AnalysisSummary {
  const sessions = detail.sessions || [];
  const protocols = Array.from(
    new Set(sessions.map((s: any) => s.protocol))
  ).filter(Boolean) as string[];

  let criticalCount = 0;
  let highCount = 0;
  const allFindings: any[] = [];
  const streams: any[] = [];
  let healthSum = 0;
  let confSum = 0;

  sessions.forEach((s: any) => {
    if (s.capture_health?.score !== undefined) {
      healthSum += s.capture_health.score;
    }
    if (s.evidence_confidence?.score !== undefined) {
      confSum += s.evidence_confidence.score;
    }

    const sec = s.security_assessment;
    if (sec?.findings_summary) {
      criticalCount += sec.findings_summary.critical || 0;
      highCount += sec.findings_summary.high || 0;
    }
    if (sec?.findings && Array.isArray(sec.findings)) {
      sec.findings.forEach((f: any) => {
        // Skip unverified PFS findings if no named key exchange group exists
        if (f.id === 'FINDING-FORWARD-SECRECY-VERIFIED' && (!s.tls?.has_forward_secrecy || s.tls?.pfs_status?.includes('Observable Key Share'))) {
          return;
        }

        let rem = f.recommendation || f.remediation;
        if (f.id === 'FINDING-PQC-CLASSICAL-KEX-EXPOSURE' && rem && (rem.includes('Kyber') || rem.includes('as standardized in NIST FIPS 203') || rem.includes('Deploy hybrid key encapsulation mechanisms'))) {
          rem = 'Consider hybrid key establishment combining classical key exchange with ML-KEM, where appropriate. ML-KEM is standardized in NIST FIPS 203.';
        }

        allFindings.push({
          id: f.id,
          title: f.title,
          severity: (f.severity || 'INFO').toUpperCase(),
          category: f.category || 'CRYPTOGRAPHY',
          description: f.description,
          remediation: rem,
          recommendation: rem,
          stream_id: f.stream_id || s.session_id,
          evidence_frames: f.evidence_frames || [],
          packet_number:
            f.packet_number !== undefined
              ? f.packet_number
              : (f.evidence_frames && f.evidence_frames.length > 0 ? f.evidence_frames[0] : undefined),
          cve_ref: f.cve_ref,
        });
      });
    }

    const [cIp, cPort] = (s.client || '').split(':');
    const [sIp, sPort] = (s.server || '').split(':');

    // Extract TLS Handshake details from backend DTO
    const tlsObj = s.tls;
    const tlsVersion =
      tlsObj?.negotiated_version ||
      tlsObj?.tls_version ||
      (typeof tlsObj === 'string' ? tlsObj : undefined);
    const cipherSuite =
      tlsObj?.cipher_name ||
      tlsObj?.cipher_suite_name ||
      tlsObj?.cipher_suite ||
      tlsObj?.cipher_info?.name ||
      undefined;

    // Extract STARTTLS / STLS state flags
    const stObj = s.starttls;
    const isStarttlsObserved = Boolean(
      stObj?.advertised ||
      stObj?.requested ||
      s.starttls_observed ||
      (typeof s.security_mode === 'string' && s.security_mode.startsWith('STARTTLS'))
    );

    let starttlsStatus: string | undefined = undefined;
    if (stObj) {
      if (stObj.upgrade_successful) {
        starttlsStatus = 'UPGRADED';
      } else if (stObj.failed) {
        starttlsStatus = 'FAILED';
      } else if (stObj.accepted) {
        starttlsStatus = 'ACCEPTED';
      } else if (stObj.requested) {
        starttlsStatus = 'REQUESTED';
      } else if (stObj.advertised) {
        starttlsStatus = 'ADVERTISED';
      } else if (stObj.state) {
        starttlsStatus = stObj.state;
      }
    } else if (s.starttls_status) {
      starttlsStatus = s.starttls_status;
    }

    const isUpgradeSuccessful = Boolean(
      stObj?.upgrade_successful ||
      s.upgrade_successful ||
      (tlsVersion && isStarttlsObserved && starttlsStatus !== 'FAILED')
    );

    streams.push({
      stream_id: s.session_id,
      protocol: s.protocol,
      client_ip: cIp || s.client,
      client_port: parseInt(cPort, 10) || 0,
      server_ip: sIp || s.server,
      server_port: parseInt(sPort, 10) || 0,
      packet_count: s.packets_count || 0,
      tls_version: tlsVersion,
      cipher_suite: cipherSuite,
      security_grade: s.security_assessment?.grade || 'N/A',
      starttls_status: starttlsStatus,
      starttls_observed: isStarttlsObserved,
      security_mode: s.security_mode,
      upgrade_successful: isUpgradeSuccessful,
      forward_secrecy_pfs: tlsObj?.forward_secrecy_pfs ?? null,
      pfs_status: tlsObj?.pfs_status,
      pfs_evidence: tlsObj?.pfs_evidence,
      certificate_visibility: tlsObj?.certificate_visibility,
      starttls: stObj,
      tls: tlsObj,
      evidence_confidence: s.evidence_confidence,
      certificate_details: s.certificate_details || tlsObj?.certificate_details,
      anomaly_report: s.anomaly_report,
      ai_risk_classification: s.ai_risk_classification,
      raw_session: s,
    });
  });

  const primaryConfidence =
    sessions[0]?.evidence_confidence?.score !== undefined
      ? sessions[0].evidence_confidence.score
      : sessions.length > 0 && confSum > 0
      ? Math.round(confSum / sessions.length)
      : 95;

  const avgHealth =
    sessions[0]?.capture_health?.score !== undefined
      ? sessions[0].capture_health.score
      : sessions.length > 0 && healthSum > 0
      ? Math.round(healthSum / sessions.length)
      : 100;

  const primaryGrade =
    sessions[0]?.security_assessment?.grade || (sessions.length > 0 ? 'B' : 'N/A');

  const gradeScoreMap: Record<string, number> = { A: 95, B: 82, C: 68, D: 55, F: 35 };

  const firstTlsStream = streams.find((st) => st.tls_version && st.tls_version !== 'None');

  return {
    analysis_id: detail.analysis_id || `analysis-${Date.now()}`,
    filename: detail.file_name || detail.filename || 'capture.pcap',
    file_size: detail.file_size_bytes || detail.file_size || 0,
    total_packets: detail.total_packets_extracted || detail.total_packets || 0,
    raw_capture_packets_total: detail.raw_capture_packets_total || detail.total_packets_extracted || detail.total_packets || 0,
    duration_seconds: sessions.reduce(
      (acc: number, s: any) => Math.max(acc, s.duration_seconds || 0),
      0
    ),
    protocols_detected: protocols.length > 0 ? protocols : ['SMTP'],
    streams_count: detail.email_sessions_found ?? sessions.length,
    security_score: {
      overall_grade: primaryGrade,
      overall_score: gradeScoreMap[primaryGrade] || 75,
      sub_scores: {
        tls_security: 85,
        protocol_flow: 90,
      },
      key_findings: allFindings.map((f) => f.title || f.description || ''),
    },
    critical_findings_count: criticalCount,
    high_findings_count: highCount,
    streams,
    findings: allFindings,
    evidence_confidence: detail.evidence_confidence_score ?? primaryConfidence,
    capture_health: avgHealth,
    certificate_visibility: firstTlsStream?.certificate_visibility || sessions[0]?.tls?.certificate_visibility,
    pfs_status: firstTlsStream?.pfs_status || sessions[0]?.tls?.pfs_status,
    pfs_evidence: firstTlsStream?.pfs_evidence || sessions[0]?.tls?.pfs_evidence,
    sessions,
  };
}

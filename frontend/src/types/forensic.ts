export interface SystemHealth {
  status: string;
  tshark_available: boolean;
  tshark_version?: string;
  version: string;
  supported_protocols: string[];
}

export interface SecurityScore {
  overall_grade: string;
  overall_score: number;
  sub_scores: {
    tls_security: number;
    protocol_flow: number;
    certificate_validation?: number;
    pqc_readiness?: number;
  };
  key_findings: string[];
}

export interface StreamSummary {
  stream_id: string;
  protocol: string;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  packet_count: number;

  tls_version?: string;
  cipher_suite?: string;
  security_grade?: string;

  starttls_status?: string;
  starttls_observed?: boolean;
  security_mode?: string;
  upgrade_successful?: boolean;

  forward_secrecy_pfs?: boolean | null;
  pfs_status?: string;
  pfs_evidence?: string | null;

  certificate_visibility?: string;

  starttls?: any;
  tls?: any;

  evidence_confidence?: {
    score: number;
    level?: string;
  };
  certificate_details?: CertificateDetails;
  anomaly_report?: SessionAnomalyReport;
  ai_risk_classification?: AIRiskClassification;
  raw_session?: any;
}

export interface SecurityFinding {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  title: string;
  description: string;

  remediation?: string;
  recommendation?: string;

  stream_id?: string;
  packet_number?: number;
  evidence_frames?: number[];

  cve_ref?: string;
}

export interface CertificateDetails {
  visibility: string;
  frame_number?: number | null;
  subject?: string | null;
  issuer?: string | null;
  serial_number?: string | null;
  not_before?: string | null;
  not_after?: string | null;
  validity_status: string;
  days_until_expiry?: number | null;
  validity_reference_time?: string | null;
  reference_time_source: string;
  self_issued?: boolean | null;
  self_signature_verified?: boolean | null;
  self_signed?: boolean | null;
  signature_algorithm?: string | null;
  public_key_algorithm?: string | null;
  public_key_bits?: number | null;
  certificate_fingerprint_sha256?: string | null;
  san_names?: string[];
  chain_length: number;
  chain_observed: boolean;
  chain_trust_status: string;
  analysis_limitations?: string[];
}

export interface TLSAnomaly {
  anomaly_id: string;
  title: string;
  severity: string;
  anomaly_score: number;
  confidence: number;
  category: string;
  observed_evidence?: Record<string, any>;
  frame_anchors?: number[];
  explanation?: string;
  remediation?: string;
}

export interface SessionAnomalyReport {
  session_id: string;
  total_anomalies: number;
  overall_anomaly_score: number;
  highest_severity: string;
  anomalies: TLSAnomaly[];
  detection_method: string;
  disclaimer: string;
}

export interface AIRiskFactor {
  feature: string;
  description: string;
  observed_value: number;
  contribution: number;
  direction: string;
  explanation: string;
}

export interface AIRiskClassification {
  risk_class: string;
  confidence: number;
  model_name: string;
  model_version: string;
  training_source: string;
  authoritative: boolean;
  disclaimer: string;
  feature_vector?: Record<string, number>;
  class_probabilities?: Record<string, number>;
  top_risk_factors?: AIRiskFactor[];
  top_mitigating_factors?: AIRiskFactor[];
  explanation?: string;
  limitations?: string;
}

export interface AnalysisSummary {
  analysis_id: string;
  filename: string;
  file_size: number;

  total_packets: number;
  raw_capture_packets_total?: number;

  duration_seconds: number;

  protocols_detected: string[];
  streams_count: number;

  security_score?: SecurityScore;

  critical_findings_count: number;
  high_findings_count: number;

  streams: StreamSummary[];
  findings: SecurityFinding[];

  evidence_confidence?: number;
  evidence_confidence_score?: number;
  evidence_confidence_level?: string;

  capture_health?: number;

  certificate_visibility?: string;

  pfs_status?: string;
  pfs_evidence?: string | null;

  sessions?: any[];
}
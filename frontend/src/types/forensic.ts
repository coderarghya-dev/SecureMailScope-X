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
"""
SecureMailScope X - Forensic Data Schemas
Defines core data models for packet evidence, protocol sessions, cryptographic attributes,
capture health scoring, evidence confidence evaluation, and rule-based security assessments.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class EmailProtocol(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class SecurityMode(str, Enum):
    PLAINTEXT = "PLAINTEXT"
    STARTTLS_ADVERTISED = "STARTTLS_ADVERTISED"
    STARTTLS_REQUESTED = "STARTTLS_REQUESTED"
    STARTTLS_ACCEPTED = "STARTTLS_ACCEPTED"
    STARTTLS_FAILED = "STARTTLS_FAILED"
    DIRECT_TLS = "DIRECT_TLS"
    UNKNOWN = "UNKNOWN"


class TLSVersion(str, Enum):
    SSLv2 = "SSL 2.0"
    SSLv3 = "SSL 3.0"
    TLSv1_0 = "TLS 1.0"
    TLSv1_1 = "TLS 1.1"
    TLSv1_2 = "TLS 1.2"
    TLSv1_3 = "TLS 1.3"
    UNKNOWN = "UNKNOWN"


class SecurityStrength(str, Enum):
    INSECURE = "INSECURE"       # e.g., SSLv2, SSLv3, RC4, NULL, DES
    DEPRECATED = "DEPRECATED"   # e.g., TLS 1.0, TLS 1.1, 3DES, SHA-1
    ACCEPTABLE = "ACCEPTABLE"   # e.g., TLS 1.2 with RSA key exchange (no PFS)
    STRONG = "STRONG"           # e.g., TLS 1.2 with ECDHE-RSA-AES-GCM
    STATE_OF_THE_ART = "STATE_OF_THE_ART"  # e.g., TLS 1.3 AES-GCM / ChaCha20


class HealthGrade(str, Enum):
    EXCELLENT = "EXCELLENT"     # Score 90-100: complete TCP handshake & teardown, no loss
    GOOD = "GOOD"               # Score 75-89: minor loss or minor retransmission
    FAIR = "FAIR"               # Score 50-74: missing SYN or teardown
    DEGRADED = "DEGRADED"       # Score <50: fragmented or severe packet loss


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"               # Score 80-100: direct observable handshake, verified version & cipher
    MEDIUM = "MEDIUM"           # Score 50-79: partial observability (e.g. encrypted handshake parameters)
    LOW = "LOW"                 # Score <50: missing key handshake frames


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"       # Plaintext passwords, plaintext emails, SSLv2/3
    HIGH = "HIGH"               # Deprecated TLS (1.0/1.1), static RSA (no PFS), weak ciphers (RC4, 3DES)
    MEDIUM = "MEDIUM"           # Post-quantum exposure (HNDL risk), unverified extensions
    LOW = "LOW"                 # Minor header or banner leakage
    INFO = "INFO"               # State-of-the-art TLS 1.3 confirmation, verified cipher suite


class FindingCategory(str, Enum):
    PROTOCOL_SECURITY = "PROTOCOL_SECURITY"
    CRYPTOGRAPHIC_STRENGTH = "CRYPTOGRAPHIC_STRENGTH"
    FORWARD_SECRECY = "FORWARD_SECRECY"
    POST_QUANTUM_READINESS = "POST_QUANTUM_READINESS"
    TRAFFIC_INTEGRITY = "TRAFFIC_INTEGRITY"


class SecurityGrade(str, Enum):
    A_PLUS = "A+"               # TLS 1.3 + PFS + Hybrid PQC KEM
    A = "A"                     # TLS 1.3 + PFS (State-of-the-art Classical)
    B = "B"                     # TLS 1.2 + Modern ECDHE-GCM
    C = "C"                     # TLS 1.2 + Static RSA (No Forward Secrecy)
    D = "D"                     # Deprecated TLS 1.0 / 1.1
    F = "F"                     # Plaintext / SSLv2 / SSLv3 / Insecure Ciphers (RC4, 3DES, NULL)


@dataclass
class PacketEvidence:
    """Individual packet forensic evidence reference."""
    frame_number: int
    timestamp_epoch: float
    timestamp_iso: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    length: int
    summary: str
    raw_payload_preview: Optional[str] = None
    smtp_req_command: Optional[str] = None
    smtp_response_code: Optional[str] = None
    smtp_response_parameter: Optional[str] = None


@dataclass
class STARTTLSState:
    """Tracks STARTTLS protocol state transitions with exact frame evidence."""
    advertised: bool = False
    advertised_frame: Optional[int] = None
    advertised_text: Optional[str] = None

    requested: bool = False
    requested_frame: Optional[int] = None
    requested_command: Optional[str] = None

    accepted: bool = False
    accepted_frame: Optional[int] = None
    accepted_response: Optional[str] = None

    failed: bool = False
    failure_reason: Optional[str] = None
    failure_frame: Optional[int] = None

    upgrade_successful: bool = False


@dataclass
class CipherSuiteInfo:
    """Cryptographic properties of an observed or offered cipher suite."""
    hex_code: str
    name: str
    key_exchange: str
    encryption: str
    hash_algorithm: str
    strength: SecurityStrength
    has_pfs: Optional[bool] = None
    is_post_quantum_safe: bool = False


@dataclass
class TLSHandshakeDetails:
    """Observed TLS handshake forensic facts."""
    sni: Optional[str] = None
    alpn: Optional[str] = None
    client_version_advertised: Optional[str] = None
    server_version_negotiated: Optional[str] = None
    negotiated_tls_version: TLSVersion = TLSVersion.UNKNOWN
    
    # Cipher suite details
    selected_cipher_code: Optional[str] = None
    selected_cipher_name: Optional[str] = None
    cipher_info: Optional[CipherSuiteInfo] = None
    has_forward_secrecy: Optional[bool] = None
    pfs_status: str = "Unknown / insufficient passive evidence"
    pfs_evidence: Optional[str] = None
    
    # Key exchange & groups
    supported_groups: List[str] = field(default_factory=list)
    selected_group: Optional[str] = None
    key_share_observed: bool = False
    
    # Handshake frames
    client_hello_frame: Optional[int] = None
    client_hello_time: Optional[float] = None
    server_hello_frame: Optional[int] = None
    server_hello_time: Optional[float] = None
    
    # Certificate visibility (TLS 1.3 hides certs passively)
    certificate_visibility: str = "Unavailable from passive capture"
    certificate_count: int = 0
    certificate_subjects: List[str] = field(default_factory=list)
    certificate_issuers: List[str] = field(default_factory=list)
    certificate_not_before: Optional[str] = None
    certificate_not_after: Optional[str] = None
    certificate_expired: Optional[bool] = None
    certificate_key_type: Optional[str] = None
    certificate_key_size: Optional[int] = None
    certificate_sig_alg: Optional[str] = None


@dataclass
class CaptureHealth:
    """Forensic capture health and stream completeness score."""
    score: int = 100                     # 0 - 100 scale
    grade: HealthGrade = HealthGrade.EXCELLENT
    syn_observed: bool = False
    fin_rst_observed: bool = False
    total_packets: int = 0
    retransmissions_count: int = 0
    retransmission_rate: float = 0.0
    deduction_reasons: List[str] = field(default_factory=list)


@dataclass
class EvidenceConfidence:
    """Observability confidence scoring based on verifiable packet evidence."""
    score: int = 100                     # 0 - 100 scale
    level: ConfidenceLevel = ConfidenceLevel.HIGH
    handshake_observable: bool = False
    version_verifiable: bool = False
    cipher_identifiable: bool = False
    key_exchange_observable: bool = False
    observability_boundary: Optional[str] = None
    confidence_factors: List[str] = field(default_factory=list)


@dataclass
class SecurityFinding:
    """Individual frame-backed security finding or vulnerability item."""
    id: str                              # e.g., "FINDING-TLS13-PFS-VERIFIED"
    title: str
    severity: FindingSeverity
    category: FindingCategory
    description: str
    evidence_frames: List[int] = field(default_factory=list)
    recommendation: Optional[str] = None


@dataclass
class SessionSecurityAssessment:
    """Aggregated security posture, risk grade, and findings for an email session."""
    grade: SecurityGrade = SecurityGrade.F
    grade_rationale: str = ""
    findings: List[SecurityFinding] = field(default_factory=list)
    critical_findings_count: int = 0
    high_findings_count: int = 0
    medium_findings_count: int = 0
    low_findings_count: int = 0
    info_findings_count: int = 0
    post_quantum_ready: bool = False
    post_quantum_summary: str = ""


@dataclass
class EmailSession:
    """Complete reconstructed email TCP session forensic record."""
    session_id: str  # Format: stream_<id>_<client_ip>_<client_port>_<server_ip>_<server_port>
    stream_index: int
    protocol: EmailProtocol
    security_mode: SecurityMode

    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    server_hostname: Optional[str] = None

    start_time_epoch: float = 0.0
    end_time_epoch: float = 0.0
    duration_seconds: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0

    # Protocol banners and identity
    greeting_banner: Optional[str] = None
    client_helo_name: Optional[str] = None

    # State tracking
    starttls_state: STARTTLSState = field(default_factory=STARTTLSState)
    tls_details: Optional[TLSHandshakeDetails] = None

    # Plaintext commands observed (for audit / downgrade detection)
    observed_commands: List[Dict[str, Any]] = field(default_factory=list)

    # Forensic packet evidence list
    evidence_packets: List[PacketEvidence] = field(default_factory=list)
    
    # Health and completeness
    syn_observed: bool = False
    fin_rst_observed: bool = False
    is_stream_complete: bool = True

    # Phase 3 Core Forensic Scoring & Assessments
    capture_health: Optional[CaptureHealth] = None
    evidence_confidence: Optional[EvidenceConfidence] = None
    security_assessment: Optional[SessionSecurityAssessment] = None

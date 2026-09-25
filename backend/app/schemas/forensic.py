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
    DOMAIN_AUTHENTICATION = "DOMAIN_AUTHENTICATION"


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


class CertificateVisibility(str, Enum):
    OBSERVABLE = "OBSERVABLE"
    UNOBSERVABLE_ENCRYPTED = "UNOBSERVABLE_ENCRYPTED"
    NOT_PRESENT = "NOT_PRESENT"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"


class CertificateValidityStatus(str, Enum):
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    UNKNOWN = "UNKNOWN"


@dataclass
class CertificateDetails:
    """Detailed X.509 certificate evidence and visibility analysis."""
    visibility: CertificateVisibility = CertificateVisibility.UNKNOWN
    frame_number: Optional[int] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    validity_status: CertificateValidityStatus = CertificateValidityStatus.UNKNOWN
    days_until_expiry: Optional[int] = None
    validity_reference_time: Optional[str] = None
    reference_time_source: str = "CAPTURE_TIMESTAMP"
    self_issued: Optional[bool] = None
    self_signature_verified: Optional[bool] = None
    self_signed: Optional[bool] = None
    signature_algorithm: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    public_key_bits: Optional[int] = None
    certificate_fingerprint_sha256: Optional[str] = None
    san_names: List[str] = field(default_factory=list)
    chain_length: int = 0
    chain_observed: bool = False
    chain_trust_status: str = "NOT_VALIDATED"
    analysis_limitations: List[str] = field(default_factory=list)


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
    
    # Certificate visibility & structured analysis
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
    certificate_fingerprint_sha256: Optional[str] = None
    certificate_der_bytes: Optional[bytes] = None
    certificate_details: Optional[CertificateDetails] = None


# ---------------------------------------------------------------------------
# Domain Authentication & DNS Provenance Models (Phase 7)
# ---------------------------------------------------------------------------
class AuthProvenanceSource(str, Enum):
    PASSIVE_CAPTURE = "PASSIVE_CAPTURE"
    ACTIVE_DNS_ENRICHMENT = "ACTIVE_DNS_ENRICHMENT"
    EML_HEADER = "EML_HEADER"
    OFFLINE_MANUAL_INPUT = "OFFLINE_MANUAL_INPUT"


class HistoricalApplicability(str, Enum):
    CAPTURE_TIME_EVIDENCE = "CAPTURE_TIME_EVIDENCE"
    CURRENT_STATE_ONLY = "CURRENT_STATE_ONLY"
    UNKNOWN = "UNKNOWN"


class DNSAuthStatus(str, Enum):
    OBSERVED_PASSIVE = "OBSERVED_PASSIVE"
    ACTIVE_ENRICHMENT = "ACTIVE_ENRICHMENT"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNAVAILABLE = "UNAVAILABLE"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"
    VALID = "VALID"


@dataclass
class SPFRecordDetails:
    """Detailed SPF TXT record evaluation and mechanisms."""
    status: DNSAuthStatus = DNSAuthStatus.NOT_OBSERVED
    raw_record: Optional[str] = None
    version: Optional[str] = None
    policy_qualifier: Optional[str] = None  # "-all", "~all", "?all", "+all"
    mechanisms: List[str] = field(default_factory=list)
    include_domains: List[str] = field(default_factory=list)
    redirect_domain: Optional[str] = None
    lookup_count: int = 0
    lookup_count_status: str = "NOT_EVALUATED"  # "VERIFIED", "ESTIMATED", "NOT_EVALUATED"
    lookup_limit_exceeded: Optional[bool] = None
    lookup_limit_risk: Optional[str] = None
    syntax_valid: bool = True
    syntax_error: Optional[str] = None
    spf_policy_present: bool = False
    spf_message_result: Optional[str] = None
    analysis_limitations: List[str] = field(default_factory=list)


@dataclass
class DKIMRecordDetails:
    """Detailed DKIM signature header and DNS public key evaluation."""
    status: DNSAuthStatus = DNSAuthStatus.NOT_OBSERVED
    selector: Optional[str] = None
    signing_domain: Optional[str] = None
    algorithm: Optional[str] = None
    canonicalization: Optional[str] = None
    body_hash_present: bool = False
    body_hash: Optional[str] = None
    public_key_record: Optional[str] = None
    public_key_type: Optional[str] = None
    public_key_bits: Optional[int] = None
    dkim_verification_status: str = "NOT_VERIFIED"  # Strictly NOT_VERIFIED unless actual crypto verification occurs
    signature_present: bool = False
    analysis_limitations: List[str] = field(default_factory=list)


@dataclass
class DMARCRecordDetails:
    """Detailed DMARC policy record evaluation."""
    status: DNSAuthStatus = DNSAuthStatus.NOT_OBSERVED
    raw_record: Optional[str] = None
    policy_p: Optional[str] = None  # "none", "quarantine", "reject"
    subdomain_policy_sp: Optional[str] = None
    percentage_pct: Optional[int] = 100
    rua_uris: List[str] = field(default_factory=list)
    ruf_uris: List[str] = field(default_factory=list)
    adkim_mode: str = "r"
    aspf_mode: str = "r"
    syntax_valid: bool = True
    alignment_evaluated: bool = False
    message_dmarc_result: str = "NOT_EVALUATED"  # Strictly NOT_EVALUATED unless sender/DKIM cryptographic result is known
    analysis_limitations: List[str] = field(default_factory=list)


@dataclass
class MTASTSRecordDetails:
    """Detailed MTA-STS policy record evaluation."""
    status: DNSAuthStatus = DNSAuthStatus.NOT_OBSERVED
    raw_record: Optional[str] = None
    version: Optional[str] = None
    id_tag: Optional[str] = None
    policy_mode: Optional[str] = None  # "enforce", "testing", "none"
    max_age_seconds: Optional[int] = None
    mx_patterns: List[str] = field(default_factory=list)
    https_policy_fetched: bool = False
    https_policy_url: Optional[str] = None
    https_fetch_timestamp: Optional[str] = None
    analysis_limitations: List[str] = field(default_factory=list)


@dataclass
class BIMIRecordDetails:
    """Detailed BIMI brand indicator record evaluation."""
    status: DNSAuthStatus = DNSAuthStatus.NOT_OBSERVED
    raw_record: Optional[str] = None
    version: Optional[str] = None
    location_svg: Optional[str] = None
    authority_vmc: Optional[str] = None
    vmc_validation_status: str = "NOT_VALIDATED"
    brand_validation_claimed: bool = False
    analysis_limitations: List[str] = field(default_factory=list)


@dataclass
class DANERecordDetails:
    """Detailed DANE TLSA and DNSSEC record evaluation."""
    status: DNSAuthStatus = DNSAuthStatus.NOT_OBSERVED
    tlsa_records: List[str] = field(default_factory=list)
    parsed_usages: List[int] = field(default_factory=list)
    dnssec_status: str = "NOT_VALIDATED"  # Strictly NOT_VALIDATED unless real cryptographic DNSSEC validation occurs
    analysis_limitations: List[str] = field(default_factory=list)


@dataclass
class DomainAuthenticationAssessment:
    """Aggregated domain email authentication assessment with strict provenance separation."""
    domain: str
    source: AuthProvenanceSource = AuthProvenanceSource.PASSIVE_CAPTURE
    historical_applicability: HistoricalApplicability = HistoricalApplicability.UNKNOWN
    queried_at_utc: Optional[str] = None
    resolver_provider: Optional[str] = None
    resolver_endpoint: Optional[str] = None
    is_active_enrichment: bool = False
    spf: SPFRecordDetails = field(default_factory=SPFRecordDetails)
    dkim: Optional[DKIMRecordDetails] = None
    dmarc: DMARCRecordDetails = field(default_factory=DMARCRecordDetails)
    mta_sts: MTASTSRecordDetails = field(default_factory=MTASTSRecordDetails)
    bimi: BIMIRecordDetails = field(default_factory=BIMIRecordDetails)
    dane: DANERecordDetails = field(default_factory=DANERecordDetails)
    overall_auth_posture: str = "NOT_EVALUATED"
    authoritative_boundary_disclaimer: str = (
        "Active DNS enrichment results reflect current live DNS state and do NOT alter or represent historical capture evidence."
    )
    limitations: List[str] = field(default_factory=list)


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
class FindingEvidenceItem:
    """Explicit evidence element supporting a deterministic finding."""
    type: str                            # e.g., "FRAME_HEADER", "PROTOCOL_COMMAND", "CIPHER_SUITE", "TLS_VERSION", "KEY_SHARE"
    frame: Optional[int]                 # Frame number where evidence was observed (None if absent/inferred from stream)
    field: str                           # Observed attribute or field name
    observed_value: str                  # Value extracted directly from packet evidence


@dataclass
class FindingExplanation:
    """Structured explainability (XAI) metadata for a deterministic security finding."""
    finding_id: str
    rule_id: str
    why_triggered: str
    evidence: List[FindingEvidenceItem] = field(default_factory=list)
    confidence_boundary: str = "PASSIVE_OBSERVABILITY_BOUNDED"
    standards_refs: List[str] = field(default_factory=list)


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
    explanation: Optional[FindingExplanation] = None


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

    # Phase 7 Domain Email Authentication & DNS Assessment
    domain_auth: Optional[DomainAuthenticationAssessment] = None

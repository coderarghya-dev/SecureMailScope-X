"""
SecureMailScope X - API Request & Response Schemas (Pydantic DTOs)
Defines strongly typed serializable models for REST API endpoints.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# 1. Health & System Diagnostic Schemas
# ---------------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str = Field(..., example="healthy")
    tshark_available: bool = Field(..., example=True)
    tshark_version: str = Field(..., example="TShark (Wireshark) 4.6.0")
    supported_protocols: List[str] = Field(default_factory=lambda: ["SMTP", "IMAP", "POP3"])
    port_110_stls_real_capture_status: str = Field(
        default="PENDING (Target server unavailable / unserviceable on port 110)"
    )


# ---------------------------------------------------------------------------
# 2. Forensic Evidence & Handshake DTOs
# ---------------------------------------------------------------------------
class PacketEvidenceDTO(BaseModel):
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


class STARTTLSStateDTO(BaseModel):
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
    state: Optional[str] = None


class CipherSuiteInfoDTO(BaseModel):
    hex_code: str
    name: str
    has_pfs: Optional[bool] = None
    key_exchange: str
    encryption: str
    hash_algorithm: str
    strength: str
    is_post_quantum_safe: bool = False


class CertificateDetailsDTO(BaseModel):
    visibility: str = "UNKNOWN"
    frame_number: Optional[int] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    validity_status: str = "UNKNOWN"
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
    san_names: List[str] = []
    chain_length: int = 0
    chain_observed: bool = False
    chain_trust_status: str = "NOT_VALIDATED"
    analysis_limitations: List[str] = []


class TLSHandshakeDTO(BaseModel):
    negotiated_version: str
    tls_version: Optional[str] = None
    cipher_name: Optional[str] = None
    cipher_suite_name: Optional[str] = None
    cipher_code: Optional[str] = None
    cipher_info: Optional[CipherSuiteInfoDTO] = None
    forward_secrecy_pfs: Optional[bool] = None
    pfs_status: str
    pfs_evidence: Optional[str] = None
    sni: Optional[str] = None
    alpn: Optional[str] = None
    client_hello_frame: Optional[int] = None
    server_hello_frame: Optional[int] = None
    certificate_visibility: str
    certificate_details: Optional[CertificateDetailsDTO] = None


class CaptureHealthDTO(BaseModel):
    score: int
    grade: str
    syn_observed: bool
    fin_rst_observed: bool
    total_packets: int
    retransmissions_count: int
    retransmission_rate: float
    deduction_reasons: List[str]


class EvidenceConfidenceDTO(BaseModel):
    score: int
    level: str
    handshake_observable: bool = False
    version_verifiable: bool = False
    cipher_identifiable: bool = False
    key_exchange_observable: bool = False
    observability_boundary: Optional[str] = None
    confidence_factors: List[str] = []


class FindingEvidenceItemDTO(BaseModel):
    type: str
    frame: Optional[int] = None
    field: str
    observed_value: str


class FindingExplanationDTO(BaseModel):
    finding_id: str
    rule_id: str
    why_triggered: str
    evidence: List[FindingEvidenceItemDTO] = []
    confidence_boundary: str
    standards_refs: List[str] = []


class SecurityFindingDTO(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    description: str
    evidence_frames: List[int] = []
    recommendation: Optional[str] = None
    explanation: Optional[FindingExplanationDTO] = None


class FindingsSummaryDTO(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class SecurityAssessmentDTO(BaseModel):
    grade: str
    grade_rationale: str
    post_quantum_ready: bool
    post_quantum_summary: str
    findings_summary: FindingsSummaryDTO
    findings: List[SecurityFindingDTO]


class EvidenceFrameDTO(BaseModel):
    frame: int
    time_epoch: float
    protocol: str
    summary: str


# ---------------------------------------------------------------------------
# 3. Session Overview & Detail DTOs
# ---------------------------------------------------------------------------
class SessionSummaryDTO(BaseModel):
    session_id: str
    stream_index: int
    protocol: str
    security_mode: str
    client: str
    server: str
    server_hostname: Optional[str] = None
    start_time_iso: Optional[str] = None
    duration_seconds: float
    packets_count: int
    security_grade: str
    health_score: int
    health_grade: str
    confidence_level: str
    post_quantum_ready: bool


class MLFeatureContributionDTO(BaseModel):
    feature: str
    description: str
    value: float
    contribution: float


class MLTriageDTO(BaseModel):
    enabled: bool = True
    model_status: str = "EXPERIMENTAL_ENGINEERING_MODEL"
    advisory_risk_class: str
    risk_probability: float
    model_version: str
    model_type: str
    authoritative: bool = False
    disclaimer: str
    feature_vector: Dict[str, float]
    top_risk_contributors: List[MLFeatureContributionDTO] = []
    top_protective_factors: List[MLFeatureContributionDTO] = []


# ---------------------------------------------------------------------------
# Domain Authentication & DNS DTOs (Phase 7)
# ---------------------------------------------------------------------------
class SPFRecordDetailsDTO(BaseModel):
    status: str = "NOT_OBSERVED"
    raw_record: Optional[str] = None
    version: Optional[str] = None
    policy_qualifier: Optional[str] = None
    mechanisms: List[str] = []
    include_domains: List[str] = []
    redirect_domain: Optional[str] = None
    lookup_count: int = 0
    lookup_count_status: str = "NOT_EVALUATED"
    lookup_limit_exceeded: Optional[bool] = None
    lookup_limit_risk: Optional[str] = None
    syntax_valid: bool = True
    syntax_error: Optional[str] = None
    spf_policy_present: bool = False
    spf_message_result: Optional[str] = None
    analysis_limitations: List[str] = []


class DKIMRecordDetailsDTO(BaseModel):
    status: str = "NOT_OBSERVED"
    selector: Optional[str] = None
    signing_domain: Optional[str] = None
    algorithm: Optional[str] = None
    canonicalization: Optional[str] = None
    body_hash_present: bool = False
    body_hash: Optional[str] = None
    public_key_record: Optional[str] = None
    public_key_type: Optional[str] = None
    public_key_bits: Optional[int] = None
    dkim_verification_status: str = "NOT_VERIFIED"
    signature_present: bool = False
    analysis_limitations: List[str] = []


class DMARCRecordDetailsDTO(BaseModel):
    status: str = "NOT_OBSERVED"
    raw_record: Optional[str] = None
    policy_p: Optional[str] = None
    subdomain_policy_sp: Optional[str] = None
    percentage_pct: Optional[int] = 100
    rua_uris: List[str] = []
    ruf_uris: List[str] = []
    adkim_mode: str = "r"
    aspf_mode: str = "r"
    syntax_valid: bool = True
    alignment_evaluated: bool = False
    message_dmarc_result: str = "NOT_EVALUATED"
    analysis_limitations: List[str] = []


class MTASTSRecordDetailsDTO(BaseModel):
    status: str = "NOT_OBSERVED"
    raw_record: Optional[str] = None
    version: Optional[str] = None
    id_tag: Optional[str] = None
    policy_mode: Optional[str] = None
    max_age_seconds: Optional[int] = None
    mx_patterns: List[str] = []
    https_policy_fetched: bool = False
    https_policy_url: Optional[str] = None
    https_fetch_timestamp: Optional[str] = None
    analysis_limitations: List[str] = []


class BIMIRecordDetailsDTO(BaseModel):
    status: str = "NOT_OBSERVED"
    raw_record: Optional[str] = None
    version: Optional[str] = None
    location_svg: Optional[str] = None
    authority_vmc: Optional[str] = None
    vmc_validation_status: str = "NOT_VALIDATED"
    brand_validation_claimed: bool = False
    analysis_limitations: List[str] = []


class DANERecordDetailsDTO(BaseModel):
    status: str = "NOT_OBSERVED"
    tlsa_records: List[str] = []
    parsed_usages: List[int] = []
    dnssec_status: str = "NOT_VALIDATED"
    analysis_limitations: List[str] = []


class DomainAuthenticationAssessmentDTO(BaseModel):
    domain: str
    source: str = "PASSIVE_CAPTURE"
    historical_applicability: str = "UNKNOWN"
    queried_at_utc: Optional[str] = None
    resolver_provider: Optional[str] = None
    resolver_endpoint: Optional[str] = None
    is_active_enrichment: bool = False
    spf: SPFRecordDetailsDTO = SPFRecordDetailsDTO()
    dkim: Optional[DKIMRecordDetailsDTO] = None
    dmarc: DMARCRecordDetailsDTO = DMARCRecordDetailsDTO()
    mta_sts: MTASTSRecordDetailsDTO = MTASTSRecordDetailsDTO()
    bimi: BIMIRecordDetailsDTO = BIMIRecordDetailsDTO()
    dane: DANERecordDetailsDTO = DANERecordDetailsDTO()
    overall_auth_posture: str = "NOT_EVALUATED"
    authoritative_boundary_disclaimer: str = (
        "Active DNS enrichment results reflect current live DNS state and do NOT alter or represent historical capture evidence."
    )
    limitations: List[str] = []


class SessionDetailDTO(BaseModel):
    session_id: str
    stream_index: int
    protocol: str
    security_mode: str
    client: str
    server: str
    server_hostname: Optional[str] = None
    start_time_iso: Optional[str] = None
    duration_seconds: float
    packets_count: int
    greeting_banner: Optional[str] = None
    client_helo_name: Optional[str] = None
    starttls: STARTTLSStateDTO
    tls: Optional[TLSHandshakeDTO] = None
    capture_health: CaptureHealthDTO
    evidence_confidence: EvidenceConfidenceDTO
    security_assessment: SecurityAssessmentDTO
    evidence_frames: List[EvidenceFrameDTO] = []
    ml_triage: Optional[MLTriageDTO] = None
    certificate_details: Optional[CertificateDetailsDTO] = None
    domain_auth: Optional[DomainAuthenticationAssessmentDTO] = None


# ---------------------------------------------------------------------------
# 3b. Incident Correlation & Multi-Session Summary DTOs
# ---------------------------------------------------------------------------
class CorrelatedIncidentDTO(BaseModel):
    incident_id: str
    incident_type: str
    severity: str
    session_ids: List[str] = []
    finding_ids: List[str] = []
    evidence_frames: List[int] = []
    correlation_reasons: List[str] = []
    confidence: str = "HIGH"
    authoritative: bool = True
    evidence_backed: bool = True
    correlation_method: str = "DETERMINISTIC_RULE_CORRELATION"
    pattern_name: Optional[str] = None
    endpoint: Optional[str] = None
    evidence_summary: Optional[str] = None
    recommendation: Optional[str] = None


class MultiSessionSummaryDTO(BaseModel):
    total_sessions: int = 0
    sessions_with_findings: int = 0
    incident_count: int = 0
    critical_high_incident_count: int = 0
    repeated_pattern_count: int = 0
    uncorrelated_sessions_count: int = 0


# ---------------------------------------------------------------------------
# 4. Analysis Summary & Listing Responses
# ---------------------------------------------------------------------------
class AnalysisSummaryResponse(BaseModel):
    analysis_id: str
    file_name: str
    file_size_bytes: int
    analysis_time_utc: str
    tshark_version: str
    total_packets_extracted: int
    raw_capture_packets_total: Optional[int] = None
    email_sessions_found: int
    sessions: List[SessionSummaryDTO]
    multi_session_summary: Optional[MultiSessionSummaryDTO] = None
    correlated_incidents: List[CorrelatedIncidentDTO] = []


class AnalysisDetailResponse(BaseModel):
    analysis_id: str
    file_name: str
    file_size_bytes: int
    analysis_time_utc: str
    tshark_version: str
    total_packets_extracted: int
    raw_capture_packets_total: Optional[int] = None
    email_sessions_found: int
    sessions: List[SessionDetailDTO]
    evidence_confidence_score: Optional[int] = None
    evidence_confidence_level: Optional[str] = None
    multi_session_summary: Optional[MultiSessionSummaryDTO] = None
    correlated_incidents: List[CorrelatedIncidentDTO] = []


# ---------------------------------------------------------------------------
# 5. Rule Catalog Schemas
# ---------------------------------------------------------------------------
class RuleMetadataDTO(BaseModel):
    id: str
    title: str
    category: str
    default_severity: str
    standard_reference: str
    description: str
    mitigation: Optional[str] = None


class RulesCatalogResponse(BaseModel):
    total_rules: int
    rules: List[RuleMetadataDTO]


# ---------------------------------------------------------------------------
# 6. Forensic Report Schemas
# ---------------------------------------------------------------------------
class CaseMetadataDTO(BaseModel):
    filename: str
    analysis_id: str
    file_size_bytes: int
    raw_pcap_frame_count: int
    reconstructed_session_count: int
    protocols_detected: List[str]
    analysis_timestamp_utc: str
    tshark_version: str


class ExecutiveSummaryDTO(BaseModel):
    security_grade: str
    security_score: int
    capture_health_score: int
    capture_health_grade: str
    evidence_confidence_score: int
    evidence_confidence_level: str
    critical_findings_count: int
    high_findings_count: int
    medium_findings_count: int
    low_findings_count: int
    info_findings_count: int
    overall_transport_posture: str
    pqc_hndl_assessment_state: str


class SessionReportItemDTO(BaseModel):
    session_id: str
    client: str
    server: str
    server_hostname: Optional[str] = None
    protocol: str
    transport_mode: str
    starttls_state: str
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_visibility: str
    pfs_evidence_state: str
    pqc_evidence_state: str


class FindingReportItemDTO(BaseModel):
    severity: str
    finding_id: str
    title: str
    description: str
    remediation: Optional[str] = None
    standards_reference: str
    session_id: str
    native_frame_anchors: List[int] = []
    frame_anchors_display: str


class EvidenceMappingItemDTO(BaseModel):
    session_id: str
    protocol: str
    raw_capture_total_frames: int
    session_packet_count: int
    advertised_frame: Optional[int] = None
    requested_frame: Optional[int] = None
    accepted_frame: Optional[int] = None
    client_hello_frame: Optional[int] = None
    server_hello_frame: Optional[int] = None


class CryptographicPostureDTO(BaseModel):
    tls_versions: List[str]
    cipher_suites: List[str]
    transport_encryption_coverage: str
    certificate_visibility: str
    forward_secrecy_evidence_state: str
    legacy_crypto_exposure: str


class PQCHNDLAssessmentDTO(BaseModel):
    status: str
    observed_key_exchange: str
    hndl_exposure_summary: str
    recommended_kem_standard: str
    standards_references: List[str]


class ForensicReportResponse(BaseModel):
    case_metadata: CaseMetadataDTO
    executive_summary: ExecutiveSummaryDTO
    session_inventory: List[SessionReportItemDTO]
    findings: List[FindingReportItemDTO]
    evidence_mapping: List[EvidenceMappingItemDTO]
    cryptographic_posture: CryptographicPostureDTO
    pqc_hndl_assessment: PQCHNDLAssessmentDTO
    forensic_limitations: List[str]


# ---------------------------------------------------------------------------
# 7. Chain of Custody & Evidence Sealing Schemas
# ---------------------------------------------------------------------------
class CustodyEventDTO(BaseModel):
    event_id: str
    analysis_id: str
    timestamp_utc: str
    event_type: str
    artifact_hash: str
    previous_event_hash: str
    current_event_hash: str
    details: Optional[str] = None
    actor_id: Optional[str] = "SYSTEM"
    actor_display_name: Optional[str] = "SecureMailScope X"
    actor_identity_source: Optional[str] = "SYSTEM"
    actor_attribution_status: Optional[str] = "SYSTEM_GENERATED"
    hash_format_version: Optional[str] = "CUSTODY_EVENT_HASH_V2"


class CaptureIntegrityDTO(BaseModel):
    filename: str
    file_size_bytes: int
    sha256: str
    ingestion_timestamp_utc: str
    status: str


class ManifestIntegrityDTO(BaseModel):
    manifest_hash: str
    canonicalization_method: str
    created_at_utc: str
    raw_pcap_frame_count: int
    reconstructed_session_count: int
    findings_count: int
    status: str


class ReportIntegrityDTO(BaseModel):
    pdf_sha256: Optional[str] = None
    status: str


class CustodyRecordResponse(BaseModel):
    analysis_id: str
    overall_status: str
    verification_timestamp_utc: Optional[str] = None
    capture_integrity: CaptureIntegrityDTO
    manifest_integrity: ManifestIntegrityDTO
    report_integrity: ReportIntegrityDTO
    audit_events: List[CustodyEventDTO]
    verification_details: Optional[str] = None


# ---------------------------------------------------------------------------
# 8. Manifest Versioning & Report Artifact Schemas (Phase 13)
# ---------------------------------------------------------------------------
class ReportArtifactDTO(BaseModel):
    report_artifact_id: str
    analysis_id: str
    report_type: str = "PDF"
    report_version: int = 1
    filename: str
    media_type: str = "application/pdf"
    artifact_sha256: str
    artifact_size_bytes: int
    generated_at: str
    generated_by_actor_id: str = "SYSTEM"
    generated_by_actor_display_name: str = "SecureMailScope X"
    actor_identity_source: str = "SYSTEM"
    actor_attribution_status: str = "SYSTEM_GENERATED"
    generator_version: str = "SecureMailScope X 1.0.0"
    source_manifest_version_id: str
    status: str = "GENERATED"
    file_path: Optional[str] = None
    raw_bytes: Optional[bytes] = None


class CustodyManifestVersionDTO(BaseModel):
    manifest_version_id: str
    analysis_id: str
    version_number: int
    manifest_type: str
    parent_manifest_version_id: Optional[str] = None
    previous_manifest_sha256: str
    manifest_json: str
    manifest_dict: Optional[Dict[str, Any]] = None
    manifest_sha256: str
    canonicalization_version: str = "SECUREMAILSCOPE_CANONICAL_JSON_V1"
    created_at: str
    created_by_actor_id: str = "UNATTRIBUTED"
    created_by_actor_display_name: str = "Unattributed Analyst"
    actor_identity_source: str = "UNKNOWN"
    actor_attribution_status: str = "UNATTRIBUTED"
    sealed: bool = True
    supersedes_version_id: Optional[str] = None
    purpose: Optional[str] = None
    schema_version: str = "1.0"
    linked_report_artifacts: List[Dict[str, Any]] = []
    linked_signatures: List[Dict[str, Any]] = []


class ManifestChainVerificationResponse(BaseModel):
    analysis_id: str
    overall_status: str  # "VERIFIED" | "INTEGRITY_FAILED" | "INCOMPLETE"
    versions_count: int
    versions_verified: List[Dict[str, Any]] = []
    verification_timestamp_utc: str
    details: Optional[str] = None


# ---------------------------------------------------------------------------
# 9. Digital Report Signing & Signature Schemas (Phase 14)
# ---------------------------------------------------------------------------
class ReportSignatureRequest(BaseModel):
    key_id: Optional[str] = None
    private_key_pem: Optional[str] = None
    private_key_password: Optional[str] = None
    algorithm: Optional[str] = None


class DigitalSignatureDTO(BaseModel):
    signature_id: str
    analysis_id: str
    report_artifact_id: str
    manifest_version_id: str
    signature_algorithm: str
    signature_format: str = "BASE64"
    signature_value: str
    signed_digest_algorithm: str = "SHA256"
    signed_digest_value: str
    public_key_fingerprint_sha256: str
    public_key_pem: str
    key_id: str
    signed_at: str
    signed_by_actor_id: str = "UNATTRIBUTED"
    signed_by_actor_display_name: str = "Unattributed Analyst"
    actor_identity_source: str = "UNKNOWN"
    actor_attribution_status: str = "UNATTRIBUTED"
    verification_status: str = "VERIFIED"
    schema_version: str = "1.0"


class SignatureVerificationResponse(BaseModel):
    signature_id: str
    analysis_id: str
    report_artifact_id: str
    manifest_version_id: str
    verification_status: str  # VERIFIED | SIGNATURE_INVALID | ARTIFACT_INTEGRITY_FAILED | MANIFEST_INTEGRITY_FAILED | PUBLIC_KEY_MISMATCH | UNSUPPORTED_ALGORITHM | INCOMPLETE
    signature_algorithm: str
    public_key_fingerprint_sha256: str
    key_id: str
    signed_at: str
    signed_by_actor: Dict[str, Any]
    verification_timestamp_utc: str
    details: Optional[str] = None


class ReportSignaturesListResponse(BaseModel):
    analysis_id: str
    report_artifact_id: str
    total_signatures: int
    signatures: List[DigitalSignatureDTO]


# ---------------------------------------------------------------------------
# 10. Notarization Provider & External Blockchain Anchoring Schemas (Phase 15 & 16)
# ---------------------------------------------------------------------------
class NotarizationRequest(BaseModel):
    signature_id: Optional[str] = None
    mode: str = "LOCAL_ONLY"


class NotarizationRecordDTO(BaseModel):
    notarization_id: str
    analysis_id: str
    report_artifact_id: str
    signature_id: str
    manifest_version_id: str
    notarization_mode: str = "LOCAL_ONLY"
    provider_name: Optional[str] = None
    provider_reference: Optional[str] = None
    submitted_payload_sha256: Optional[str] = None
    local_proof_sha256: str
    provider_proof_json: Optional[str] = None
    provider_proof_sha256: Optional[str] = None
    status: str = "LOCAL_PROOF_CREATED"
    chain_id: Optional[int] = None
    transaction_hash: Optional[str] = None
    block_number: Optional[int] = None
    receipt_status: Optional[int] = None
    anchored_value: Optional[str] = None
    submitted_at: Optional[str] = None
    confirmed_at: Optional[str] = None
    external_verification_timestamp: Optional[str] = None
    created_at: str
    created_by_actor_id: str = "UNATTRIBUTED"
    created_by_actor_display_name: str = "Unattributed Analyst"
    actor_identity_source: str = "UNKNOWN"
    actor_attribution_status: str = "UNATTRIBUTED"
    schema_version: str = "1.0"


class NotarizationVerificationResponse(BaseModel):
    notarization_id: str
    analysis_id: str
    report_artifact_id: str
    signature_id: str
    manifest_version_id: str
    notarization_mode: str
    status: str
    verification_status: str  # VERIFIED_LOCAL_PROOF | VERIFIED_EXTERNAL_ANCHOR | INTEGRITY_FAILED | SIGNATURE_INVALID | REPORT_INTEGRITY_FAILED | MANIFEST_INTEGRITY_FAILED | INCOMPLETE | UNSUPPORTED_PROVIDER | TRANSACTION_NOT_FOUND | RECEIPT_PENDING | TRANSACTION_REVERTED | CHAIN_ID_MISMATCH | ANCHOR_VALUE_MISMATCH
    local_proof_sha256: str
    chain_id: Optional[int] = None
    transaction_hash: Optional[str] = None
    block_number: Optional[int] = None
    receipt_status: Optional[int] = None
    anchored_value: Optional[str] = None
    created_at: str
    created_by_actor: Dict[str, Any]
    verification_timestamp_utc: str
    details: Optional[str] = None


class AnalysisNotarizationsListResponse(BaseModel):
    analysis_id: str
    report_artifact_id: Optional[str] = None
    total_notarizations: int
    notarizations: List[NotarizationRecordDTO]


class BlockchainProviderStatusResponse(BaseModel):
    configured: bool = False
    provider_type: str = "LOCAL_ONLY"
    submission_mode: str = "RPC_MANAGED_ACCOUNT"
    chain_id: Optional[int] = None
    connection_status: str = "NOT_CONFIGURED"
    network_connection_status: Optional[str] = None
    local_private_key_signing: str = "NOT_IMPLEMENTED"
    implementation_status: str = "IMPLEMENTED_AND_MOCK_TESTED"
    live_chain_verified: bool = False
    from_address_configured: bool = False
    anchor_address_configured: bool = False



# ---------------------------------------------------------------------------
# 11. Standard Error Response
# ---------------------------------------------------------------------------
class ErrorResponse(BaseModel):
    status_code: int
    error_code: str
    message: str
    details: Optional[Any] = None





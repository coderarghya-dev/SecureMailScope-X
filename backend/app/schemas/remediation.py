# ==============================================================================
# SecureMailScope X — Phase 23: Remediation Playbooks & Simulate-Fix Schemas
# ==============================================================================
"""Data models and schemas for evidence-based remediation playbooks, platform
configuration guidance (Postfix, Exim, Dovecot, Sendmail, Generic), deterministic
simulate-fix risk projections, and verify-after-fix forensic workflows.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RemediationPlatform(str, Enum):
    POSTFIX = "POSTFIX"
    EXIM = "EXIM"
    DOVECOT = "DOVECOT"
    SENDMAIL = "SENDMAIL"
    GENERIC = "GENERIC"


class RemediationCategory(str, Enum):
    TLS_CONFIGURATION = "TLS_CONFIGURATION"
    CIPHER_SUITE = "CIPHER_SUITE"
    CERTIFICATE = "CERTIFICATE"
    STARTTLS = "STARTTLS"
    PFS = "PFS"
    EMAIL_AUTHENTICATION = "EMAIL_AUTHENTICATION"
    PQC_MIGRATION = "PQC_MIGRATION"
    MAIL_SERVER_HARDENING = "MAIL_SERVER_HARDENING"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    DRIFT_RESOLUTION = "DRIFT_RESOLUTION"


class RemediationPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RemediationStatus(str, Enum):
    PROPOSED = "PROPOSED"
    USER_REPORTED_APPLIED = "USER_REPORTED_APPLIED"
    AWAITING_VERIFICATION = "AWAITING_VERIFICATION"
    VERIFIED = "VERIFIED"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationMethod(str, Enum):
    ACTIVE_SCAN = "ACTIVE_SCAN"
    PCAP_ANALYSIS = "PCAP_ANALYSIS"
    MANUAL = "MANUAL"


class PostureLabel(str, Enum):
    OBSERVED = "OBSERVED"
    ASSUMED_AFTER_FIX = "ASSUMED_AFTER_FIX"
    UNCHANGED = "UNCHANGED"
    UNAVAILABLE = "UNAVAILABLE"


class RemediationGuidanceItem(BaseModel):
    remediation_id: str
    finding_code: str
    action_title: str
    category: RemediationCategory
    priority: RemediationPriority
    platform: RemediationPlatform
    guidance_text: str
    config_snippet: str
    expected_security_effect: str
    validation_steps: List[str] = Field(default_factory=list)
    rollback_guidance: str
    assumptions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class PlaybookGenerationRequest(BaseModel):
    analysis_id: Optional[str] = None
    case_id: Optional[str] = None
    target_id: Optional[str] = None
    finding_codes: Optional[List[str]] = None
    platform: RemediationPlatform = RemediationPlatform.GENERIC


class PlaybookGenerationResponse(BaseModel):
    platform: RemediationPlatform
    total_recommendations: int
    items: List[RemediationGuidanceItem] = Field(default_factory=list)
    generated_at: str


class SimulateFixRequest(BaseModel):
    analysis_id: Optional[str] = None
    session_id: Optional[str] = None
    case_id: Optional[str] = None
    remediation_ids: List[str] = Field(default_factory=list)
    parameters: Optional[Dict[str, Any]] = None


class SimulateFixResponse(BaseModel):
    session_id: str
    observed_grade: str
    observed_score: int
    observed_findings_count: int
    projected_grade: str
    projected_score: int
    projected_findings_count: int
    applied_remediations: List[str] = Field(default_factory=list)
    not_applicable_remediations: List[str] = Field(default_factory=list)
    findings_resolved: List[Dict[str, Any]] = Field(default_factory=list)
    findings_remaining: List[Dict[str, Any]] = Field(default_factory=list)
    posture_labels: Dict[str, PostureLabel] = Field(default_factory=dict)
    assumptions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    disclaimer: str = (
        "PROJECTED POSTURE ONLY — In-memory simulation based on policy assumptions. "
        "Does not modify live server state, network services, or authoritative forensic records."
    )


class RemediationPlanItem(BaseModel):
    item_id: str
    plan_id: str
    finding_id: Optional[str] = None
    finding_code: str
    remediation_id: str
    action_title: str
    category: RemediationCategory
    priority: RemediationPriority
    guidance_text: str
    config_snippet: Optional[str] = None
    expected_security_effect: Optional[str] = None
    validation_steps: List[str] = Field(default_factory=list)
    rollback_guidance: Optional[str] = None
    status: RemediationStatus = RemediationStatus.PROPOSED
    evidence_reference: Optional[str] = None
    created_at: str


class RemediationPlan(BaseModel):
    plan_id: str
    case_id: Optional[str] = None
    analysis_id: Optional[str] = None
    target_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    platform: RemediationPlatform = RemediationPlatform.GENERIC
    status: RemediationStatus = RemediationStatus.PROPOSED
    version: int = 1
    supersedes_plan_id: Optional[str] = None
    assumptions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    items: List[RemediationPlanItem] = Field(default_factory=list)
    created_by: str
    created_at: str
    updated_at: str
    applied_by: Optional[str] = None
    applied_at: Optional[str] = None
    verified_by: Optional[str] = None
    verified_at: Optional[str] = None


class RemediationPlanCreateRequest(BaseModel):
    case_id: Optional[str] = None
    analysis_id: Optional[str] = None
    target_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    platform: RemediationPlatform = RemediationPlatform.GENERIC
    finding_codes: Optional[List[str]] = None
    custom_items: Optional[List[Dict[str, Any]]] = None


class RemediationPlanUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    platform: Optional[RemediationPlatform] = None
    status: Optional[RemediationStatus] = None


class MarkAppliedRequest(BaseModel):
    item_ids: Optional[List[str]] = None
    notes: Optional[str] = None


class VerificationRequest(BaseModel):
    verification_method: VerificationMethod = VerificationMethod.ACTIVE_SCAN
    new_analysis_id: Optional[str] = None
    new_scan_id: Optional[str] = None
    notes: Optional[str] = None


class VerificationRecord(BaseModel):
    verification_id: str
    plan_id: str
    verified_by: str
    verified_at: str
    verification_status: VerificationStatus
    verification_method: VerificationMethod
    verification_evidence_reference: Optional[str] = None
    prior_finding_count: int
    resolved_finding_count: int
    remaining_finding_count: int
    notes: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

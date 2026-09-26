"""
SecureMailScope X - Post-Quantum Cryptography Migration Planner Schemas (Phase 24)

Deterministic, evidence-backed PQC readiness assessment, quantum exposure modeling,
and 7-phase hybrid transition roadmap data transfer objects.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class PQCReadinessClassification(str, Enum):
    NOT_ASSESSED = "NOT_ASSESSED"
    CLASSICAL_ONLY = "CLASSICAL_ONLY"
    PQC_AWARE = "PQC_AWARE"
    HYBRID_READY = "HYBRID_READY"
    PQC_READY = "PQC_READY"
    UNKNOWN = "UNKNOWN"


class QuantumExposureLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class DataSensitivityLifetime(str, Enum):
    UNKNOWN = "UNKNOWN"
    SHORT_TERM = "SHORT_TERM"       # < 1 year
    MEDIUM_TERM = "MEDIUM_TERM"     # 1-5 years
    LONG_TERM = "LONG_TERM"         # > 5 years (high HNDL impact)


class PQCTransitionTargetArchitecture(str, Enum):
    HYBRID_KEM_TARGET = "HYBRID_KEM_TARGET"                         # Dual classical + ML-KEM KEX
    HYBRID_SIGNATURE_TARGET = "HYBRID_SIGNATURE_TARGET"             # Dual classical + ML-DSA / Falcon
    PQC_CERTIFICATE_TARGET = "PQC_CERTIFICATE_TARGET"               # Composite / PQC X.509 certificates
    PQC_CAPABLE_MAIL_GATEWAY = "PQC_CAPABLE_MAIL_GATEWAY"           # Mail gateway supporting hybrid TLS & S/MIME
    PQC_AWARE_TLS_TERMINATOR = "PQC_AWARE_TLS_TERMINATOR"           # Edge reverse proxy / TLS terminator


class MigrationPhaseName(str, Enum):
    PHASE_A_INVENTORY = "PHASE_A_INVENTORY"
    PHASE_B_RISK_ASSESSMENT = "PHASE_B_RISK_ASSESSMENT"
    PHASE_C_TARGET_ARCHITECTURE_SELECTION = "PHASE_C_TARGET_ARCHITECTURE_SELECTION"
    PHASE_D_PILOT_HYBRID_KEM = "PHASE_D_PILOT_HYBRID_KEM"
    PHASE_E_HYBRID_SIGNATURES = "PHASE_E_HYBRID_SIGNATURES"
    PHASE_F_PQC_PRIMARY_TRANSITION = "PHASE_F_PQC_PRIMARY_TRANSITION"
    PHASE_G_VERIFICATION = "PHASE_G_VERIFICATION"


class MigrationStepStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


class GapSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PQCRoadmapStatus(str, Enum):
    DRAFT = "DRAFT"
    IN_REVIEW = "IN_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ARCHIVED = "ARCHIVED"


# ---------------------------------------------------------------------------
# Cryptographic Asset DTOs
# ---------------------------------------------------------------------------

class CryptoAssetItem(BaseModel):
    asset_id: str
    analysis_id: Optional[str] = None
    case_id: Optional[str] = None
    target_id: Optional[str] = None
    protocol: str = "TLS"
    endpoint: str
    crypto_layer: str  # e.g., "KEY_EXCHANGE", "CIPHER", "SIGNATURE", "CERTIFICATE"
    algorithm_family: str  # e.g., "RSA", "ECDHE", "ML-KEM", "HYBRID"
    algorithm_name: str
    key_size: Optional[int] = None
    certificate_fingerprint: Optional[str] = None
    certificate_key_algorithm: Optional[str] = None
    kex_type: Optional[str] = None
    signature_algorithm: Optional[str] = None
    pqc_status: PQCReadinessClassification = PQCReadinessClassification.UNKNOWN
    hybrid_status: bool = False
    evidence_reference: str
    observed_at: str


class CryptoAssetInventoryResponse(BaseModel):
    total_assets: int
    classical_count: int
    hybrid_count: int
    pqc_ready_count: int
    unknown_count: int
    assets: List[CryptoAssetItem]


# ---------------------------------------------------------------------------
# Quantum Exposure & HNDL Risk DTOs
# ---------------------------------------------------------------------------

class PQCExposureAssessmentResponse(BaseModel):
    overall_exposure: QuantumExposureLevel
    hndl_vulnerability_level: QuantumExposureLevel
    data_sensitivity: DataSensitivityLifetime = DataSensitivityLifetime.UNKNOWN
    forward_secrecy_present: bool
    vulnerable_kex_algorithms: List[str] = Field(default_factory=list)
    vulnerable_signature_algorithms: List[str] = Field(default_factory=list)
    risk_summary: str
    evidence_references: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Gap Finding DTOs
# ---------------------------------------------------------------------------

class PQCGapFindingItem(BaseModel):
    gap_id: str
    roadmap_id: Optional[str] = None
    asset_id: Optional[str] = None
    gap_type: str  # e.g., "NO_HYBRID_KEM", "CLASSICAL_RSA_KEY", "DEPRECATED_SIGNATURE"
    severity: GapSeverity
    description: str
    evidence_reference: str
    remediation_action: str
    created_at: str


class PQCGapAnalysisRequest(BaseModel):
    analysis_id: Optional[str] = None
    target_id: Optional[str] = None
    target_architecture: PQCTransitionTargetArchitecture = PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET


class PQCGapAnalysisResponse(BaseModel):
    target_architecture: PQCTransitionTargetArchitecture
    current_readiness: PQCReadinessClassification
    total_gaps: int
    gaps: List[PQCGapFindingItem]
    readiness_summary: str


# ---------------------------------------------------------------------------
# Roadmap Step & Roadmap DTOs
# ---------------------------------------------------------------------------

class PQCMigrationStepItem(BaseModel):
    step_id: str
    roadmap_id: str
    phase_name: MigrationPhaseName
    sequence_order: int
    objective: str
    recommended_actions: List[str]
    validation_criteria: List[str]
    rollback_considerations: List[str]
    blocking_issues: List[str] = Field(default_factory=list)
    status: MigrationStepStatus = MigrationStepStatus.PENDING
    created_at: str


class PQCRoadmapCreateRequest(BaseModel):
    title: str
    description: str = ""
    case_id: Optional[str] = None
    target_id: Optional[str] = None
    analysis_id: Optional[str] = None
    target_architecture: PQCTransitionTargetArchitecture = PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET
    data_sensitivity: DataSensitivityLifetime = DataSensitivityLifetime.UNKNOWN


class PQCRoadmapUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[PQCRoadmapStatus] = None
    step_updates: Optional[Dict[str, MigrationStepStatus]] = None


class PQCRoadmapApprovalRequest(BaseModel):
    roadmap_id: str
    reviewer_analyst_id: str
    signature_algorithm: str = "Ed25519"
    signature_hex: str
    public_key_hex: str
    comments: Optional[str] = None


class PQCRoadmapResponse(BaseModel):
    roadmap_id: str
    case_id: Optional[str] = None
    target_id: Optional[str] = None
    analysis_id: Optional[str] = None
    title: str
    description: str
    current_readiness: PQCReadinessClassification
    target_profile: PQCTransitionTargetArchitecture
    exposure_level: QuantumExposureLevel
    status: PQCRoadmapStatus
    version: int = 1
    steps: List[PQCMigrationStepItem] = Field(default_factory=list)
    gaps: List[PQCGapFindingItem] = Field(default_factory=list)
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    approval_signature: Optional[str] = None
    created_by: str
    created_at: str
    updated_at: str


class PQCRoadmapListResponse(BaseModel):
    total: int
    roadmaps: List[PQCRoadmapResponse]

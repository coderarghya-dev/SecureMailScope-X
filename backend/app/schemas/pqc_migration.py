# ==============================================================================
# SecureMailScope X — Phase 24 / 25: Post-Quantum Cryptography Migration Schemas
# ==============================================================================
"""Data models and schemas for post-quantum cryptographic asset discovery,
categorical HNDL quantum exposure assessments, 7-phase transition roadmaps,
and cryptographic peer sign-offs.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PQCReadinessClassification(str, Enum):
    CLASSICAL_ONLY = "CLASSICAL_ONLY"
    PQC_READY = "PQC_READY"
    HYBRID_READY = "HYBRID_READY"
    UNKNOWN = "UNKNOWN"


class QuantumExposureLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class DataSensitivityLifetime(str, Enum):
    UNDER_5_YEARS = "UNDER_5_YEARS"
    BETWEEN_5_AND_10_YEARS = "BETWEEN_5_AND_10_YEARS"
    OVER_10_YEARS = "OVER_10_YEARS"
    UNKNOWN = "UNKNOWN"


class PQCTransitionTargetArchitecture(str, Enum):
    NIST_FIPS_203_ML_KEM = "NIST_FIPS_203_ML_KEM"
    NIST_FIPS_204_ML_DSA = "NIST_FIPS_204_ML_DSA"
    NIST_FIPS_205_SLH_DSA = "NIST_FIPS_205_SLH_DSA"
    HYBRID_CLASSICAL_PQC = "HYBRID_CLASSICAL_PQC"


class MigrationPhaseName(str, Enum):
    PHASE_A_DISCOVERY = "PHASE_A_DISCOVERY"
    PHASE_B_POLICY_GOVERNANCE = "PHASE_B_POLICY_GOVERNANCE"
    PHASE_C_HYBRID_KEM = "PHASE_C_HYBRID_KEM"
    PHASE_D_PQC_AUTH = "PHASE_D_PQC_AUTH"
    PHASE_E_QUANTUM_RESISTANT_TRANSPORT = "PHASE_E_QUANTUM_RESISTANT_TRANSPORT"
    PHASE_F_PQC_PRIMARY_TRANSITION = "PHASE_F_PQC_PRIMARY_TRANSITION"
    PHASE_G_COMPLIANCE_AUDIT = "PHASE_G_COMPLIANCE_AUDIT"


class MigrationStepStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    DEFERRED = "DEFERRED"


class GapSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PQCRoadmapStatus(str, Enum):
    DRAFT = "DRAFT"
    PROPOSED = "PROPOSED"
    REVIEWED = "REVIEWED"
    SIGNED = "SIGNED"
    DEPRECATED = "DEPRECATED"


class PQCCryptoAssetDTO(BaseModel):
    asset_id: str
    analysis_id: Optional[str] = None
    target_id: Optional[str] = None
    asset_type: str
    identifier: str
    key_exchange_algorithm: Optional[str] = None
    cipher_algorithm: Optional[str] = None
    signature_algorithm: Optional[str] = None
    key_length_bits: Optional[int] = None
    has_forward_secrecy: bool
    pqc_readiness: PQCReadinessClassification
    hndl_exposure: QuantumExposureLevel
    data_sensitivity_lifetime: DataSensitivityLifetime
    first_observed_at: str
    last_observed_at: str
    evidence_reference: Optional[str] = None


class PQCGapFindingDTO(BaseModel):
    gap_id: str
    roadmap_id: str
    asset_id: Optional[str] = None
    severity: GapSeverity
    title: str
    description: str
    affected_component: str
    recommended_pqc_replacement: str
    nist_standard_ref: str


class PQCMigrationStepDTO(BaseModel):
    step_id: str
    roadmap_id: str
    phase_number: int
    phase_name: MigrationPhaseName
    title: str
    description: str
    target_standards: List[str]
    deliverables: List[str]
    status: MigrationStepStatus
    order_index: int
    notes: Optional[str] = None
    completed_at: Optional[str] = None


class PQCMigrationStepUpdate(BaseModel):
    status: Optional[MigrationStepStatus] = None
    notes: Optional[str] = None


class PQCMigrationRoadmapDTO(BaseModel):
    roadmap_id: str
    title: str
    target_architecture: PQCTransitionTargetArchitecture
    current_readiness: PQCReadinessClassification
    highest_exposure: QuantumExposureLevel
    status: PQCRoadmapStatus
    total_steps: int
    completed_steps: int
    canonical_roadmap_sha256: str
    signed_by_analyst_id: Optional[str] = None
    signed_by_analyst_name: Optional[str] = None
    signature_algorithm: Optional[str] = None
    signature_value: Optional[str] = None
    created_by: str
    created_at: str
    updated_at: str
    steps: List[PQCMigrationStepDTO] = Field(default_factory=list)
    gaps: List[PQCGapFindingDTO] = Field(default_factory=list)


class PQCRoadmapCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=150)
    target_architecture: PQCTransitionTargetArchitecture = PQCTransitionTargetArchitecture.HYBRID_CLASSICAL_PQC
    analysis_ids: Optional[List[str]] = None
    target_ids: Optional[List[str]] = None


class PQCRoadmapSignRequest(BaseModel):
    private_key_pem: Optional[str] = None
    key_id: Optional[str] = None


class PQCDiscoveryRequest(BaseModel):
    analysis_id: Optional[str] = None
    target_id: Optional[str] = None
    data_sensitivity_lifetime: DataSensitivityLifetime = DataSensitivityLifetime.UNKNOWN


class PQCDiscoveryResult(BaseModel):
    discovered_assets: List[PQCCryptoAssetDTO]
    overall_pqc_readiness: PQCReadinessClassification
    highest_exposure: QuantumExposureLevel

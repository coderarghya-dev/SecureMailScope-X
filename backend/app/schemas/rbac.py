# ==============================================================================
# SecureMailScope X — Phase 20/21: Multi-Analyst RBAC & Peer Review Schemas
# ==============================================================================
"""Data models and schemas for role-based access control (RBAC), multi-analyst
case assignments, review workflows, cryptographic peer sign-offs, and monitoring capabilities.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AnalystRole(str, Enum):
    FORENSIC_ANALYST = "FORENSIC_ANALYST"
    LEAD_INVESTIGATOR = "LEAD_INVESTIGATOR"
    REVIEWER = "REVIEWER"
    AUDITOR = "AUDITOR"
    ADMIN = "ADMIN"


class Capability(str, Enum):
    VIEW_CASE = "VIEW_CASE"
    EDIT_CASE = "EDIT_CASE"
    ASSIGN_ANALYST = "ASSIGN_ANALYST"
    REQUEST_REVIEW = "REQUEST_REVIEW"
    SUBMIT_REVIEW = "SUBMIT_REVIEW"
    SIGN_OFF = "SIGN_OFF"
    SEAL_CASE = "SEAL_CASE"
    OVERRIDE_POLICY = "OVERRIDE_POLICY"
    MANAGE_ROLES = "MANAGE_ROLES"
    VIEW_MONITORING = "VIEW_MONITORING"
    MANAGE_MONITORED_TARGETS = "MANAGE_MONITORED_TARGETS"
    RUN_MONITOR_SCAN = "RUN_MONITOR_SCAN"
    PIN_POSTURE_BASELINE = "PIN_POSTURE_BASELINE"
    VIEW_DRIFT_HISTORY = "VIEW_DRIFT_HISTORY"
    VIEW_REMEDIATION = "VIEW_REMEDIATION"
    CREATE_REMEDIATION_PLAN = "CREATE_REMEDIATION_PLAN"
    EDIT_REMEDIATION_PLAN = "EDIT_REMEDIATION_PLAN"
    RUN_SIMULATION = "RUN_SIMULATION"
    MARK_APPLIED = "MARK_APPLIED"
    VERIFY_REMEDIATION = "VERIFY_REMEDIATION"
    VIEW_ALERTS = "VIEW_ALERTS"
    MANAGE_ALERT_RULES = "MANAGE_ALERT_RULES"
    EVALUATE_ALERTS = "EVALUATE_ALERTS"
    ACKNOWLEDGE_ALERT = "ACKNOWLEDGE_ALERT"
    RESOLVE_ALERT = "RESOLVE_ALERT"
    VIEW_PQC_ROADMAP = "VIEW_PQC_ROADMAP"
    CREATE_PQC_ROADMAP = "CREATE_PQC_ROADMAP"
    EDIT_PQC_ROADMAP = "EDIT_PQC_ROADMAP"
    SIGN_PQC_ROADMAP = "SIGN_PQC_ROADMAP"



class AssignmentRole(str, Enum):
    PRIMARY_INVESTIGATOR = "PRIMARY_INVESTIGATOR"
    ASSIGNED_ANALYST = "ASSIGNED_ANALYST"
    ASSIGNED_REVIEWER = "ASSIGNED_REVIEWER"


class ReviewStatus(str, Enum):
    NOT_REQUESTED = "NOT_REQUESTED"
    PENDING_REVIEW = "PENDING_REVIEW"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AnalystRecord(BaseModel):
    analyst_id: str
    display_name: str
    email_or_label: Optional[str] = None
    role: AnalystRole = AnalystRole.FORENSIC_ANALYST
    identity_source: str = "LOCAL_DECLARED"
    attribution_status: str = "ATTRIBUTED"
    is_active: bool = True
    created_at: str
    updated_at: str


class RoleUpdateRequest(BaseModel):
    role: AnalystRole
    reason: Optional[str] = None


class CaseAssignment(BaseModel):
    assignment_id: str
    case_id: str
    analyst_id: str
    analyst_name: str
    role: AssignmentRole = AssignmentRole.ASSIGNED_ANALYST
    assigned_by: str
    assigned_at: str
    is_active: bool = True


class AssignAnalystRequest(BaseModel):
    analyst_id: str
    role: AssignmentRole = AssignmentRole.ASSIGNED_ANALYST


class CaseReviewPolicy(BaseModel):
    policy_id: str
    case_id: str
    min_approvals_required: int = 1
    require_lead_investigator_approval: bool = False
    allow_self_review: bool = False
    created_at: str
    updated_at: str


class CaseReviewPolicyUpdate(BaseModel):
    min_approvals_required: Optional[int] = Field(None, ge=1, le=10)
    require_lead_investigator_approval: Optional[bool] = None
    allow_self_review: Optional[bool] = None


class CaseReview(BaseModel):
    review_id: str
    case_id: str
    manifest_sha256_at_review: str
    reviewer_id: str
    reviewer_name: str
    reviewer_role: AnalystRole
    decision: ReviewStatus
    comments: Optional[str] = None
    signature_id: Optional[str] = None
    signature_value: Optional[str] = None
    signed_payload_sha256: Optional[str] = None
    public_key_pem: Optional[str] = None
    public_key_fingerprint: Optional[str] = None
    reviewed_at: str
    is_active: bool = True
    manifest_matches_current: bool = True


class RequestReviewRequest(BaseModel):
    target_reviewer_ids: Optional[List[str]] = None
    comments: Optional[str] = None


class SubmitReviewRequest(BaseModel):
    decision: ReviewStatus
    comments: Optional[str] = None
    private_key_pem: Optional[str] = None
    key_id: Optional[str] = None


class SignOffDTO(BaseModel):
    case_id: str
    manifest_sha256: str
    reviewer_id: str
    reviewer_name: str
    decision: ReviewStatus
    timestamp: str
    signature_value: str
    public_key_pem: str
    key_id: str


class CaseAuthorizationStatus(BaseModel):
    case_id: str
    current_manifest_sha256: str
    review_status: ReviewStatus
    policy: CaseReviewPolicy
    approvals_count: int
    required_approvals: int
    can_seal: bool
    unmet_reasons: List[str] = Field(default_factory=list)
    reviews: List[CaseReview] = Field(default_factory=list)


class SignatureVerificationRequest(BaseModel):
    case_id: str
    review_id: str


class SignatureVerificationResponse(BaseModel):
    valid: bool
    manifest_matches_current: bool
    public_key_fingerprint: Optional[str] = None
    verification_details: str

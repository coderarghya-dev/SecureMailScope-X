# ==============================================================================
# SecureMailScope X — Phase 20: RBAC & Peer Review REST Endpoints
# ==============================================================================
"""REST API endpoints for analyst role management, case assignments, review
policies, peer sign-offs, signature verification, and case sealing.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query

from app.schemas.identity import ActorContext
from app.schemas.rbac import (
    AnalystRecord,
    AnalystRole,
    AssignAnalystRequest,
    Capability,
    CaseAssignment,
    CaseAuthorizationStatus,
    CaseReview,
    CaseReviewPolicy,
    CaseReviewPolicyUpdate,
    RequestReviewRequest,
    RoleUpdateRequest,
    SignatureVerificationRequest,
    SignatureVerificationResponse,
    SubmitReviewRequest,
)
from app.services.rbac_service import (
    ROLE_CAPABILITIES,
    AuthorizationService,
    CaseAssignmentService,
    CaseManifestService,
    PeerReviewService,
)

router = APIRouter(prefix="/rbac")


def _get_actor(x_actor_id: Optional[str], x_actor_name: Optional[str]) -> ActorContext:
    return ActorContext(
        actor_id=x_actor_id or "local-analyst-01",
        actor_display_name=x_actor_name or "Local Forensic Analyst",
        identity_source="LOCAL_DECLARED",
        attribution_status="ATTRIBUTED",
    )


# ------------------------------------------------------------------------------
# 1. Roles & Analyst Management
# ------------------------------------------------------------------------------

@router.get("/roles")
def get_roles_and_capabilities():
    """Retrieve system RBAC roles and their associated capabilities."""
    return {
        role.value: [cap.value for cap in sorted(caps, key=lambda x: x.value)]
        for role, caps in ROLE_CAPABILITIES.items()
    }


@router.get("/analysts", response_model=List[AnalystRecord])
def list_analysts():
    """List all registered analysts."""
    return AuthorizationService.list_analysts()


@router.get("/analysts/{analyst_id}", response_model=AnalystRecord)
def get_analyst(analyst_id: str):
    """Get single analyst profile."""
    analyst = AuthorizationService.get_analyst(analyst_id)
    if not analyst:
        raise HTTPException(status_code=404, detail=f"Analyst '{analyst_id}' not found")
    return analyst


@router.post("/analysts/{analyst_id}/role", response_model=AnalystRecord)
def update_analyst_role(
    analyst_id: str,
    req: RoleUpdateRequest,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Update an analyst's RBAC role."""
    actor = _get_actor(x_actor_id, x_actor_name)
    try:
        return AuthorizationService.set_analyst_role(
            analyst_id=analyst_id,
            new_role=req.role,
            reason=req.reason,
            actor=actor,
        )
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))


# ------------------------------------------------------------------------------
# 2. Case Assignments
# ------------------------------------------------------------------------------

@router.get("/cases/{case_id}/assignments", response_model=List[CaseAssignment])
def get_case_assignments(
    case_id: str,
    active_only: bool = Query(True),
):
    """List all assignments for a case."""
    return CaseAssignmentService.list_assignments(case_id, active_only=active_only)


@router.post("/cases/{case_id}/assignments", response_model=CaseAssignment)
def assign_analyst_to_case(
    case_id: str,
    req: AssignAnalystRequest,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Assign an analyst to a case."""
    actor = _get_actor(x_actor_id, x_actor_name)
    try:
        return CaseAssignmentService.assign_analyst(
            case_id=case_id,
            analyst_id=req.analyst_id,
            role=req.role,
            assigned_by=actor.actor_id,
            actor=actor,
        )
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))


@router.delete("/cases/{case_id}/assignments/{assignment_id}")
def remove_case_assignment(
    case_id: str,
    assignment_id: str,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Deactivate an analyst case assignment."""
    actor = _get_actor(x_actor_id, x_actor_name)
    success = CaseAssignmentService.remove_assignment(case_id, assignment_id, actor=actor)
    if not success:
        raise HTTPException(status_code=404, detail="Assignment not found")
    return {"status": "deactivated", "assignment_id": assignment_id}


# ------------------------------------------------------------------------------
# 3. Manifest & Policies
# ------------------------------------------------------------------------------

@router.get("/cases/{case_id}/manifest")
def get_case_manifest(case_id: str):
    """Compute and return current canonical case manifest SHA-256."""
    try:
        manifest_sha = CaseManifestService.compute_case_manifest_sha256(case_id)
        return {"case_id": case_id, "manifest_sha256": manifest_sha}
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))


@router.get("/cases/{case_id}/policy", response_model=CaseReviewPolicy)
def get_case_policy(case_id: str):
    """Get the review and sealing policy for a case."""
    return PeerReviewService.get_or_create_policy(case_id)


@router.put("/cases/{case_id}/policy", response_model=CaseReviewPolicy)
@router.post("/cases/{case_id}/policy", response_model=CaseReviewPolicy)
def update_case_policy(
    case_id: str,
    req: CaseReviewPolicyUpdate,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Update the review and sealing policy for a case."""
    actor = _get_actor(x_actor_id, x_actor_name)
    return PeerReviewService.update_policy(case_id, req, actor=actor)


# ------------------------------------------------------------------------------
# 4. Peer Review Lifecycle & Sign-Offs
# ------------------------------------------------------------------------------

@router.get("/cases/{case_id}/review/status", response_model=CaseAuthorizationStatus)
def get_review_status(case_id: str):
    """Evaluate whether case meets peer review criteria for sealing."""
    try:
        return PeerReviewService.get_case_authorization_status(case_id)
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))


@router.post("/cases/{case_id}/review/request")
def request_case_review(
    case_id: str,
    req: RequestReviewRequest,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Request peer review for current case state."""
    actor = _get_actor(x_actor_id, x_actor_name)
    try:
        return PeerReviewService.request_review(
            case_id=case_id,
            requested_by=actor.actor_id,
            target_reviewer_ids=req.target_reviewer_ids,
            comments=req.comments,
            actor=actor,
        )
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))


@router.post("/cases/{case_id}/review/submit", response_model=CaseReview)
def submit_case_review(
    case_id: str,
    req: SubmitReviewRequest,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Submit a peer review decision and optional cryptographic sign-off."""
    actor = _get_actor(x_actor_id, x_actor_name)
    try:
        return PeerReviewService.submit_review(
            case_id=case_id,
            reviewer_id=actor.actor_id,
            decision=req.decision,
            comments=req.comments,
            private_key_pem=req.private_key_pem,
            key_id=req.key_id,
            actor=actor,
        )
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))
    except PermissionError as ex:
        raise HTTPException(status_code=403, detail=str(ex))


@router.get("/cases/{case_id}/review/history", response_model=List[CaseReview])
def list_case_reviews(case_id: str):
    """List all reviews and cryptographic sign-offs for a case."""
    try:
        return PeerReviewService.list_reviews(case_id)
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))


@router.post("/cases/{case_id}/review/verify", response_model=SignatureVerificationResponse)
def verify_review_signature(
    case_id: str,
    req: SignatureVerificationRequest,
):
    """Verify cryptographic authenticity of a review sign-off."""
    return PeerReviewService.verify_review_signature(case_id, req.review_id)


@router.post("/cases/{case_id}/seal")
def seal_case_authorized(
    case_id: str,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Authorize and seal a case if RBAC capabilities and M-of-N sign-offs are satisfied."""
    actor = _get_actor(x_actor_id, x_actor_name)
    try:
        return PeerReviewService.authorize_and_seal_case(
            case_id=case_id,
            actor_id=actor.actor_id,
            actor=actor,
        )
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))
    except PermissionError as ex:
        raise HTTPException(status_code=403, detail=str(ex))

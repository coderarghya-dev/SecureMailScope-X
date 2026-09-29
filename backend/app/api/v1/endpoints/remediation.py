# ==============================================================================
# SecureMailScope X — Phase 23: Remediation Endpoints
# ==============================================================================
"""REST API endpoints for evidence-based remediation playbooks, deterministic
simulate-fix engine, case remediation planning, and verify-after-fix tracking.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query

from app.schemas.identity import ActorContext
from app.schemas.remediation import (
    PlaybookGenerationRequest,
    PlaybookGenerationResponse,
    SimulateFixRequest,
    SimulateFixResponse,
    RemediationPlan,
    RemediationPlanCreateRequest,
    RemediationPlanUpdateRequest,
    MarkAppliedRequest,
    VerificationRequest,
    VerificationRecord,
)
from app.schemas.rbac import Capability
from app.services.remediation_service import RemediationService
from app.services.rbac_service import AuthorizationService

router = APIRouter(prefix="/remediation")


def _get_actor_context(
    x_actor_id: Optional[str] = None,
    x_actor_name: Optional[str] = None,
) -> ActorContext:
    actor_id = x_actor_id or "local-analyst-01"
    actor_name = x_actor_name or actor_id
    return ActorContext.local_declared(analyst_id=actor_id, display_name=actor_name)


def _enforce_capability(actor_id: str, capability: Capability):
    """Enforces that the actor has the required capability."""
    analyst = AuthorizationService.get_analyst(actor_id)
    if analyst:
        if not AuthorizationService.can(analyst.role, capability):
            raise HTTPException(
                status_code=403,
                detail=f"Analyst '{actor_id}' with role '{analyst.role.value}' lacks capability '{capability.value}'",
            )
    else:
        # Default local unconfigured analyst has standard lead/admin capabilities in offline local mode
        pass


# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# 1. Playbook Generation & Simulate-Fix
# ------------------------------------------------------------------------------

from app.api.v1.endpoints.auth import get_optional_current_user
from fastapi import Depends


@router.post("/playbooks/generate", response_model=PlaybookGenerationResponse)
def generate_playbooks(
    req: PlaybookGenerationRequest,
    current_user: Optional[dict] = Depends(get_optional_current_user),
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Generate deterministic platform-specific remediation playbooks for finding codes."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.RUN_SIMULATION)
    user_id = current_user.get("id") if current_user else None
    try:
        return RemediationService.generate_playbook(req, user_id=user_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/simulate", response_model=SimulateFixResponse)
def simulate_fix(
    req: SimulateFixRequest,
    current_user: Optional[dict] = Depends(get_optional_current_user),
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Run in-memory deterministic simulate-fix engine against forensic findings."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.RUN_SIMULATION)
    return RemediationService.simulate_fix(req)


# ------------------------------------------------------------------------------
# 2. Remediation Plan Lifecycle Management
# ------------------------------------------------------------------------------

@router.get("/plans", response_model=List[RemediationPlan])
def list_plans(
    case_id: Optional[str] = Query(None, description="Filter by case ID"),
    target_id: Optional[str] = Query(None, description="Filter by target ID"),
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """List persisted remediation plans with optional filtering."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.VIEW_REMEDIATION)
    return RemediationService.list_plans(case_id=case_id, target_id=target_id)


@router.post("/plans", response_model=RemediationPlan)
def create_plan(
    req: RemediationPlanCreateRequest,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Create a new remediation plan with itemized playbook actions."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.CREATE_REMEDIATION_PLAN)
    return RemediationService.create_plan(req, created_by=actor.actor_id, actor=actor)


@router.get("/plans/{plan_id}", response_model=RemediationPlan)
def get_plan(
    plan_id: str,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Retrieve details and itemized actions of a remediation plan."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.VIEW_REMEDIATION)
    plan = RemediationService.get_plan(plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail=f"Remediation plan '{plan_id}' not found")
    return plan


@router.put("/plans/{plan_id}", response_model=RemediationPlan)
def update_plan(
    plan_id: str,
    req: RemediationPlanUpdateRequest,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Update title, description, or notes on a proposed remediation plan."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.EDIT_REMEDIATION_PLAN)
    plan = RemediationService.update_plan(plan_id, req, actor=actor)
    if not plan:
        raise HTTPException(status_code=404, detail=f"Remediation plan '{plan_id}' not found")
    return plan


@router.post("/plans/{plan_id}/apply", response_model=RemediationPlan)
def mark_plan_applied(
    plan_id: str,
    req: MarkAppliedRequest,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Mark a plan as user-reported applied awaiting forensic verification."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.MARK_APPLIED)
    plan = RemediationService.mark_applied(plan_id, req, applied_by=actor.actor_id, actor=actor)
    if not plan:
        raise HTTPException(status_code=404, detail=f"Remediation plan '{plan_id}' not found")
    return plan


# ------------------------------------------------------------------------------
# 3. Verify-After-Fix Workflow & Audit Logs
# ------------------------------------------------------------------------------

@router.post("/plans/{plan_id}/verify", response_model=VerificationRecord)
def verify_plan(
    plan_id: str,
    req: VerificationRequest,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """Verify remediation plan against newly observed forensic evidence."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.VERIFY_REMEDIATION)
    try:
        record = RemediationService.verify_plan(plan_id, req, verified_by=actor.actor_id, actor=actor)
        return record
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/plans/{plan_id}/verifications", response_model=List[VerificationRecord])
def list_verifications(
    plan_id: str,
    x_actor_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
):
    """List forensic verification audit records for a remediation plan."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.VIEW_REMEDIATION)
    return RemediationService.list_verifications(plan_id)


"""
SecureMailScope X - Phase 24: PQC Migration Endpoints

REST API endpoints for post-quantum cryptographic asset discovery, quantum risk exposure
modeling, gap analysis, and 7-phase transition roadmaps with peer sign-off.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query

from app.schemas.identity import ActorContext
from app.schemas.pqc_migration import (
    CryptoAssetInventoryResponse,
    DataSensitivityLifetime,
    PQCExposureAssessmentResponse,
    PQCGapAnalysisRequest,
    PQCGapAnalysisResponse,
    PQCRoadmapApprovalRequest,
    PQCRoadmapCreateRequest,
    PQCRoadmapListResponse,
    PQCRoadmapResponse,
    PQCRoadmapUpdateRequest,
    PQCTransitionTargetArchitecture,
)
from app.schemas.rbac import Capability
from app.services.pqc_migration_service import PQCMigrationService
from app.services.rbac_service import AuthorizationService

router = APIRouter(prefix="/pqc")


def _get_actor_context(
    x_actor_id: Optional[str] = None,
    x_actor_name: Optional[str] = None,
) -> ActorContext:
    actor_id = x_actor_id or "local-analyst-01"
    actor_name = x_actor_name or actor_id
    return ActorContext(actor_id=actor_id, actor_display_name=actor_name)


def _enforce_capability(actor_id: str, capability: Capability):
    """Enforce that the actor role possesses the required capability."""
    analyst = AuthorizationService.get_analyst(actor_id)
    if analyst:
        if not AuthorizationService.can(analyst.role, capability):
            raise HTTPException(
                status_code=403,
                detail=f"Analyst '{actor_id}' with role '{analyst.role.value}' lacks capability '{capability.value}'",
            )


# ------------------------------------------------------------------------------
# 1. Cryptographic Asset Inventory
# ------------------------------------------------------------------------------

@router.get("/inventory", response_model=CryptoAssetInventoryResponse)
def get_crypto_inventory(
    analysis_id: Optional[str] = Query(None, description="Forensic analysis session ID"),
    target_id: Optional[str] = Query(None, description="Monitored target ID"),
    case_id: Optional[str] = Query(None, description="Forensic case ID"),
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
):
    """Extract or retrieve cryptographic asset inventory from forensic evidence."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.VIEW_PQC_MIGRATION)
    return PQCMigrationService.extract_or_get_inventory(
        analysis_id=analysis_id,
        target_id=target_id,
        case_id=case_id,
    )


# ------------------------------------------------------------------------------
# 2. Quantum Risk & Exposure Assessment
# ------------------------------------------------------------------------------

@router.get("/exposure", response_model=PQCExposureAssessmentResponse)
def get_quantum_exposure(
    analysis_id: Optional[str] = Query(None, description="Forensic analysis session ID"),
    target_id: Optional[str] = Query(None, description="Monitored target ID"),
    case_id: Optional[str] = Query(None, description="Forensic case ID"),
    data_sensitivity: DataSensitivityLifetime = Query(DataSensitivityLifetime.UNKNOWN, description="Data sensitivity lifetime"),
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
):
    """Evaluate Harvest-Now-Decrypt-Later (HNDL) exposure and quantum risk."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.VIEW_PQC_MIGRATION)
    return PQCMigrationService.evaluate_quantum_exposure(
        analysis_id=analysis_id,
        target_id=target_id,
        case_id=case_id,
        data_sensitivity=data_sensitivity,
    )


# ------------------------------------------------------------------------------
# 3. Migration Gap Analysis
# ------------------------------------------------------------------------------

@router.post("/gap-analysis", response_model=PQCGapAnalysisResponse)
def run_pqc_gap_analysis(
    req: PQCGapAnalysisRequest,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
):
    """Compare observed cryptography against target architecture to identify migration gaps."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.RUN_PQC_GAP_ANALYSIS)
    return PQCMigrationService.run_gap_analysis(
        analysis_id=req.analysis_id,
        target_id=req.target_id,
        target_architecture=req.target_architecture,
    )


# ------------------------------------------------------------------------------
# 4. Migration Roadmaps & Peer Sign-Off
# ------------------------------------------------------------------------------

@router.post("/roadmaps", response_model=PQCRoadmapResponse)
def create_pqc_roadmap(
    req: PQCRoadmapCreateRequest,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
):
    """Generate a deterministic 7-phase hybrid transition roadmap."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.CREATE_PQC_ROADMAP)
    return PQCMigrationService.create_roadmap(req, creator_actor=actor)


@router.get("/roadmaps", response_model=PQCRoadmapListResponse)
def list_pqc_roadmaps(
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
):
    """List all created PQC migration roadmaps."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.VIEW_PQC_MIGRATION)
    return PQCMigrationService.list_roadmaps()


@router.get("/roadmaps/{roadmap_id}", response_model=PQCRoadmapResponse)
def get_pqc_roadmap(
    roadmap_id: str,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
):
    """Get full details of a migration roadmap including 7-phase steps and gaps."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.VIEW_PQC_MIGRATION)
    rm = PQCMigrationService.get_roadmap(roadmap_id)
    if not rm:
        raise HTTPException(status_code=404, detail=f"Roadmap '{roadmap_id}' not found")
    return rm


@router.put("/roadmaps/{roadmap_id}", response_model=PQCRoadmapResponse)
def update_pqc_roadmap(
    roadmap_id: str,
    req: PQCRoadmapUpdateRequest,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
):
    """Update roadmap metadata or step status."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.EDIT_PQC_ROADMAP)
    try:
        return PQCMigrationService.update_roadmap(roadmap_id, req, actor=actor)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/roadmaps/{roadmap_id}/approve", response_model=PQCRoadmapResponse)
def approve_pqc_roadmap(
    roadmap_id: str,
    req: PQCRoadmapApprovalRequest,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
):
    """Cryptographically sign and approve a roadmap with Ed25519/RSA-PSS."""
    actor = _get_actor_context(x_actor_id, x_actor_name)
    _enforce_capability(actor.actor_id, Capability.APPROVE_PQC_ROADMAP)
    if req.roadmap_id != roadmap_id:
        req.roadmap_id = roadmap_id
    try:
        return PQCMigrationService.approve_roadmap(req, actor=actor)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

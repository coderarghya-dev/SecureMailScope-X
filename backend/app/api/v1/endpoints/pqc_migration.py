# ==============================================================================
# SecureMailScope X — Phase 24 / 25: Post-Quantum Cryptography Migration REST API
# ==============================================================================
"""FastAPI endpoints for PQC asset discovery, 7-phase transition roadmaps,
gap findings, and cryptographic peer sign-offs.
"""

from typing import List, Optional
from fastapi import APIRouter, Header, HTTPException, status

from app.schemas.pqc_migration import (
    PQCDiscoveryRequest,
    PQCDiscoveryResult,
    PQCMigrationRoadmapDTO,
    PQCMigrationStepDTO,
    PQCMigrationStepUpdate,
    PQCRoadmapCreateRequest,
    PQCRoadmapSignRequest,
)
from app.schemas.rbac import Capability
from app.services.pqc_migration_service import PQCMigrationService
from app.services.rbac_service import AuthorizationService

router = APIRouter(prefix="/pqc", tags=["Post-Quantum Cryptography Migration"])


def _get_actor_id(x_actor_id: Optional[str]) -> str:
    return x_actor_id or "local-analyst-01"


def _enforce_capability(actor_id: str, capability: Capability) -> None:
    analyst = AuthorizationService.get_analyst(actor_id)
    if analyst:
        if not AuthorizationService.can(analyst.role, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Analyst '{actor_id}' with role '{analyst.role.value}' lacks capability '{capability.value}'",
            )
    else:
        # Default local unconfigured analyst has standard lead/admin capabilities in offline local mode
        pass


@router.post("/discover", response_model=PQCDiscoveryResult)
def discover_pqc_assets(
    req: PQCDiscoveryRequest,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_PQC_ROADMAP)
    return PQCMigrationService.discover_assets(
        analysis_id=req.analysis_id,
        target_id=req.target_id,
        lifetime=req.data_sensitivity_lifetime,
    )


@router.post("/roadmaps", response_model=PQCMigrationRoadmapDTO, status_code=status.HTTP_201_CREATED)
def create_pqc_roadmap(
    req: PQCRoadmapCreateRequest,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.CREATE_PQC_ROADMAP)
    return PQCMigrationService.create_roadmap(req, created_by=actor_id)


@router.get("/roadmaps", response_model=List[PQCMigrationRoadmapDTO])
def list_pqc_roadmaps(
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_PQC_ROADMAP)
    return PQCMigrationService.list_roadmaps()


@router.get("/roadmaps/{roadmap_id}", response_model=PQCMigrationRoadmapDTO)
def get_pqc_roadmap(
    roadmap_id: str,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_PQC_ROADMAP)
    roadmap = PQCMigrationService.get_roadmap(roadmap_id)
    if not roadmap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PQC Migration Roadmap not found")
    return roadmap


@router.put("/roadmaps/{roadmap_id}/steps/{step_id}", response_model=PQCMigrationStepDTO)
def update_pqc_step(
    roadmap_id: str,
    step_id: str,
    req: PQCMigrationStepUpdate,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.EDIT_PQC_ROADMAP)
    updated = PQCMigrationService.update_step(step_id, req)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Migration step not found")
    return updated


@router.post("/roadmaps/{roadmap_id}/sign", response_model=PQCMigrationRoadmapDTO)
def sign_pqc_roadmap(
    roadmap_id: str,
    req: PQCRoadmapSignRequest,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.SIGN_PQC_ROADMAP)
    analyst = AuthorizationService.get_analyst(actor_id)
    analyst_name = analyst.display_name if analyst else actor_id
    signed = PQCMigrationService.sign_roadmap(
        roadmap_id=roadmap_id,
        analyst_id=actor_id,
        analyst_name=analyst_name,
        private_key_pem=req.private_key_pem,
        key_id=req.key_id,
    )
    if not signed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PQC Migration Roadmap not found")
    return signed

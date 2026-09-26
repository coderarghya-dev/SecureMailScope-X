# ==============================================================================
# SecureMailScope X — Phase 21: Posture Monitoring Endpoints
# ==============================================================================
"""REST API endpoints for continuous mail security posture monitoring,
target management, active scanning, baseline pinning, drift tracking, and local scheduling.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query

from app.schemas.identity import ActorContext
from app.schemas.monitoring import (
    MonitoredTarget,
    TargetCreateRequest,
    TargetUpdateRequest,
    PostureSnapshot,
    PostureDriftEvent,
    MonitoringSummaryResponse,
)
from app.schemas.rbac import Capability, AnalystRole
from app.services.monitoring_service import PostureMonitoringService
from app.services.rbac_service import AuthorizationService

router = APIRouter(prefix="/monitoring")


def _get_actor_id(x_actor_id: Optional[str]) -> str:
    return x_actor_id or "local-analyst-01"


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
# 1. Monitored Targets Management
# ------------------------------------------------------------------------------

@router.get("/targets", response_model=List[MonitoredTarget])
def list_targets(
    enabled_only: bool = Query(False, description="Filter only enabled targets"),
    x_actor_id: Optional[str] = Header(None),
):
    """List all registered mail server monitored targets."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_MONITORING)
    return PostureMonitoringService.list_targets(enabled_only=enabled_only)


@router.post("/targets", response_model=MonitoredTarget)
def create_target(
    req: TargetCreateRequest,
    x_actor_id: Optional[str] = Header(None),
):
    """Register a new mail server target for posture monitoring."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.MANAGE_MONITORED_TARGETS)
    try:
        return PostureMonitoringService.create_target(req, actor_id=actor_id)
    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.get("/targets/{target_id}", response_model=MonitoredTarget)
def get_target(
    target_id: str,
    x_actor_id: Optional[str] = Header(None),
):
    """Retrieve details for a specific monitored target."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_MONITORING)
    target = PostureMonitoringService.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail=f"Monitored target '{target_id}' not found")
    return target


@router.put("/targets/{target_id}", response_model=MonitoredTarget)
def update_target(
    target_id: str,
    req: TargetUpdateRequest,
    x_actor_id: Optional[str] = Header(None),
):
    """Update properties or schedule configuration of a monitored target."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.MANAGE_MONITORED_TARGETS)
    try:
        updated = PostureMonitoringService.update_target(target_id, req, actor_id=actor_id)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Monitored target '{target_id}' not found")
        return updated
    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.delete("/targets/{target_id}")
def delete_target(
    target_id: str,
    x_actor_id: Optional[str] = Header(None),
):
    """Delete a monitored target along with its snapshots and drift events."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.MANAGE_MONITORED_TARGETS)
    deleted = PostureMonitoringService.delete_target(target_id, actor_id=actor_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Monitored target '{target_id}' not found")
    return {"status": "DELETED", "target_id": target_id}


# ------------------------------------------------------------------------------
# 2. On-Demand Active Scanning & Baseline Pinning
# ------------------------------------------------------------------------------

@router.post("/targets/{target_id}/scan")
def scan_target(
    target_id: str,
    allow_local_testing: bool = Query(False, description="Allow localhost/private IPs for testing"),
    validate_cert_trust: bool = Query(False, description="Validate TLS certificate trust chain"),
    x_actor_id: Optional[str] = Header(None),
):
    """Execute an opt-in active posture probe against target and detect configuration drift."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.RUN_MONITOR_SCAN)
    try:
        snapshot, drift_events = PostureMonitoringService.scan_target(
            target_id=target_id,
            actor_id=actor_id,
            allow_local_testing=allow_local_testing,
            validate_cert_trust=validate_cert_trust,
        )
        return {
            "snapshot": snapshot,
            "drift_events": drift_events,
            "drift_count": len(drift_events),
        }
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(ex)}")


@router.post("/targets/{target_id}/baseline/{snapshot_id}", response_model=MonitoredTarget)
def pin_baseline(
    target_id: str,
    snapshot_id: str,
    x_actor_id: Optional[str] = Header(None),
):
    """Pin a verified snapshot as the authoritative baseline for future drift comparison."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.PIN_POSTURE_BASELINE)
    try:
        target = PostureMonitoringService.pin_baseline(
            target_id=target_id,
            snapshot_id=snapshot_id,
            actor_id=actor_id,
        )
        if not target:
            raise HTTPException(status_code=404, detail=f"Target '{target_id}' not found")
        return target
    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex))


# ------------------------------------------------------------------------------
# 3. Snapshots, Drift History & Summary
# ------------------------------------------------------------------------------

@router.get("/targets/{target_id}/snapshots", response_model=List[PostureSnapshot])
def list_target_snapshots(
    target_id: str,
    limit: int = Query(50, ge=1, le=200),
    x_actor_id: Optional[str] = Header(None),
):
    """List historical posture snapshots for a specific target."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_DRIFT_HISTORY)
    return PostureMonitoringService.list_snapshots(target_id=target_id, limit=limit)


@router.get("/snapshots/{snapshot_id}", response_model=PostureSnapshot)
def get_snapshot(
    snapshot_id: str,
    x_actor_id: Optional[str] = Header(None),
):
    """Retrieve details and canonical hash of a single posture snapshot."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_DRIFT_HISTORY)
    snap = PostureMonitoringService.get_snapshot(snapshot_id)
    if not snap:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot_id}' not found")
    return snap


@router.get("/drift", response_model=List[PostureDriftEvent])
def list_drift(
    target_id: Optional[str] = Query(None, description="Optional target ID filter"),
    limit: int = Query(100, ge=1, le=500),
    x_actor_id: Optional[str] = Header(None),
):
    """List detected posture drift events across one or all targets."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_DRIFT_HISTORY)
    return PostureMonitoringService.list_drift_events(target_id=target_id, limit=limit)


@router.get("/summary", response_model=MonitoringSummaryResponse)
def get_monitoring_summary(
    x_actor_id: Optional[str] = Header(None),
):
    """Retrieve high-level metrics and statistics on monitored posture and drift."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_MONITORING)
    return PostureMonitoringService.get_monitoring_summary()


# ------------------------------------------------------------------------------
# 4. Local Scheduler Run
# ------------------------------------------------------------------------------

@router.post("/scheduler/run-due")
def run_due_scans(
    allow_local_testing: bool = Query(False, description="Allow localhost/private IPs for testing"),
    x_actor_id: Optional[str] = Header(None),
):
    """Evaluate and trigger due scans for all scheduled, enabled targets locally."""
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.RUN_MONITOR_SCAN)
    return PostureMonitoringService.run_due_scans(
        actor_id=actor_id,
        allow_local_testing=allow_local_testing,
    )

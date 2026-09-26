# ==============================================================================
# SecureMailScope X — Phase 22 / 25: Automated Forensic Alerting REST API
# ==============================================================================
"""FastAPI endpoints for forensic alert rules, evidence evaluations, and alert management."""

from typing import List, Optional
from fastapi import APIRouter, Header, HTTPException, Query, status

from app.schemas.alerting import (
    AlertAcknowledgeRequest,
    AlertDTO,
    AlertEvaluationRequest,
    AlertEvaluationResult,
    AlertResolveRequest,
    AlertRuleCreate,
    AlertRuleDTO,
    AlertRuleUpdate,
    AlertSeverity,
    AlertStatus,
)
from app.schemas.rbac import Capability
from app.services.alerting_service import AlertingService
from app.services.rbac_service import AuthorizationService

router = APIRouter(prefix="/alerts", tags=["Automated Forensic Alerting"])


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


@router.get("/rules", response_model=List[AlertRuleDTO])
def list_alert_rules(
    enabled_only: bool = False,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_ALERTS)
    return AlertingService.list_rules(enabled_only=enabled_only)


@router.post("/rules", response_model=AlertRuleDTO, status_code=status.HTTP_201_CREATED)
def create_alert_rule(
    rule_in: AlertRuleCreate,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.MANAGE_ALERT_RULES)
    return AlertingService.create_rule(rule_in, created_by=actor_id)


@router.get("/rules/{rule_id}", response_model=AlertRuleDTO)
def get_alert_rule(
    rule_id: str,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_ALERTS)
    rule = AlertingService.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found")
    return rule


@router.put("/rules/{rule_id}", response_model=AlertRuleDTO)
def update_alert_rule(
    rule_id: str,
    rule_in: AlertRuleUpdate,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.MANAGE_ALERT_RULES)
    updated = AlertingService.update_rule(rule_id, rule_in)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found")
    return updated


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert_rule(
    rule_id: str,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.MANAGE_ALERT_RULES)
    if not AlertingService.delete_rule(rule_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found")
    return None


@router.post("/evaluate", response_model=AlertEvaluationResult)
def evaluate_alerts(
    req: AlertEvaluationRequest,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.EVALUATE_ALERTS)
    return AlertingService.evaluate_evidence_against_rules(
        analysis_id=req.analysis_id,
        target_id=req.target_id,
    )


@router.get("", response_model=List[AlertDTO])
def list_alerts(
    status_filter: Optional[AlertStatus] = Query(None, alias="status"),
    severity: Optional[AlertSeverity] = None,
    limit: int = Query(100, ge=1, le=500),
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_ALERTS)
    return AlertingService.list_alerts(status=status_filter, severity=severity, limit=limit)


@router.get("/{alert_id}", response_model=AlertDTO)
def get_alert(
    alert_id: str,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.VIEW_ALERTS)
    alert = AlertingService.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.post("/{alert_id}/acknowledge", response_model=AlertDTO)
def acknowledge_alert(
    alert_id: str,
    req: AlertAcknowledgeRequest,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.ACKNOWLEDGE_ALERT)
    alert = AlertingService.acknowledge_alert(alert_id, analyst_id=actor_id, notes=req.notes)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.post("/{alert_id}/resolve", response_model=AlertDTO)
def resolve_alert(
    alert_id: str,
    req: AlertResolveRequest,
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
):
    actor_id = _get_actor_id(x_actor_id)
    _enforce_capability(actor_id, Capability.RESOLVE_ALERT)
    alert = AlertingService.resolve_alert(alert_id, analyst_id=actor_id, resolution_notes=req.resolution_notes)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert

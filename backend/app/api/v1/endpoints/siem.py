# ==============================================================================
# SecureMailScope X — Phase 19: SIEM / SOC Integration Endpoints
# ==============================================================================
"""REST API endpoints for querying normalized SOC telemetry, exporting events
(JSON, CEF, RFC 5424 Syslog), executing deliveries, and inspecting audit logs.
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Response

from app.schemas.siem import (
    NormalizedSOCEvent,
    SIEMDeliveryRecord,
    SIEMDeliveryRequest,
    SIEMEventFilter,
    SIEMSummaryResponse,
    SOCEventSeverity,
    SOCEventType,
    SOCExportFormat,
)
from app.services.siem_service import (
    deliver_soc_events,
    export_soc_events,
    filter_soc_events,
    get_all_soc_events,
    get_siem_summary,
    list_siem_deliveries,
)

router = APIRouter(prefix="/siem")


@router.get("/events", response_model=List[NormalizedSOCEvent])
def get_events(
    severity: Optional[SOCEventSeverity] = Query(None, description="Filter by event severity"),
    event_type: Optional[SOCEventType] = Query(None, description="Filter by event type"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    analysis_id: Optional[str] = Query(None, description="Filter by analysis ID"),
    case_id: Optional[str] = Query(None, description="Filter by case ID"),
    start_time: Optional[str] = Query(None, description="ISO start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO end timestamp"),
):
    """Retrieve normalized SOC telemetry events with optional filtering."""
    events = get_all_soc_events()
    filter_req = SIEMEventFilter(
        severity=severity,
        event_type=event_type,
        protocol=protocol,
        analysis_id=analysis_id,
        case_id=case_id,
        start_time=start_time,
        end_time=end_time,
    )
    return filter_soc_events(events, filter_req)


@router.get("/events/{event_id}", response_model=NormalizedSOCEvent)
def get_single_event(event_id: str):
    """Retrieve a single normalized SOC telemetry event by ID."""
    events = get_all_soc_events()
    match = next((e for e in events if e.event_id == event_id), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"SOC Event '{event_id}' not found")
    return match


@router.get("/export/json")
def export_json(
    severity: Optional[SOCEventSeverity] = Query(None),
    protocol: Optional[str] = Query(None),
    case_id: Optional[str] = Query(None),
):
    """Export normalized SOC events in deterministic JSON format."""
    filter_req = SIEMEventFilter(severity=severity, protocol=protocol, case_id=case_id)
    content = export_soc_events(SOCExportFormat.JSON, filter_criteria=filter_req)
    return Response(content=content, media_type="application/json")


@router.get("/export/cef")
def export_cef(
    severity: Optional[SOCEventSeverity] = Query(None),
    protocol: Optional[str] = Query(None),
    case_id: Optional[str] = Query(None),
):
    """Export normalized SOC events in ArcSight Common Event Format (CEF)."""
    filter_req = SIEMEventFilter(severity=severity, protocol=protocol, case_id=case_id)
    content = export_soc_events(SOCExportFormat.CEF, filter_criteria=filter_req)
    return Response(content=content, media_type="text/plain")


@router.get("/export/syslog")
def export_syslog(
    severity: Optional[SOCEventSeverity] = Query(None),
    protocol: Optional[str] = Query(None),
    case_id: Optional[str] = Query(None),
):
    """Export normalized SOC events in RFC 5424 Syslog format."""
    filter_req = SIEMEventFilter(severity=severity, protocol=protocol, case_id=case_id)
    content = export_soc_events(SOCExportFormat.RFC5424, filter_criteria=filter_req)
    return Response(content=content, media_type="text/plain")


@router.post("/deliver", response_model=SIEMDeliveryRecord)
def deliver_events(req: SIEMDeliveryRequest):
    """Deliver normalized SOC events to a configured transport and log delivery audit."""
    return deliver_soc_events(req)


@router.get("/status", response_model=SIEMSummaryResponse)
def get_status():
    """Retrieve aggregate statistics of available SOC telemetry and past deliveries."""
    return get_siem_summary()


@router.get("/deliveries", response_model=List[SIEMDeliveryRecord])
def get_deliveries():
    """List historical SIEM/SOC event delivery audit records."""
    return list_siem_deliveries()

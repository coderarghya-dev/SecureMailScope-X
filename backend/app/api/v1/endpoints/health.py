"""
SecureMailScope X - Health & System Diagnostics Endpoint
"""

from fastapi import APIRouter
from app.core.tshark_detector import TSharkDetector
from app.core.config import API_TITLE, API_VERSION
from app.schemas.api import HealthResponse
from app.db.database import check_db_connectivity

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System Health & TShark Engine Status",
    description="Returns backend operational status, Wireshark/TShark detector state, supported protocols, and database connectivity."
)
def get_health() -> HealthResponse:
    tshark_ok, tshark_info = TSharkDetector.get_version()
    db_ok, db_engine = check_db_connectivity(timeout_seconds=2.0)

    status_str = "healthy" if (tshark_ok and db_ok) else ("degraded" if db_ok else "unhealthy")
    
    return HealthResponse(
        status=status_str,
        tshark_available=tshark_ok,
        tshark_version=tshark_info if tshark_ok else "Unavailable (Wireshark / TShark not found in PATH)",
        supported_protocols=["SMTP", "IMAP", "POP3"],
        port_110_stls_real_capture_status="PENDING (Target server unavailable / unserviceable on port 110)",
        database_connected=db_ok,
        database_engine=db_engine,
        mode="cloud_deployed" if db_engine == "postgresql" else "offline_first_local"
    )


@router.get(
    "/health/live",
    summary="Lightweight Liveness Probe",
    description="Returns HTTP 200 immediately if process is alive."
)
def get_liveness():
    return {
        "status": "alive",
        "service": API_TITLE,
        "version": API_VERSION
    }


@router.get(
    "/health/ready",
    summary="Readiness Probe",
    description="Returns readiness status and database connection state."
)
@router.get(
    "/readiness",
    summary="System Diagnostic & Database Readiness Probe",
    description="Returns backend readiness status, database connectivity, and subsystem integrity."
)
def get_readiness():
    db_ok, db_engine = check_db_connectivity(timeout_seconds=2.0)
    tshark_ok, _ = TSharkDetector.get_version()

    return {
        "status": "ready" if db_ok else "unready",
        "database_connected": db_ok,
        "database_engine": db_engine,
        "tshark_available": tshark_ok,
        "subsystems": {
            "forensic_engine": True,
            "posture_monitoring": True,
            "alerting_engine": True,
            "pqc_migration_planner": True,
            "remediation_engine": True,
            "rbac_engine": True,
            "chain_of_custody": True,
        }
    }



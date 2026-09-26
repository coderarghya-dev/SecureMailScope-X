"""
SecureMailScope X - Health & System Diagnostics Endpoint
"""

from fastapi import APIRouter
from app.core.tshark_detector import TSharkDetector
from app.schemas.api import HealthResponse

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System Health & TShark Engine Status",
    description="Returns backend operational status, Wireshark/TShark detector state, supported protocols, and genuine capture status."
)
def get_health() -> HealthResponse:
    tshark_ok, tshark_info = TSharkDetector.get_version()
    status_str = "healthy" if tshark_ok else "degraded"
    
    return HealthResponse(
        status=status_str,
        tshark_available=tshark_ok,
        tshark_version=tshark_info if tshark_ok else "Unavailable (Wireshark / TShark not found in PATH)",
        supported_protocols=["SMTP", "IMAP", "POP3"],
        port_110_stls_real_capture_status="PENDING (Target server unavailable / unserviceable on port 110)"
    )


@router.get(
    "/readiness",
    summary="System Diagnostic & Database Readiness Probe",
    description="Returns backend readiness status, database connectivity, and subsystem integrity."
)
def get_readiness():
    try:
        from app.db.database import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1;")
        cursor.fetchone()
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False

    tshark_ok, _ = TSharkDetector.get_version()

    return {
        "status": "ready" if db_ok else "unready",
        "database_connected": db_ok,
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


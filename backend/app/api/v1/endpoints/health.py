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

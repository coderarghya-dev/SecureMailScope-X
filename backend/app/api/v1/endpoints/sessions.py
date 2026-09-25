"""
SecureMailScope X - Session Forensics & Drill-Down Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from app.schemas.api import (
    SessionDetailDTO,
    SessionSummaryDTO,
    PacketEvidenceDTO,
    SecurityFindingDTO
)
from app.services.analysis_service import AnalysisService

router = APIRouter()


@router.get(
    "/analyses/{analysis_id}/sessions",
    response_model=List[SessionSummaryDTO],
    summary="List Sessions for an Analysis",
    description="Returns high-level summary cards for all email sessions reconstructed from the specified capture."
)
def list_sessions(analysis_id: str) -> List[SessionSummaryDTO]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found."
        )

    summaries: List[SessionSummaryDTO] = []
    for s in analysis.sessions:
        summaries.append(SessionSummaryDTO(
            session_id=s.session_id,
            stream_index=s.stream_index,
            protocol=s.protocol,
            security_mode=s.security_mode,
            client=s.client,
            server=s.server,
            server_hostname=s.server_hostname,
            start_time_iso=s.start_time_iso,
            duration_seconds=s.duration_seconds,
            packets_count=s.packets_count,
            security_grade=s.security_assessment.grade,
            health_score=s.capture_health.score,
            health_grade=s.capture_health.grade,
            confidence_level=s.evidence_confidence.level,
            post_quantum_ready=s.security_assessment.post_quantum_ready
        ))
    return summaries


@router.get(
    "/analyses/{analysis_id}/sessions/{session_id}",
    response_model=SessionDetailDTO,
    summary="Get Detailed Session Forensics",
    description="Returns full cryptographic parameters, STARTTLS/STLS state, Capture Health, Evidence Confidence, and findings for a specific session."
)
def get_session_detail(analysis_id: str, session_id: str) -> SessionDetailDTO:
    session = AnalysisService.get_session(analysis_id, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found in analysis '{analysis_id}'."
        )
    return session


@router.get(
    "/analyses/{analysis_id}/sessions/{session_id}/packets",
    response_model=List[PacketEvidenceDTO],
    summary="Get Raw Packet Evidence for Session",
    description="Returns paginated list of packet frames associated with the reconstructed email TCP stream."
)
def get_session_packets(
    analysis_id: str,
    session_id: str,
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Pagination limit")
) -> List[PacketEvidenceDTO]:
    packets = AnalysisService.get_session_packets(analysis_id, session_id)
    if packets is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Packets for session '{session_id}' in analysis '{analysis_id}' not found."
        )
    return packets[offset:offset + limit]


@router.get(
    "/analyses/{analysis_id}/sessions/{session_id}/findings",
    response_model=List[SecurityFindingDTO],
    summary="Get Security Findings for Session",
    description="Returns frame-backed cryptographic security findings, risk categorizations, and NIST SP 800-52r2 remediation advice."
)
def get_session_findings(
    analysis_id: str,
    session_id: str,
    severity: Optional[str] = Query(None, description="Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
) -> List[SecurityFindingDTO]:
    session = AnalysisService.get_session(analysis_id, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found in analysis '{analysis_id}'."
        )
    
    findings = session.security_assessment.findings
    if severity:
        findings = [f for f in findings if f.severity.upper() == severity.upper()]
    return findings

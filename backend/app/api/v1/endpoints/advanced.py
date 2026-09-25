"""
SecureMailScope X - Advanced Capabilities Endpoints
Includes Active Mail Scanner, Simulate Fix, Incident Correlation, ML Triage & XAI, Digital Signatures, Notarization, and Case Management.
"""

from fastapi import APIRouter, HTTPException, status, Body, Header, Depends
from typing import Dict, Any, Optional, List
from pydantic import BaseModel

from app.db.repository import ForensicRepository
from app.services.analysis_service import AnalysisService
from app.services.case_service import CaseService
from app.scanner.active_scanner import ActiveMailScanner
from app.scanner.mail_posture_scanner import MailPostureScanner
from app.forensic.remediation_simulator import RemediationSimulator
from app.simulation.simulate_fix import SimulateFixEngine
from app.forensic.incident_correlator import IncidentCorrelator
from app.ml.risk_classifier import MLRiskClassifier
from app.forensic.pqc_analyzer import PQCAnalyzer
from app.security.report_signer import ReportSigner
from app.security.notarization import NotarizationService
from app.schemas.identity import (
    ActorContext,
    AnalystIdentityDTO,
    RegisterAnalystRequest,
    UpdateAnalystProfileRequest,
)


router = APIRouter()


def get_actor_context(
    x_analyst_id: Optional[str] = Header(None, alias="X-Analyst-ID"),
    x_analyst_name: Optional[str] = Header(None, alias="X-Analyst-Name"),
) -> ActorContext:
    """Derive actor context from optional declared request headers."""
    return ActorContext.from_headers(x_analyst_id=x_analyst_id, x_analyst_name=x_analyst_name)


class ActiveScanRequest(BaseModel):
    target_host: str
    ports: Optional[List[int]] = None


class MailPostureScanRequest(BaseModel):
    target: str
    ports: Optional[List[int]] = None
    validate_cert_trust: bool = False


class SimulateFixRequest(BaseModel):
    analysis_id: Optional[str] = None
    session_id: str
    remediations: Optional[List[str]] = None
    parameters: Optional[Dict[str, Any]] = None
    require_tls13: bool = False
    require_tls12_plus: bool = True
    remove_static_rsa: bool = True
    remove_deprecated_ciphers: bool = True
    enable_pqc_hybrid: bool = False


class CaseCreateRequest(BaseModel):
    title: str
    description: Optional[str] = ""
    analyst_id: Optional[str] = None
    analyst_name: Optional[str] = None
    tags: Optional[List[str]] = None


class CaseNoteRequest(BaseModel):
    author: Optional[str] = None
    text: str
    analyst_id: Optional[str] = None


class CaseArtifactRequest(BaseModel):
    artifact_type: str
    filename: str
    sha256: str
    analysis_id: Optional[str] = None


class SignReportRequest(BaseModel):
    analyst_name: Optional[str] = "Local Forensic Analyst"


# ---------------------------------------------------------------------------
# 0. Analyst Identity Registry (Phase 12)
# ---------------------------------------------------------------------------
@router.get("/analysts", summary="List Registered Analyst Identities", response_model=List[AnalystIdentityDTO])
def list_analysts() -> List[AnalystIdentityDTO]:
    """Lists registered declared analyst identities (Attribution Registry, NOT Authentication)."""
    return ForensicRepository.list_analysts()


@router.post("/analysts", summary="Register Declared Analyst Identity", response_model=AnalystIdentityDTO)
def register_analyst(req: RegisterAnalystRequest) -> AnalystIdentityDTO:
    """Registers a declared analyst identity in the local registry."""
    return ForensicRepository.register_analyst(
        analyst_id=req.analyst_id,
        display_name=req.display_name,
        email_or_label=req.email_or_label,
        identity_source=req.identity_source,
        metadata=req.metadata,
    )


@router.get("/analysts/{analyst_id}", summary="Get Analyst Identity Profile", response_model=AnalystIdentityDTO)
def get_analyst_profile(analyst_id: str) -> AnalystIdentityDTO:
    """Retrieve analyst identity profile from the attribution registry."""
    analyst = ForensicRepository.get_analyst(analyst_id)
    if not analyst:
        raise HTTPException(status_code=404, detail=f"Analyst '{analyst_id}' not found.")
    return analyst


@router.patch("/analysts/{analyst_id}", summary="Update Analyst Identity Profile", response_model=AnalystIdentityDTO)
def update_analyst_profile(analyst_id: str, req: UpdateAnalystProfileRequest) -> AnalystIdentityDTO:
    """Updates display name or active status in registry without rewriting historical audit events."""
    updated = ForensicRepository.update_analyst_profile(
        analyst_id=analyst_id,
        display_name=req.display_name,
        email_or_label=req.email_or_label,
        is_active=req.is_active,
        metadata=req.metadata,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Analyst '{analyst_id}' not found.")
    return updated


# 1. Active Scanner (Phase 9 Posture Scanner & Legacy Probe)
@router.post("/scanner/mail-posture", summary="Execute Explicit Opt-In Active Mail Server Posture Scan")
def scan_mail_posture(
    req: MailPostureScanRequest,
    actor: ActorContext = Depends(get_actor_context),
) -> Dict[str, Any]:
    if not req.target:
        raise HTTPException(status_code=400, detail="Target host is required.")
    # allow_local_testing is strictly hardcoded False for public API calls (SSRF safety)
    report = MailPostureScanner.scan(
        target=req.target,
        ports=req.ports,
        allow_local_testing=False,
        validate_cert_trust=req.validate_cert_trust,
    )
    res_dict = report.to_dict()
    try:
        ForensicRepository.save_active_scan(
            scan_id=report.scan_id,
            target_host=report.target_host,
            connected_ip=report.resolved_ip,
            ports_scanned=[p.port for p in report.ports],
            result_dict=res_dict,
            provenance="ACTIVE_NETWORK_PROBE",
            actor=actor,
        )
    except Exception:
        pass
    return res_dict


@router.post("/scanner/probe", summary="Execute Active Mail Server Security Probe (Legacy)")
def probe_mail_server(
    req: ActiveScanRequest,
    actor: ActorContext = Depends(get_actor_context),
) -> Dict[str, Any]:
    if not req.target_host:
        raise HTTPException(status_code=400, detail="Target host is required.")
    report = ActiveMailScanner.scan_target(req.target_host, req.ports)
    return report.to_dict()


# 2. Simulate Fix / What-If Remediation (Phase 10)
@router.post("/analyses/{analysis_id}/simulate-fix", summary="Execute Evidence-Preserving Remediation Simulation")
def simulate_analysis_fix(
    analysis_id: str,
    req: SimulateFixRequest,
    actor: ActorContext = Depends(get_actor_context),
) -> Dict[str, Any]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")

    target_session = None
    for s in analysis.sessions:
        if s.session_id == req.session_id:
            target_session = s
            break
    if not target_session:
        raise HTTPException(status_code=404, detail=f"Session '{req.session_id}' not found in analysis.")

    actions = req.remediations
    if not actions:
        actions = []
        if req.require_tls12_plus or req.require_tls13:
            actions.append("DISABLE_DEPRECATED_TLS")
        if req.remove_static_rsa:
            actions.append("ENABLE_FORWARD_SECRECY")
        if req.remove_deprecated_ciphers:
            actions.append("REPLACE_WEAK_CIPHER")
        if req.enable_pqc_hybrid:
            actions.append("ENABLE_HYBRID_PQC")

    report = RemediationSimulator.simulate(
        session=target_session,
        remediations=actions,
        parameters=req.parameters,
    )
    res_dict = report.to_dict()
    try:
        ForensicRepository.save_simulation(
            simulation_id=report.simulation_id,
            analysis_id=analysis_id,
            session_id=req.session_id,
            requested_actions=actions,
            projection_dict=res_dict,
            parameters=req.parameters,
            actor=actor,
        )
    except Exception:
        pass
    return res_dict


@router.post("/simulation/simulate", summary="Execute Deterministic What-If Fix Simulation (Legacy Bridge)")
def simulate_fix(req: SimulateFixRequest) -> Dict[str, Any]:
    target_aid = req.analysis_id
    if not target_aid:
        raise HTTPException(status_code=400, detail="analysis_id is required.")
    analysis = AnalysisService.get_analysis(target_aid)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis '{target_aid}' not found.")
    
    target_session = None
    for s in analysis.sessions:
        if s.session_id == req.session_id:
            target_session = s
            break
    if not target_session:
        raise HTTPException(status_code=404, detail=f"Session '{req.session_id}' not found in analysis.")

    projected = SimulateFixEngine.simulate(
        session=target_session,
        require_tls13=req.require_tls13,
        require_tls12_plus=req.require_tls12_plus,
        remove_static_rsa=req.remove_static_rsa,
        remove_deprecated_ciphers=req.remove_deprecated_ciphers,
        enable_pqc_hybrid=req.enable_pqc_hybrid,
        remediations=req.remediations,
    )
    return projected.to_dict()


# 3. Incident Correlation
@router.get("/analyses/{analysis_id}/incidents", summary="Correlate Incidents Across Streams")
def get_analysis_incidents(analysis_id: str) -> List[Dict[str, Any]]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
    if analysis.correlated_incidents:
        return [i.model_dump() if hasattr(i, "model_dump") else i.dict() for i in analysis.correlated_incidents]
    item = AnalysisService._cache.get(analysis_id)
    if item:
        incidents = IncidentCorrelator.correlate_sessions(item[1])
        return [i.to_dict() for i in incidents]
    return []


# 4. ML Triage & XAI
@router.get("/analyses/{analysis_id}/sessions/{session_id}/ml-triage", summary="Get ML Risk Triage and XAI Explanations")
def get_session_ml_triage(analysis_id: str, session_id: str) -> Dict[str, Any]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
    target_session = None
    for s in analysis.sessions:
        if s.session_id == session_id:
            target_session = s
            break
    if not target_session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return MLRiskClassifier.classify_session(target_session)


# 5. PQC Assessment
@router.get("/analyses/{analysis_id}/sessions/{session_id}/pqc-assessment", summary="Get PQC & HNDL Risk Assessment")
def get_session_pqc_assessment(analysis_id: str, session_id: str) -> Dict[str, Any]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
    target_session = None
    for s in analysis.sessions:
        if s.session_id == session_id:
            target_session = s
            break
    if not target_session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    assessment = PQCAnalyzer.analyze_session(target_session)
    return assessment.to_dict()


# 6. Digital Signatures
@router.post("/analyses/{analysis_id}/sign-report", summary="Locally Sign Forensic Report")
def sign_report(analysis_id: str, req: SignReportRequest) -> Dict[str, Any]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
    sig = ReportSigner.sign_hash(analysis.file_sha256, analyst_name=req.analyst_name or "Local Forensic Analyst")
    return sig


# 7. External Notarization State
@router.get("/analyses/{analysis_id}/notarization", summary="Get Notarization State")
def get_notarization_state(analysis_id: str) -> Dict[str, Any]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
    proof = NotarizationService.notarize(analysis.file_sha256)
    return proof.to_dict()


# 8. Cases Management
@router.get("/cases", summary="List All Forensic Cases")
def list_cases() -> List[Dict[str, Any]]:
    return CaseService.list_cases()


@router.post("/cases", summary="Create New Forensic Case")
def create_case(
    req: CaseCreateRequest,
    actor: ActorContext = Depends(get_actor_context),
) -> Dict[str, Any]:
    # Use declared actor if explicit headers provided, otherwise use body fields if present
    effective_actor = actor
    if effective_actor.attribution_status == "UNATTRIBUTED" and (req.analyst_id or req.analyst_name):
        effective_actor = ActorContext(
            actor_id=req.analyst_id or "UNATTRIBUTED",
            actor_display_name=req.analyst_name or req.analyst_id or "Unattributed Actor",
            identity_source="LOCAL_DECLARED",
            attribution_status="ATTRIBUTED" if req.analyst_id else "UNATTRIBUTED",
        )
    case = CaseService.create_case(
        title=req.title,
        description=req.description or "",
        analyst_id=effective_actor.actor_id,
        analyst_name=effective_actor.actor_display_name,
        tags=req.tags,
        actor=effective_actor,
    )
    return case.to_dict()


@router.get("/cases/{case_id}", summary="Get Case Details")
def get_case(case_id: str) -> Dict[str, Any]:
    case = CaseService.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return case


@router.post("/cases/{case_id}/notes", summary="Add Analyst Note to Case")
def add_case_note(
    case_id: str,
    req: CaseNoteRequest,
    actor: ActorContext = Depends(get_actor_context),
) -> Dict[str, Any]:
    effective_actor = actor
    if effective_actor.attribution_status == "UNATTRIBUTED" and (req.analyst_id or req.author):
        effective_actor = ActorContext(
            actor_id=req.analyst_id or "UNATTRIBUTED",
            actor_display_name=req.author or req.analyst_id or "Unattributed Actor",
            identity_source="LOCAL_DECLARED",
            attribution_status="ATTRIBUTED" if req.analyst_id else "UNATTRIBUTED",
        )
    updated = CaseService.add_note_to_case(
        case_id=case_id,
        author=effective_actor.actor_display_name,
        note_text=req.text,
        analyst_id=effective_actor.actor_id,
        actor=effective_actor,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return updated


@router.post("/cases/{case_id}/artifacts", summary="Add Artifact to Case")
def add_case_artifact(
    case_id: str,
    req: CaseArtifactRequest,
    actor: ActorContext = Depends(get_actor_context),
) -> Dict[str, Any]:
    updated = CaseService.add_artifact_to_case(
        case_id=case_id,
        artifact_type=req.artifact_type,
        filename=req.filename,
        sha256=req.sha256,
        analysis_id=req.analysis_id,
        actor=actor,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return updated


@router.post("/cases/{case_id}/analyses/{analysis_id}", summary="Attach Forensic Analysis to Case")
def attach_analysis_to_case(
    case_id: str,
    analysis_id: str,
    actor: ActorContext = Depends(get_actor_context),
) -> Dict[str, Any]:
    case = CaseService.attach_analysis_to_case(
        case_id=case_id,
        analysis_id=analysis_id,
        analyst_id=actor.actor_id,
        actor=actor,
    )
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' or Analysis '{analysis_id}' not found.")
    return case


@router.delete("/cases/{case_id}/analyses/{analysis_id}", summary="Detach Forensic Analysis from Case")
def detach_analysis_from_case(
    case_id: str,
    analysis_id: str,
    actor: ActorContext = Depends(get_actor_context),
) -> Dict[str, Any]:
    case = CaseService.detach_analysis_from_case(
        case_id=case_id,
        analysis_id=analysis_id,
        actor=actor,
    )
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return case


@router.post("/cases/{case_id}/archive", summary="Soft-Archive Forensic Case")
def archive_case(
    case_id: str,
    actor: ActorContext = Depends(get_actor_context),
) -> Dict[str, Any]:
    case = CaseService.archive_case(case_id, actor=actor)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return case


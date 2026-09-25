"""
SecureMailScope X - Advanced Capabilities Endpoints
Includes Active Mail Scanner, Simulate Fix, Incident Correlation, ML Triage & XAI, Digital Signatures, Notarization, and Case Management.
"""

from fastapi import APIRouter, HTTPException, status, Body
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


router = APIRouter()


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
    analyst_id: Optional[str] = "analyst-01"
    analyst_name: Optional[str] = "Default Local Analyst"
    tags: Optional[List[str]] = None


class CaseNoteRequest(BaseModel):
    author: str
    text: str


class CaseArtifactRequest(BaseModel):
    artifact_type: str
    filename: str
    sha256: str
    analysis_id: Optional[str] = None


class SignReportRequest(BaseModel):
    analyst_name: Optional[str] = "Local Forensic Analyst"


# 1. Active Scanner (Phase 9 Posture Scanner & Legacy Probe)
@router.post("/scanner/mail-posture", summary="Execute Explicit Opt-In Active Mail Server Posture Scan")
def scan_mail_posture(req: MailPostureScanRequest) -> Dict[str, Any]:
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
            provenance="ACTIVE_NETWORK_PROBE"
        )
    except Exception:
        pass
    return res_dict


@router.post("/scanner/probe", summary="Execute Active Mail Server Security Probe (Legacy)")
def probe_mail_server(req: ActiveScanRequest) -> Dict[str, Any]:
    if not req.target_host:
        raise HTTPException(status_code=400, detail="Target host is required.")
    report = ActiveMailScanner.scan_target(req.target_host, req.ports)
    return report.to_dict()


# 2. Simulate Fix / What-If Remediation (Phase 10)
@router.post("/analyses/{analysis_id}/simulate-fix", summary="Execute Evidence-Preserving Remediation Simulation")
def simulate_analysis_fix(analysis_id: str, req: SimulateFixRequest) -> Dict[str, Any]:
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
            parameters=req.parameters
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
def create_case(req: CaseCreateRequest) -> Dict[str, Any]:
    case = CaseService.create_case(
        title=req.title,
        description=req.description or "",
        analyst_id=req.analyst_id or "analyst-01",
        analyst_name=req.analyst_name or "Default Local Analyst",
        tags=req.tags,
    )
    return case.to_dict()


@router.get("/cases/{case_id}", summary="Get Case Details")
def get_case(case_id: str) -> Dict[str, Any]:
    case = CaseService.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return case


@router.post("/cases/{case_id}/notes", summary="Add Analyst Note to Case")
def add_case_note(case_id: str, req: CaseNoteRequest) -> Dict[str, Any]:
    updated = CaseService.add_note_to_case(case_id, author=req.author, note_text=req.text)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return updated


@router.post("/cases/{case_id}/artifacts", summary="Add Artifact to Case")
def add_case_artifact(case_id: str, req: CaseArtifactRequest) -> Dict[str, Any]:
    updated = CaseService.add_artifact_to_case(
        case_id=case_id,
        artifact_type=req.artifact_type,
        filename=req.filename,
        sha256=req.sha256,
        analysis_id=req.analysis_id,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return updated


@router.post("/cases/{case_id}/analyses/{analysis_id}", summary="Attach Forensic Analysis to Case")
def attach_analysis_to_case(case_id: str, analysis_id: str) -> Dict[str, Any]:
    case = CaseService.attach_analysis_to_case(case_id, analysis_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' or Analysis '{analysis_id}' not found.")
    return case


@router.delete("/cases/{case_id}/analyses/{analysis_id}", summary="Detach Forensic Analysis from Case")
def detach_analysis_from_case(case_id: str, analysis_id: str) -> Dict[str, Any]:
    case = CaseService.detach_analysis_from_case(case_id, analysis_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return case


@router.post("/cases/{case_id}/archive", summary="Soft-Archive Forensic Case")
def archive_case(case_id: str) -> Dict[str, Any]:
    case = CaseService.archive_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return case

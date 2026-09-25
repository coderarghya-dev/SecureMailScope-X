from fastapi import APIRouter, UploadFile, File, HTTPException, Response, status, Query, Header, Depends
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from app.schemas.api import (
    AnalysisDetailResponse,
    ForensicReportResponse,
    CustodyRecordResponse,
    CustodyManifestVersionDTO,
    ReportArtifactDTO,
    ManifestChainVerificationResponse,
    ReportSignatureRequest,
    DigitalSignatureDTO,
    SignatureVerificationResponse,
    ReportSignaturesListResponse,
)
from app.schemas.identity import ActorContext
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportService
from app.services.custody_service import CustodyService
from app.db.repository import ForensicRepository, IntegrityVerificationError
from app.services.case_service import CaseService


router = APIRouter()


@router.post(
    "/analyze",
    response_model=AnalysisDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload & Analyze PCAP/PCAPNG File",
    description="Upload a packet capture file to execute passive email protocol dissection, STARTTLS state extraction, TLS cryptographic inspection, health scoring, and security assessment."
)
async def analyze_pcap_upload(
    file: UploadFile = File(...),
    x_analyst_id: Optional[str] = Header(None, alias="X-Analyst-ID"),
    x_analyst_name: Optional[str] = Header(None, alias="X-Analyst-Name"),
) -> AnalysisDetailResponse:
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required."
        )

    actor = ActorContext.from_headers(x_analyst_id=x_analyst_id, x_analyst_name=x_analyst_name)

    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(e)}"
        )

    try:
        report = AnalysisService.process_pcap_bytes(file.filename, content, actor=actor)
        return report
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except RuntimeError as run_err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forensic engine error: {str(run_err)}"
        )


class AnalysisNoteRequest(BaseModel):
    author: Optional[str] = None
    text: str
    analyst_id: Optional[str] = None


@router.get(
    "/analyses",
    summary="List Historical Analyses",
    description="Lists all persisted forensic analyses with metadata, SHA-256 seals, session counts, and security grades."
)
def list_analyses(include_archived: bool = False) -> List[Dict[str, Any]]:
    return AnalysisService.list_analyses(include_archived=include_archived)


@router.get(
    "/analyze/{analysis_id}",
    response_model=AnalysisDetailResponse,
    summary="Get Analysis Report by ID",
    description="Retrieve full analysis report and reconstructed email sessions for a previously analyzed capture."
)
@router.get(
    "/analyses/{analysis_id}",
    response_model=AnalysisDetailResponse,
    include_in_schema=False
)
def get_analysis_by_id(analysis_id: str) -> AnalysisDetailResponse:
    report = AnalysisService.get_analysis(analysis_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis report '{analysis_id}' not found."
        )
    return report


@router.post(
    "/analyses/{analysis_id}/notes",
    summary="Add Additive Analyst Note to Analysis",
    description="Appends an immutable, cryptographic analyst note associated with this analysis."
)
def add_analysis_note(
    analysis_id: str,
    req: AnalysisNoteRequest,
    x_analyst_id: Optional[str] = Header(None, alias="X-Analyst-ID"),
    x_analyst_name: Optional[str] = Header(None, alias="X-Analyst-Name"),
) -> Dict[str, Any]:
    actor = ActorContext.from_headers(x_analyst_id=x_analyst_id, x_analyst_name=x_analyst_name)
    if actor.attribution_status == "UNATTRIBUTED" and (req.analyst_id or req.author):
        actor = ActorContext(
            actor_id=req.analyst_id or "UNATTRIBUTED",
            actor_display_name=req.author or req.analyst_id or "Unattributed Actor",
            identity_source="LOCAL_DECLARED",
            attribution_status="ATTRIBUTED" if req.analyst_id else "UNATTRIBUTED",
        )
    note = CaseService.add_note_to_analysis(
        analysis_id=analysis_id,
        author=actor.actor_display_name,
        note_text=req.text,
        analyst_id=actor.actor_id,
        actor=actor,
    )
    if not note:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
    return note



@router.get(
    "/analyses/{analysis_id}/notes",
    summary="Get Analyst Notes for Analysis",
    description="Retrieves the chronological, append-only analyst notes log for this analysis."
)
def get_analysis_notes(analysis_id: str) -> List[Dict[str, Any]]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
    return ForensicRepository.get_analyst_notes("ANALYSIS", analysis_id)


@router.get(
    "/analyses/{analysis_id}/history",
    summary="Get Analysis History & Provenance",
    description="Returns full audit event trail and provenance record for this analysis."
)
def get_analysis_history(analysis_id: str) -> Dict[str, Any]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
    custody = CustodyService.verify_integrity(analysis_id)
    notes = ForensicRepository.get_analyst_notes("ANALYSIS", analysis_id)
    return {
        "analysis_id": analysis_id,
        "filename": analysis.file_name,
        "analysis_time_utc": analysis.analysis_time_utc,
        "tshark_version": analysis.tshark_version,
        "overall_custody_status": custody.overall_status,
        "audit_events": [e.model_dump() if hasattr(e, "model_dump") else e.dict() for e in custody.audit_events],
        "analyst_notes": notes
    }


@router.get(
    "/analyze/{analysis_id}/report",
    response_model=ForensicReportResponse,
    summary="Get Structured Forensic Audit Report",
    description="Returns full 8-section forensic report model with evidence mappings, cryptographic posture, and limitations."
)
@router.get(
    "/analyses/{analysis_id}/report",
    response_model=ForensicReportResponse,
    include_in_schema=False
)
def get_forensic_report_by_id(analysis_id: str) -> ForensicReportResponse:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis report '{analysis_id}' not found."
        )
    return ReportService.generate_report_model(analysis)


@router.get(
    "/analyze/{analysis_id}/pdf",
    summary="Export Forensic Report as PDF",
    description="Generates and downloads a publication-grade PDF report with running headers, footers, tables, and evidence frames."
)
@router.get(
    "/analyses/{analysis_id}/report/pdf",
    include_in_schema=False
)
@router.get(
    "/analyses/{analysis_id}/pdf",
    include_in_schema=False
)
def export_forensic_report_pdf(analysis_id: str):
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis report '{analysis_id}' not found."
        )
    try:
        pdf_bytes = ReportService.generate_pdf_bytes(analysis)
        clean_filename = analysis.file_name.rsplit(".", 1)[0]
        pdf_filename = f"{clean_filename}_forensic_report.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{pdf_filename}"',
                "Content-Type": "application/pdf"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to render PDF report: {str(e)}"
        )


@router.get(
    "/analyses/{analysis_id}/custody",
    response_model=CustodyRecordResponse,
    summary="Get Cryptographic Chain of Custody Record",
    description="Returns verified capture SHA-256 seal, analysis manifest hash, and append-only audit event chain."
)
@router.get(
    "/analyze/{analysis_id}/custody",
    response_model=CustodyRecordResponse,
    include_in_schema=False
)
def get_analysis_custody(analysis_id: str) -> CustodyRecordResponse:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis report '{analysis_id}' not found."
        )
    return CustodyService.verify_integrity(analysis_id, record_verification_event=False)


@router.post(
    "/analyses/{analysis_id}/custody/verify",
    response_model=CustodyRecordResponse,
    summary="Re-Verify Chain of Custody & Evidence Sealing",
    description="Executes a live cryptographic re-verification over the raw capture bytes, sealed manifest, and chained audit event trail."
)
@router.post(
    "/analyze/{analysis_id}/custody/verify",
    response_model=CustodyRecordResponse,
    include_in_schema=False
)
def verify_analysis_custody(analysis_id: str) -> CustodyRecordResponse:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis report '{analysis_id}' not found."
        )
    return CustodyService.verify_integrity(analysis_id, record_verification_event=True)


@router.post(
    "/analyses/{analysis_id}/custody/tamper-demo",
    response_model=CustodyRecordResponse,
    summary="Controlled Tamper Demonstration (Non-Destructive)",
    description="Tests real hash-chain cryptographic verification by introducing a 1-byte mutation or hash mismatch on an isolated test copy without modifying original PCAP bytes."
)
@router.post(
    "/analyze/{analysis_id}/custody/tamper-demo",
    response_model=CustodyRecordResponse,
    include_in_schema=False
)
def tamper_demo_custody(
    analysis_id: str,
    target: str = Query("capture", enum=["capture", "manifest", "event", "restore"], description="Target artifact to tamper in test copy")
) -> CustodyRecordResponse:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis report '{analysis_id}' not found."
        )
    record = CustodyService.get_record(analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Custody record '{analysis_id}' not found."
        )

    if target == "restore":
        return CustodyService.verify_integrity(analysis_id)
    elif target == "capture":
        # Mutate 1 byte in a test copy of raw capture bytes
        test_bytes = bytearray(record.raw_bytes)
        if len(test_bytes) > 0:
            test_bytes[0] ^= 0xFF
        return CustodyService.verify_integrity(analysis_id, override_capture_bytes=bytes(test_bytes))
    elif target == "manifest":
        # Mutate 1 field in manifest dictionary test copy
        test_manifest = dict(record.manifest_dict or {})
        test_manifest["findings_count"] = (test_manifest.get("findings_count", 0)) + 99
        return CustodyService.verify_integrity(analysis_id, override_manifest_dict=test_manifest)
    elif target == "event":
        # Mutate event #0 hash in audit chain test copy
        tampered_hash = "f" * 64
        return CustodyService.verify_integrity(analysis_id, override_event=(0, tampered_hash))
    else:
        return CustodyService.verify_integrity(analysis_id)


# ---------------------------------------------------------------------------
# Phase 13 Manifest Versioning & Report Artifact Endpoints
# ---------------------------------------------------------------------------
@router.get(
    "/analyses/{analysis_id}/manifests",
    response_model=List[CustodyManifestVersionDTO],
    summary="List Custody Manifest Versions",
    description="Returns the chronological, immutable chain of sealed manifest versions for this analysis."
)
@router.get(
    "/analyze/{analysis_id}/manifests",
    response_model=List[CustodyManifestVersionDTO],
    include_in_schema=False
)
def list_analysis_manifests(analysis_id: str) -> List[CustodyManifestVersionDTO]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found."
        )
    versions = ForensicRepository.get_manifest_versions(analysis_id)
    return [CustodyManifestVersionDTO(**v) for v in versions]


@router.get(
    "/analyses/{analysis_id}/manifests/verify",
    response_model=ManifestChainVerificationResponse,
    summary="Verify Manifest Version Chain & Artifact Integrity",
    description="Performs read-only tamper and chain verification over all manifest versions and linked report artifacts."
)
@router.get(
    "/analyze/{analysis_id}/manifests/verify",
    response_model=ManifestChainVerificationResponse,
    include_in_schema=False
)
def verify_analysis_manifest_chain(analysis_id: str) -> ManifestChainVerificationResponse:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found."
        )
    res = ForensicRepository.verify_manifest_chain(analysis_id)
    return ManifestChainVerificationResponse(**res)


@router.get(
    "/analyses/{analysis_id}/manifests/{version}",
    response_model=CustodyManifestVersionDTO,
    summary="Get Specific Custody Manifest Version",
    description="Retrieves a specific sealed manifest version by version number or version ID."
)
@router.get(
    "/analyze/{analysis_id}/manifests/{version}",
    response_model=CustodyManifestVersionDTO,
    include_in_schema=False
)
def get_analysis_manifest_version(analysis_id: str, version: str) -> CustodyManifestVersionDTO:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found."
        )
    v_data = ForensicRepository.get_manifest_version(analysis_id, version)
    if not v_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Manifest version '{version}' for analysis '{analysis_id}' not found."
        )
    return CustodyManifestVersionDTO(**v_data)


@router.get(
    "/analyses/{analysis_id}/reports",
    response_model=List[ReportArtifactDTO],
    summary="List Report Artifacts",
    description="Returns the full generation history of report artifacts associated with this analysis."
)
@router.get(
    "/analyze/{analysis_id}/reports",
    response_model=List[ReportArtifactDTO],
    include_in_schema=False
)
def list_analysis_reports(analysis_id: str) -> List[ReportArtifactDTO]:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found."
        )
    artifacts = ForensicRepository.get_report_artifacts(analysis_id)
    return [ReportArtifactDTO(**a) for a in artifacts]


@router.get(
    "/analyses/{analysis_id}/reports/{report_artifact_id}",
    summary="Get Report Artifact or Download PDF",
    description="Retrieves report artifact metadata or downloads raw PDF bytes if requested."
)
@router.get(
    "/analyze/{analysis_id}/reports/{report_artifact_id}",
    include_in_schema=False
)
def get_analysis_report_artifact(
    analysis_id: str,
    report_artifact_id: str,
    download: bool = Query(False, description="Whether to download raw PDF binary bytes")
):
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found."
        )
    art = ForensicRepository.get_report_artifact(report_artifact_id)
    if not art or art.get("analysis_id") != analysis_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report artifact '{report_artifact_id}' for analysis '{analysis_id}' not found."
        )

    if download:
        pdf_bytes = art.get("raw_bytes")
        if not pdf_bytes and art.get("file_path") and os.path.isfile(art["file_path"]):
            with open(art["file_path"], "rb") as f:
                pdf_bytes = f.read()

        if not pdf_bytes:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report artifact binary bytes for '{report_artifact_id}' not found."
            )

        return Response(
            content=pdf_bytes,
            media_type=art.get("media_type", "application/pdf"),
            headers={
                "Content-Disposition": f'attachment; filename="{art["filename"]}"',
                "Content-Type": art.get("media_type", "application/pdf"),
            }
        )

    return ReportArtifactDTO(**art)


# ---------------------------------------------------------------------------
# Phase 14 Digital Report Signing & Signature Verification Endpoints
# ---------------------------------------------------------------------------
@router.post(
    "/analyses/{analysis_id}/reports/{report_artifact_id}/sign",
    response_model=DigitalSignatureDTO,
    summary="Cryptographically Sign Report Artifact",
    description="Generates an asymmetric digital signature (Ed25519/ECDSA/RSA-PSS) for a report artifact and appends a SIGNATURE_LINKAGE_MANIFEST."
)
@router.post(
    "/analyze/{analysis_id}/reports/{report_artifact_id}/sign",
    response_model=DigitalSignatureDTO,
    include_in_schema=False
)
def sign_analysis_report(
    analysis_id: str,
    report_artifact_id: str,
    req: Optional[ReportSignatureRequest] = None,
    x_analyst_id: Optional[str] = Header(None, alias="X-Analyst-ID"),
    x_analyst_name: Optional[str] = Header(None, alias="X-Analyst-Name"),
) -> DigitalSignatureDTO:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found."
        )

    actor = ActorContext.from_headers(x_analyst_id=x_analyst_id, x_analyst_name=x_analyst_name)
    key_id = req.key_id if req else None
    priv_pem = req.private_key_pem if req else None
    priv_pwd = req.private_key_password if req else None
    algo = req.algorithm if req else None

    try:
        from app.services.signature_service import (
            SignatureService,
            SigningUnavailableError,
            UnsupportedAlgorithmError,
            SigningError,
        )
        sig_data = SignatureService.sign_report_artifact(
            analysis_id=analysis_id,
            report_artifact_id=report_artifact_id,
            key_id=key_id,
            private_key_pem=priv_pem,
            password=priv_pwd,
            algorithm=algo,
            actor=actor,
        )
        return DigitalSignatureDTO(**sig_data)
    except SigningUnavailableError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"SIGNING_UNAVAILABLE: {str(e)}"
        )
    except UnsupportedAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"UNSUPPORTED_ALGORITHM: {str(e)}"
        )
    except (IntegrityVerificationError, SigningError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Signature generation failed: {str(e)}"
        )


@router.get(
    "/analyses/{analysis_id}/reports/{report_artifact_id}/signatures",
    response_model=ReportSignaturesListResponse,
    summary="List Signatures for Report Artifact",
    description="Lists all asymmetric digital signatures issued for a specific report artifact."
)
@router.get(
    "/analyze/{analysis_id}/reports/{report_artifact_id}/signatures",
    response_model=ReportSignaturesListResponse,
    include_in_schema=False
)
def list_report_signatures(analysis_id: str, report_artifact_id: str) -> ReportSignaturesListResponse:
    analysis = AnalysisService.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found."
        )
    sigs = ForensicRepository.get_report_signatures(analysis_id, report_artifact_id)
    return ReportSignaturesListResponse(
        analysis_id=analysis_id,
        report_artifact_id=report_artifact_id,
        total_signatures=len(sigs),
        signatures=[DigitalSignatureDTO(**s) for s in sigs]
    )


@router.get(
    "/signatures/{signature_id}",
    response_model=DigitalSignatureDTO,
    summary="Get Digital Signature Record",
    description="Retrieves public digital signature metadata, public key PEM, and fingerprint."
)
def get_signature_by_id(signature_id: str) -> DigitalSignatureDTO:
    sig = ForensicRepository.get_digital_signature(signature_id)
    if not sig:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Digital signature '{signature_id}' not found."
        )
    return DigitalSignatureDTO(**sig)


@router.get(
    "/signatures/{signature_id}/verify",
    response_model=SignatureVerificationResponse,
    summary="Verify Digital Signature",
    description="Performs read-only cryptographic verification over the digital signature, public key fingerprint, report artifact, and source manifest."
)
def verify_signature_by_id(signature_id: str) -> SignatureVerificationResponse:
    from app.services.signature_service import SignatureService
    res = SignatureService.verify_signature(signature_id)
    return SignatureVerificationResponse(**res)





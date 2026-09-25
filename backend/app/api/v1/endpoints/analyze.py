"""
SecureMailScope X - Forensic PCAP Analysis Endpoints
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, Response, status, Query
from app.schemas.api import AnalysisDetailResponse, ForensicReportResponse, CustodyRecordResponse
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportService
from app.services.custody_service import CustodyService

router = APIRouter()


@router.post(
    "/analyze",
    response_model=AnalysisDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload & Analyze PCAP/PCAPNG File",
    description="Upload a packet capture file to execute passive email protocol dissection, STARTTLS state extraction, TLS cryptographic inspection, health scoring, and security assessment."
)
async def analyze_pcap_upload(file: UploadFile = File(...)) -> AnalysisDetailResponse:
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required."
        )

    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(e)}"
        )

    try:
        report = AnalysisService.process_pcap_bytes(file.filename, content)
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


@router.get(
    "/analyze/{analysis_id}",
    response_model=AnalysisDetailResponse,
    summary="Get Analysis Report by ID",
    description="Retrieve full analysis report and reconstructed email sessions for a previously analyzed capture."
)
def get_analysis_by_id(analysis_id: str) -> AnalysisDetailResponse:
    report = AnalysisService.get_analysis(analysis_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis report '{analysis_id}' not found."
        )
    return report


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
    return CustodyService.verify_integrity(analysis_id)


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
    return CustodyService.verify_integrity(analysis_id)


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




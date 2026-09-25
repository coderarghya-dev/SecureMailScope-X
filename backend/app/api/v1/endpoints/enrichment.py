"""
SecureMailScope X - Email Domain Auth & .EML Forensics Endpoints
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, status, Body
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from app.dns.email_auth_analyzer import EmailAuthAnalyzer
from app.eml.eml_analyzer import EMLForensicAnalyzer


router = APIRouter()


class DNSAuthRequest(BaseModel):
    domain: str
    txt_records: Optional[List[str]] = None
    dmarc_record: Optional[str] = None
    mta_sts_record: Optional[str] = None
    bimi_record: Optional[str] = None
    active_lookup: bool = False


@router.post(
    "/enrichment/dns-auth",
    summary="Evaluate Domain Email Authentication (SPF, DMARC, MTA-STS, BIMI)",
    description="Analyzes email authentication records. Performs active DoH lookup ONLY if active_lookup is True."
)
def analyze_dns_auth(req: DNSAuthRequest) -> Dict[str, Any]:
    if not req.domain:
        raise HTTPException(status_code=400, detail="Domain name is required.")
    
    if req.active_lookup:
        assessment = EmailAuthAnalyzer.query_active_domain(req.domain)
    else:
        assessment = EmailAuthAnalyzer.analyze_records(
            domain=req.domain,
            txt_records=req.txt_records or [],
            dmarc_txt=req.dmarc_record,
            mta_sts_txt=req.mta_sts_record,
            bimi_txt=req.bimi_record,
            is_active=False,
            data_source="Offline Provided DNS Records",
        )
    return assessment.to_dict()


@router.post(
    "/eml/analyze",
    summary="Upload and Analyze RFC 5322 .EML Message File",
    description="Parses email headers, extracts Received relay hop chains, and evaluates Authentication-Results."
)
async def analyze_eml_file(file: UploadFile = File(...)) -> Dict[str, Any]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required.")
    try:
        content = await file.read()
        report = EMLForensicAnalyzer.parse_eml_content(content)
        return report.to_dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse .EML file: {str(e)}")

"""
SecureMailScope X - Cross-Case Correlation & IOC Intelligence Engine API Endpoints (Phase 18)
Exposes REST endpoints for summary statistics, graph topologies, offline IOC search,
case/analysis correlation drilldown, and STIX 2.1 export.
"""

from typing import List, Optional
from fastapi import APIRouter, Query, HTTPException, status
from fastapi.responses import JSONResponse

from app.schemas.correlation import (
    CorrelationSummaryResponse,
    CorrelationGraphDTO,
    IOCSearchResultDTO,
    CorrelationRelationship,
)
from app.services.correlation_service import CorrelationService
from app.db.repository import ForensicRepository

router = APIRouter()


@router.get(
    "/correlation/summary",
    response_model=CorrelationSummaryResponse,
    summary="Get Correlation Summary & Top Indicators",
    description="Retrieves aggregated cross-analysis and cross-case correlation statistics and highest degree indicators."
)
def get_correlation_summary():
    try:
        return CorrelationService.get_correlation_summary()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate correlation summary: {str(e)}"
        )


@router.get(
    "/correlation/graph",
    response_model=CorrelationGraphDTO,
    summary="Get Correlation Graph Topology",
    description="Retrieves deterministic multi-entity graph nodes and edges for cases, analyses, and observed indicators."
)
def get_correlation_graph(
    case_id: Optional[str] = Query(None, description="Filter graph by specific Case ID"),
    analysis_id: Optional[str] = Query(None, description="Filter graph by specific Analysis ID"),
    ioc_type: Optional[str] = Query(None, description="Filter graph by IOC category (IP_ADDRESS, DOMAIN, etc.)")
):
    try:
        return CorrelationService.build_correlation_graph(
            case_id=case_id,
            analysis_id=analysis_id,
            ioc_type=ioc_type
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate correlation graph: {str(e)}"
        )


@router.get(
    "/correlation/search",
    response_model=IOCSearchResultDTO,
    summary="Search Indicators of Compromise Offline",
    description="Searches normalized indicators across the local repository with provenance and matched correlations."
)
def search_iocs(
    value: str = Query(..., min_length=1, description="Indicator search query term"),
    ioc_type: Optional[str] = Query(None, description="Optional IOC type filter")
):
    try:
        return CorrelationService.search_iocs(query=value, ioc_type=ioc_type)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute IOC search: {str(e)}"
        )


@router.get(
    "/cases/{case_id}/correlations",
    response_model=List[CorrelationRelationship],
    summary="Get Correlations for Specific Case",
    description="Retrieves all cross-analysis and cross-case correlation links associated with the specified case."
)
def get_case_correlations(case_id: str):
    case = ForensicRepository.get_case(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic case '{case_id}' not found."
        )
    all_correlations = CorrelationService.compute_correlations()
    return [c for c in all_correlations if case_id in c.matched_cases]


@router.get(
    "/analyses/{analysis_id}/correlations",
    response_model=List[CorrelationRelationship],
    summary="Get Correlations for Specific Analysis",
    description="Retrieves all cross-analysis correlation links associated with the specified analysis."
)
def get_analysis_correlations(analysis_id: str):
    analysis = ForensicRepository.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic analysis '{analysis_id}' not found."
        )
    all_correlations = CorrelationService.compute_correlations()
    return [c for c in all_correlations if analysis_id in c.matched_analyses]


@router.get(
    "/correlation/export/stix",
    summary="Export STIX 2.1 Correlation Bundle",
    description="Generates and downloads a standardized STIX 2.1 JSON bundle representing forensic observations and relationships."
)
def export_stix21_bundle(
    case_id: Optional[str] = Query(None, description="Optional case ID to scope export"),
    analysis_id: Optional[str] = Query(None, description="Optional analysis ID to scope export")
):
    try:
        bundle = CorrelationService.export_stix21_bundle(
            case_id=case_id,
            analysis_id=analysis_id
        )
        return JSONResponse(
            content=bundle,
            headers={
                "Content-Disposition": "attachment; filename=sms_stix21_correlation_bundle.json",
                "Content-Type": "application/json"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export STIX 2.1 bundle: {str(e)}"
        )

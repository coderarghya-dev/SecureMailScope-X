"""
SecureMailScope X - Cross-Case Correlation & IOC Intelligence Engine Schemas (Phase 18)
Provides normalized IOC representations, cross-analysis correlation relationships,
deterministic graph data structures, and STIX 2.1 export specifications.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    HOSTNAME = "HOSTNAME"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    CERTIFICATE_FINGERPRINT = "CERTIFICATE_FINGERPRINT"
    CERTIFICATE_SUBJECT = "CERTIFICATE_SUBJECT"
    CERTIFICATE_ISSUER = "CERTIFICATE_ISSUER"
    MESSAGE_ID = "MESSAGE_ID"
    ARTIFACT_SHA256 = "ARTIFACT_SHA256"
    MAIL_ENDPOINT = "MAIL_ENDPOINT"
    TLS_CONFIGURATION = "TLS_CONFIGURATION"


class CorrelationRelationshipType(str, Enum):
    SHARED_IP = "SHARED_IP"
    SHARED_DOMAIN = "SHARED_DOMAIN"
    SHARED_HOSTNAME = "SHARED_HOSTNAME"
    SHARED_EMAIL = "SHARED_EMAIL"
    SHARED_CERTIFICATE = "SHARED_CERTIFICATE"
    SHARED_CERTIFICATE_SUBJECT = "SHARED_CERTIFICATE_SUBJECT"
    SHARED_CERTIFICATE_ISSUER = "SHARED_CERTIFICATE_ISSUER"
    SHARED_MESSAGE_ID = "SHARED_MESSAGE_ID"
    SHARED_ARTIFACT = "SHARED_ARTIFACT"
    SHARED_MAIL_ENDPOINT = "SHARED_MAIL_ENDPOINT"
    SHARED_TLS_CONFIG = "SHARED_TLS_CONFIG"


class IOCProvenance(BaseModel):
    """Detailed evidence provenance identifying exact origin of an observed indicator."""
    analysis_id: str = Field(..., description="Unique identifier of the forensic analysis")
    case_id: Optional[str] = Field(None, description="Forensic case ID if linked")
    session_id: Optional[str] = Field(None, description="Stream session ID where indicator was observed")
    protocol: Optional[str] = Field(None, description="Observed protocol (SMTP, IMAP, POP3, TLS, DNS)")
    frame_number: Optional[int] = Field(None, description="Exact packet frame number if derived from PCAP")
    evidence_source: str = Field("PCAP_PACKET", description="Source category (PCAP_PACKET, EML_HEADER, TLS_CERTIFICATE, DNS_ENRICHMENT, ACTIVE_SCAN, MANIFEST)")
    observed_at_utc: Optional[str] = Field(None, description="UTC timestamp of the observed evidence")


class NormalizedIOC(BaseModel):
    """Normalized indicator of compromise extracted from verified forensic evidence."""
    ioc_type: IOCType = Field(..., description="Normalized category of the indicator")
    raw_value: str = Field(..., description="Raw observed indicator value before normalization")
    normalized_value: str = Field(..., description="Canonically normalized indicator value")
    provenance: List[IOCProvenance] = Field(default_factory=list, description="All observation origins")
    first_seen_utc: str = Field(..., description="Earliest observation timestamp")
    last_seen_utc: str = Field(..., description="Latest observation timestamp")
    observation_count: int = Field(1, description="Total number of observations across all analyses")
    associated_findings: List[str] = Field(default_factory=list, description="Security finding IDs linked to this indicator")


class CorrelationRelationship(BaseModel):
    """Evidence-backed relationship linking multiple forensic analyses or cases."""
    relationship_id: str = Field(..., description="Deterministic relationship identifier")
    relationship_type: CorrelationRelationshipType = Field(..., description="Relationship category")
    ioc_type: IOCType = Field(..., description="Normalized IOC type")
    ioc_value: str = Field(..., description="Normalized IOC value forming the link")
    matched_analyses: List[str] = Field(default_factory=list, description="Analysis IDs sharing this indicator")
    matched_cases: List[str] = Field(default_factory=list, description="Case IDs sharing this indicator")
    observation_count: int = Field(..., description="Total observations across matches")
    evidence_summary: str = Field(..., description="Explainable factual summary of the shared evidence")
    risk_context: Optional[str] = Field(None, description="Objective security risk context if findings are attached")
    first_observed_utc: str = Field(..., description="First observation UTC")
    last_observed_utc: str = Field(..., description="Latest observation UTC")


class GraphNodeType(str, Enum):
    CASE = "CASE"
    ANALYSIS = "ANALYSIS"
    IP = "IP"
    DOMAIN = "DOMAIN"
    HOSTNAME = "HOSTNAME"
    EMAIL = "EMAIL"
    CERTIFICATE = "CERTIFICATE"
    MAIL_ENDPOINT = "MAIL_ENDPOINT"
    ARTIFACT = "ARTIFACT"
    TLS_CONFIG = "TLS_CONFIG"


class GraphEdgeType(str, Enum):
    CASE_CONTAINS_ANALYSIS = "CASE_CONTAINS_ANALYSIS"
    ANALYSIS_OBSERVED_IP = "ANALYSIS_OBSERVED_IP"
    ANALYSIS_OBSERVED_DOMAIN = "ANALYSIS_OBSERVED_DOMAIN"
    ANALYSIS_OBSERVED_HOSTNAME = "ANALYSIS_OBSERVED_HOSTNAME"
    ANALYSIS_OBSERVED_EMAIL = "ANALYSIS_OBSERVED_EMAIL"
    ANALYSIS_OBSERVED_CERT = "ANALYSIS_OBSERVED_CERT"
    ANALYSIS_OBSERVED_ENDPOINT = "ANALYSIS_OBSERVED_ENDPOINT"
    ANALYSIS_PRODUCED_ARTIFACT = "ANALYSIS_PRODUCED_ARTIFACT"
    ANALYSIS_OBSERVED_TLS_CONFIG = "ANALYSIS_OBSERVED_TLS_CONFIG"


class CorrelationGraphNode(BaseModel):
    node_id: str = Field(..., description="Unique node ID (e.g. case:CASE-1, ioc:IP:1.2.3.4)")
    node_type: GraphNodeType = Field(..., description="Node categorization")
    label: str = Field(..., description="Display label for the graph node")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Metadata attributes")


class CorrelationGraphEdge(BaseModel):
    source_id: str = Field(..., description="Origin node ID")
    target_id: str = Field(..., description="Destination node ID")
    edge_type: GraphEdgeType = Field(..., description="Edge categorization")
    label: str = Field(..., description="Display label for the graph edge")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Metadata attributes")


class CorrelationGraphDTO(BaseModel):
    nodes: List[CorrelationGraphNode] = Field(default_factory=list, description="Graph nodes")
    edges: List[CorrelationGraphEdge] = Field(default_factory=list, description="Graph edges")
    total_nodes: int = Field(0, description="Total node count")
    total_edges: int = Field(0, description="Total edge count")


class CorrelationSummaryResponse(BaseModel):
    total_cases_evaluated: int = Field(0, description="Total forensic cases evaluated")
    total_analyses_evaluated: int = Field(0, description="Total forensic analyses evaluated")
    total_unique_iocs: int = Field(0, description="Total unique normalized IOCs across corpus")
    total_relationships: int = Field(0, description="Total cross-analysis or cross-case relationships")
    relationships: List[CorrelationRelationship] = Field(default_factory=list, description="Identified relationships")
    ioc_breakdown_by_type: Dict[str, int] = Field(default_factory=dict, description="Counts of unique IOCs by type")
    top_correlated_iocs: List[Dict[str, Any]] = Field(default_factory=list, description="Highest degree correlated IOCs")


class IOCSearchResultDTO(BaseModel):
    query: str = Field(..., description="Query search term")
    matched_iocs: List[NormalizedIOC] = Field(default_factory=list, description="Matching normalized indicators")
    correlated_relationships: List[CorrelationRelationship] = Field(default_factory=list, description="Related correlation links")
    linked_analyses: List[str] = Field(default_factory=list, description="Distinct analyses where query was observed")
    linked_cases: List[str] = Field(default_factory=list, description="Distinct cases where query was observed")


class STIX21BundleDTO(BaseModel):
    type: str = Field("bundle", description="STIX object type")
    id: str = Field(..., description="STIX bundle UUID")
    spec_version: str = Field("2.1", description="STIX specification version")
    objects: List[Dict[str, Any]] = Field(default_factory=list, description="STIX Domain and Cyber Observable objects")

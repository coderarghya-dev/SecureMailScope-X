# ==============================================================================
# SecureMailScope X — Phase 19: SIEM / SOC Integration Schemas
# ==============================================================================
"""Pydantic schemas for normalized SOC telemetry events, export formats,
transports, delivery records, and filtering.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SOCEventType(str, Enum):
    FORENSIC_ANALYSIS_COMPLETED = "FORENSIC_ANALYSIS_COMPLETED"
    TLS_WEAKNESS_DETECTED = "TLS_WEAKNESS_DETECTED"
    CERTIFICATE_ANOMALY = "CERTIFICATE_ANOMALY"
    EMAIL_AUTH_FAILURE = "EMAIL_AUTH_FAILURE"
    PQC_RISK_IDENTIFIED = "PQC_RISK_IDENTIFIED"
    EVIDENCE_TAMPER_DETECTED = "EVIDENCE_TAMPER_DETECTED"
    CUSTODY_EVENT = "CUSTODY_EVENT"
    NOTARIZATION_CONFIRMED = "NOTARIZATION_CONFIRMED"
    IOC_CORRELATION_OBSERVED = "IOC_CORRELATION_OBSERVED"
    CASE_CREATED = "CASE_CREATED"
    CASE_SEALED = "CASE_SEALED"
    CASE_ARCHIVED = "CASE_ARCHIVED"


class SOCEventSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SOCExportFormat(str, Enum):
    JSON = "JSON"
    CEF = "CEF"
    RFC5424 = "RFC5424"


class SIEMTransportType(str, Enum):
    LOCAL_FILE = "LOCAL_FILE"
    UDP_SYSLOG = "UDP_SYSLOG"
    TCP_SYSLOG = "TCP_SYSLOG"
    JSON_WEBHOOK = "JSON_WEBHOOK"


class DeliveryStatus(str, Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"


class NormalizedSOCEvent(BaseModel):
    event_id: str
    event_type: SOCEventType
    timestamp: str
    severity: SOCEventSeverity = SOCEventSeverity.INFO
    source_component: str = "SecureMailScope"
    analysis_id: Optional[str] = None
    case_id: Optional[str] = None
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    finding_code: Optional[str] = None
    message: str = ""
    mitigation: Optional[str] = None
    manifest_sha256: Optional[str] = None
    blockchain_transaction_hash: Optional[str] = None
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    evidence_reference: Optional[str] = None
    frame_numbers: List[int] = Field(default_factory=list)
    raw_details: Dict[str, Any] = Field(default_factory=dict)


class SIEMEventFilter(BaseModel):
    severity: Optional[SOCEventSeverity] = None
    event_type: Optional[SOCEventType] = None
    protocol: Optional[str] = None
    analysis_id: Optional[str] = None
    case_id: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None


class SIEMDeliveryRequest(BaseModel):
    format: SOCExportFormat = SOCExportFormat.JSON
    transport: SIEMTransportType = SIEMTransportType.LOCAL_FILE
    destination_path: Optional[str] = None
    syslog_host: Optional[str] = None
    syslog_port: Optional[int] = None
    webhook_url: Optional[str] = None
    webhook_auth_header: Optional[str] = None
    filter: Optional[SIEMEventFilter] = None


class SIEMDeliveryRecord(BaseModel):
    delivery_id: str
    created_at: str
    format: SOCExportFormat
    transport: SIEMTransportType
    destination_label: str
    event_count: int
    status: DeliveryStatus
    error_message: Optional[str] = None


class SIEMSummaryResponse(BaseModel):
    total_events: int
    total_deliveries: int
    events_by_severity: Dict[str, int]
    events_by_type: Dict[str, int]
    last_delivery_timestamp: Optional[str] = None
    notice: str

# ==============================================================================
# SecureMailScope X — Phase 21: Posture Monitoring & Drift Detection Schemas
# ==============================================================================
"""Data models and schemas for monitored mail targets, active posture snapshots,
deterministic snapshot hashing, configuration drift events, and baseline pinning.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScheduleType(str, Enum):
    MANUAL = "MANUAL"
    HOURLY = "HOURLY"
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"


class MonitoredProtocol(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"


class MonitoredSecurityMode(str, Enum):
    PLAIN_WITH_STARTTLS = "PLAIN_WITH_STARTTLS"
    DIRECT_TLS = "DIRECT_TLS"
    STARTTLS = "STARTTLS"
    STLS = "STLS"


class DriftType(str, Enum):
    TLS_VERSION_CHANGED = "TLS_VERSION_CHANGED"
    TLS_DOWNGRADE = "TLS_DOWNGRADE"
    TLS_UPGRADE = "TLS_UPGRADE"
    CIPHER_CHANGED = "CIPHER_CHANGED"
    CERTIFICATE_CHANGED = "CERTIFICATE_CHANGED"
    CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED"
    CERTIFICATE_RENEWED = "CERTIFICATE_RENEWED"
    STARTTLS_DISABLED = "STARTTLS_DISABLED"
    STARTTLS_ENABLED = "STARTTLS_ENABLED"
    PFS_STATUS_CHANGED = "PFS_STATUS_CHANGED"
    PQC_STATUS_CHANGED = "PQC_STATUS_CHANGED"
    ENDPOINT_BECAME_UNREACHABLE = "ENDPOINT_BECAME_UNREACHABLE"
    ENDPOINT_RECOVERED = "ENDPOINT_RECOVERED"


class DriftClassification(str, Enum):
    IMPROVEMENT = "IMPROVEMENT"
    REGRESSION = "REGRESSION"
    NEUTRAL = "NEUTRAL"
    UNKNOWN = "UNKNOWN"


class MonitoredTarget(BaseModel):
    target_id: str
    display_name: str
    hostname: str
    port: int
    protocol: MonitoredProtocol
    security_mode: MonitoredSecurityMode
    enabled: bool = True
    schedule_type: ScheduleType = ScheduleType.MANUAL
    schedule_value: Optional[str] = None
    baseline_snapshot_id: Optional[str] = None
    baseline_pinned_by: Optional[str] = None
    baseline_pinned_at: Optional[str] = None
    last_scanned_at: Optional[str] = None
    next_scan_due_at: Optional[str] = None
    created_at: str
    updated_at: str
    created_by: str = "analyst-01"


class TargetCreateRequest(BaseModel):
    display_name: str
    hostname: str
    port: int
    protocol: Optional[MonitoredProtocol] = None
    security_mode: Optional[MonitoredSecurityMode] = None
    enabled: bool = True
    schedule_type: ScheduleType = ScheduleType.MANUAL
    schedule_value: Optional[str] = None


class TargetUpdateRequest(BaseModel):
    display_name: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[MonitoredProtocol] = None
    security_mode: Optional[MonitoredSecurityMode] = None
    enabled: Optional[bool] = None
    schedule_type: Optional[ScheduleType] = None
    schedule_value: Optional[str] = None


class PostureSnapshot(BaseModel):
    snapshot_id: str
    target_id: str
    scanned_at: str
    reachable: bool
    protocol: str
    security_mode: str
    starttls_supported: Optional[bool] = None
    starttls_accepted: Optional[bool] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_fingerprint: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_not_before: Optional[str] = None
    certificate_not_after: Optional[str] = None
    certificate_valid: Optional[bool] = None
    pfs_status: Optional[str] = None
    pqc_status: Optional[str] = None
    auth_posture: Optional[str] = None
    raw_evidence_reference: Optional[str] = None
    scan_result_sha256: str
    canonical_snapshot_sha256: str


class PostureDriftEvent(BaseModel):
    event_id: str
    target_id: str
    prior_snapshot_id: Optional[str] = None
    current_snapshot_id: str
    drift_type: DriftType
    classification: DriftClassification
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    details: str
    detected_at: str
    compared_against_baseline: bool = False


class MonitoringSummaryResponse(BaseModel):
    total_targets: int
    enabled_targets: int
    total_snapshots: int
    total_drift_events: int
    regressions_count: int
    improvements_count: int
    neutral_count: int
    last_scan_timestamp: Optional[str] = None

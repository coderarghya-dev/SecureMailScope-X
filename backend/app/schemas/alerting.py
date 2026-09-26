# ==============================================================================
# SecureMailScope X — Phase 22 / 25: Automated Forensic Alerting Schemas
# ==============================================================================
"""Data transfer models and schemas for deterministic rule-based forensic alerting,
multi-channel delivery audit logs, and alert lifecycle states.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SNOOZED = "SNOOZED"


class AlertRuleType(str, Enum):
    FINDING_MATCH = "FINDING_MATCH"
    POSTURE_DRIFT = "POSTURE_DRIFT"
    CUSTODY_TAMPERING = "CUSTODY_TAMPERING"
    CERT_EXPIRY = "CERT_EXPIRY"
    WEAK_CRYPTO = "WEAK_CRYPTO"


class AlertSourceType(str, Enum):
    PCAP_ANALYSIS = "PCAP_ANALYSIS"
    POSTURE_MONITORING = "POSTURE_MONITORING"
    CUSTODY_CHAIN = "CUSTODY_CHAIN"
    MANUAL = "MANUAL"


class DeliveryChannelType(str, Enum):
    LOCAL_LOG = "LOCAL_LOG"
    SYSLOG = "SYSLOG"
    WEBHOOK = "WEBHOOK"


class DeliveryStatus(str, Enum):
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    SUPPRESSED = "SUPPRESSED"


class AlertRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = None
    rule_type: AlertRuleType
    severity: AlertSeverity = AlertSeverity.MEDIUM
    enabled: bool = True
    condition_criteria: Dict[str, Any] = Field(default_factory=dict)
    cooldown_seconds: int = Field(default=300, ge=0, le=86400)
    channels: List[DeliveryChannelType] = Field(default_factory=lambda: [DeliveryChannelType.LOCAL_LOG])


class AlertRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rule_type: Optional[AlertRuleType] = None
    severity: Optional[AlertSeverity] = None
    enabled: Optional[bool] = None
    condition_criteria: Optional[Dict[str, Any]] = None
    cooldown_seconds: Optional[int] = None
    channels: Optional[List[DeliveryChannelType]] = None


class AlertRuleDTO(BaseModel):
    rule_id: str
    name: str
    description: Optional[str] = None
    rule_type: AlertRuleType
    severity: AlertSeverity
    enabled: bool
    condition_criteria: Dict[str, Any]
    cooldown_seconds: int
    channels: List[DeliveryChannelType]
    created_by: str
    created_at: str
    updated_at: str


class AlertDeliveryDTO(BaseModel):
    delivery_id: str
    alert_id: str
    channel: DeliveryChannelType
    status: DeliveryStatus
    destination: str
    payload_json: Optional[str] = None
    error_message: Optional[str] = None
    delivered_at: str


class AlertDTO(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    severity: AlertSeverity
    status: AlertStatus
    title: str
    summary: str
    source_type: AlertSourceType
    source_id: Optional[str] = None
    evidence_reference: Optional[str] = None
    fingerprint: str
    details: Dict[str, Any] = Field(default_factory=dict)
    triggered_at: str
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[str] = None
    resolution_notes: Optional[str] = None
    deliveries: List[AlertDeliveryDTO] = Field(default_factory=list)


class AlertAcknowledgeRequest(BaseModel):
    notes: Optional[str] = None


class AlertResolveRequest(BaseModel):
    resolution_notes: str = Field(..., min_length=1)


class AlertEvaluationRequest(BaseModel):
    analysis_id: Optional[str] = None
    target_id: Optional[str] = None


class AlertEvaluationResult(BaseModel):
    evaluated_rules_count: int
    matched_alerts_count: int
    suppressed_alerts_count: int
    generated_alerts: List[AlertDTO]

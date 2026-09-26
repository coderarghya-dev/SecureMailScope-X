# ==============================================================================
# SecureMailScope X — Phase 19: SIEM / SOC Event Formatters
# ==============================================================================
"""Deterministic formatters for exporting normalized SOC telemetry events to
JSON, RFC 5424 Syslog, and ArcSight Common Event Format (CEF).
"""

import json
from typing import List
from datetime import datetime, timezone

from app.schemas.siem import (
    NormalizedSOCEvent,
    SOCEventSeverity,
    SOCEventType,
)


def _rfc5424_escape_sd_param(val: str) -> str:
    """Escape special characters in RFC 5424 structured data param values."""
    if val is None:
        return ""
    val_str = str(val)
    # Must escape backslash, double-quote, and close-bracket
    val_str = val_str.replace("\\", "\\\\")
    val_str = val_str.replace('"', '\\"')
    val_str = val_str.replace("]", "\\]")
    return val_str


def _cef_escape_header(val: str) -> str:
    """Escape backslashes and pipes in CEF header fields."""
    if val is None:
        return ""
    val_str = str(val)
    val_str = val_str.replace("\\", "\\\\")
    val_str = val_str.replace("|", "\\|")
    return val_str


def _cef_escape_extension(val: str) -> str:
    """Escape backslashes, equals signs, and newlines in CEF extension values."""
    if val is None:
        return ""
    val_str = str(val)
    val_str = val_str.replace("\\", "\\\\")
    val_str = val_str.replace("=", "\\=")
    val_str = val_str.replace("\n", "\\n")
    val_str = val_str.replace("\r", "\\r")
    return val_str


def _severity_to_syslog_pri(severity: SOCEventSeverity) -> int:
    """Calculate RFC 5424 PRI value (Facility local0 = 16)."""
    facility = 16
    sev_map = {
        SOCEventSeverity.CRITICAL: 2,  # Critical
        SOCEventSeverity.HIGH: 3,      # Error
        SOCEventSeverity.MEDIUM: 4,    # Warning
        SOCEventSeverity.LOW: 5,       # Notice
        SOCEventSeverity.INFO: 6,      # Informational
    }
    sev_num = sev_map.get(severity, 6)
    return facility * 8 + sev_num


def _severity_to_cef_int(severity: SOCEventSeverity) -> int:
    """Map SOC severity to CEF integer severity scale (0-10)."""
    sev_map = {
        SOCEventSeverity.CRITICAL: 10,
        SOCEventSeverity.HIGH: 8,
        SOCEventSeverity.MEDIUM: 5,
        SOCEventSeverity.LOW: 3,
        SOCEventSeverity.INFO: 1,
    }
    return sev_map.get(severity, 1)


def format_event_rfc5424(event: NormalizedSOCEvent, hostname: str = "sms-forensics") -> str:
    """Format a single NormalizedSOCEvent as an RFC 5424 Syslog message."""
    pri = _severity_to_syslog_pri(event.severity)
    
    # Format timestamp
    ts = event.timestamp
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            ts_str = dt.isoformat()
        except Exception:
            ts_str = ts
    else:
        ts_str = datetime.now(timezone.utc).isoformat()

    app_name = "SecureMailScopeX"
    proc_id = "-"
    msg_id = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)

    # Build Structured Data (SD-ID: evidence@52159)
    sd_params = [
        f'eventId="{_rfc5424_escape_sd_param(event.event_id)}"',
        f'severity="{_rfc5424_escape_sd_param(event.severity.value)}"',
    ]
    if event.analysis_id:
        sd_params.append(f'analysisId="{_rfc5424_escape_sd_param(event.analysis_id)}"')
    if event.case_id:
        sd_params.append(f'caseId="{_rfc5424_escape_sd_param(event.case_id)}"')
    if event.finding_code:
        sd_params.append(f'findingCode="{_rfc5424_escape_sd_param(event.finding_code)}"')
    if event.frame_numbers:
        fn_str = ",".join(str(n) for n in event.frame_numbers)
        sd_params.append(f'frameNumbers="{_rfc5424_escape_sd_param(fn_str)}"')
    if event.manifest_sha256:
        sd_params.append(f'manifestSha256="{_rfc5424_escape_sd_param(event.manifest_sha256)}"')
    if event.blockchain_transaction_hash:
        sd_params.append(f'txHash="{_rfc5424_escape_sd_param(event.blockchain_transaction_hash)}"')

    sd_str = f'[evidence@52159 {" ".join(sd_params)}]'
    msg_body = event.message or ""
    
    return f"<{pri}>1 {ts_str} {hostname} {app_name} {proc_id} {msg_id} {sd_str} {msg_body}".strip()


def format_events_rfc5424(events: List[NormalizedSOCEvent], hostname: str = "sms-forensics") -> str:
    """Format multiple events as newline-delimited RFC 5424 Syslog messages."""
    return "\n".join(format_event_rfc5424(e, hostname=hostname) for e in events)


def format_event_cef(event: NormalizedSOCEvent) -> str:
    """Format a single NormalizedSOCEvent as an ArcSight CEF log string."""
    device_vendor = _cef_escape_header("SecureMailScope")
    device_product = _cef_escape_header("SecureMailScope X")
    device_version = _cef_escape_header("1.0.0")
    device_event_class_id = _cef_escape_header(event.finding_code or event.event_type.value)
    name = _cef_escape_header(event.event_type.value.replace("_", " ").title())
    severity = _severity_to_cef_int(event.severity)

    # Build extensions
    extensions = []
    if event.src_ip:
        extensions.append(f"src={_cef_escape_extension(event.src_ip)}")
    if event.src_port:
        extensions.append(f"spt={event.src_port}")
    if event.dst_ip:
        extensions.append(f"dst={_cef_escape_extension(event.dst_ip)}")
    if event.dst_port:
        extensions.append(f"dpt={event.dst_port}")
    if event.protocol:
        extensions.append(f"proto={_cef_escape_extension(event.protocol)}")
    if event.analysis_id:
        extensions.append(f"cs1={_cef_escape_extension(event.analysis_id)} cs1Label=AnalysisID")
    if event.case_id:
        extensions.append(f"cs2={_cef_escape_extension(event.case_id)} cs2Label=CaseID")
    if event.frame_numbers:
        extensions.append(f"cn1={event.frame_numbers[0]} cn1Label=FrameNumber")
    if event.message:
        extensions.append(f"msg={_cef_escape_extension(event.message)}")
    if event.source_component:
        extensions.append(f"cat={_cef_escape_extension(event.source_component)}")
    if event.manifest_sha256:
        extensions.append(f"cs3={_cef_escape_extension(event.manifest_sha256)} cs3Label=ManifestSHA256")
    if event.blockchain_transaction_hash:
        extensions.append(f"cs4={_cef_escape_extension(event.blockchain_transaction_hash)} cs4Label=TxHash")

    ext_str = " ".join(extensions)
    header = f"CEF:0|{device_vendor}|{device_product}|{device_version}|{device_event_class_id}|{name}|{severity}|"
    return f"{header}{ext_str}"


def format_events_cef(events: List[NormalizedSOCEvent]) -> str:
    """Format multiple events as newline-delimited ArcSight CEF logs."""
    return "\n".join(format_event_cef(e) for e in events)


def format_events_json(events: List[NormalizedSOCEvent]) -> str:
    """Format multiple events as deterministic pretty-printed JSON."""
    return json.dumps([e.model_dump() for e in events], indent=2)

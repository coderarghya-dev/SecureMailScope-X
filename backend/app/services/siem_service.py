# ==============================================================================
# SecureMailScope X — Phase 19: SIEM / SOC Integration Service
# ==============================================================================
"""Core service for normalizing forensic evidence, filtering SOC events,
executing exports (JSON, CEF, RFC 5424), and dispatching via transports.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.db.database import get_db_connection
from app.schemas.siem import (
    DeliveryStatus,
    NormalizedSOCEvent,
    SIEMDeliveryRecord,
    SIEMDeliveryRequest,
    SIEMEventFilter,
    SIEMSummaryResponse,
    SIEMTransportType,
    SOCEventSeverity,
    SOCEventType,
    SOCExportFormat,
)
from app.services.siem_formatters import (
    format_events_cef,
    format_events_json,
    format_events_rfc5424,
)
from app.services.siem_transports import (
    JsonWebhookTransport,
    LocalFileTransport,
    TcpSyslogTransport,
    UdpSyslogTransport,
)


def _parse_ip_port(endpoint_str: Optional[str]) -> (Optional[str], Optional[int]):
    """Helper to split IP and port from string like '192.168.1.50:50123'."""
    if not endpoint_str or ":" not in endpoint_str:
        return endpoint_str, None
    parts = endpoint_str.rsplit(":", 1)
    try:
        return parts[0], int(parts[1])
    except ValueError:
        return endpoint_str, None


def _map_finding_severity(sev_str: Optional[str]) -> SOCEventSeverity:
    """Map arbitrary severity strings to SOCEventSeverity enum."""
    if not sev_str:
        return SOCEventSeverity.INFO
    s = str(sev_str).upper()
    if s == "CRITICAL":
        return SOCEventSeverity.CRITICAL
    elif s == "HIGH":
        return SOCEventSeverity.HIGH
    elif s == "MEDIUM":
        return SOCEventSeverity.MEDIUM
    elif s == "LOW":
        return SOCEventSeverity.LOW
    elif s == "INFO" or s == "INFORMATIONAL":
        return SOCEventSeverity.INFO
    return SOCEventSeverity.INFO


def _map_finding_type(finding_id: Optional[str], default_type: SOCEventType = SOCEventType.TLS_WEAKNESS_DETECTED) -> SOCEventType:
    """Determine event type from finding identifier."""
    if not finding_id:
        return default_type
    fid = finding_id.upper()
    if "CERT" in fid:
        return SOCEventType.CERTIFICATE_ANOMALY
    elif "SPF" in fid or "DKIM" in fid or "DMARC" in fid or "AUTH" in fid:
        return SOCEventType.EMAIL_AUTH_FAILURE
    elif "PQC" in fid or "KEX" in fid or "HNDL" in fid:
        return SOCEventType.PQC_RISK_IDENTIFIED
    elif "TLS" in fid or "CIPHER" in fid:
        return SOCEventType.TLS_WEAKNESS_DETECTED
    return default_type


def extract_soc_events_from_analysis(analysis_row: dict) -> List[NormalizedSOCEvent]:
    """Extract normalized SOC events from an analysis record and its observed results."""
    events: List[NormalizedSOCEvent] = []
    analysis_id = analysis_row.get("analysis_id", "unknown-analysis")
    created_at = analysis_row.get("created_at") or datetime.now(timezone.utc).isoformat()
    manifest_sha = analysis_row.get("custody_link_hash") or analysis_row.get("manifest_sha256")

    # 1. Forensic Analysis Completed Summary Event
    events.append(
        NormalizedSOCEvent(
            event_id=f"evt-analysis-{analysis_id}",
            event_type=SOCEventType.FORENSIC_ANALYSIS_COMPLETED,
            timestamp=created_at,
            severity=SOCEventSeverity.INFO,
            source_component="AnalyzerService",
            analysis_id=analysis_id,
            manifest_sha256=manifest_sha,
            message=f"Forensic PCAP analysis completed for {analysis_row.get('filename', 'capture')}",
            raw_details={"filename": analysis_row.get("filename"), "total_packets": analysis_row.get("total_packets")}
        )
    )

    # 2. Parse observed result JSON
    observed_raw = analysis_row.get("observed_result_json") or analysis_row.get("observed_result")
    observed_dict: Dict[str, Any] = {}
    if isinstance(observed_raw, dict):
        observed_dict = observed_raw
    elif isinstance(observed_raw, str) and observed_raw.strip():
        try:
            observed_dict = json.loads(observed_raw)
        except Exception:
            observed_dict = {}

    # Extract session findings
    sessions = observed_dict.get("sessions", [])
    for idx, session in enumerate(sessions):
        proto = session.get("protocol", "TCP")
        src_ip, src_port = _parse_ip_port(session.get("client"))
        dst_ip, dst_port = _parse_ip_port(session.get("server"))
        session_id = session.get("session_id", f"sess-{idx}")

        findings = session.get("findings", [])
        for f_idx, finding in enumerate(findings):
            fid = finding.get("id") or finding.get("finding_id") or f"FINDING-{idx}-{f_idx}"
            sev = _map_finding_severity(finding.get("severity"))
            ev_type = _map_finding_type(fid)
            msg = finding.get("message") or finding.get("description") or "Protocol finding observed"
            mitigation = finding.get("mitigation") or finding.get("recommendation")
            frame_nums = finding.get("frame_numbers") or []
            if not isinstance(frame_nums, list):
                frame_nums = [frame_nums]

            events.append(
                NormalizedSOCEvent(
                    event_id=f"evt-{analysis_id}-{session_id}-{fid}",
                    event_type=ev_type,
                    timestamp=created_at,
                    severity=sev,
                    source_component="RuleEngine",
                    analysis_id=analysis_id,
                    protocol=proto,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    finding_code=fid,
                    message=msg,
                    mitigation=mitigation,
                    manifest_sha256=manifest_sha,
                    frame_numbers=frame_nums,
                    raw_details={"session_id": session_id}
                )
            )

    # Extract certificate analysis findings
    cert_analysis = observed_dict.get("certificate_analysis", {})
    for c_idx, finding in enumerate(cert_analysis.get("findings", [])):
        fid = finding.get("id") or finding.get("finding_id") or f"CERT-{c_idx}"
        sev = _map_finding_severity(finding.get("severity"))
        events.append(
            NormalizedSOCEvent(
                event_id=f"evt-{analysis_id}-cert-{fid}",
                event_type=SOCEventType.CERTIFICATE_ANOMALY,
                timestamp=created_at,
                severity=sev,
                source_component="CertificateEngine",
                analysis_id=analysis_id,
                finding_code=fid,
                message=finding.get("description") or finding.get("message") or "Certificate anomaly observed",
                manifest_sha256=manifest_sha,
                evidence_reference=finding.get("evidence_reference")
            )
        )

    # Extract email auth findings
    email_auth = observed_dict.get("email_auth", {})
    for e_idx, finding in enumerate(email_auth.get("findings", [])):
        fid = finding.get("id") or finding.get("finding_id") or f"AUTH-{e_idx}"
        sev = _map_finding_severity(finding.get("severity"))
        events.append(
            NormalizedSOCEvent(
                event_id=f"evt-{analysis_id}-auth-{fid}",
                event_type=SOCEventType.EMAIL_AUTH_FAILURE,
                timestamp=created_at,
                severity=sev,
                source_component="EmailAuthEngine",
                analysis_id=analysis_id,
                finding_code=fid,
                message=finding.get("description") or finding.get("message") or "Email authentication finding",
                manifest_sha256=manifest_sha
            )
        )

    # Extract PQC readiness findings
    pqc_analysis = observed_dict.get("pqc_readiness", {})
    for p_idx, finding in enumerate(pqc_analysis.get("findings", [])):
        fid = finding.get("id") or finding.get("finding_id") or f"PQC-{p_idx}"
        sev = _map_finding_severity(finding.get("severity"))
        events.append(
            NormalizedSOCEvent(
                event_id=f"evt-{analysis_id}-pqc-{fid}",
                event_type=SOCEventType.PQC_RISK_IDENTIFIED,
                timestamp=created_at,
                severity=sev,
                source_component="PQCEngine",
                analysis_id=analysis_id,
                finding_code=fid,
                message=finding.get("description") or finding.get("message") or "PQC vulnerability identified",
                manifest_sha256=manifest_sha
            )
        )

    return events


def extract_soc_events_from_case(case_dict: dict) -> List[NormalizedSOCEvent]:
    """Extract normalized SOC events for case lifecycle operations."""
    events: List[NormalizedSOCEvent] = []
    case_id = case_dict.get("id") or case_dict.get("case_id") or "unknown-case"
    case_title = case_dict.get("title") or case_dict.get("case_name") or case_id
    created_at = case_dict.get("created_at") or datetime.now(timezone.utc).isoformat()

    # Case Created Event
    events.append(
        NormalizedSOCEvent(
            event_id=f"evt-case-create-{case_id}",
            event_type=SOCEventType.CASE_CREATED,
            timestamp=created_at,
            severity=SOCEventSeverity.INFO,
            source_component="CaseService",
            case_id=case_id,
            message=f"Forensic case '{case_title}' opened",
            raw_details={"created_by": case_dict.get("created_by_display_name")}
        )
    )

    # Case Sealed Event
    if case_dict.get("status") == "SEALED" or case_dict.get("sealed_at"):
        sealed_ts = case_dict.get("sealed_at") or case_dict.get("updated_at") or created_at
        events.append(
            NormalizedSOCEvent(
                event_id=f"evt-case-seal-{case_id}",
                event_type=SOCEventType.CASE_SEALED,
                timestamp=sealed_ts,
                severity=SOCEventSeverity.INFO,
                source_component="CaseService",
                case_id=case_id,
                message=f"Forensic case '{case_title}' cryptographically sealed"
            )
        )

    # Case Archived Event
    if case_dict.get("is_archived") or case_dict.get("status") == "ARCHIVED":
        archived_ts = case_dict.get("updated_at") or created_at
        events.append(
            NormalizedSOCEvent(
                event_id=f"evt-case-archive-{case_id}",
                event_type=SOCEventType.CASE_ARCHIVED,
                timestamp=archived_ts,
                severity=SOCEventSeverity.INFO,
                source_component="CaseService",
                case_id=case_id,
                message=f"Forensic case '{case_title}' archived"
            )
        )

    return events


def extract_soc_events_from_custody(custody_row: dict) -> List[NormalizedSOCEvent]:
    """Extract normalized SOC events from chain of custody entries."""
    events: List[NormalizedSOCEvent] = []
    event_id = custody_row.get("event_id", f"c-evt-{uuid.uuid4().hex[:8]}")
    analysis_id = custody_row.get("analysis_id")
    event_type_str = custody_row.get("event_type", "CUSTODY_EVENT")
    ts = custody_row.get("timestamp_utc") or datetime.now(timezone.utc).isoformat()
    manifest_sha = custody_row.get("artifact_hash") or custody_row.get("manifest_sha256")
    desc = custody_row.get("details") or custody_row.get("description") or f"Custody audit event: {event_type_str}"

    if event_type_str == "EVIDENCE_TAMPER_DETECTED":
        soc_type = SOCEventType.EVIDENCE_TAMPER_DETECTED
        sev = SOCEventSeverity.CRITICAL
    else:
        soc_type = SOCEventType.CUSTODY_EVENT
        sev = SOCEventSeverity.INFO

    events.append(
        NormalizedSOCEvent(
            event_id=f"evt-custody-{event_id}",
            event_type=soc_type,
            timestamp=ts,
            severity=sev,
            source_component="CustodyService",
            analysis_id=analysis_id,
            manifest_sha256=manifest_sha,
            message=desc,
            raw_details={"custody_event_type": event_type_str}
        )
    )
    return events


def extract_soc_events_from_notarization(notarize_row: dict) -> List[NormalizedSOCEvent]:
    """Extract normalized SOC events from blockchain notarization entries."""
    events: List[NormalizedSOCEvent] = []
    notarize_id = notarize_row.get("notarization_id", f"not-{uuid.uuid4().hex[:8]}")
    analysis_id = notarize_row.get("analysis_id")
    status = notarize_row.get("status")
    tx_hash = notarize_row.get("transaction_hash")
    ts = notarize_row.get("created_at") or datetime.now(timezone.utc).isoformat()

    if status == "CONFIRMED":
        events.append(
            NormalizedSOCEvent(
                event_id=f"evt-notarize-{notarize_id}",
                event_type=SOCEventType.NOTARIZATION_CONFIRMED,
                timestamp=ts,
                severity=SOCEventSeverity.INFO,
                source_component="NotarizationService",
                analysis_id=analysis_id,
                blockchain_transaction_hash=tx_hash,
                message=f"Forensic proof anchored to blockchain: tx {tx_hash or 'confirmed'}",
                evidence_reference=notarize_row.get("local_proof_sha256")
            )
        )
    return events


def get_all_soc_events(db_path: Optional[str] = None) -> List[NormalizedSOCEvent]:
    """Retrieve and normalize all SOC events across analyses, cases, custody, and notarizations."""
    events: List[NormalizedSOCEvent] = []
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    try:
        # 1. Fetch analyses
        cursor.execute("SELECT * FROM analyses ORDER BY created_at ASC;")
        for row in cursor.fetchall():
            events.extend(extract_soc_events_from_analysis(dict(row)))

        # 2. Fetch cases
        cursor.execute("SELECT * FROM cases ORDER BY created_at ASC;")
        for row in cursor.fetchall():
            events.extend(extract_soc_events_from_case(dict(row)))

        # 3. Fetch custody events
        cursor.execute("SELECT * FROM custody_events ORDER BY timestamp_utc ASC;")
        for row in cursor.fetchall():
            events.extend(extract_soc_events_from_custody(dict(row)))

        # 4. Fetch notarization records
        cursor.execute("SELECT * FROM notarization_records ORDER BY created_at ASC;")
        for row in cursor.fetchall():
            events.extend(extract_soc_events_from_notarization(dict(row)))

    except Exception:
        pass
    finally:
        conn.close()

    return events


def filter_soc_events(
    events: List[NormalizedSOCEvent],
    filter_criteria: Optional[SIEMEventFilter]
) -> List[NormalizedSOCEvent]:
    """Deterministically filter SOC events based on filter criteria."""
    if not filter_criteria:
        return events

    filtered = []
    for ev in events:
        if filter_criteria.severity and ev.severity != filter_criteria.severity:
            continue
        if filter_criteria.event_type and ev.event_type != filter_criteria.event_type:
            continue
        if filter_criteria.protocol and ev.protocol != filter_criteria.protocol:
            continue
        if filter_criteria.analysis_id and ev.analysis_id != filter_criteria.analysis_id:
            continue
        if filter_criteria.case_id and ev.case_id != filter_criteria.case_id:
            continue
        if filter_criteria.start_time and ev.timestamp < filter_criteria.start_time:
            continue
        if filter_criteria.end_time and ev.timestamp > filter_criteria.end_time:
            continue
        filtered.append(ev)

    return filtered


def export_soc_events(
    format: SOCExportFormat,
    filter_criteria: Optional[SIEMEventFilter] = None,
    db_path: Optional[str] = None
) -> str:
    """Format and export SOC events into JSON, CEF, or RFC 5424 Syslog."""
    events = get_all_soc_events(db_path=db_path)
    if filter_criteria:
        events = filter_soc_events(events, filter_criteria)

    if format == SOCExportFormat.JSON:
        return format_events_json(events)
    elif format == SOCExportFormat.CEF:
        return format_events_cef(events)
    elif format == SOCExportFormat.RFC5424:
        return format_events_rfc5424(events)
    return format_events_json(events)


def deliver_soc_events(
    req: SIEMDeliveryRequest,
    db_path: Optional[str] = None
) -> SIEMDeliveryRecord:
    """Export and deliver SOC events via selected transport and log to audit table."""
    events = get_all_soc_events(db_path=db_path)
    if req.filter:
        events = filter_soc_events(events, req.filter)

    # Format payload
    if req.format == SOCExportFormat.CEF:
        payload = format_events_cef(events)
    elif req.format == SOCExportFormat.RFC5424:
        payload = format_events_rfc5424(events)
    else:
        payload = format_events_json(events)

    # Select Transport
    if req.transport == SIEMTransportType.LOCAL_FILE:
        path = req.destination_path or "siem_export.json"
        transport = LocalFileTransport(path)
    elif req.transport == SIEMTransportType.UDP_SYSLOG:
        transport = UdpSyslogTransport(host=req.syslog_host or "127.0.0.1", port=req.syslog_port or 514)
    elif req.transport == SIEMTransportType.TCP_SYSLOG:
        transport = TcpSyslogTransport(host=req.syslog_host or "127.0.0.1", port=req.syslog_port or 6514)
    elif req.transport == SIEMTransportType.JSON_WEBHOOK:
        transport = JsonWebhookTransport(url=req.webhook_url or "http://localhost:8080", auth_header=req.webhook_auth_header)
    else:
        transport = LocalFileTransport("siem_export.json")

    success, err_msg = transport.deliver(payload)
    status = DeliveryStatus.SENT if success else DeliveryStatus.FAILED

    delivery_id = f"deliv-{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat()

    record = SIEMDeliveryRecord(
        delivery_id=delivery_id,
        created_at=created_at,
        format=req.format,
        transport=req.transport,
        destination_label=transport.destination_label,
        event_count=len(events),
        status=status,
        error_message=err_msg
    )

    # Record delivery in SQLite
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO siem_deliveries (
            delivery_id, created_at, format, transport, destination_label, event_count, status, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            record.delivery_id,
            record.created_at,
            record.format.value,
            record.transport.value,
            record.destination_label,
            record.event_count,
            record.status.value,
            record.error_message
        )
    )
    conn.commit()
    conn.close()

    return record


def list_siem_deliveries(db_path: Optional[str] = None) -> List[SIEMDeliveryRecord]:
    """Retrieve all logged SIEM delivery records from SQLite."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM siem_deliveries ORDER BY created_at DESC;")
    rows = cursor.fetchall()
    conn.close()

    records = []
    for r in rows:
        row_dict = dict(r)
        records.append(
            SIEMDeliveryRecord(
                delivery_id=row_dict["delivery_id"],
                created_at=row_dict["created_at"],
                format=SOCExportFormat(row_dict["format"]),
                transport=SIEMTransportType(row_dict["transport"]),
                destination_label=row_dict["destination_label"],
                event_count=row_dict["event_count"],
                status=DeliveryStatus(row_dict["status"]),
                error_message=row_dict["error_message"]
            )
        )
    return records


def get_siem_summary(db_path: Optional[str] = None) -> SIEMSummaryResponse:
    """Compute summary statistics over all SOC events and deliveries."""
    events = get_all_soc_events(db_path=db_path)
    deliveries = list_siem_deliveries(db_path=db_path)

    sev_counts: Dict[str, int] = {}
    type_counts: Dict[str, int] = {}

    for ev in events:
        sev_key = ev.severity.value if hasattr(ev.severity, "value") else str(ev.severity)
        type_key = ev.event_type.value if hasattr(ev.event_type, "value") else str(ev.event_type)
        sev_counts[sev_key] = sev_counts.get(sev_key, 0) + 1
        type_counts[type_key] = type_counts.get(type_key, 0) + 1

    last_ts = deliveries[0].created_at if deliveries else None

    return SIEMSummaryResponse(
        total_events=len(events),
        total_deliveries=len(deliveries),
        events_by_severity=sev_counts,
        events_by_type=type_counts,
        last_delivery_timestamp=last_ts,
        notice="Exported SOC telemetry reflects authoritative local forensic observations with complete provenance tracking."
    )

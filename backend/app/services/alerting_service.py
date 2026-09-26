# ==============================================================================
# SecureMailScope X — Phase 22 / 25: Forensic Alerting Service
# ==============================================================================
"""Core deterministic rule evaluator, multi-channel delivery logger, and alert
lifecycle management service grounded in real forensic evidence.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.db.database import get_db_connection
from app.schemas.alerting import (
    AlertDTO,
    AlertDeliveryDTO,
    AlertEvaluationResult,
    AlertRuleCreate,
    AlertRuleDTO,
    AlertRuleType,
    AlertRuleUpdate,
    AlertSeverity,
    AlertSourceType,
    AlertStatus,
    DeliveryChannelType,
    DeliveryStatus,
)


class AlertingService:

    @staticmethod
    def seed_default_rules() -> None:
        """Seed deterministic default rules if none exist in the repository."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM alert_rules;")
        count = cursor.fetchone()["cnt"]
        if count == 0:
            now = datetime.now(timezone.utc).isoformat()
            default_rules = [
                (
                    "rule-tls10-critical",
                    "Obsolete TLS 1.0/1.1 Usage Detected",
                    "Triggers CRITICAL alert when deprecated TLS 1.0 or TLS 1.1 protocol handshakes are observed in traffic.",
                    AlertRuleType.FINDING_MATCH.value,
                    AlertSeverity.CRITICAL.value,
                    1,
                    json.dumps({"finding_codes": ["OBSOLETE_TLS_1_0", "OBSOLETE_TLS_1_1", "DEPRECATED_TLS_VERSION"]}),
                    300,
                    json.dumps([DeliveryChannelType.LOCAL_LOG.value, DeliveryChannelType.SYSLOG.value]),
                    "system",
                    now,
                    now,
                ),
                (
                    "rule-cleartext-auth",
                    "Cleartext Authentication Credentials Observed",
                    "Triggers CRITICAL alert when plaintext credentials or auth commands are detected prior to TLS upgrade.",
                    AlertRuleType.FINDING_MATCH.value,
                    AlertSeverity.CRITICAL.value,
                    1,
                    json.dumps({"finding_codes": ["CLEARTEXT_AUTH_COMMAND", "INSECURE_AUTH_OFFERED"]}),
                    300,
                    json.dumps([DeliveryChannelType.LOCAL_LOG.value, DeliveryChannelType.SYSLOG.value]),
                    "system",
                    now,
                    now,
                ),
                (
                    "rule-posture-downgrade",
                    "Host Security Posture Drift / Downgrade",
                    "Triggers HIGH alert when continuous monitoring detects a security downgrade from pinned baseline.",
                    AlertRuleType.POSTURE_DRIFT.value,
                    AlertSeverity.HIGH.value,
                    1,
                    json.dumps({"drift_classifications": ["REGRESSION"], "drift_types": ["TLS_VERSION_DOWNGRADE", "STARTTLS_DISABLED"]}),
                    600,
                    json.dumps([DeliveryChannelType.LOCAL_LOG.value]),
                    "system",
                    now,
                    now,
                ),
                (
                    "rule-cert-expired",
                    "Expired or Untrusted Mail Server Certificate",
                    "Triggers HIGH alert when an expired, untrusted, or self-signed certificate is observed.",
                    AlertRuleType.CERT_EXPIRY.value,
                    AlertSeverity.HIGH.value,
                    1,
                    json.dumps({"finding_codes": ["CERTIFICATE_EXPIRED", "CERTIFICATE_NOT_YET_VALID", "SELF_SIGNED_CERTIFICATE"]}),
                    3600,
                    json.dumps([DeliveryChannelType.LOCAL_LOG.value]),
                    "system",
                    now,
                    now,
                ),
                (
                    "rule-weak-crypto",
                    "Weak or Non-PFS Cipher Suite Negotiated",
                    "Triggers MEDIUM alert when static RSA key exchange or legacy 3DES/RC4/CBC ciphers are negotiated.",
                    AlertRuleType.WEAK_CRYPTO.value,
                    AlertSeverity.MEDIUM.value,
                    1,
                    json.dumps({"finding_codes": ["WEAK_CIPHER_SUITE", "NO_FORWARD_SECRECY", "EXPORT_CIPHER_SUITE"]}),
                    600,
                    json.dumps([DeliveryChannelType.LOCAL_LOG.value]),
                    "system",
                    now,
                    now,
                ),
            ]
            cursor.executemany(
                """
                INSERT INTO alert_rules (
                    rule_id, name, description, rule_type, severity, enabled,
                    condition_criteria_json, cooldown_seconds, channels_json,
                    created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                default_rules,
            )
            conn.commit()
        conn.close()

    @staticmethod
    def create_rule(rule_in: AlertRuleCreate, created_by: str = "analyst-01") -> AlertRuleDTO:
        rule_id = f"rule-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO alert_rules (
                rule_id, name, description, rule_type, severity, enabled,
                condition_criteria_json, cooldown_seconds, channels_json,
                created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                rule_id,
                rule_in.name,
                rule_in.description,
                rule_in.rule_type.value,
                rule_in.severity.value,
                1 if rule_in.enabled else 0,
                json.dumps(rule_in.condition_criteria),
                rule_in.cooldown_seconds,
                json.dumps([c.value for c in rule_in.channels]),
                created_by,
                now,
                now,
            ),
        )
        conn.commit()
        conn.close()
        return AlertingService.get_rule(rule_id)  # type: ignore

    @staticmethod
    def get_rule(rule_id: str) -> Optional[AlertRuleDTO]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alert_rules WHERE rule_id = ?;", (rule_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return AlertRuleDTO(
            rule_id=row["rule_id"],
            name=row["name"],
            description=row["description"],
            rule_type=AlertRuleType(row["rule_type"]),
            severity=AlertSeverity(row["severity"]),
            enabled=bool(row["enabled"]),
            condition_criteria=json.loads(row["condition_criteria_json"] or "{}"),
            cooldown_seconds=row["cooldown_seconds"],
            channels=[DeliveryChannelType(c) for c in json.loads(row["channels_json"] or "[]")],
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def list_rules(enabled_only: bool = False) -> List[AlertRuleDTO]:
        AlertingService.seed_default_rules()
        conn = get_db_connection()
        cursor = conn.cursor()
        if enabled_only:
            cursor.execute("SELECT * FROM alert_rules WHERE enabled = 1 ORDER BY created_at ASC;")
        else:
            cursor.execute("SELECT * FROM alert_rules ORDER BY created_at ASC;")
        rows = cursor.fetchall()
        conn.close()
        rules = []
        for row in rows:
            rules.append(
                AlertRuleDTO(
                    rule_id=row["rule_id"],
                    name=row["name"],
                    description=row["description"],
                    rule_type=AlertRuleType(row["rule_type"]),
                    severity=AlertSeverity(row["severity"]),
                    enabled=bool(row["enabled"]),
                    condition_criteria=json.loads(row["condition_criteria_json"] or "{}"),
                    cooldown_seconds=row["cooldown_seconds"],
                    channels=[DeliveryChannelType(c) for c in json.loads(row["channels_json"] or "[]")],
                    created_by=row["created_by"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )
            )
        return rules

    @staticmethod
    def update_rule(rule_id: str, rule_in: AlertRuleUpdate) -> Optional[AlertRuleDTO]:
        existing = AlertingService.get_rule(rule_id)
        if not existing:
            return None
        now = datetime.now(timezone.utc).isoformat()
        name = rule_in.name if rule_in.name is not None else existing.name
        description = rule_in.description if rule_in.description is not None else existing.description
        rule_type = rule_in.rule_type.value if rule_in.rule_type is not None else existing.rule_type.value
        severity = rule_in.severity.value if rule_in.severity is not None else existing.severity.value
        enabled = (1 if rule_in.enabled else 0) if rule_in.enabled is not None else (1 if existing.enabled else 0)
        criteria = json.dumps(rule_in.condition_criteria if rule_in.condition_criteria is not None else existing.condition_criteria)
        cooldown = rule_in.cooldown_seconds if rule_in.cooldown_seconds is not None else existing.cooldown_seconds
        channels = json.dumps([c.value for c in (rule_in.channels if rule_in.channels is not None else existing.channels)])

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE alert_rules
            SET name = ?, description = ?, rule_type = ?, severity = ?, enabled = ?,
                condition_criteria_json = ?, cooldown_seconds = ?, channels_json = ?, updated_at = ?
            WHERE rule_id = ?;
            """,
            (name, description, rule_type, severity, enabled, criteria, cooldown, channels, now, rule_id),
        )
        conn.commit()
        conn.close()
        return AlertingService.get_rule(rule_id)

    @staticmethod
    def delete_rule(rule_id: str) -> bool:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alert_rules WHERE rule_id = ?;", (rule_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    @staticmethod
    def evaluate_evidence_against_rules(
        analysis_id: Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> AlertEvaluationResult:
        """Deterministically evaluates observed forensic evidence / drift events against active rules."""
        AlertingService.seed_default_rules()
        active_rules = AlertingService.list_rules(enabled_only=True)
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()

        generated_alerts: List[AlertDTO] = []
        suppressed_count = 0

        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Evaluate Findings if analysis_id provided
        if analysis_id:
            cursor.execute("SELECT * FROM findings WHERE analysis_id = ?;", (analysis_id,))
            findings = cursor.fetchall()
            for finding in findings:
                f_code = (
                    finding["finding_code"] if ("finding_code" in finding.keys() and finding["finding_code"])
                    else finding["finding_id"] if ("finding_id" in finding.keys() and finding["finding_id"])
                    else finding["rule_id"] if ("rule_id" in finding.keys() and finding["rule_id"])
                    else finding["id"]
                )
                f_severity = finding["severity"] if "severity" in finding.keys() else "MEDIUM"
                f_desc = finding["description"] if "description" in finding.keys() else "Finding detected"
                f_evidence = f"Analysis {analysis_id} Frame {finding['frame_number'] if 'frame_number' in finding.keys() else 0}"

                for rule in active_rules:
                    target_codes = rule.condition_criteria.get("finding_codes", [])
                    if rule.rule_type in (AlertRuleType.FINDING_MATCH, AlertRuleType.WEAK_CRYPTO, AlertRuleType.CERT_EXPIRY):
                        if not target_codes or f_code in target_codes:
                            fingerprint = hashlib.sha256(f"{rule.rule_id}:{analysis_id}:{f_code}".encode("utf-8")).hexdigest()
                            cursor.execute(
                                "SELECT triggered_at FROM alerts WHERE fingerprint = ? ORDER BY triggered_at DESC LIMIT 1;",
                                (fingerprint,),
                            )
                            last_alert = cursor.fetchone()
                            if last_alert:
                                last_time = datetime.fromisoformat(last_alert["triggered_at"])
                                if (now_dt - last_time).total_seconds() < rule.cooldown_seconds:
                                    suppressed_count += 1
                                    continue

                            alert_id = f"alert-{uuid.uuid4().hex[:12]}"
                            title = f"[{rule.severity.value}] {rule.name}: {f_code}"
                            summary = f"Observed finding {f_code} in PCAP analysis {analysis_id}: {f_desc}"
                            details = {
                                "analysis_id": analysis_id,
                                "finding_code": f_code,
                                "finding_severity": f_severity,
                                "rule_criteria": rule.condition_criteria,
                            }
                            cursor.execute(
                                """
                                INSERT INTO alerts (
                                    alert_id, rule_id, rule_name, severity, status, title, summary,
                                    source_type, source_id, evidence_reference, fingerprint,
                                    details_json, triggered_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                                """,
                                (
                                    alert_id,
                                    rule.rule_id,
                                    rule.name,
                                    rule.severity.value,
                                    AlertStatus.NEW.value,
                                    title,
                                    summary,
                                    AlertSourceType.PCAP_ANALYSIS.value,
                                    analysis_id,
                                    f_evidence,
                                    fingerprint,
                                    json.dumps(details),
                                    now_iso,
                                ),
                            )
                            for ch in rule.channels:
                                deliv_id = f"deliv-{uuid.uuid4().hex[:12]}"
                                cursor.execute(
                                    """
                                    INSERT INTO alert_deliveries (
                                        delivery_id, alert_id, channel, status, destination,
                                        payload_json, delivered_at
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?);
                                    """,
                                    (
                                        deliv_id,
                                        alert_id,
                                        ch.value,
                                        DeliveryStatus.DELIVERED.value,
                                        "LOCAL_STORAGE" if ch == DeliveryChannelType.LOCAL_LOG else "LOCAL_SYSLOG_DAEMON",
                                        json.dumps({"alert_id": alert_id, "title": title, "summary": summary}),
                                        now_iso,
                                    ),
                                )
                            conn.commit()
                            alert_dto = AlertingService.get_alert(alert_id)
                            if alert_dto:
                                generated_alerts.append(alert_dto)

        # 2. Evaluate Drift Events if target_id provided
        if target_id:
            cursor.execute("SELECT * FROM posture_drift_events WHERE target_id = ?;", (target_id,))
            drift_events = cursor.fetchall()
            for drift in drift_events:
                d_type = drift["drift_type"]
                d_class = drift["classification"]
                d_details = drift["details"]

                for rule in active_rules:
                    if rule.rule_type == AlertRuleType.POSTURE_DRIFT:
                        target_classes = rule.condition_criteria.get("drift_classifications", [])
                        target_types = rule.condition_criteria.get("drift_types", [])
                        if (not target_classes or d_class in target_classes) and (not target_types or d_type in target_types):
                            fingerprint = hashlib.sha256(f"{rule.rule_id}:{target_id}:{d_type}:{drift['event_id']}".encode("utf-8")).hexdigest()
                            cursor.execute(
                                "SELECT triggered_at FROM alerts WHERE fingerprint = ? ORDER BY triggered_at DESC LIMIT 1;",
                                (fingerprint,),
                            )
                            last_alert = cursor.fetchone()
                            if last_alert:
                                last_time = datetime.fromisoformat(last_alert["triggered_at"])
                                if (now_dt - last_time).total_seconds() < rule.cooldown_seconds:
                                    suppressed_count += 1
                                    continue

                            alert_id = f"alert-{uuid.uuid4().hex[:12]}"
                            title = f"[{rule.severity.value}] Posture Drift: {d_type} ({d_class})"
                            summary = f"Detected configuration drift on monitored target {target_id}: {d_details}"
                            details = {
                                "target_id": target_id,
                                "drift_type": d_type,
                                "classification": d_class,
                                "old_value": drift["old_value"],
                                "new_value": drift["new_value"],
                            }
                            cursor.execute(
                                """
                                INSERT INTO alerts (
                                    alert_id, rule_id, rule_name, severity, status, title, summary,
                                    source_type, source_id, evidence_reference, fingerprint,
                                    details_json, triggered_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                                """,
                                (
                                    alert_id,
                                    rule.rule_id,
                                    rule.name,
                                    rule.severity.value,
                                    AlertStatus.NEW.value,
                                    title,
                                    summary,
                                    AlertSourceType.POSTURE_MONITORING.value,
                                    target_id,
                                    f"Snapshot {drift['current_snapshot_id']}",
                                    fingerprint,
                                    json.dumps(details),
                                    now_iso,
                                ),
                            )
                            for ch in rule.channels:
                                deliv_id = f"deliv-{uuid.uuid4().hex[:12]}"
                                cursor.execute(
                                    """
                                    INSERT INTO alert_deliveries (
                                        delivery_id, alert_id, channel, status, destination,
                                        payload_json, delivered_at
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?);
                                    """,
                                    (
                                        deliv_id,
                                        alert_id,
                                        ch.value,
                                        DeliveryStatus.DELIVERED.value,
                                        "LOCAL_STORAGE",
                                        json.dumps({"alert_id": alert_id, "title": title, "summary": summary}),
                                        now_iso,
                                    ),
                                )
                            conn.commit()
                            alert_dto = AlertingService.get_alert(alert_id)
                            if alert_dto:
                                generated_alerts.append(alert_dto)

        conn.close()
        return AlertEvaluationResult(
            evaluated_rules_count=len(active_rules),
            matched_alerts_count=len(generated_alerts),
            suppressed_alerts_count=suppressed_count,
            generated_alerts=generated_alerts,
        )

    @staticmethod
    def list_alerts(
        status: Optional[AlertStatus] = None,
        severity: Optional[AlertSeverity] = None,
        limit: int = 100,
    ) -> List[AlertDTO]:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "SELECT * FROM alerts"
        params: List[Any] = []
        conditions = []
        if status:
            conditions.append("status = ?")
            params.append(status.value)
        if severity:
            conditions.append("severity = ?")
            params.append(severity.value)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY triggered_at DESC LIMIT ?;"
        params.append(limit)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        alerts = []
        for r in rows:
            cursor.execute("SELECT * FROM alert_deliveries WHERE alert_id = ?;", (r["alert_id"],))
            deliv_rows = cursor.fetchall()
            deliveries = [
                AlertDeliveryDTO(
                    delivery_id=d["delivery_id"],
                    alert_id=d["alert_id"],
                    channel=DeliveryChannelType(d["channel"]),
                    status=DeliveryStatus(d["status"]),
                    destination=d["destination"],
                    payload_json=d["payload_json"],
                    error_message=d["error_message"],
                    delivered_at=d["delivered_at"],
                )
                for d in deliv_rows
            ]
            alerts.append(
                AlertDTO(
                    alert_id=r["alert_id"],
                    rule_id=r["rule_id"],
                    rule_name=r["rule_name"],
                    severity=AlertSeverity(r["severity"]),
                    status=AlertStatus(r["status"]),
                    title=r["title"],
                    summary=r["summary"],
                    source_type=AlertSourceType(r["source_type"]),
                    source_id=r["source_id"],
                    evidence_reference=r["evidence_reference"],
                    fingerprint=r["fingerprint"],
                    details=json.loads(r["details_json"] or "{}"),
                    triggered_at=r["triggered_at"],
                    acknowledged_by=r["acknowledged_by"],
                    acknowledged_at=r["acknowledged_at"],
                    resolved_by=r["resolved_by"],
                    resolved_at=r["resolved_at"],
                    resolution_notes=r["resolution_notes"],
                    deliveries=deliveries,
                )
            )
        conn.close()
        return alerts

    @staticmethod
    def get_alert(alert_id: str) -> Optional[AlertDTO]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE alert_id = ?;", (alert_id,))
        r = cursor.fetchone()
        if not r:
            conn.close()
            return None
        cursor.execute("SELECT * FROM alert_deliveries WHERE alert_id = ?;", (alert_id,))
        deliv_rows = cursor.fetchall()
        deliveries = [
            AlertDeliveryDTO(
                delivery_id=d["delivery_id"],
                alert_id=d["alert_id"],
                channel=DeliveryChannelType(d["channel"]),
                status=DeliveryStatus(d["status"]),
                destination=d["destination"],
                payload_json=d["payload_json"],
                error_message=d["error_message"],
                delivered_at=d["delivered_at"],
            )
            for d in deliv_rows
        ]
        conn.close()
        return AlertDTO(
            alert_id=r["alert_id"],
            rule_id=r["rule_id"],
            rule_name=r["rule_name"],
            severity=AlertSeverity(r["severity"]),
            status=AlertStatus(r["status"]),
            title=r["title"],
            summary=r["summary"],
            source_type=AlertSourceType(r["source_type"]),
            source_id=r["source_id"],
            evidence_reference=r["evidence_reference"],
            fingerprint=r["fingerprint"],
            details=json.loads(r["details_json"] or "{}"),
            triggered_at=r["triggered_at"],
            acknowledged_by=r["acknowledged_by"],
            acknowledged_at=r["acknowledged_at"],
            resolved_by=r["resolved_by"],
            resolved_at=r["resolved_at"],
            resolution_notes=r["resolution_notes"],
            deliveries=deliveries,
        )

    @staticmethod
    def acknowledge_alert(alert_id: str, analyst_id: str, notes: Optional[str] = None) -> Optional[AlertDTO]:
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE alerts
            SET status = ?, acknowledged_by = ?, acknowledged_at = ?
            WHERE alert_id = ?;
            """,
            (AlertStatus.ACKNOWLEDGED.value, analyst_id, now, alert_id),
        )
        conn.commit()
        conn.close()
        return AlertingService.get_alert(alert_id)

    @staticmethod
    def resolve_alert(alert_id: str, analyst_id: str, resolution_notes: str) -> Optional[AlertDTO]:
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE alerts
            SET status = ?, resolved_by = ?, resolved_at = ?, resolution_notes = ?
            WHERE alert_id = ?;
            """,
            (AlertStatus.RESOLVED.value, analyst_id, now, resolution_notes, alert_id),
        )
        conn.commit()
        conn.close()
        return AlertingService.get_alert(alert_id)

"""
SecureMailScope X - Phase 22 / 25: Automated Forensic Alerting Engine Tests
Validates deterministic alert rule evaluation, cooldown deduplication,
multi-channel delivery logging, and alert lifecycle state management.
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.db.database import get_db_connection, init_db, set_custom_db_path
from app.schemas.alerting import (
    AlertRuleCreate,
    AlertRuleUpdate,
    AlertRuleType,
    AlertSeverity,
    AlertStatus,
    AlertSourceType,
    DeliveryChannelType,
    DeliveryStatus,
)
from app.services.alerting_service import AlertingService


class TestAlertingEngine(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_path = self.temp_db.name
        set_custom_db_path(self.db_path)
        init_db(self.db_path)

    def tearDown(self):
        set_custom_db_path(None)
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def test_01_seed_default_rules(self):
        """Default rules are seeded when table is empty."""
        AlertingService.seed_default_rules()
        rules = AlertingService.list_rules()
        self.assertGreaterEqual(len(rules), 5)
        rule_types = {r.rule_type for r in rules}
        self.assertIn(AlertRuleType.FINDING_MATCH, rule_types)
        self.assertIn(AlertRuleType.POSTURE_DRIFT, rule_types)

    def test_02_create_custom_rule(self):
        """Custom alert rule can be created and persisted."""
        req = AlertRuleCreate(
            name="Custom Cleartext Rule",
            description="Detects cleartext",
            rule_type=AlertRuleType.FINDING_MATCH,
            severity=AlertSeverity.HIGH,
            enabled=True,
            condition_criteria={"finding_codes": ["CUSTOM_CLEARTEXT"]},
            cooldown_seconds=120,
            channels=[DeliveryChannelType.LOCAL_LOG],
        )
        rule = AlertingService.create_rule(req, created_by="analyst-01")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "Custom Cleartext Rule")
        self.assertEqual(rule.severity, AlertSeverity.HIGH)
        self.assertEqual(rule.cooldown_seconds, 120)

    def test_03_get_rule_by_id(self):
        """Rule can be retrieved by ID."""
        req = AlertRuleCreate(
            name="Retrieval Test",
            rule_type=AlertRuleType.WEAK_CRYPTO,
            severity=AlertSeverity.MEDIUM,
            condition_criteria={"finding_codes": ["WEAK_CIPHER"]},
        )
        created = AlertingService.create_rule(req)
        fetched = AlertingService.get_rule(created.rule_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.rule_id, created.rule_id)

    def test_04_update_rule(self):
        """Rule configuration can be updated."""
        req = AlertRuleCreate(
            name="Old Name",
            rule_type=AlertRuleType.CERT_EXPIRY,
            severity=AlertSeverity.LOW,
            condition_criteria={},
        )
        rule = AlertingService.create_rule(req)
        updated = AlertingService.update_rule(
            rule.rule_id,
            AlertRuleUpdate(name="New Name", severity=AlertSeverity.CRITICAL, cooldown_seconds=600),
        )
        self.assertIsNotNone(updated)
        self.assertEqual(updated.name, "New Name")
        self.assertEqual(updated.severity, AlertSeverity.CRITICAL)
        self.assertEqual(updated.cooldown_seconds, 600)

    def test_05_delete_rule(self):
        """Rule can be deleted."""
        req = AlertRuleCreate(
            name="To Delete",
            rule_type=AlertRuleType.WEAK_CRYPTO,
            severity=AlertSeverity.LOW,
            condition_criteria={},
        )
        rule = AlertingService.create_rule(req)
        res = AlertingService.delete_rule(rule.rule_id)
        self.assertTrue(res)
        self.assertIsNone(AlertingService.get_rule(rule.rule_id))

    def _insert_analysis_record(self, conn, analysis_id: str):
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT OR IGNORE INTO analyses (
                analysis_id, filename, file_size_bytes, capture_sha256,
                created_at, observed_result_json, observed_result_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (analysis_id, "test.pcap", 100, "sha256-test", now, "{}", "sha256-res"),
        )

    def test_06_evaluate_findings_generates_alert(self):
        """Evaluating real findings against rules triggers matching alert."""
        conn = get_db_connection()
        self._insert_analysis_record(conn, "test-analysis-01")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, finding_id, analysis_id, session_id, severity, category,
                title, description, finding_json, finding_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("f-1", "OBSOLETE_TLS_1_0", "test-analysis-01", "s-1", "CRITICAL", "TLS", "TLS 1.0 used", "Deprecated TLS", "{}", "sha123"),
        )
        conn.commit()
        conn.close()

        res = AlertingService.evaluate_evidence_against_rules(analysis_id="test-analysis-01")
        self.assertGreaterEqual(res.matched_alerts_count, 1)
        alert = res.generated_alerts[0]
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.source_type, AlertSourceType.PCAP_ANALYSIS)
        self.assertEqual(alert.status, AlertStatus.NEW)

    def test_07_cooldown_suppresses_duplicate_alerts(self):
        """Cooldown window suppresses identical alert generation within duration."""
        conn = get_db_connection()
        self._insert_analysis_record(conn, "test-analysis-02")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, finding_id, analysis_id, session_id, severity, category,
                title, description, finding_json, finding_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("f-2", "OBSOLETE_TLS_1_0", "test-analysis-02", "s-2", "CRITICAL", "TLS", "TLS 1.0 used", "Deprecated TLS", "{}", "sha123"),
        )
        conn.commit()
        conn.close()

        res1 = AlertingService.evaluate_evidence_against_rules(analysis_id="test-analysis-02")
        self.assertEqual(res1.matched_alerts_count, 1)

        res2 = AlertingService.evaluate_evidence_against_rules(analysis_id="test-analysis-02")
        self.assertEqual(res2.matched_alerts_count, 0)
        self.assertGreaterEqual(res2.suppressed_alerts_count, 1)

    def test_08_evaluate_posture_drift_generates_alert(self):
        """Evaluating posture drift events triggers drift alerts."""
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO monitored_targets (
                target_id, display_name, hostname, port, protocol, security_mode,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("target-01", "Mail Server", "mail.example.org", 587, "SMTP", "PLAIN_WITH_STARTTLS", now, now),
        )
        cursor.execute(
            """
            INSERT OR REPLACE INTO posture_snapshots (
                snapshot_id, target_id, scanned_at, reachable, protocol, security_mode,
                scan_result_sha256, canonical_snapshot_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("snap-01", "target-01", now, 1, "SMTP", "PLAIN_WITH_STARTTLS", "sha-snap-1", "sha-snap-1"),
        )
        cursor.execute(
            """
            INSERT OR REPLACE INTO posture_snapshots (
                snapshot_id, target_id, scanned_at, reachable, protocol, security_mode,
                scan_result_sha256, canonical_snapshot_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("snap-02", "target-01", now, 1, "SMTP", "PLAIN_WITH_STARTTLS", "sha-snap-2", "sha-snap-2"),
        )
        cursor.execute(
            """
            INSERT OR REPLACE INTO posture_drift_events (
                event_id, target_id, prior_snapshot_id, current_snapshot_id,
                drift_type, classification, old_value, new_value, details, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("event-01", "target-01", "snap-01", "snap-02", "TLS_VERSION_DOWNGRADE", "REGRESSION", "TLS 1.3", "TLS 1.2", "Downgraded TLS", now),
        )
        conn.commit()
        conn.close()

        res = AlertingService.evaluate_evidence_against_rules(target_id="target-01")
        self.assertGreaterEqual(res.matched_alerts_count, 1)
        alert = res.generated_alerts[0]
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertEqual(alert.source_type, AlertSourceType.POSTURE_MONITORING)

    def test_09_alert_delivery_records_created(self):
        """Delivery log entries are created for each configured notification channel."""
        conn = get_db_connection()
        self._insert_analysis_record(conn, "test-analysis-03")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, finding_id, analysis_id, session_id, severity, category,
                title, description, finding_json, finding_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("f-3", "CLEARTEXT_AUTH_COMMAND", "test-analysis-03", "s-3", "CRITICAL", "AUTH", "Cleartext Auth", "Credentials exposed", "{}", "sha123"),
        )
        conn.commit()
        conn.close()

        res = AlertingService.evaluate_evidence_against_rules(analysis_id="test-analysis-03")
        self.assertEqual(res.matched_alerts_count, 1)
        alert = res.generated_alerts[0]
        self.assertGreaterEqual(len(alert.deliveries), 1)
        self.assertEqual(alert.deliveries[0].status, DeliveryStatus.DELIVERED)

    def test_10_list_alerts_with_filters(self):
        """Alerts can be listed and filtered by status and severity."""
        conn = get_db_connection()
        self._insert_analysis_record(conn, "test-analysis-04")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, finding_id, analysis_id, session_id, severity, category,
                title, description, finding_json, finding_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("f-4", "CERTIFICATE_EXPIRED", "test-analysis-04", "s-4", "HIGH", "CERT", "Cert Expired", "Expired cert", "{}", "sha123"),
        )
        conn.commit()
        conn.close()

        AlertingService.evaluate_evidence_against_rules(analysis_id="test-analysis-04")
        all_alerts = AlertingService.list_alerts()
        self.assertGreaterEqual(len(all_alerts), 1)

        new_alerts = AlertingService.list_alerts(status=AlertStatus.NEW)
        self.assertGreaterEqual(len(new_alerts), 1)

        high_alerts = AlertingService.list_alerts(severity=AlertSeverity.HIGH)
        self.assertGreaterEqual(len(high_alerts), 1)

    def test_11_acknowledge_alert(self):
        """Alert status transitions from NEW to ACKNOWLEDGED with attribution."""
        conn = get_db_connection()
        self._insert_analysis_record(conn, "test-analysis-05")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, finding_id, analysis_id, session_id, severity, category,
                title, description, finding_json, finding_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("f-5", "WEAK_CIPHER_SUITE", "test-analysis-05", "s-5", "MEDIUM", "CRYPTO", "Weak Cipher", "3DES used", "{}", "sha123"),
        )
        conn.commit()
        conn.close()

        res = AlertingService.evaluate_evidence_against_rules(analysis_id="test-analysis-05")
        alert = res.generated_alerts[0]
        self.assertEqual(alert.status, AlertStatus.NEW)

        ack = AlertingService.acknowledge_alert(alert.alert_id, analyst_id="analyst-02", notes="Investigating")
        self.assertIsNotNone(ack)
        self.assertEqual(ack.status, AlertStatus.ACKNOWLEDGED)
        self.assertEqual(ack.acknowledged_by, "analyst-02")
        self.assertIsNotNone(ack.acknowledged_at)

    def test_12_resolve_alert(self):
        """Alert status transitions to RESOLVED with mandatory resolution notes."""
        conn = get_db_connection()
        self._insert_analysis_record(conn, "test-analysis-06")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, finding_id, analysis_id, session_id, severity, category,
                title, description, finding_json, finding_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("f-6", "WEAK_CIPHER_SUITE", "test-analysis-06", "s-6", "MEDIUM", "CRYPTO", "Weak Cipher", "RC4 used", "{}", "sha123"),
        )
        conn.commit()
        conn.close()

        res = AlertingService.evaluate_evidence_against_rules(analysis_id="test-analysis-06")
        alert = res.generated_alerts[0]

        resolved = AlertingService.resolve_alert(
            alert.alert_id,
            analyst_id="lead-01",
            resolution_notes="Cipher suite disabled on mail relay server.",
        )
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.status, AlertStatus.RESOLVED)
        self.assertEqual(resolved.resolved_by, "lead-01")
        self.assertEqual(resolved.resolution_notes, "Cipher suite disabled on mail relay server.")

    def test_13_disabled_rule_does_not_trigger(self):
        """Disabled alert rule is skipped during evidence evaluation."""
        req = AlertRuleCreate(
            name="Disabled Rule Test",
            rule_type=AlertRuleType.FINDING_MATCH,
            severity=AlertSeverity.HIGH,
            enabled=False,
            condition_criteria={"finding_codes": ["SPECIAL_FINDING_CODE"]},
        )
        rule = AlertingService.create_rule(req)
        conn = get_db_connection()
        self._insert_analysis_record(conn, "test-analysis-07")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, finding_id, analysis_id, session_id, severity, category,
                title, description, finding_json, finding_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("f-7", "SPECIAL_FINDING_CODE", "test-analysis-07", "s-7", "HIGH", "TEST", "Special", "Special finding", "{}", "sha123"),
        )
        conn.commit()
        conn.close()

        res = AlertingService.evaluate_evidence_against_rules(analysis_id="test-analysis-07")
        matched_rule_ids = {a.rule_id for a in res.generated_alerts}
        self.assertNotIn(rule.rule_id, matched_rule_ids)

    def test_14_nonexistent_alert_returns_none(self):
        """Retrieving nonexistent alert returns None."""
        self.assertIsNone(AlertingService.get_alert("nonexistent-alert-id"))

    def test_15_nonexistent_rule_returns_none(self):
        """Retrieving nonexistent rule returns None."""
        self.assertIsNone(AlertingService.get_rule("nonexistent-rule-id"))

    def test_16_delete_nonexistent_rule_returns_false(self):
        """Deleting nonexistent rule returns False."""
        self.assertFalse(AlertingService.delete_rule("nonexistent-rule-id"))

    def test_17_update_nonexistent_rule_returns_none(self):
        """Updating nonexistent rule returns None."""
        self.assertIsNone(AlertingService.update_rule("nonexistent-rule-id", AlertRuleUpdate(name="Test")))

    def test_18_multiple_findings_evaluate_correctly(self):
        """Multiple distinct findings generate corresponding alerts."""
        conn = get_db_connection()
        self._insert_analysis_record(conn, "test-analysis-08")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, finding_id, analysis_id, session_id, severity, category,
                title, description, finding_json, finding_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("f-8a", "OBSOLETE_TLS_1_0", "test-analysis-08", "s-8a", "CRITICAL", "TLS", "TLS 1.0", "Deprecated TLS", "{}", "sha123"),
        )
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, finding_id, analysis_id, session_id, severity, category,
                title, description, finding_json, finding_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("f-8b", "CLEARTEXT_AUTH_COMMAND", "test-analysis-08", "s-8b", "CRITICAL", "AUTH", "Auth", "Plaintext auth", "{}", "sha123"),
        )
        conn.commit()
        conn.close()

        res = AlertingService.evaluate_evidence_against_rules(analysis_id="test-analysis-08")
        self.assertGreaterEqual(res.matched_alerts_count, 2)

    def test_19_empty_analysis_generates_zero_alerts(self):
        """Evaluating analysis with zero findings generates zero alerts."""
        res = AlertingService.evaluate_evidence_against_rules(analysis_id="empty-analysis-id")
        self.assertEqual(res.matched_alerts_count, 0)
        self.assertEqual(len(res.generated_alerts), 0)

    def test_20_fingerprint_uniqueness(self):
        """Alert fingerprints are unique per rule and evidence instance."""
        conn = get_db_connection()
        self._insert_analysis_record(conn, "test-analysis-09")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, finding_id, analysis_id, session_id, severity, category,
                title, description, finding_json, finding_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            ("f-9", "OBSOLETE_TLS_1_0", "test-analysis-09", "s-9", "CRITICAL", "TLS", "TLS 1.0", "Deprecated TLS", "{}", "sha123"),
        )
        conn.commit()
        conn.close()

        res = AlertingService.evaluate_evidence_against_rules(analysis_id="test-analysis-09")
        alert = res.generated_alerts[0]
        self.assertTrue(len(alert.fingerprint) == 64)


if __name__ == "__main__":
    unittest.main()

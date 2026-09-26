# ==============================================================================
# SecureMailScope X — Phase 21: Posture Monitoring & Drift Engine Test Suite
# ==============================================================================
"""Comprehensive tests for continuous mail security posture monitoring,
deterministic snapshot canonical hashing, configuration drift detection,
baseline pinning, local scheduler evaluation, SIEM event derivation, and RBAC enforcement.
"""

import os
import sys
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from fastapi.testclient import TestClient

from app.db.database import init_db, get_db_connection
from app.main import app
from app.schemas.monitoring import (
    MonitoredTarget,
    TargetCreateRequest,
    TargetUpdateRequest,
    PostureSnapshot,
    PostureDriftEvent,
    ScheduleType,
    MonitoredProtocol,
    MonitoredSecurityMode,
    DriftType,
    DriftClassification,
)
from app.schemas.rbac import AnalystRole, Capability
from app.schemas.siem import SOCEventSeverity, SOCEventType
from app.services.monitoring_service import PostureMonitoringService
from app.services.rbac_service import AuthorizationService


class TestPostureMonitoringService(unittest.TestCase):
    """Unit and integration tests for PostureMonitoringService."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_path = self.temp_db.name
        init_db(self.db_path)
        self.client = TestClient(app)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    # 1. Target CRUD Lifecycle
    def test_target_crud_lifecycle(self):
        req = TargetCreateRequest(
            display_name="Inbound Gateway MX1",
            hostname="mx1.example.com",
            port=25,
            protocol=MonitoredProtocol.SMTP,
            security_mode=MonitoredSecurityMode.PLAIN_WITH_STARTTLS,
            enabled=True,
            schedule_type=ScheduleType.DAILY,
        )
        target = PostureMonitoringService.create_target(req, actor_id="analyst-01", db_path=self.db_path)
        self.assertIsNotNone(target)
        self.assertTrue(target.target_id.startswith("target-"))
        self.assertEqual(target.display_name, "Inbound Gateway MX1")
        self.assertEqual(target.port, 25)

        # Get
        fetched = PostureMonitoringService.get_target(target.target_id, db_path=self.db_path)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.hostname, "mx1.example.com")

        # Update
        update_req = TargetUpdateRequest(
            display_name="Inbound Gateway MX1 Primary",
            schedule_type=ScheduleType.HOURLY,
        )
        updated = PostureMonitoringService.update_target(target.target_id, update_req, db_path=self.db_path)
        self.assertEqual(updated.display_name, "Inbound Gateway MX1 Primary")
        self.assertEqual(updated.schedule_type, ScheduleType.HOURLY)

        # List
        all_targets = PostureMonitoringService.list_targets(db_path=self.db_path)
        self.assertEqual(len(all_targets), 1)

        # Delete
        deleted = PostureMonitoringService.delete_target(target.target_id, db_path=self.db_path)
        self.assertTrue(deleted)
        self.assertIsNone(PostureMonitoringService.get_target(target.target_id, db_path=self.db_path))

    # 2. Target Invalid Port Rejected
    def test_target_invalid_port_rejected(self):
        req = TargetCreateRequest(
            display_name="Web Server Port 80",
            hostname="web.example.com",
            port=80,
        )
        with self.assertRaises(ValueError):
            PostureMonitoringService.create_target(req, db_path=self.db_path)

    # 3. Protocol and Mode Auto-Derivation
    def test_target_default_protocol_derivation(self):
        req = TargetCreateRequest(
            display_name="IMAPS Server",
            hostname="imap.example.com",
            port=993,
        )
        target = PostureMonitoringService.create_target(req, db_path=self.db_path)
        self.assertEqual(target.protocol, MonitoredProtocol.IMAP)
        self.assertEqual(target.security_mode, MonitoredSecurityMode.DIRECT_TLS)

    # 4. Canonical Snapshot Hashing Determinism
    def test_canonical_snapshot_hashing(self):
        data1 = {
            "target_id": "target-123",
            "reachable": True,
            "protocol": "SMTP",
            "security_mode": "PLAIN_WITH_STARTTLS",
            "starttls_supported": True,
            "starttls_accepted": True,
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "certificate_fingerprint": "abc123def456",
            "certificate_valid": True,
            "pfs_status": "SUPPORTED",
            "pqc_status": "CLASSICAL_ONLY",
            "scan_result_sha256": "feedbeef00112233",
        }
        # Exact same data in different key insertion order
        data2 = {
            "scan_result_sha256": "feedbeef00112233",
            "target_id": "target-123",
            "reachable": True,
            "security_mode": "PLAIN_WITH_STARTTLS",
            "protocol": "SMTP",
            "starttls_supported": True,
            "starttls_accepted": True,
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "tls_version": "TLSv1.3",
            "certificate_valid": True,
            "certificate_fingerprint": "abc123def456",
            "pqc_status": "CLASSICAL_ONLY",
            "pfs_status": "SUPPORTED",
        }
        hash1 = PostureMonitoringService.compute_canonical_snapshot_sha256(data1)
        hash2 = PostureMonitoringService.compute_canonical_snapshot_sha256(data2)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

        # Changing an attribute changes hash
        data3 = dict(data1)
        data3["tls_version"] = "TLSv1.2"
        hash3 = PostureMonitoringService.compute_canonical_snapshot_sha256(data3)
        self.assertNotEqual(hash1, hash3)

    # 5. Mocked Active Scan Execution
    @patch("app.services.monitoring_service.TargetValidator.is_safe_public_target")
    @patch("app.services.monitoring_service.MailPostureScanner.probe_port")
    def test_scan_target_mocked_success(self, mock_probe, mock_validate):
        mock_validate.return_value = (True, "93.184.216.34", "", ["93.184.216.34"])

        mock_probe_result = MagicMock()
        mock_probe_result.connection_status = "SUCCESS"
        mock_probe_result.starttls_advertised = True
        mock_probe_result.starttls_accepted = True
        mock_probe_result.starttls_status = "STARTTLS_ACCEPTED"
        mock_probe_result.tls = MagicMock(negotiated_version="TLSv1.3", selected_cipher="TLS_AES_256_GCM_SHA384")
        mock_probe_result.certificate = MagicMock(
            sha256_fingerprint="aa11bb22cc33",
            subject="CN=mail.example.com",
            issuer="CN=Let's Encrypt",
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
            is_expired=False,
        )
        mock_probe_result.to_dict.return_value = {"status": "SUCCESS", "port": 587}
        mock_probe.return_value = mock_probe_result

        target = PostureMonitoringService.create_target(
            TargetCreateRequest(display_name="Submission Host", hostname="mail.example.com", port=587),
            db_path=self.db_path,
        )

        snapshot, drift = PostureMonitoringService.scan_target(target.target_id, db_path=self.db_path)
        self.assertIsNotNone(snapshot)
        self.assertTrue(snapshot.reachable)
        self.assertEqual(snapshot.tls_version, "TLSv1.3")
        self.assertEqual(snapshot.pfs_status, "SUPPORTED")
        self.assertEqual(snapshot.pqc_status, "CLASSICAL_ONLY")
        self.assertTrue(len(snapshot.canonical_snapshot_sha256) == 64)
        self.assertEqual(len(drift), 0)  # First scan -> no drift

    # 6. SSRF Safety Protection
    @patch("app.services.monitoring_service.TargetValidator.is_safe_public_target")
    def test_scan_target_ssrf_safety(self, mock_validate):
        mock_validate.return_value = (False, None, "SSRF Blocked: Loopback or Private IP", [])

        target = PostureMonitoringService.create_target(
            TargetCreateRequest(display_name="Internal Host", hostname="127.0.0.1", port=25),
            db_path=self.db_path,
        )

        snapshot, drift = PostureMonitoringService.scan_target(target.target_id, db_path=self.db_path)
        self.assertFalse(snapshot.reachable)
        self.assertIsNone(snapshot.tls_version)

    # 7. Drift Detection - No Prior Snapshot
    def test_drift_detection_no_prior(self):
        curr = PostureSnapshot(
            snapshot_id="s1",
            target_id="t1",
            scanned_at="2026-09-26T00:00:00Z",
            reachable=True,
            protocol="SMTP",
            security_mode="PLAIN_WITH_STARTTLS",
            tls_version="TLSv1.3",
            scan_result_sha256="abc",
            canonical_snapshot_sha256="def",
        )
        drifts = PostureMonitoringService.detect_drift(None, curr)
        self.assertEqual(drifts, [])

    # 8. Drift Detection - Reachability Loss (Regression)
    def test_drift_detection_reachability_loss(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=False, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0].drift_type, DriftType.ENDPOINT_BECAME_UNREACHABLE)
        self.assertEqual(drifts[0].classification, DriftClassification.REGRESSION)

    # 9. Drift Detection - Reachability Recovery (Improvement)
    def test_drift_detection_reachability_recovery(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=False, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0].drift_type, DriftType.ENDPOINT_RECOVERED)
        self.assertEqual(drifts[0].classification, DriftClassification.IMPROVEMENT)

    # 10. Drift Detection - TLS Downgrade (Regression)
    def test_drift_detection_tls_downgrade(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            tls_version="TLSv1.3", scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            tls_version="TLSv1.2", scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertTrue(any(d.drift_type == DriftType.TLS_DOWNGRADE for d in drifts))
        self.assertEqual(drifts[0].classification, DriftClassification.REGRESSION)

    # 11. Drift Detection - TLS Upgrade (Improvement)
    def test_drift_detection_tls_upgrade(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            tls_version="TLSv1.2", scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            tls_version="TLSv1.3", scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertTrue(any(d.drift_type == DriftType.TLS_UPGRADE for d in drifts))
        self.assertEqual(drifts[0].classification, DriftClassification.IMPROVEMENT)

    # 12. Drift Detection - STARTTLS Disabled (Regression)
    def test_drift_detection_starttls_disabled(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            starttls_supported=True, scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            starttls_supported=False, scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertTrue(any(d.drift_type == DriftType.STARTTLS_DISABLED for d in drifts))
        self.assertEqual(drifts[0].classification, DriftClassification.REGRESSION)

    # 13. Drift Detection - STARTTLS Enabled (Improvement)
    def test_drift_detection_starttls_enabled(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            starttls_supported=False, scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            starttls_supported=True, scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertTrue(any(d.drift_type == DriftType.STARTTLS_ENABLED for d in drifts))
        self.assertEqual(drifts[0].classification, DriftClassification.IMPROVEMENT)

    # 14. Drift Detection - Cipher Suite Changed (Neutral)
    def test_drift_detection_cipher_changed(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            cipher_suite="ECDHE-RSA-AES128-GCM-SHA256", scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            cipher_suite="ECDHE-RSA-AES256-GCM-SHA384", scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertTrue(any(d.drift_type == DriftType.CIPHER_CHANGED for d in drifts))
        self.assertEqual(drifts[0].classification, DriftClassification.NEUTRAL)

    # 15. Drift Detection - Certificate Expired (Regression)
    def test_drift_detection_certificate_expired(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            certificate_fingerprint="fp1", certificate_valid=True,
            scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            certificate_fingerprint="fp1", certificate_valid=False,
            scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertTrue(any(d.drift_type == DriftType.CERTIFICATE_EXPIRED for d in drifts))
        self.assertEqual(drifts[0].classification, DriftClassification.REGRESSION)

    # 16. Drift Detection - Certificate Renewed (Improvement)
    def test_drift_detection_certificate_renewed(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            certificate_fingerprint="fp_old", certificate_valid=False,
            scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            certificate_fingerprint="fp_new", certificate_valid=True,
            scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertTrue(any(d.drift_type == DriftType.CERTIFICATE_RENEWED for d in drifts))
        self.assertEqual(drifts[0].classification, DriftClassification.IMPROVEMENT)

    # 17. Drift Detection - PFS Lost (Regression)
    def test_drift_detection_pfs_lost(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            pfs_status="SUPPORTED", scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            pfs_status="NOT_SUPPORTED", scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertTrue(any(d.drift_type == DriftType.PFS_STATUS_CHANGED for d in drifts))
        self.assertEqual(drifts[0].classification, DriftClassification.REGRESSION)

    # 18. Drift Detection - PFS Gained (Improvement)
    def test_drift_detection_pfs_gained(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            pfs_status="NOT_SUPPORTED", scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            pfs_status="SUPPORTED", scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertTrue(any(d.drift_type == DriftType.PFS_STATUS_CHANGED for d in drifts))
        self.assertEqual(drifts[0].classification, DriftClassification.IMPROVEMENT)

    # 19. Drift Detection - PQC Hybrid Gained (Improvement)
    def test_drift_detection_pqc_transition(self):
        prior = PostureSnapshot(
            snapshot_id="s1", target_id="t1", scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            pqc_status="CLASSICAL_ONLY", scan_result_sha256="a", canonical_snapshot_sha256="b",
        )
        curr = PostureSnapshot(
            snapshot_id="s2", target_id="t1", scanned_at="2026-09-26T01:00:00Z",
            reachable=True, protocol="SMTP", security_mode="PLAIN_WITH_STARTTLS",
            pqc_status="HYBRID_READY", scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        drifts = PostureMonitoringService.detect_drift(prior, curr)
        self.assertTrue(any(d.drift_type == DriftType.PQC_STATUS_CHANGED for d in drifts))
        self.assertEqual(drifts[0].classification, DriftClassification.IMPROVEMENT)

    # 20. Baseline Pinning
    def test_baseline_pinning(self):
        target = PostureMonitoringService.create_target(
            TargetCreateRequest(display_name="MX Target", hostname="mx.example.com", port=25),
            db_path=self.db_path,
        )

        # Manually create snapshot
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO posture_snapshots (
                snapshot_id, target_id, scanned_at, reachable, protocol, security_mode,
                tls_version, scan_result_sha256, canonical_snapshot_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("snap-test-01", target.target_id, "2026-09-26T00:00:00Z", 1, "SMTP", "PLAIN_WITH_STARTTLS", "TLSv1.3", "a", "b"),
        )
        conn.commit()
        conn.close()

        updated = PostureMonitoringService.pin_baseline(
            target.target_id, "snap-test-01", actor_id="analyst-lead", db_path=self.db_path
        )
        self.assertIsNotNone(updated)
        self.assertEqual(updated.baseline_snapshot_id, "snap-test-01")
        self.assertEqual(updated.baseline_pinned_by, "analyst-lead")
        self.assertIsNotNone(updated.baseline_pinned_at)

    # 21. Drift Detection Against Pinned Baseline
    def test_drift_detection_against_baseline(self):
        target = PostureMonitoringService.create_target(
            TargetCreateRequest(display_name="Secure POP3", hostname="pop.example.com", port=995),
            db_path=self.db_path,
        )
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO posture_snapshots (
                snapshot_id, target_id, scanned_at, reachable, protocol, security_mode,
                tls_version, scan_result_sha256, canonical_snapshot_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("snap-baseline", target.target_id, "2026-09-25T00:00:00Z", 1, "POP3", "DIRECT_TLS", "TLSv1.3", "a", "b"),
        )
        conn.commit()
        conn.close()

        PostureMonitoringService.pin_baseline(target.target_id, "snap-baseline", db_path=self.db_path)

        curr = PostureSnapshot(
            snapshot_id="snap-curr", target_id=target.target_id, scanned_at="2026-09-26T00:00:00Z",
            reachable=True, protocol="POP3", security_mode="DIRECT_TLS",
            tls_version="TLSv1.2", scan_result_sha256="c", canonical_snapshot_sha256="d",
        )
        base = PostureMonitoringService.get_snapshot("snap-baseline", db_path=self.db_path)
        drifts = PostureMonitoringService.detect_drift(base, curr, is_baseline_comparison=True)
        self.assertEqual(len(drifts), 1)
        self.assertTrue(drifts[0].compared_against_baseline)

    # 22. Local Scheduler Due Evaluation
    def test_local_scheduler_due_evaluation(self):
        target_manual = MonitoredTarget(
            target_id="t-man", display_name="Manual", hostname="m.com", port=25,
            protocol=MonitoredProtocol.SMTP, security_mode=MonitoredSecurityMode.PLAIN_WITH_STARTTLS,
            enabled=True, schedule_type=ScheduleType.MANUAL, created_at="2026-09-26T00:00:00Z", updated_at="2026-09-26T00:00:00Z",
        )
        self.assertFalse(PostureMonitoringService.is_scan_due(target_manual))

        target_hourly = MonitoredTarget(
            target_id="t-hr", display_name="Hourly", hostname="h.com", port=25,
            protocol=MonitoredProtocol.SMTP, security_mode=MonitoredSecurityMode.PLAIN_WITH_STARTTLS,
            enabled=True, schedule_type=ScheduleType.HOURLY,
            last_scanned_at="2026-09-26T00:00:00+00:00", created_at="2026-09-26T00:00:00Z", updated_at="2026-09-26T00:00:00Z",
        )
        now_30m = datetime.fromisoformat("2026-09-26T00:30:00+00:00")
        self.assertFalse(PostureMonitoringService.is_scan_due(target_hourly, as_of=now_30m))

        now_65m = datetime.fromisoformat("2026-09-26T01:05:00+00:00")
        self.assertTrue(PostureMonitoringService.is_scan_due(target_hourly, as_of=now_65m))

    # 23. Local Scheduler Run Due Scans
    @patch("app.services.monitoring_service.TargetValidator.is_safe_public_target")
    @patch("app.services.monitoring_service.MailPostureScanner.probe_port")
    def test_local_scheduler_run_due_scans(self, mock_probe, mock_validate):
        mock_validate.return_value = (True, "93.184.216.34", "", ["93.184.216.34"])
        mock_probe_res = MagicMock()
        mock_probe_res.connection_status = "SUCCESS"
        mock_probe_res.tls = MagicMock(negotiated_version="TLSv1.3", selected_cipher="TLS_AES_256_GCM_SHA384")
        mock_probe_res.certificate = None
        mock_probe_res.starttls_advertised = True
        mock_probe_res.starttls_accepted = True
        mock_probe_res.starttls_status = "STARTTLS_ACCEPTED"
        mock_probe_res.to_dict.return_value = {"status": "SUCCESS"}
        mock_probe.return_value = mock_probe_res

        t1 = PostureMonitoringService.create_target(
            TargetCreateRequest(display_name="Due Target", hostname="due.example.com", port=25, schedule_type=ScheduleType.HOURLY),
            db_path=self.db_path,
        )

        res = PostureMonitoringService.run_due_scans(db_path=self.db_path)
        self.assertEqual(res["scanned_count"], 1)
        self.assertEqual(res["results"][0]["status"], "SUCCESS")

    # 24. SIEM Event Derivation
    def test_siem_event_derivation(self):
        target = MonitoredTarget(
            target_id="target-99", display_name="Inbound Relay", hostname="relay.example.com", port=25,
            protocol=MonitoredProtocol.SMTP, security_mode=MonitoredSecurityMode.PLAIN_WITH_STARTTLS,
            created_at="2026-09-26T00:00:00Z", updated_at="2026-09-26T00:00:00Z",
        )
        drift = PostureDriftEvent(
            event_id="drift-01", target_id="target-99", prior_snapshot_id="s1", current_snapshot_id="s2",
            drift_type=DriftType.TLS_DOWNGRADE, classification=DriftClassification.REGRESSION,
            old_value="TLSv1.3", new_value="TLSv1.2", details="TLS version downgraded from TLSv1.3 to TLSv1.2",
            detected_at="2026-09-26T02:00:00Z",
        )
        siem_event = PostureMonitoringService.derive_siem_events_from_drift(drift, target)
        self.assertEqual(siem_event.event_type, SOCEventType.POSTURE_DRIFT_OBSERVED)
        self.assertEqual(siem_event.severity, SOCEventSeverity.HIGH)
        self.assertEqual(siem_event.dst_ip, "relay.example.com")
        self.assertEqual(siem_event.dst_port, 25)

    # 25. Monitoring Summary Aggregation
    def test_monitoring_summary_aggregation(self):
        PostureMonitoringService.create_target(
            TargetCreateRequest(display_name="T1", hostname="t1.com", port=25),
            db_path=self.db_path,
        )
        summary = PostureMonitoringService.get_monitoring_summary(db_path=self.db_path)
        self.assertEqual(summary.total_targets, 1)
        self.assertEqual(summary.enabled_targets, 1)
        self.assertEqual(summary.total_snapshots, 0)
        self.assertEqual(summary.total_drift_events, 0)

    # 26. REST API - Target List and Create
    def test_api_list_and_create_target(self):
        res = self.client.get("/api/v1/monitoring/targets")
        self.assertEqual(res.status_code, 200)

        post_res = self.client.post(
            "/api/v1/monitoring/targets",
            json={
                "display_name": "API MX",
                "hostname": "api-mx.example.com",
                "port": 587,
                "schedule_type": "DAILY",
            },
        )
        self.assertEqual(post_res.status_code, 200)
        created = post_res.json()
        self.assertEqual(created["display_name"], "API MX")
        self.assertEqual(created["port"], 587)

    # 27. REST API - On-Demand Scan
    @patch("app.services.monitoring_service.TargetValidator.is_safe_public_target")
    @patch("app.services.monitoring_service.MailPostureScanner.probe_port")
    def test_api_scan_target_endpoint(self, mock_probe, mock_validate):
        mock_validate.return_value = (True, "93.184.216.34", "", ["93.184.216.34"])
        mock_probe_res = MagicMock()
        mock_probe_res.connection_status = "SUCCESS"
        mock_probe_res.tls = MagicMock(negotiated_version="TLSv1.3", selected_cipher="TLS_AES_256_GCM_SHA384")
        mock_probe_res.certificate = None
        mock_probe_res.starttls_advertised = True
        mock_probe_res.starttls_accepted = True
        mock_probe_res.starttls_status = "STARTTLS_ACCEPTED"
        mock_probe_res.to_dict.return_value = {"status": "SUCCESS"}
        mock_probe.return_value = mock_probe_res

        post_res = self.client.post(
            "/api/v1/monitoring/targets",
            json={"display_name": "Scan Target", "hostname": "scan.example.com", "port": 25},
        )
        tid = post_res.json()["target_id"]

        scan_res = self.client.post(f"/api/v1/monitoring/targets/{tid}/scan?allow_local_testing=true")
        self.assertEqual(scan_res.status_code, 200)
        body = scan_res.json()
        self.assertIn("snapshot", body)
        self.assertIn("drift_events", body)

    # 28. REST API - Pin Baseline
    @patch("app.services.monitoring_service.TargetValidator.is_safe_public_target")
    @patch("app.services.monitoring_service.MailPostureScanner.probe_port")
    def test_api_pin_baseline_endpoint(self, mock_probe, mock_validate):
        mock_validate.return_value = (True, "93.184.216.34", "", ["93.184.216.34"])
        mock_probe_res = MagicMock()
        mock_probe_res.connection_status = "SUCCESS"
        mock_probe_res.tls = MagicMock(negotiated_version="TLSv1.3", selected_cipher="TLS_AES_256_GCM_SHA384")
        mock_probe_res.certificate = None
        mock_probe_res.starttls_advertised = True
        mock_probe_res.starttls_accepted = True
        mock_probe_res.starttls_status = "STARTTLS_ACCEPTED"
        mock_probe_res.to_dict.return_value = {"status": "SUCCESS"}
        mock_probe.return_value = mock_probe_res

        post_res = self.client.post(
            "/api/v1/monitoring/targets",
            json={"display_name": "Pin Target", "hostname": "pin.example.com", "port": 25},
        )
        tid = post_res.json()["target_id"]

        scan_res = self.client.post(f"/api/v1/monitoring/targets/{tid}/scan?allow_local_testing=true")
        sid = scan_res.json()["snapshot"]["snapshot_id"]

        pin_res = self.client.post(f"/api/v1/monitoring/targets/{tid}/baseline/{sid}")
        self.assertEqual(pin_res.status_code, 200)
        self.assertEqual(pin_res.json()["baseline_snapshot_id"], sid)

    # 29. REST API - Drift and Summary Endpoints
    def test_api_drift_and_summary_endpoints(self):
        drift_res = self.client.get("/api/v1/monitoring/drift")
        self.assertEqual(drift_res.status_code, 200)
        self.assertIsInstance(drift_res.json(), list)

        summary_res = self.client.get("/api/v1/monitoring/summary")
        self.assertEqual(summary_res.status_code, 200)
        self.assertIn("total_targets", summary_res.json())

    # 30. RBAC Enforcement on Monitoring Endpoints
    def test_rbac_enforcement_on_monitoring_endpoints(self):
        # Register an auditor analyst who only has VIEW capabilities, not MANAGE or RUN_SCAN
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO analysts (analyst_id, display_name, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?)
            """,
            ("auditor-01", "Compliance Auditor", AnalystRole.AUDITOR.value, "2026-09-26T00:00:00Z", "2026-09-26T00:00:00Z"),
        )
        conn.commit()
        conn.close()

        # Auditor CAN view monitoring
        view_res = self.client.get("/api/v1/monitoring/targets", headers={"x-actor-id": "auditor-01"})
        self.assertEqual(view_res.status_code, 200)

        # Auditor CANNOT create targets (requires MANAGE_MONITORED_TARGETS)
        create_res = self.client.post(
            "/api/v1/monitoring/targets",
            headers={"x-actor-id": "auditor-01"},
            json={"display_name": "Unauthorized Target", "hostname": "unauth.com", "port": 25},
        )
        self.assertEqual(create_res.status_code, 403)

        # Auditor CANNOT trigger scans (requires RUN_MONITOR_SCAN)
        scan_res = self.client.post(
            "/api/v1/monitoring/targets/target-fake/scan",
            headers={"x-actor-id": "auditor-01"},
        )
        self.assertEqual(scan_res.status_code, 403)


if __name__ == "__main__":
    unittest.main()

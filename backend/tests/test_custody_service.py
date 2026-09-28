"""
SecureMailScope X - Cryptographic Chain of Custody & Tamper Verification Tests
Validates SHA-256 capture sealing, canonical manifest hashing, append-only hash chains,
tamper detection, and REST API custody endpoints.
"""

import os
import sys
import shutil
import tempfile
import unittest
from fastapi.testclient import TestClient

# Ensure backend root is on sys.path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.db.database import set_custom_db_path, init_db
from app.main import app
from app.services.analysis_service import AnalysisService
from app.services.custody_service import CustodyService, compute_sha256
from app.services.report_service import ReportService


class TestCustodyService(unittest.TestCase):
    SMTP_PCAP = r"D:\SecureMailScope\pcap_samples\smtp-starttls-test.pcapng"

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="sms_custody_test_")
        cls.db_path = os.path.join(cls.temp_dir, "test_custody.db")
        set_custom_db_path(cls.db_path)
        init_db(cls.db_path)
        CustodyService._records.clear()
        AnalysisService._cache.clear()

        cls.client = TestClient(app)
        if os.path.isfile(cls.SMTP_PCAP):
            cls.analysis = AnalysisService.process_local_pcap_path(cls.SMTP_PCAP)
            cls.analysis_id = cls.analysis.analysis_id
        else:
            cls.analysis = None
            cls.analysis_id = None

    @classmethod
    def tearDownClass(cls):
        CustodyService._records.clear()
        AnalysisService._cache.clear()
        set_custom_db_path(None)
        if hasattr(cls, "temp_dir") and os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_01_capture_hashing_and_initial_events(self):
        """Verify capture SHA-256 and initial chained custody events."""
        if not self.analysis:
            self.skipTest(f"PCAP not found: {self.SMTP_PCAP}")

        record = CustodyService.get_record(self.analysis_id)
        self.assertIsNotNone(record)
        self.assertEqual(len(record.capture_sha256), 64)
        self.assertEqual(record.filename, "smtp-starttls-test.pcapng")

        # Events list should contain at least CAPTURE_INGESTED, CAPTURE_HASHED, ANALYSIS_STARTED, ANALYSIS_COMPLETED
        event_types = [e.event_type for e in record.events]
        self.assertIn("CAPTURE_INGESTED", event_types)
        self.assertIn("CAPTURE_HASHED", event_types)
        self.assertIn("ANALYSIS_STARTED", event_types)
        self.assertIn("ANALYSIS_COMPLETED", event_types)

    def test_02_untouched_capture_verified(self):
        """Verify untouched capture passes all cryptographic checks."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        res = CustodyService.verify_integrity(self.analysis_id)
        self.assertEqual(res.overall_status, "VERIFIED")
        self.assertEqual(res.capture_integrity.status, "VERIFIED")
        self.assertEqual(res.manifest_integrity.status, "VERIFIED")
        self.assertIn(res.report_integrity.status, ["VERIFIED", "UNAVAILABLE"])

    def test_03_tamper_modified_capture_byte_fails(self):
        """Verify modifying single byte in capture fails integrity check."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        record = CustodyService.get_record(self.analysis_id)
        # Flip first byte of capture
        tampered_bytes = bytes([record.raw_bytes[0] ^ 0xFF]) + record.raw_bytes[1:]

        res = CustodyService.verify_integrity(self.analysis_id, override_capture_bytes=tampered_bytes)
        self.assertEqual(res.overall_status, "FAILED")
        self.assertEqual(res.capture_integrity.status, "FAILED")
        self.assertIn("mismatch", res.verification_details.lower())

    def test_04_tamper_modified_manifest_fails(self):
        """Verify modifying analysis manifest data breaks manifest seal."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        record = CustodyService.get_record(self.analysis_id)
        tampered_manifest = dict(record.manifest_dict)
        tampered_manifest["findings_count"] = 9999  # Tampered count

        res = CustodyService.verify_integrity(self.analysis_id, override_manifest_dict=tampered_manifest)
        self.assertEqual(res.overall_status, "FAILED")
        self.assertEqual(res.manifest_integrity.status, "FAILED")
        self.assertIn("manifest", res.verification_details.lower())

    def test_05_tamper_modified_audit_event_chain_fails(self):
        """Verify tampering with an event hash breaks audit trail chain."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        fake_hash = "f" * 64
        # Tamper event at index 1
        res = CustodyService.verify_integrity(self.analysis_id, override_event=(1, fake_hash))
        self.assertEqual(res.overall_status, "FAILED")
        self.assertIn("tampered", res.verification_details.lower())

    def test_06_report_generation_updates_custody(self):
        """Verify generating PDF report records REPORT_GENERATED event and updates manifest seal."""
        if not self.analysis:
            self.skipTest(f"PCAP not found: {self.SMTP_PCAP}")

        pdf_bytes = ReportService.generate_pdf_bytes(self.analysis)
        record = CustodyService.get_record(self.analysis_id)
        self.assertIsNotNone(record.report_pdf_hash)
        self.assertEqual(record.report_pdf_hash, compute_sha256(pdf_bytes))

        # Re-verify integrity
        res = CustodyService.verify_integrity(self.analysis_id)
        self.assertEqual(res.overall_status, "VERIFIED")
        self.assertEqual(res.report_integrity.status, "VERIFIED")

    def test_07_api_custody_get_endpoint(self):
        """GET /api/v1/analyses/{analysis_id}/custody returns custody record."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        res = self.client.get(f"/api/v1/analyses/{self.analysis_id}/custody")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["analysis_id"], self.analysis_id)
        self.assertEqual(data["overall_status"], "VERIFIED")
        self.assertGreaterEqual(len(data["audit_events"]), 4)

    def test_08_api_custody_verify_post_endpoint(self):
        """POST /api/v1/analyses/{analysis_id}/custody/verify executes live reverification."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        res = self.client.post(f"/api/v1/analyses/{self.analysis_id}/custody/verify")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["overall_status"], "VERIFIED")
        # Should have appended INTEGRITY_REVERIFIED event
        event_types = [e["event_type"] for e in data["audit_events"]]
        self.assertIn("INTEGRITY_REVERIFIED", event_types)

    def test_09_api_tamper_demo_endpoint(self):
        """POST /api/v1/analyses/{analysis_id}/custody/tamper-demo runs non-destructive test."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        # 1. Tamper capture test copy
        res = self.client.post(f"/api/v1/analyses/{self.analysis_id}/custody/tamper-demo?target=capture")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["overall_status"], "FAILED")
        self.assertEqual(data["capture_integrity"]["status"], "FAILED")

        # 2. Tamper manifest test copy
        res_m = self.client.post(f"/api/v1/analyses/{self.analysis_id}/custody/tamper-demo?target=manifest")
        self.assertEqual(res_m.status_code, 200)
        self.assertEqual(res_m.json()["overall_status"], "FAILED")

        # 3. Tamper event test copy
        res_e = self.client.post(f"/api/v1/analyses/{self.analysis_id}/custody/tamper-demo?target=event")
        self.assertEqual(res_e.status_code, 200)
        self.assertEqual(res_e.json()["overall_status"], "FAILED")

        # 4. Restore / verify untouched
        res_r = self.client.post(f"/api/v1/analyses/{self.analysis_id}/custody/tamper-demo?target=restore")
        self.assertEqual(res_r.status_code, 200)
        self.assertEqual(res_r.json()["overall_status"], "VERIFIED")


if __name__ == "__main__":
    unittest.main(verbosity=2)


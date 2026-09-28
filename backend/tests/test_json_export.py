"""
SecureMailScope X - JSON Export Unit and Integration Tests (Phase 26)
Validates formatted JSON forensic report serialization and dedicated REST endpoints.
"""

import os
import sys
import json
import unittest
from fastapi.testclient import TestClient

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.main import app
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportService


class TestJsonExport(unittest.TestCase):
    SMTP_PCAP = r"D:\SecureMailScope\pcap_samples\smtp-starttls-test.pcapng"

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        if os.path.isfile(cls.SMTP_PCAP):
            cls.analysis = AnalysisService.process_local_pcap_path(cls.SMTP_PCAP)
            cls.analysis_id = cls.analysis.analysis_id
        else:
            cls.analysis = None
            cls.analysis_id = None

    def test_01_json_string_serialization(self):
        """Verify ReportService.generate_json_str produces valid, parseable JSON with all 8 sections."""
        if not self.analysis:
            self.skipTest(f"PCAP not found: {self.SMTP_PCAP}")

        json_str = ReportService.generate_json_str(self.analysis)
        self.assertIsInstance(json_str, str)
        self.assertGreater(len(json_str), 100)

        data = json.loads(json_str)
        self.assertIn("case_metadata", data)
        self.assertIn("executive_summary", data)
        self.assertIn("session_inventory", data)
        self.assertIn("findings", data)
        self.assertIn("evidence_mapping", data)
        self.assertIn("cryptographic_posture", data)
        self.assertIn("pqc_hndl_assessment", data)
        self.assertIn("forensic_limitations", data)

        self.assertEqual(data["case_metadata"]["filename"], "smtp-starttls-test.pcapng")
        self.assertEqual(data["executive_summary"]["security_grade"], "A")
        self.assertEqual(len(data["session_inventory"]), 1)
        self.assertEqual(data["session_inventory"][0]["protocol"], "SMTP")
        self.assertEqual(data["session_inventory"][0]["tls_version"], "TLS 1.3")

    def test_02_json_export_endpoint(self):
        """Verify GET /api/v1/analyze/{analysis_id}/export/json returns valid JSON file attachment."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        res = self.client.get(f"/api/v1/analyze/{self.analysis_id}/export/json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "application/json")
        self.assertIn("attachment", res.headers.get("content-disposition", ""))
        self.assertIn(".json", res.headers.get("content-disposition", ""))

        data = res.json()
        self.assertEqual(data["case_metadata"]["analysis_id"], self.analysis_id)
        self.assertEqual(data["case_metadata"]["raw_pcap_frame_count"], 4309)

    def test_03_json_export_aliases(self):
        """Verify alias routes /api/v1/analyses/{analysis_id}/export/json and /json work correctly."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        res1 = self.client.get(f"/api/v1/analyses/{self.analysis_id}/export/json")
        self.assertEqual(res1.status_code, 200)

        res2 = self.client.get(f"/api/v1/analyses/{self.analysis_id}/json")
        self.assertEqual(res2.status_code, 200)

    def test_04_json_export_404_for_nonexistent(self):
        """Verify 404 status code returned for non-existent analysis ID."""
        res = self.client.get("/api/v1/analyze/analysis_nonexistent_999/export/json")
        self.assertEqual(res.status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)

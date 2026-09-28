"""
SecureMailScope X - HTML Export Unit and Integration Tests (Phase 26)
Validates standalone offline HTML forensic report generation with embedded CSS and dedicated REST endpoints.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.main import app
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportService


class TestHtmlExport(unittest.TestCase):
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

    def test_01_html_string_generation(self):
        """Verify ReportService.generate_html_str renders self-contained HTML with embedded styles."""
        if not self.analysis:
            self.skipTest(f"PCAP not found: {self.SMTP_PCAP}")

        html_str = ReportService.generate_html_str(self.analysis)
        self.assertIsInstance(html_str, str)
        self.assertGreater(len(html_str), 500)

        # HTML Structure assertions
        self.assertTrue(html_str.startswith("<!DOCTYPE html>"))
        self.assertIn("<html", html_str)
        self.assertIn("</html>", html_str)
        self.assertIn("<style>", html_str)
        self.assertIn("</style>", html_str)

        # Ensure no external scripts or CDNs are embedded
        self.assertNotIn("<script src=", html_str)
        self.assertNotIn("http://", html_str)
        self.assertNotIn("https://", html_str)

        # Content assertions
        self.assertIn("smtp-starttls-test.pcapng", html_str)
        self.assertIn("SECUREMAILSCOPE X", html_str)
        self.assertIn("Grade A", html_str)
        self.assertIn("TLS 1.3", html_str)
        self.assertIn("TLS_AES_256_GCM_SHA384", html_str)
        self.assertIn("Post-Quantum Readiness", html_str)
        self.assertIn("Forensic Limitations", html_str)

    def test_02_html_export_endpoint(self):
        """Verify GET /api/v1/analyze/{analysis_id}/export/html returns HTML attachment."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        res = self.client.get(f"/api/v1/analyze/{self.analysis_id}/export/html")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers["content-type"])
        self.assertIn("attachment", res.headers.get("content-disposition", ""))
        self.assertIn(".html", res.headers.get("content-disposition", ""))
        self.assertTrue(res.text.startswith("<!DOCTYPE html>"))

    def test_03_html_export_aliases(self):
        """Verify alias routes /api/v1/analyses/{analysis_id}/export/html and /html work."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        res1 = self.client.get(f"/api/v1/analyses/{self.analysis_id}/export/html")
        self.assertEqual(res1.status_code, 200)

        res2 = self.client.get(f"/api/v1/analyses/{self.analysis_id}/html")
        self.assertEqual(res2.status_code, 200)

    def test_04_html_export_404_for_nonexistent(self):
        """Verify 404 status code returned for non-existent analysis ID."""
        res = self.client.get("/api/v1/analyze/analysis_nonexistent_999/export/html")
        self.assertEqual(res.status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)

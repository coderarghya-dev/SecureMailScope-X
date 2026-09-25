"""
SecureMailScope X - Forensic Report & PDF Export Unit & Integration Tests
Validates structured report generation and PDF binary output against real PCAP captures.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure backend root is on sys.path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.main import app
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportService


class TestForensicReportService(unittest.TestCase):
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

    def test_01_report_model_generation(self):
        """Verify strongly typed report model contains all required forensic sections."""
        if not self.analysis:
            self.skipTest(f"PCAP not found: {self.SMTP_PCAP}")

        report = ReportService.generate_report_model(self.analysis)

        # 1. Case Metadata
        self.assertEqual(report.case_metadata.filename, "smtp-starttls-test.pcapng")
        self.assertEqual(report.case_metadata.raw_pcap_frame_count, 4309)
        self.assertEqual(report.case_metadata.reconstructed_session_count, 1)
        self.assertIn("SMTP", report.case_metadata.protocols_detected)

        # 2. Executive Summary
        self.assertEqual(report.executive_summary.security_grade, "A")
        self.assertEqual(report.executive_summary.security_score, 95)
        self.assertEqual(report.executive_summary.capture_health_score, 100)
        self.assertEqual(report.executive_summary.evidence_confidence_score, 80)
        self.assertIn("Assessment Incomplete", report.executive_summary.pqc_hndl_assessment_state)

        # 3. Session Inventory
        self.assertEqual(len(report.session_inventory), 1)
        sess = report.session_inventory[0]
        self.assertEqual(sess.protocol, "SMTP")
        self.assertEqual(sess.tls_version, "TLS 1.3")
        self.assertEqual(sess.cipher_suite, "TLS_AES_256_GCM_SHA384")
        self.assertIn("Unknown / insufficient passive evidence", sess.pfs_evidence_state)

        # 4. Findings
        self.assertEqual(len(report.findings), 2)
        finding_ids = [f.finding_id for f in report.findings]
        self.assertIn("FINDING-TLS13-STATE-OF-THE-ART", finding_ids)
        self.assertIn("FINDING-PQC-CLASSICAL-KEX-EXPOSURE", finding_ids)
        self.assertNotIn("FINDING-FORWARD-SECRECY-VERIFIED", finding_ids)

        # 5. Evidence Mapping
        self.assertEqual(len(report.evidence_mapping), 1)
        em = report.evidence_mapping[0]
        self.assertEqual(em.raw_capture_total_frames, 4309)
        self.assertEqual(em.session_packet_count, 27)
        self.assertEqual(em.requested_frame, 2292)
        self.assertEqual(em.accepted_frame, 2294)
        self.assertEqual(em.client_hello_frame, 2295)
        self.assertEqual(em.server_hello_frame, 2298)

        # 6. Cryptographic Posture
        self.assertIn("TLS 1.3", report.cryptographic_posture.tls_versions)
        self.assertIn("TLS_AES_256_GCM_SHA384", report.cryptographic_posture.cipher_suites)
        self.assertEqual(report.cryptographic_posture.forward_secrecy_evidence_state, "Unknown / Insufficient passive evidence")

        # 7. PQC / HNDL Assessment
        self.assertEqual(report.pqc_hndl_assessment.status, "Assessment Incomplete")
        self.assertIn("NIST FIPS 203", report.pqc_hndl_assessment.recommended_kem_standard)

        # 8. Forensic Limitations
        self.assertGreaterEqual(len(report.forensic_limitations), 3)

    def test_02_pdf_generation(self):
        """Verify ReportLab renders a valid PDF document with %PDF- header."""
        if not self.analysis:
            self.skipTest(f"PCAP not found: {self.SMTP_PCAP}")

        pdf_bytes = ReportService.generate_pdf_bytes(self.analysis)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 1000)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"), "PDF must start with binary %PDF- magic header")

    def test_03_report_api_endpoint(self):
        """GET /api/v1/analyze/{analysis_id}/report returns structured JSON report."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        res = self.client.get(f"/api/v1/analyze/{self.analysis_id}/report")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("case_metadata", data)
        self.assertIn("executive_summary", data)
        self.assertIn("session_inventory", data)
        self.assertIn("findings", data)
        self.assertIn("evidence_mapping", data)
        self.assertIn("cryptographic_posture", data)
        self.assertIn("pqc_hndl_assessment", data)
        self.assertIn("forensic_limitations", data)
        self.assertEqual(data["case_metadata"]["raw_pcap_frame_count"], 4309)
        self.assertEqual(data["evidence_mapping"][0]["session_packet_count"], 27)

    def test_04_pdf_api_endpoint(self):
        """GET /api/v1/analyze/{analysis_id}/pdf returns application/pdf with attachment header."""
        if not self.analysis_id:
            self.skipTest("No analysis ID available.")

        res = self.client.get(f"/api/v1/analyze/{self.analysis_id}/pdf")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "application/pdf")
        self.assertIn("attachment", res.headers.get("content-disposition", ""))
        self.assertIn(".pdf", res.headers.get("content-disposition", ""))
        self.assertTrue(res.content.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

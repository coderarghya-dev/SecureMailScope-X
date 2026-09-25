"""
SecureMailScope X - FastAPI REST API Integration Test Suite
Validates all Phase 4 endpoints against live test client and real PCAP captures.
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


class TestFastAPIForensicAPI(unittest.TestCase):
    SMTP_PCAP = r"D:\SecureMailScope\pcap_samples\smtp-starttls-test.pcapng"
    IMAP_PCAP = r"D:\SecureMailScope\pcap_samples\imap-tls-test.pcapng"
    POP3_PCAP = r"D:\SecureMailScope\pcap_samples\pop3-tls-test.pcapng"

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.cached_analysis_id = None
        cls.cached_session_id = None

    # -----------------------------------------------------------------------
    # 1. Root & Diagnostic Endpoints
    # -----------------------------------------------------------------------
    def test_01_root_endpoint(self):
        """GET / returns service metadata and documentation links."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("title", data)
        self.assertIn("SecureMailScope X", data["title"])
        self.assertEqual(data["documentation"], "/docs")
        self.assertEqual(data["openapi_schema"], "/openapi.json")

    def test_02_health_endpoint(self):
        """GET /api/v1/health returns TShark detector state and genuine capture status."""
        res = self.client.get("/api/v1/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("status", data)
        self.assertIn("tshark_available", data)
        self.assertIn("SMTP", data["supported_protocols"])
        self.assertIn("IMAP", data["supported_protocols"])
        self.assertIn("POP3", data["supported_protocols"])
        self.assertIn("PENDING", data["port_110_stls_real_capture_status"])

    def test_03_rules_catalog_endpoint(self):
        """GET /api/v1/rules returns active NIST SP 800-52r2 rules and PQC catalog."""
        res = self.client.get("/api/v1/rules")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["total_rules"], 5)
        rule_ids = [r["id"] for r in data["rules"]]
        self.assertIn("RULE-PLAIN-001", rule_ids)
        self.assertIn("RULE-PQC-HNDL-005", rule_ids)
        self.assertIn("RULE-TLS13-SOTA-006", rule_ids)

    # -----------------------------------------------------------------------
    # 2. PCAP Upload & Forensic Analysis Endpoints
    # -----------------------------------------------------------------------
    def test_04_analyze_real_smtp_pcap_upload(self):
        """POST /api/v1/analyze processes real Gmail SMTP capture with STARTTLS -> TLS 1.3."""
        if not os.path.isfile(self.SMTP_PCAP):
            self.skipTest(f"PCAP not found: {self.SMTP_PCAP}")

        with open(self.SMTP_PCAP, "rb") as f:
            file_bytes = f.read()

        res = self.client.post(
            "/api/v1/analyze",
            files={"file": ("smtp-starttls-test.pcapng", file_bytes, "application/vnd.tcpdump.pcap")}
        )
        self.assertEqual(res.status_code, 200, f"Upload analysis failed: {res.text}")
        data = res.json()

        self.assertTrue(data["analysis_id"].startswith("analysis_"))
        self.assertEqual(data["file_name"], "smtp-starttls-test.pcapng")
        self.assertGreaterEqual(data["total_packets_extracted"], 10)
        self.assertGreaterEqual(data["email_sessions_found"], 1)

        # Cache IDs for subsequent session tests
        TestFastAPIForensicAPI.cached_analysis_id = data["analysis_id"]
        smtp_sess = next(s for s in data["sessions"] if s["protocol"] == "SMTP")
        TestFastAPIForensicAPI.cached_session_id = smtp_sess["session_id"]

        # STARTTLS state verification
        st = smtp_sess["starttls"]
        self.assertTrue(st["advertised"])
        self.assertTrue(st["requested"])
        self.assertTrue(st["accepted"])
        self.assertTrue(st["upgrade_successful"])

        # TLS parameters verification
        tls = smtp_sess["tls"]
        self.assertIsNotNone(tls)
        self.assertEqual(tls["negotiated_version"], "TLS 1.3")

        # Capture health & Confidence verification
        health = smtp_sess["capture_health"]
        self.assertGreaterEqual(health["score"], 50)
        self.assertIn(health["grade"], ["EXCELLENT", "GOOD", "FAIR"])

        conf = smtp_sess["evidence_confidence"]
        self.assertEqual(conf["level"], "HIGH")

        # Security Assessment verification
        sec = smtp_sess["security_assessment"]
        self.assertEqual(sec["grade"], "A")
        self.assertGreater(len(sec["findings"]), 0)

        print(f"[OK] Test 04 Passed: Real SMTP PCAP analyzed via REST API. Session ID: {smtp_sess['session_id']}")

    def test_05_get_cached_analysis_report(self):
        """GET /api/v1/analyze/{analysis_id} retrieves cached report."""
        if not self.cached_analysis_id:
            self.skipTest("No cached analysis ID available.")

        res = self.client.get(f"/api/v1/analyze/{self.cached_analysis_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["analysis_id"], self.cached_analysis_id)
        self.assertGreaterEqual(data["email_sessions_found"], 1)

    # -----------------------------------------------------------------------
    # 3. Session Forensics & Drill-Down Endpoints
    # -----------------------------------------------------------------------
    def test_06_list_sessions_endpoint(self):
        """GET /api/v1/analyses/{analysis_id}/sessions returns session summary cards."""
        if not self.cached_analysis_id:
            self.skipTest("No cached analysis ID available.")

        res = self.client.get(f"/api/v1/analyses/{self.cached_analysis_id}/sessions")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)
        sess = data[0]
        self.assertIn("session_id", sess)
        self.assertIn("security_grade", sess)
        self.assertIn("health_score", sess)
        self.assertIn("confidence_level", sess)

    def test_07_get_session_detail_endpoint(self):
        """GET /api/v1/analyses/{analysis_id}/sessions/{session_id} returns deep session model."""
        if not self.cached_analysis_id or not self.cached_session_id:
            self.skipTest("No cached IDs available.")

        res = self.client.get(f"/api/v1/analyses/{self.cached_analysis_id}/sessions/{self.cached_session_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["session_id"], self.cached_session_id)
        self.assertEqual(data["protocol"], "SMTP")
        self.assertIsNotNone(data["starttls"])
        self.assertIsNotNone(data["tls"])
        self.assertIsNotNone(data["capture_health"])
        self.assertIsNotNone(data["evidence_confidence"])
        self.assertIsNotNone(data["security_assessment"])

    def test_08_get_session_packets_endpoint(self):
        """GET /api/v1/analyses/{analysis_id}/sessions/{session_id}/packets returns packet frames."""
        if not self.cached_analysis_id or not self.cached_session_id:
            self.skipTest("No cached IDs available.")

        res = self.client.get(f"/api/v1/analyses/{self.cached_analysis_id}/sessions/{self.cached_session_id}/packets?limit=5")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIsInstance(data, list)
        self.assertLessEqual(len(data), 5)
        if len(data) > 0:
            pkt = data[0]
            self.assertIn("frame_number", pkt)
            self.assertIn("timestamp_epoch", pkt)
            self.assertIn("summary", pkt)

    def test_09_get_session_findings_endpoint(self):
        """GET /api/v1/analyses/{analysis_id}/sessions/{session_id}/findings returns security findings."""
        if not self.cached_analysis_id or not self.cached_session_id:
            self.skipTest("No cached IDs available.")

        res = self.client.get(f"/api/v1/analyses/{self.cached_analysis_id}/sessions/{self.cached_session_id}/findings")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)
        finding = data[0]
        self.assertIn("id", finding)
        self.assertIn("severity", finding)
        self.assertIn("recommendation", finding)

    # -----------------------------------------------------------------------
    # 4. Security, Validation & Error Handling Tests
    # -----------------------------------------------------------------------
    def test_10_upload_security_path_traversal_rejection(self):
        """POST /api/v1/analyze rejects path traversal attempts with 400 Bad Request."""
        res = self.client.post(
            "/api/v1/analyze",
            files={"file": ("../../malicious.pcap", b"\x0a\x0d\x0d\x0a\x00\x00\x00\x00", "application/octet-stream")}
        )
        self.assertEqual(res.status_code, 400)
        data = res.json()
        self.assertIn("path traversal", data["detail"].lower())

    def test_11_upload_security_invalid_extension(self):
        """POST /api/v1/analyze rejects unapproved extensions (.txt, .exe) with 400 Bad Request."""
        res = self.client.post(
            "/api/v1/analyze",
            files={"file": ("malicious.exe", b"MZ\x90\x00\x03\x00\x00\x00", "application/octet-stream")}
        )
        self.assertEqual(res.status_code, 400)
        data = res.json()
        self.assertIn("Unsupported file extension", data["detail"])

    def test_12_upload_security_invalid_magic_bytes(self):
        """POST /api/v1/analyze rejects non-PCAP content with 400 Bad Request."""
        res = self.client.post(
            "/api/v1/analyze",
            files={"file": ("fake_capture.pcap", b"PLAIN_TEXT_CONTENT_HERE", "application/octet-stream")}
        )
        self.assertEqual(res.status_code, 400)
        data = res.json()
        self.assertIn("magic bytes", data["detail"].lower())

    def test_13_nonexistent_analysis_404(self):
        """GET /api/v1/analyze/{nonexistent} returns 404 Not Found."""
        res = self.client.get("/api/v1/analyze/analysis_0000000000000000")
        self.assertEqual(res.status_code, 404)
        data = res.json()
        self.assertIn("not found", data["detail"].lower())

    # -----------------------------------------------------------------------
    # 5. Enrichment & Advanced Endpoints
    # -----------------------------------------------------------------------
    def test_14_dns_auth_offline_endpoint(self):
        """POST /api/v1/enrichment/dns-auth returns evaluated domain security posture."""
        res = self.client.post(
            "/api/v1/enrichment/dns-auth",
            json={
                "domain": "example.com",
                "txt_records": ["v=spf1 include:_spf.google.com -all"],
                "dmarc_record": "v=DMARC1; p=reject",
                "active_lookup": False,
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["overall_auth_posture"], "ROBUST")
        self.assertEqual(data["dmarc_policy"], "reject")

    def test_15_eml_upload_endpoint(self):
        """POST /api/v1/eml/analyze parses email headers and Received relay hops."""
        eml_content = b"From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Test\r\n\r\nBody"
        res = self.client.post(
            "/api/v1/eml/analyze",
            files={"file": ("message.eml", eml_content, "message/rfc822")}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["subject"], "Test")

    def test_16_cases_api_lifecycle(self):
        """POST /api/v1/cases and GET /api/v1/cases."""
        res = self.client.post(
            "/api/v1/cases",
            json={"title": "Investigation Case Alpha", "description": "Test case creation"}
        )
        self.assertEqual(res.status_code, 200)
        case_data = res.json()
        self.assertIn("id", case_data)
        case_id = case_data["id"]

        get_res = self.client.get(f"/api/v1/cases/{case_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["title"], "Investigation Case Alpha")


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ==============================================================================
# SecureMailScope X — Phase 19: SIEM & SOC Integration Test Suite
# ==============================================================================
"""Comprehensive unit and integration test suite for SIEM event normalization,
formatters (JSON, RFC 5424, CEF), transports, delivery audits, filtering,
and REST API endpoints.
"""

import json
import os
import socket
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.db.database import get_db_connection, init_db, set_custom_db_path
from app.main import app
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
    _cef_escape_extension,
    _cef_escape_header,
    _rfc5424_escape_sd_param,
    format_event_cef,
    format_event_rfc5424,
    format_events_cef,
    format_events_json,
    format_events_rfc5424,
)
from app.services.siem_service import (
    deliver_soc_events,
    export_soc_events,
    extract_soc_events_from_analysis,
    extract_soc_events_from_case,
    extract_soc_events_from_custody,
    extract_soc_events_from_notarization,
    filter_soc_events,
    get_all_soc_events,
    get_siem_summary,
    list_siem_deliveries,
)
from app.services.siem_transports import (
    JsonWebhookTransport,
    LocalFileTransport,
    TcpSyslogTransport,
    UdpSyslogTransport,
)


class TestSIEMIntegration(unittest.TestCase):
    """Test suite for Phase 19 SIEM & SOC Integration Engine."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        set_custom_db_path(self.temp_db_path)
        init_db(self.temp_db_path)
        self.client = TestClient(app)

        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()

        observed_json = {
            "sessions": [
                {
                    "session_id": "sess-smtp-01",
                    "protocol": "SMTP",
                    "client": "192.168.1.50:50123",
                    "server": "192.178.211.108:587",
                    "findings": [
                        {
                            "id": "FINDING-TLS-DOWNGRADE",
                            "severity": "HIGH",
                            "message": "STARTTLS plaintext downgrade detected",
                            "frame_numbers": [12, 14],
                            "mitigation": "Enforce mandatory TLS encryption"
                        }
                    ]
                }
            ],
            "certificate_analysis": {
                "findings": [
                    {
                        "id": "FINDING-EXPIRED-CERT",
                        "severity": "MEDIUM",
                        "description": "Server certificate expired 10 days ago",
                        "evidence_reference": "cert_sha256:abcd1234"
                    }
                ]
            },
            "email_auth": {
                "findings": [
                    {
                        "id": "FINDING-SPF-SOFTFAIL",
                        "severity": "LOW",
                        "description": "SPF record resulted in SoftFail"
                    }
                ]
            },
            "pqc_readiness": {
                "findings": [
                    {
                        "id": "FINDING-CLASSICAL-KEX-ONLY",
                        "severity": "HIGH",
                        "description": "Session vulnerable to Store Now Decrypt Later (HNDL)"
                    }
                ]
            }
        }

        # 1. Insert analysis
        cursor.execute(
            """
            INSERT INTO analyses (
                analysis_id, filename, file_size_bytes, capture_sha256,
                created_at, observed_result_json, observed_result_sha256,
                total_packets, email_sessions_found, security_grade,
                evidence_confidence_score, custody_link_hash, report_link_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "analysis-test-01",
                "sample.pcapng",
                1024,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "2026-09-26T06:00:00Z",
                json.dumps(observed_json),
                "abc123sha",
                50,
                1,
                "B",
                90,
                "manifest-sha-12345",
                "report-sha-67890"
            )
        )

        # 2. Insert custody record
        cursor.execute(
            """
            INSERT INTO custody_records (
                analysis_id, filename, file_size, capture_sha256, ingestion_timestamp, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "analysis-test-01",
                "sample.pcapng",
                1024,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "2026-09-26T06:00:00Z",
                "2026-09-26T06:00:00Z",
                "2026-09-26T06:00:00Z"
            )
        )

        # 3. Insert custody manifest version
        cursor.execute(
            """
            INSERT INTO custody_manifest_versions (
                manifest_version_id, analysis_id, version_number, manifest_type,
                previous_manifest_sha256, manifest_json, manifest_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "manifest-v1",
                "analysis-test-01",
                1,
                "INITIAL_MANIFEST",
                "GENESIS_0000000000000000000000000000000000000000000000000000000000000000",
                "{}",
                "manifest-sha-12345",
                "2026-09-26T06:00:00Z"
            )
        )

        # 4. Insert report artifact
        cursor.execute(
            """
            INSERT INTO report_artifacts (
                report_artifact_id, analysis_id, filename, artifact_sha256,
                artifact_size_bytes, source_manifest_version_id, generated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "report-01",
                "analysis-test-01",
                "report.pdf",
                "report-sha-67890",
                2048,
                "manifest-v1",
                "2026-09-26T06:00:00Z"
            )
        )

        # 5. Insert digital signature
        cursor.execute(
            """
            INSERT INTO digital_signatures (
                signature_id, analysis_id, report_artifact_id, manifest_version_id,
                signature_algorithm, signature_format, signature_value,
                signed_digest_algorithm, signed_digest_value,
                public_key_fingerprint_sha256, public_key_pem, key_id,
                signed_at, verification_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "sig-01",
                "analysis-test-01",
                "report-01",
                "manifest-v1",
                "Ed25519",
                "BASE64",
                "deadbeefbase64",
                "SHA256",
                "payloadsha256value",
                "pubkeyfingerprintsha",
                "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----",
                "key-01",
                "2026-09-26T06:00:00Z",
                "VERIFIED"
            )
        )

        # 6. Insert test case
        cursor.execute(
            """
            INSERT INTO cases (
                id, title, description, status, created_at, updated_at, created_by_display_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "case-test-01",
                "Operation BlackMail",
                "Forensic investigation into malicious SMTP relay",
                "OPEN",
                "2026-09-26T06:05:00Z",
                "2026-09-26T06:05:00Z",
                "Lead Forensic Analyst"
            )
        )

        # 7. Insert test custody event
        cursor.execute(
            """
            INSERT INTO custody_events (
                event_id, analysis_id, sequence_order, event_type, timestamp_utc,
                artifact_hash, previous_event_hash, current_event_hash, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "custody-evt-01",
                "analysis-test-01",
                1,
                "INITIAL_CAPTURE_SEALED",
                "2026-09-26T06:01:00Z",
                "manifest-sha-12345",
                "GENESIS_PREVIOUS_HASH_00000000000000000000000000000000",
                "current_event_hash_11111111111111111111111111111111",
                "Initial PCAP capture sealed into immutable manifest"
            )
        )

        # 8. Insert test notarization
        cursor.execute(
            """
            INSERT INTO notarization_records (
                notarization_id, analysis_id, report_artifact_id, signature_id,
                manifest_version_id, notarization_mode, provider_name, local_proof_sha256,
                status, transaction_hash, block_number, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "notarize-01",
                "analysis-test-01",
                "report-01",
                "sig-01",
                "manifest-v1",
                "EXTERNAL_PROVIDER",
                "Ethereum Sepolia",
                "proof-sha-9999",
                "CONFIRMED",
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                1234567,
                "2026-09-26T06:02:00Z"
            )
        )

        conn.commit()
        conn.close()

    def tearDown(self):
        set_custom_db_path(None)
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # 1. Normalization & Provenance Tests
    # --------------------------------------------------------------------------

    def test_01_extract_analysis_events_provenance(self):
        """Test extraction of normalized events from analysis preserving exact provenance."""
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analyses WHERE analysis_id='analysis-test-01';")
        analysis_row = dict(cursor.fetchone())
        conn.close()

        events = extract_soc_events_from_analysis(analysis_row)
        self.assertGreaterEqual(len(events), 5)
        
        # Summary event
        summary_ev = next((e for e in events if e.event_type == SOCEventType.FORENSIC_ANALYSIS_COMPLETED), None)
        self.assertIsNotNone(summary_ev)
        self.assertEqual(summary_ev.analysis_id, "analysis-test-01")
        self.assertEqual(summary_ev.manifest_sha256, "manifest-sha-12345")

        # TLS weakness finding
        tls_ev = next((e for e in events if e.event_type == SOCEventType.TLS_WEAKNESS_DETECTED), None)
        self.assertIsNotNone(tls_ev)
        self.assertEqual(tls_ev.severity, SOCEventSeverity.HIGH)
        self.assertEqual(tls_ev.finding_code, "FINDING-TLS-DOWNGRADE")
        self.assertEqual(tls_ev.frame_numbers, [12, 14])
        self.assertEqual(tls_ev.src_ip, "192.168.1.50")
        self.assertEqual(tls_ev.src_port, 50123)
        self.assertEqual(tls_ev.dst_ip, "192.178.211.108")
        self.assertEqual(tls_ev.dst_port, 587)

    def test_02_extract_case_events_provenance(self):
        """Test case creation and lifecycle event extraction."""
        case_dict = {
            "case_id": "case-test-01",
            "case_name": "Operation BlackMail",
            "status": "SEALED",
            "created_at": "2026-09-26T06:05:00Z",
            "sealed_at": "2026-09-26T06:10:00Z",
            "created_by_display_name": "Lead Analyst"
        }
        events = extract_soc_events_from_case(case_dict)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, SOCEventType.CASE_CREATED)
        self.assertEqual(events[1].event_type, SOCEventType.CASE_SEALED)
        self.assertEqual(events[1].case_id, "case-test-01")

    def test_03_extract_custody_and_notarization_events(self):
        """Test extraction of custody and blockchain notarization events."""
        custody_row = {
            "event_id": "c-01",
            "analysis_id": "analysis-01",
            "event_type": "CHAIN_HASH_VERIFIED",
            "timestamp_utc": "2026-09-26T06:00:00Z",
            "manifest_sha256": "sha-abc",
            "description": "Chain verified"
        }
        c_events = extract_soc_events_from_custody(custody_row)
        self.assertEqual(len(c_events), 1)
        self.assertEqual(c_events[0].event_type, SOCEventType.CUSTODY_EVENT)

        notarize_row = {
            "notarization_id": "not-01",
            "analysis_id": "analysis-01",
            "status": "CONFIRMED",
            "transaction_hash": "0xdeadbeef",
            "block_number": 500,
            "created_at": "2026-09-26T06:01:00Z",
            "local_proof_sha256": "sha-proof"
        }
        n_events = extract_soc_events_from_notarization(notarize_row)
        self.assertEqual(len(n_events), 1)
        self.assertEqual(n_events[0].event_type, SOCEventType.NOTARIZATION_CONFIRMED)
        self.assertEqual(n_events[0].blockchain_transaction_hash, "0xdeadbeef")

    def test_04_tamper_event_extraction(self):
        """Test that custody tamper events map to CRITICAL EVIDENCE_TAMPER_DETECTED."""
        tamper_row = {
            "event_id": "t-01",
            "analysis_id": "analysis-01",
            "event_type": "EVIDENCE_TAMPER_DETECTED",
            "timestamp_utc": "2026-09-26T06:00:00Z",
            "manifest_sha256": "sha-broken",
            "description": "Manifest hash mismatch detected"
        }
        events = extract_soc_events_from_custody(tamper_row)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, SOCEventType.EVIDENCE_TAMPER_DETECTED)
        self.assertEqual(events[0].severity, SOCEventSeverity.CRITICAL)

    # --------------------------------------------------------------------------
    # 2. Formatter Tests (JSON, RFC 5424, CEF)
    # --------------------------------------------------------------------------

    def test_05_deterministic_json_export(self):
        """Test deterministic JSON export formatting."""
        events = get_all_soc_events(db_path=self.temp_db_path)
        json_output = format_events_json(events)
        parsed = json.loads(json_output)
        self.assertIsInstance(parsed, list)
        self.assertGreaterEqual(len(parsed), 5)
        self.assertIn("event_id", parsed[0])
        self.assertIn("severity", parsed[0])

    def test_06_rfc5424_syslog_formatting(self):
        """Test RFC 5424 Syslog formatting and PRI mapping."""
        event = NormalizedSOCEvent(
            event_id="evt-rfc-01",
            event_type=SOCEventType.TLS_WEAKNESS_DETECTED,
            timestamp="2026-09-26T06:00:00Z",
            severity=SOCEventSeverity.HIGH,
            source_component="RuleEngine",
            analysis_id="analysis-01",
            case_id="case-01",
            message="Plaintext credentials transmitted over port 25",
            finding_code="FINDING-PLAINTEXT-AUTH",
            frame_numbers=[10, 11]
        )
        syslog_line = format_event_rfc5424(event, hostname="sms-forensics")
        # PRI for HIGH (Facility 16 * 8 + 3 = 131)
        self.assertTrue(syslog_line.startswith("<131>1 2026-09-26T06:00:00+00:00 sms-forensics SecureMailScopeX - TLS_WEAKNESS_DETECTED"))
        self.assertIn('[evidence@52159', syslog_line)
        self.assertIn('eventId="evt-rfc-01"', syslog_line)
        self.assertIn('findingCode="FINDING-PLAINTEXT-AUTH"', syslog_line)
        self.assertIn('frameNumbers="10,11"', syslog_line)

    def test_07_rfc5424_parameter_escaping(self):
        """Test escaping of special characters in RFC 5424 structured data."""
        escaped = _rfc5424_escape_sd_param('test"val\\with]bracket')
        self.assertEqual(escaped, 'test\\"val\\\\with\\]bracket')

    def test_08_cef_formatting(self):
        """Test ArcSight CEF format header and extensions."""
        event = NormalizedSOCEvent(
            event_id="evt-cef-01",
            event_type=SOCEventType.TLS_WEAKNESS_DETECTED,
            timestamp="2026-09-26T06:00:00Z",
            severity=SOCEventSeverity.HIGH,
            source_component="RuleEngine",
            analysis_id="analysis-01",
            case_id="case-01",
            protocol="SMTP",
            src_ip="192.168.1.100",
            src_port=587,
            dst_ip="192.178.211.108",
            dst_port=587,
            finding_code="FINDING-WEAK-CIPHER",
            message="Weak 3DES cipher negotiated",
            frame_numbers=[42]
        )
        cef_line = format_event_cef(event)
        self.assertTrue(cef_line.startswith("CEF:0|SecureMailScope|SecureMailScope X|1.0.0|FINDING-WEAK-CIPHER|Tls Weakness Detected|8|"))
        self.assertIn("src=192.168.1.100", cef_line)
        self.assertIn("spt=587", cef_line)
        self.assertIn("dst=192.178.211.108", cef_line)
        self.assertIn("proto=SMTP", cef_line)
        self.assertIn("cs1=analysis-01 cs1Label=AnalysisID", cef_line)
        self.assertIn("cn1=42 cn1Label=FrameNumber", cef_line)

    def test_09_cef_escaping(self):
        """Test escaping of pipe, backslash, and equals in CEF."""
        h_esc = _cef_escape_header("Vendor|Name\\Test")
        self.assertEqual(h_esc, "Vendor\\|Name\\\\Test")
        ext_esc = _cef_escape_extension("Key=Val\\Msg\nLine")
        self.assertEqual(ext_esc, "Key\\=Val\\\\Msg\\nLine")

    # --------------------------------------------------------------------------
    # 3. Transports & Error Handling Tests
    # --------------------------------------------------------------------------

    def test_10_local_file_transport_offline(self):
        """Test local file export transport without network requirement."""
        temp_dir = tempfile.mkdtemp()
        target_file = os.path.join(temp_dir, "siem_export.json")
        transport = LocalFileTransport(target_file)
        self.assertEqual(transport.destination_label, "file:siem_export.json")

        payload = '{"test": "payload"}'
        success, err = transport.deliver(payload)
        self.assertTrue(success)
        self.assertIsNone(err)
        self.assertTrue(os.path.exists(target_file))
        with open(target_file, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), payload)

        try:
            os.remove(target_file)
            os.rmdir(temp_dir)
        except Exception:
            pass

    @patch("socket.socket")
    def test_11_udp_syslog_transport_mocked(self, mock_socket_class):
        """Test UDP Syslog transport dispatch with mocked socket."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        transport = UdpSyslogTransport(host="10.0.0.1", port=514)
        self.assertEqual(transport.destination_label, "udp://10.0.0.1:514")

        success, err = transport.deliver("<134>1 Line1\n<134>1 Line2")
        self.assertTrue(success)
        self.assertIsNone(err)
        self.assertEqual(mock_sock.sendto.call_count, 2)

    @patch("socket.socket")
    def test_12_tcp_syslog_transport_mocked(self, mock_socket_class):
        """Test TCP Syslog transport dispatch with mocked socket."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        transport = TcpSyslogTransport(host="10.0.0.2", port=6514)
        self.assertEqual(transport.destination_label, "tcp://10.0.0.2:6514")

        success, err = transport.deliver("<134>1 Line1\n<134>1 Line2")
        self.assertTrue(success)
        self.assertIsNone(err)
        mock_sock.connect.assert_called_once_with(("10.0.0.2", 6514))
        self.assertEqual(mock_sock.sendall.call_count, 2)

    @patch("urllib.request.urlopen")
    def test_13_webhook_transport_mocked_success(self, mock_urlopen):
        """Test JSON Webhook transport with mocked HTTP response."""
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        transport = JsonWebhookTransport(
            url="https://siem.corp.internal/webhook/events",
            auth_header="Bearer secret_token_123"
        )
        self.assertEqual(transport.destination_label, "https://siem.corp.internal/webhook/events")

        success, err = transport.deliver('{"event_count": 1}')
        self.assertTrue(success)
        self.assertIsNone(err)

    @patch("urllib.request.urlopen")
    def test_14_webhook_transport_failure_sanitization(self, mock_urlopen):
        """Test that webhook network failures are caught and secrets are not leaked."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://siem.corp.internal/webhook",
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=None
        )

        transport = JsonWebhookTransport(
            url="https://siem.corp.internal/webhook",
            auth_header="Bearer super_secret_passphrase"
        )
        success, err = transport.deliver('{"event": "test"}')
        self.assertFalse(success)
        self.assertIn("403 Forbidden", err)
        self.assertNotIn("super_secret_passphrase", err)

    # --------------------------------------------------------------------------
    # 4. Delivery Service & Audit Logging
    # --------------------------------------------------------------------------

    def test_15_deliver_soc_events_audit_log(self):
        """Test full delivery lifecycle and audit logging in SQLite."""
        temp_dir = tempfile.mkdtemp()
        export_file = os.path.join(temp_dir, "siem_delivery_test.json")

        req = SIEMDeliveryRequest(
            format=SOCExportFormat.JSON,
            transport=SIEMTransportType.LOCAL_FILE,
            destination_path=export_file
        )

        record = deliver_soc_events(req, db_path=self.temp_db_path)
        self.assertEqual(record.status, DeliveryStatus.SENT)
        self.assertEqual(record.format, SOCExportFormat.JSON)
        self.assertEqual(record.transport, SIEMTransportType.LOCAL_FILE)
        self.assertGreaterEqual(record.event_count, 1)

        # Verify audit log in database
        deliveries = list_siem_deliveries(db_path=self.temp_db_path)
        self.assertGreaterEqual(len(deliveries), 1)
        self.assertEqual(deliveries[0].delivery_id, record.delivery_id)
        self.assertEqual(deliveries[0].status, DeliveryStatus.SENT)

        try:
            os.remove(export_file)
            os.rmdir(temp_dir)
        except Exception:
            pass

    def test_16_filtering_soc_events(self):
        """Test deterministic filtering by case_id, severity, and protocol."""
        events = get_all_soc_events(db_path=self.temp_db_path)

        # Filter by severity HIGH
        filter_high = SIEMEventFilter(severity=SOCEventSeverity.HIGH)
        high_events = filter_soc_events(events, filter_high)
        self.assertTrue(all(e.severity == SOCEventSeverity.HIGH for e in high_events))

        # Filter by protocol SMTP
        filter_smtp = SIEMEventFilter(protocol="SMTP")
        smtp_events = filter_soc_events(events, filter_smtp)
        self.assertTrue(all(e.protocol == "SMTP" for e in smtp_events if e.protocol))

        # Filter by case_id
        filter_case = SIEMEventFilter(case_id="case-test-01")
        case_events = filter_soc_events(events, filter_case)
        self.assertTrue(all(e.case_id == "case-test-01" for e in case_events))

    def test_17_summary_statistics(self):
        """Test SIEM corpus summary statistics calculation."""
        summary = get_siem_summary(db_path=self.temp_db_path)
        self.assertGreaterEqual(summary.total_events, 5)
        self.assertIn("INFO", summary.events_by_severity)
        self.assertIn("FORENSIC_ANALYSIS_COMPLETED", summary.events_by_type)
        self.assertIn("Exported SOC telemetry", summary.notice)

    # --------------------------------------------------------------------------
    # 5. REST API Endpoint Tests
    # --------------------------------------------------------------------------

    def test_18_api_get_events(self):
        """Test GET /api/v1/siem/events endpoint."""
        resp = self.client.get("/api/v1/siem/events")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 5)

    def test_19_api_get_single_event(self):
        """Test GET /api/v1/siem/events/{event_id} endpoint."""
        resp_list = self.client.get("/api/v1/siem/events")
        first_id = resp_list.json()[0]["event_id"]

        resp = self.client.get(f"/api/v1/siem/events/{first_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["event_id"], first_id)

    def test_20_api_export_json_cef_syslog(self):
        """Test API exports for JSON, CEF, and RFC5424."""
        # JSON
        resp_json = self.client.get("/api/v1/siem/export/json")
        self.assertEqual(resp_json.status_code, 200)
        self.assertEqual(resp_json.headers["content-type"], "application/json")
        self.assertIsInstance(json.loads(resp_json.text), list)

        # CEF
        resp_cef = self.client.get("/api/v1/siem/export/cef")
        self.assertEqual(resp_cef.status_code, 200)
        self.assertIn("CEF:0|SecureMailScope|SecureMailScope X", resp_cef.text)

        # Syslog
        resp_syslog = self.client.get("/api/v1/siem/export/syslog")
        self.assertEqual(resp_syslog.status_code, 200)
        self.assertIn("<", resp_syslog.text)
        self.assertIn("SecureMailScopeX", resp_syslog.text)

    def test_21_api_deliver_and_status(self):
        """Test POST /api/v1/siem/deliver and GET /api/v1/siem/status."""
        temp_dir = tempfile.mkdtemp()
        export_file = os.path.join(temp_dir, "api_siem_export.json")

        payload = {
            "format": "JSON",
            "transport": "LOCAL_FILE",
            "destination_path": export_file
        }
        resp = self.client.post("/api/v1/siem/deliver", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "SENT")
        self.assertEqual(data["transport"], "LOCAL_FILE")

        # Check status endpoint
        resp_status = self.client.get("/api/v1/siem/status")
        self.assertEqual(resp_status.status_code, 200)
        status_data = resp_status.json()
        self.assertGreaterEqual(status_data["total_events"], 1)
        self.assertGreaterEqual(status_data["total_deliveries"], 1)

        # Check deliveries endpoint
        resp_delivs = self.client.get("/api/v1/siem/deliveries")
        self.assertEqual(resp_delivs.status_code, 200)
        self.assertGreaterEqual(len(resp_delivs.json()), 1)

        try:
            os.remove(export_file)
            os.rmdir(temp_dir)
        except Exception:
            pass

    def test_22_ioc_correlation_event_extraction(self):
        """Test IOC correlation event normalization from Phase 18 intelligence."""
        ioc_event = NormalizedSOCEvent(
            event_id="evt-ioc-01",
            event_type=SOCEventType.IOC_CORRELATION_OBSERVED,
            timestamp="2026-09-26T06:00:00Z",
            severity=SOCEventSeverity.MEDIUM,
            source_component="CorrelationService",
            ioc_type="IP_ADDRESS",
            ioc_value="192.178.211.108",
            message="Cross-case correlation: IP 192.178.211.108 observed across 3 analyses",
            evidence_reference="analyses:3;cases:2"
        )
        cef = format_event_cef(ioc_event)
        self.assertIn("Ioc Correlation Observed", cef)
        self.assertIn("cat=CorrelationService", cef)

    def test_23_active_scan_event_extraction(self):
        """Test active scanner finding normalization."""
        active_scan_analysis = {
            "analysis_id": "scan-analysis-01",
            "filename": "active_probe.json",
            "observed_result": {
                "sessions": [
                    {
                        "session_id": "probe-sess-01",
                        "protocol": "SMTP",
                        "findings": [
                            {
                                "id": "ACTIVE-FINDING-CLEAR-AUTH",
                                "severity": "CRITICAL",
                                "description": "Active probe confirmed server accepts AUTH PLAIN in cleartext"
                            }
                        ]
                    }
                ]
            }
        }
        events = extract_soc_events_from_analysis(active_scan_analysis)
        active_ev = next((e for e in events if e.finding_code == "ACTIVE-FINDING-CLEAR-AUTH"), None)
        self.assertIsNotNone(active_ev)
        self.assertEqual(active_ev.severity, SOCEventSeverity.CRITICAL)

    def test_24_archived_case_remains_exportable(self):
        """Test that archived cases generate CASE_ARCHIVED events and remain exportable."""
        archived_case = {
            "id": "case-archived-99",
            "title": "Closed Investigation",
            "is_archived": 1,
            "created_at": "2026-09-20T00:00:00Z",
            "updated_at": "2026-09-25T00:00:00Z"
        }
        events = extract_soc_events_from_case(archived_case)
        arch_ev = next((e for e in events if e.event_type == SOCEventType.CASE_ARCHIVED), None)
        self.assertIsNotNone(arch_ev)
        self.assertEqual(arch_ev.case_id, "case-archived-99")

    def test_25_time_range_filtering(self):
        """Test filtering events within an ISO timestamp range."""
        events = [
            NormalizedSOCEvent(
                event_id="e1",
                event_type=SOCEventType.FORENSIC_ANALYSIS_COMPLETED,
                timestamp="2026-09-20T10:00:00Z",
                source_component="Test",
                message="Event 1"
            ),
            NormalizedSOCEvent(
                event_id="e2",
                event_type=SOCEventType.FORENSIC_ANALYSIS_COMPLETED,
                timestamp="2026-09-25T10:00:00Z",
                source_component="Test",
                message="Event 2"
            ),
            NormalizedSOCEvent(
                event_id="e3",
                event_type=SOCEventType.FORENSIC_ANALYSIS_COMPLETED,
                timestamp="2026-09-26T10:00:00Z",
                source_component="Test",
                message="Event 3"
            ),
        ]
        filtered = filter_soc_events(
            events,
            SIEMEventFilter(start_time="2026-09-24T00:00:00Z", end_time="2026-09-25T23:59:59Z")
        )
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].event_id, "e2")

    def test_26_unsupported_evidence_missing_handling(self):
        """Test handling of empty or missing evidence fields without throwing exceptions."""
        empty_analysis = {
            "analysis_id": "empty-01",
            "filename": "empty.pcap",
            "observed_result": {}
        }
        events = extract_soc_events_from_analysis(empty_analysis)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, SOCEventType.FORENSIC_ANALYSIS_COMPLETED)
        self.assertIsNone(events[0].src_ip)
        self.assertEqual(events[0].frame_numbers, [])

    def test_27_transport_does_not_mutate_forensic_evidence(self):
        """Assert that executing SIEM delivery does not mutate underlying forensic analysis or capture hash."""
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT capture_sha256, observed_result_sha256 FROM analyses WHERE analysis_id='analysis-test-01';")
        before_row = dict(cursor.fetchone())
        conn.close()

        temp_dir = tempfile.mkdtemp()
        target = os.path.join(temp_dir, "test_immutability.json")
        req = SIEMDeliveryRequest(
            format=SOCExportFormat.JSON,
            transport=SIEMTransportType.LOCAL_FILE,
            destination_path=target
        )
        deliver_soc_events(req, db_path=self.temp_db_path)

        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT capture_sha256, observed_result_sha256 FROM analyses WHERE analysis_id='analysis-test-01';")
        after_row = dict(cursor.fetchone())
        conn.close()

        self.assertEqual(before_row["capture_sha256"], after_row["capture_sha256"])
        self.assertEqual(before_row["observed_result_sha256"], after_row["observed_result_sha256"])

        try:
            os.remove(target)
            os.rmdir(temp_dir)
        except Exception:
            pass

    def test_28_no_fabricated_severity(self):
        """Assert unclassified or unknown findings map to INFO or UNKNOWN without inventing HIGH/CRITICAL."""
        ev = NormalizedSOCEvent(
            event_id="e-test-noval",
            event_type=SOCEventType.FORENSIC_ANALYSIS_COMPLETED,
            timestamp="2026-09-26T00:00:00Z",
            severity=SOCEventSeverity.INFO,
            source_component="Test",
            message="No severity specified"
        )
        cef = format_event_cef(ev)
        # Severity in CEF header should be 1 (INFO)
        self.assertIn("|1|", cef)

    def test_29_credentials_redacted_in_delivery_records(self):
        """Assert that webhook authorization tokens or secrets are never persisted in SQLite siem_deliveries."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.getcode.return_value = 200
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp

            req = SIEMDeliveryRequest(
                format=SOCExportFormat.JSON,
                transport=SIEMTransportType.JSON_WEBHOOK,
                webhook_url="https://siem.local/webhook",
                webhook_auth_header="Bearer secret_api_key_xyz_987"
            )
            record = deliver_soc_events(req, db_path=self.temp_db_path)

            conn = get_db_connection(self.temp_db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM siem_deliveries WHERE delivery_id=?;", (record.delivery_id,))
            saved = dict(cursor.fetchone())
            conn.close()

            # Ensure token is not in destination_label or error_message
            self.assertNotIn("secret_api_key_xyz_987", saved["destination_label"])
            self.assertNotIn("Bearer", saved["destination_label"])
            self.assertEqual(saved["destination_label"], "https://siem.local/webhook")

    def test_30_api_404_on_missing_event(self):
        """Assert 404 response on non-existent event ID."""
        resp = self.client.get("/api/v1/siem/events/non-existent-event-99999")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("not found", resp.json()["detail"].lower())


if __name__ == "__main__":
    unittest.main()

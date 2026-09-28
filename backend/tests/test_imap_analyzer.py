"""
SecureMailScope X - IMAP Protocol Analysis & Forensic State Machine Tests (Phase 26)
Validates real IMAP Direct TLS (port 993) capture analysis and controlled/synthetic IMAP STARTTLS (port 143) flows.
"""

import os
import sys
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.schemas.forensic import (
    EmailSession,
    EmailProtocol,
    SecurityMode,
    STARTTLSState,
    TLSHandshakeDetails,
    TLSVersion,
    PacketEvidence
)
from app.forensic.session_reconstructor import SessionReconstructor
from app.forensic.pcap_reader import PCAPReader
from app.forensic.rule_engine import CryptographicRuleEngine
from app.forensic.anomaly_detector import TLSAnomalyDetector


class TestIMAPAnalyzer(unittest.TestCase):
    REAL_IMAP_PCAP = r"D:\SecureMailScope\pcap_samples\imap-tls-test.pcapng"

    def test_01_real_imap_direct_tls_capture(self):
        """Verify real IMAP Direct TLS capture on port 993 is identified as DIRECT_TLS with TLS 1.3."""
        if not os.path.isfile(self.REAL_IMAP_PCAP):
            self.skipTest(f"PCAP not found: {self.REAL_IMAP_PCAP}")

        reader = PCAPReader(self.REAL_IMAP_PCAP)
        packets = reader.read_packets()
        self.assertGreater(len(packets), 0)

        sessions = SessionReconstructor.reconstruct_sessions(packets)
        self.assertGreaterEqual(len(sessions), 1)

        imap_sess = next((s for s in sessions if s.protocol == EmailProtocol.IMAP), None)
        self.assertIsNotNone(imap_sess, "Must identify at least one IMAP session")
        self.assertEqual(imap_sess.server_port, 993)
        self.assertEqual(imap_sess.security_mode, SecurityMode.DIRECT_TLS)
        self.assertIsNotNone(imap_sess.tls_details)
        self.assertEqual(imap_sess.tls_details.negotiated_tls_version, TLSVersion.TLSv1_3)
        self.assertEqual(imap_sess.tls_details.selected_cipher_name, "TLS_AES_256_GCM_SHA384")

        # Must not falsely flag STARTTLS requested or advertised on Direct TLS
        self.assertFalse(imap_sess.starttls_state.advertised)
        self.assertFalse(imap_sess.starttls_state.requested)

        # Anomaly check: Nominal TLS 1.3 Direct TLS should have 0 critical/high anomalies
        anom = TLSAnomalyDetector.detect_session_anomalies(imap_sess)
        self.assertEqual(anom.total_anomalies, 0)
        self.assertEqual(anom.overall_anomaly_score, 0.0)

    def test_02_synthetic_imap_starttls_upgrade_flow(self):
        """Verify controlled synthetic IMAP STARTTLS flow on port 143: capability -> STARTTLS -> OK -> TLS."""
        st = STARTTLSState(
            advertised=True,
            advertised_frame=10,
            advertised_text="* CAPABILITY IMAP4rev1 STARTTLS",
            requested=True,
            requested_frame=12,
            requested_command="a001 STARTTLS",
            accepted=True,
            accepted_frame=14,
            accepted_response="a001 OK Begin TLS negotiation now",
            upgrade_successful=True
        )
        tls = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_cipher_name="TLS_AES_256_GCM_SHA384",
            client_hello_frame=16,
            server_hello_frame=18
        )
        sess = EmailSession(
            session_id="synth_imap_starttls_01",
            stream_index=1,
            protocol=EmailProtocol.IMAP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.100",
            client_port=54321,
            server_ip="10.0.0.1",
            server_port=143,
            start_time_epoch=1700000000.0,
            duration_seconds=1.2,
            total_packets=20,
            starttls_state=st,
            tls_details=tls,
            evidence_packets=[
                PacketEvidence(10, 1700000000.0, "", "10.0.0.1", 143, "192.168.1.100", 54321, "IMAP", 60, "CAPABILITY"),
                PacketEvidence(12, 1700000000.1, "", "192.168.1.100", 54321, "10.0.0.1", 143, "IMAP", 50, "STARTTLS"),
                PacketEvidence(14, 1700000000.2, "", "10.0.0.1", 143, "192.168.1.100", 54321, "IMAP", 50, "OK Begin TLS")
            ]
        )

        assessment = CryptographicRuleEngine.evaluate_session(sess)
        self.assertIn(assessment.grade.value, ["A", "A+"])
        self.assertEqual(sess.security_mode, SecurityMode.STARTTLS_ACCEPTED)
        self.assertTrue(sess.starttls_state.upgrade_successful)

    def test_03_synthetic_imap_plaintext_exposure(self):
        """Verify controlled synthetic unencrypted IMAP session produces Grade F and critical findings."""
        sess = EmailSession(
            session_id="synth_imap_plain_01",
            stream_index=2,
            protocol=EmailProtocol.IMAP,
            security_mode=SecurityMode.PLAINTEXT,
            client_ip="192.168.1.100",
            client_port=54322,
            server_ip="10.0.0.1",
            server_port=143,
            start_time_epoch=1700000000.0,
            duration_seconds=0.5,
            total_packets=10,
            evidence_packets=[
                PacketEvidence(1, 1700000000.0, "", "10.0.0.1", 143, "192.168.1.100", 54322, "IMAP", 60, "* OK IMAP4rev1 Ready"),
                PacketEvidence(2, 1700000000.1, "", "192.168.1.100", 54322, "10.0.0.1", 143, "IMAP", 70, "a001 LOGIN user pass")
            ]
        )

        assessment = CryptographicRuleEngine.evaluate_session(sess)
        self.assertEqual(assessment.grade.value, "F")
        self.assertTrue(any("PLAINTEXT" in f.id for f in assessment.findings))

        anom = TLSAnomalyDetector.detect_session_anomalies(sess)
        self.assertGreater(anom.total_anomalies, 0)
        self.assertEqual(anom.highest_severity, "CRITICAL")
        self.assertTrue(any(a.anomaly_id == "ANOMALY-PLAINTEXT-UNENCRYPTED" for a in anom.anomalies))


if __name__ == "__main__":
    unittest.main(verbosity=2)

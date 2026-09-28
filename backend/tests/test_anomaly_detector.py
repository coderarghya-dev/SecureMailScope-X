"""
SecureMailScope X - Explainable TLS Anomaly Detector Unit Tests (Phase 26)
Validates deterministic, evidence-bounded anomaly detection across all failure modes and security regressions.
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
    SecurityStrength,
    CipherSuiteInfo,
    CertificateVisibility,
    CertificateValidityStatus,
    CertificateDetails,
    PacketEvidence
)
from app.forensic.anomaly_detector import TLSAnomalyDetector, SessionAnomalyReport


class TestTLSAnomalyDetector(unittest.TestCase):

    def test_01_secure_tls13_normal_session(self):
        """Verify state-of-the-art TLS 1.3 session yields 0 anomalies and 0.0 anomaly score."""
        sess = EmailSession(
            session_id="secure_tls13_sess",
            stream_index=1,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.50",
            client_port=44556,
            server_ip="192.178.211.108",
            server_port=587,
            start_time_epoch=1700000000.0,
            duration_seconds=2.5,
            total_packets=30,
            starttls_state=STARTTLSState(
                advertised=True,
                advertised_frame=100,
                requested=True,
                requested_frame=102,
                accepted=True,
                accepted_frame=104,
                upgrade_successful=True
            ),
            tls_details=TLSHandshakeDetails(
                negotiated_tls_version=TLSVersion.TLSv1_3,
                selected_cipher_name="TLS_AES_256_GCM_SHA384",
                selected_cipher_code="0x1302",
                client_hello_frame=106,
                server_hello_frame=108,
                cipher_info=CipherSuiteInfo(
                    hex_code="0x1302",
                    name="TLS_AES_256_GCM_SHA384",
                    has_pfs=True,
                    key_exchange="ECDHE/KeyShare",
                    encryption="AES-256-GCM",
                    hash_algorithm="SHA384",
                    strength=SecurityStrength.STATE_OF_THE_ART,
                    is_post_quantum_safe=False
                )
            ),
            evidence_packets=[PacketEvidence(100, 1700000000.0, "", "192.178.211.108", 587, "192.168.1.50", 44556, "SMTP", 60, "EHLO")]
        )

        report = TLSAnomalyDetector.detect_session_anomalies(sess)
        self.assertEqual(report.total_anomalies, 0)
        self.assertEqual(report.overall_anomaly_score, 0.0)
        self.assertEqual(report.highest_severity, "NOMINAL")
        self.assertEqual(report.detection_method, "EXPLAINABLE_FEATURE_ANOMALY_ENGINE")

    def test_02_plaintext_session_anomaly(self):
        """Verify unencrypted cleartext session triggers CRITICAL anomaly with frame evidence."""
        sess = EmailSession(
            session_id="plain_sess_01",
            stream_index=2,
            protocol=EmailProtocol.POP3,
            security_mode=SecurityMode.PLAINTEXT,
            client_ip="192.168.1.20",
            client_port=50000,
            server_ip="10.0.0.5",
            server_port=110,
            start_time_epoch=1700000000.0,
            duration_seconds=1.0,
            total_packets=8,
            evidence_packets=[
                PacketEvidence(5, 1700000000.0, "", "10.0.0.5", 110, "192.168.1.20", 50000, "POP", 50, "+OK POP3 server ready"),
                PacketEvidence(6, 1700000000.1, "", "192.168.1.20", 50000, "10.0.0.5", 110, "POP", 60, "USER alice")
            ]
        )

        report = TLSAnomalyDetector.detect_session_anomalies(sess)
        self.assertGreaterEqual(report.total_anomalies, 1)
        self.assertEqual(report.highest_severity, "CRITICAL")
        self.assertGreaterEqual(report.overall_anomaly_score, 90.0)

        anom = next((a for a in report.anomalies if a.anomaly_id == "ANOMALY-PLAINTEXT-UNENCRYPTED"), None)
        self.assertIsNotNone(anom)
        self.assertIn(5, anom.frame_anchors)
        self.assertIn("STLS", anom.remediation)

    def test_03_starttls_unrequested_stripping_anomaly(self):
        """Verify advertised STARTTLS without client request flags potential downgrade stripping."""
        sess = EmailSession(
            session_id="strip_sess_01",
            stream_index=3,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.PLAINTEXT,
            client_ip="192.168.1.30",
            client_port=51111,
            server_ip="10.0.0.10",
            server_port=587,
            start_time_epoch=1700000000.0,
            duration_seconds=1.5,
            total_packets=12,
            starttls_state=STARTTLSState(
                advertised=True,
                advertised_frame=20,
                advertised_text="250-STARTTLS",
                requested=False
            ),
            evidence_packets=[PacketEvidence(20, 1700000000.0, "", "10.0.0.10", 587, "192.168.1.30", 51111, "SMTP", 60, "250-STARTTLS")]
        )

        report = TLSAnomalyDetector.detect_session_anomalies(sess)
        anom_ids = [a.anomaly_id for a in report.anomalies]
        self.assertIn("ANOMALY-STARTTLS-UNREQUESTED", anom_ids)
        unreq = next(a for a in report.anomalies if a.anomaly_id == "ANOMALY-STARTTLS-UNREQUESTED")
        self.assertEqual(unreq.severity, "HIGH")
        self.assertEqual(unreq.category, "DOWNGRADE_ATTACK")
        self.assertIn(20, unreq.frame_anchors)

    def test_04_starttls_rejected_anomaly(self):
        """Verify failed/rejected STARTTLS upgrade command generates protocol state anomaly."""
        sess = EmailSession(
            session_id="fail_sess_01",
            stream_index=4,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.PLAINTEXT,
            client_ip="192.168.1.40",
            client_port=52222,
            server_ip="10.0.0.15",
            server_port=587,
            start_time_epoch=1700000000.0,
            duration_seconds=1.0,
            total_packets=10,
            starttls_state=STARTTLSState(
                advertised=True,
                advertised_frame=30,
                requested=True,
                requested_frame=32,
                accepted=False,
                failed=True,
                failure_reason="454 TLS not available due to temporary reason",
                failure_frame=34
            ),
            evidence_packets=[PacketEvidence(34, 1700000000.0, "", "10.0.0.15", 587, "192.168.1.40", 52222, "SMTP", 70, "454 TLS error")]
        )

        report = TLSAnomalyDetector.detect_session_anomalies(sess)
        anom_ids = [a.anomaly_id for a in report.anomalies]
        self.assertIn("ANOMALY-STARTTLS-REJECTED", anom_ids)
        rej = next(a for a in report.anomalies if a.anomaly_id == "ANOMALY-STARTTLS-REJECTED")
        self.assertEqual(rej.severity, "HIGH")
        self.assertIn(34, rej.frame_anchors)

    def test_05_legacy_tls_version_anomaly(self):
        """Verify deprecated TLS 1.0/1.1 versions trigger DEPRECATED_PROTOCOL anomaly."""
        sess = EmailSession(
            session_id="legacy_tls_sess",
            stream_index=5,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.55",
            client_port=53333,
            server_ip="10.0.0.20",
            server_port=587,
            start_time_epoch=1700000000.0,
            duration_seconds=2.0,
            total_packets=15,
            starttls_state=STARTTLSState(advertised=True, requested=True, accepted=True, upgrade_successful=True),
            tls_details=TLSHandshakeDetails(
                negotiated_tls_version=TLSVersion.TLSv1_0,
                selected_cipher_name="TLS_RSA_WITH_AES_128_CBC_SHA",
                server_hello_frame=45
            ),
            evidence_packets=[PacketEvidence(45, 1700000000.0, "", "10.0.0.20", 587, "192.168.1.55", 53333, "TLS", 80, "Server Hello TLS 1.0")]
        )

        report = TLSAnomalyDetector.detect_session_anomalies(sess)
        anom_ids = [a.anomaly_id for a in report.anomalies]
        self.assertIn("ANOMALY-LEGACY-TLS-VERSION", anom_ids)
        leg = next(a for a in report.anomalies if a.anomaly_id == "ANOMALY-LEGACY-TLS-VERSION")
        self.assertEqual(leg.severity, "HIGH")
        self.assertIn("RFC 8996", leg.explanation)
        self.assertIn(45, leg.frame_anchors)

    def test_06_weak_cipher_and_static_rsa_anomaly(self):
        """Verify 3DES and non-PFS static RSA ciphers trigger WEAK_CRYPTOGRAPHY anomaly."""
        sess = EmailSession(
            session_id="weak_cipher_sess",
            stream_index=6,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.60",
            client_port=54444,
            server_ip="10.0.0.25",
            server_port=587,
            start_time_epoch=1700000000.0,
            duration_seconds=1.8,
            total_packets=18,
            starttls_state=STARTTLSState(advertised=True, requested=True, accepted=True, upgrade_successful=True),
            tls_details=TLSHandshakeDetails(
                negotiated_tls_version=TLSVersion.TLSv1_2,
                selected_cipher_name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                server_hello_frame=50,
                cipher_info=CipherSuiteInfo(
                    hex_code="0x000A",
                    name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                    has_pfs=False,
                    key_exchange="RSA",
                    encryption="3DES-CBC",
                    hash_algorithm="SHA1",
                    strength=SecurityStrength.INSECURE,
                    is_post_quantum_safe=False
                )
            ),
            evidence_packets=[PacketEvidence(50, 1700000000.0, "", "10.0.0.25", 587, "192.168.1.60", 54444, "TLS", 90, "Server Hello 3DES")]
        )

        report = TLSAnomalyDetector.detect_session_anomalies(sess)
        anom_ids = [a.anomaly_id for a in report.anomalies]
        self.assertIn("ANOMALY-WEAK-CIPHER-SUITE", anom_ids)
        weak = next(a for a in report.anomalies if a.anomaly_id == "ANOMALY-WEAK-CIPHER-SUITE")
        self.assertEqual(weak.severity, "HIGH")
        self.assertIn("3DES", weak.title)

    def test_07_certificate_anomalies(self):
        """Verify expired certificate, weak RSA (<2048 bits), and weak signature algorithm trigger anomalies."""
        cert = CertificateDetails(
            visibility=CertificateVisibility.OBSERVABLE,
            frame_number=60,
            subject="CN=expired.example.com",
            issuer="CN=Old CA",
            not_before="2020-01-01T00:00:00Z",
            not_after="2021-01-01T00:00:00Z",
            validity_status=CertificateValidityStatus.EXPIRED,
            public_key_algorithm="RSA",
            public_key_bits=1024,
            signature_algorithm="md5WithRSAEncryption",
            certificate_fingerprint_sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        )
        sess = EmailSession(
            session_id="cert_anom_sess",
            stream_index=7,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.70",
            client_port=55555,
            server_ip="10.0.0.30",
            server_port=587,
            start_time_epoch=1700000000.0,
            duration_seconds=2.0,
            total_packets=20,
            starttls_state=STARTTLSState(advertised=True, requested=True, accepted=True, upgrade_successful=True),
            tls_details=TLSHandshakeDetails(
                negotiated_tls_version=TLSVersion.TLSv1_2,
                selected_cipher_name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                server_hello_frame=58,
                certificate_details=cert
            ),
            evidence_packets=[PacketEvidence(60, 1700000000.0, "", "10.0.0.30", 587, "192.168.1.70", 55555, "TLS", 800, "Certificate Handshake")]
        )

        report = TLSAnomalyDetector.detect_session_anomalies(sess)
        anom_ids = [a.anomaly_id for a in report.anomalies]
        self.assertIn("ANOMALY-CERTIFICATE-EXPIRED", anom_ids)
        self.assertIn("ANOMALY-CERTIFICATE-WEAK-RSA", anom_ids)
        self.assertIn("ANOMALY-CERTIFICATE-WEAK-SIGNATURE", anom_ids)

    def test_08_implicit_tls_port_cleartext_incongruity(self):
        """Verify unencrypted traffic on dedicated direct TLS port 993/995/465 triggers PORT_INCONGRUITY anomaly."""
        sess = EmailSession(
            session_id="implicit_port_plain_sess",
            stream_index=8,
            protocol=EmailProtocol.IMAP,
            security_mode=SecurityMode.PLAINTEXT,
            client_ip="192.168.1.80",
            client_port=56666,
            server_ip="10.0.0.35",
            server_port=993,
            start_time_epoch=1700000000.0,
            duration_seconds=1.0,
            total_packets=10,
            evidence_packets=[PacketEvidence(70, 1700000000.0, "", "10.0.0.35", 993, "192.168.1.80", 56666, "IMAP", 60, "* OK Cleartext on port 993")]
        )

        report = TLSAnomalyDetector.detect_session_anomalies(sess)
        anom_ids = [a.anomaly_id for a in report.anomalies]
        self.assertIn("ANOMALY-IMPLICIT-PORT-CLEARTEXT", anom_ids)
        inc = next(a for a in report.anomalies if a.anomaly_id == "ANOMALY-IMPLICIT-PORT-CLEARTEXT")
        self.assertEqual(inc.severity, "CRITICAL")
        self.assertEqual(inc.category, "PORT_INCONGRUITY")


if __name__ == "__main__":
    unittest.main(verbosity=2)

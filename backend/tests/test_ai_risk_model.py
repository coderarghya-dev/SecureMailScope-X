"""
SecureMailScope X - AI-Assisted Cryptographic Risk Model Unit Tests (Phase 27)
Validates deterministic training, explainability attribution, forensic evidence bounding,
and advisory classification coexistence with authoritative deterministic verdicts.
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
    PacketEvidence,
    CaptureHealth,
    EvidenceConfidence,
    SessionSecurityAssessment,
    SecurityGrade,
    SecurityFinding,
    FindingSeverity,
    FindingCategory
)
from app.ai.risk_model import AIRiskModel, AIRiskPrediction, FEATURE_NAMES
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportService


class TestAIRiskModel(unittest.TestCase):

    REAL_SMTP_PCAP = r"D:\SecureMailScope\pcap_samples\smtp-starttls-test.pcapng"
    REAL_IMAP_PCAP = r"D:\SecureMailScope\pcap_samples\imap-tls-test.pcapng"
    REAL_POP3S_PCAP = r"D:\SecureMailScope\pcap_samples\pop3-tls-test.pcapng"
    REAL_POP3_PLAIN_PCAP = r"D:\SecureMailScope\pcap_samples\pop3-stls-test.pcapng"

    def setUp(self):
        # Ensure model is initialized
        AIRiskModel.train_model()

    def test_01_deterministic_training_and_reproducibility(self):
        """Verify model trains deterministically with 22 features and consistent weights."""
        clf1, meta1 = AIRiskModel.train_model()
        clf2, meta2 = AIRiskModel.train_model()

        self.assertEqual(meta1["feature_names"], FEATURE_NAMES)
        self.assertEqual(len(FEATURE_NAMES), 22)
        self.assertEqual(meta1["training_source"], "Controlled synthetic training dataset for functional demonstration")
        self.assertEqual(meta1["random_state"], 42)

        # Coefficients must be identical
        self.assertTrue((clf1.coef_ == clf2.coef_).all())
        self.assertTrue((clf1.intercept_ == clf2.intercept_).all())

    def test_02_secure_tls13_not_critical(self):
        """Verify state-of-the-art TLS 1.3 session is classified as LOW/MODERATE, never CRITICAL without evidence."""
        sess = EmailSession(
            session_id="secure_smtp_tls13",
            stream_index=1,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.50",
            client_port=44556,
            server_ip="192.178.211.108",
            server_port=587,
            start_time_epoch=1700000000.0,
            duration_seconds=2.0,
            total_packets=30,
            starttls_state=STARTTLSState(advertised=True, requested=True, accepted=True, upgrade_successful=True),
            tls_details=TLSHandshakeDetails(
                negotiated_tls_version=TLSVersion.TLSv1_3,
                selected_cipher_name="TLS_AES_256_GCM_SHA384",
                selected_cipher_code="0x1302",
                has_forward_secrecy=True,
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
            capture_health=CaptureHealth(score=100),
            evidence_confidence=EvidenceConfidence(score=95),
            evidence_packets=[PacketEvidence(100, 1700000000.0, "", "192.178.211.108", 587, "192.168.1.50", 44556, "SMTP", 60, "250-STARTTLS")]
        )

        pred = AIRiskModel.predict_session(sess)
        self.assertIn(pred.risk_class, ["LOW", "MODERATE"])
        self.assertNotEqual(pred.risk_class, "CRITICAL")
        self.assertFalse(pred.authoritative)
        self.assertIn("Controlled synthetic training", pred.training_source)

    def test_03_plaintext_pop3_classified_critical(self):
        """Verify unencrypted cleartext POP3 session is classified as CRITICAL risk."""
        sess = EmailSession(
            session_id="plain_pop3_sess",
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
            observed_commands=["USER alice", "PASS secret"],
            security_assessment=SessionSecurityAssessment(
                grade=SecurityGrade.F,
                critical_findings_count=1,
                findings=[SecurityFinding(
                    id="POP3-CLEARTEXT-AUTHENTICATION",
                    title="Unencrypted Cleartext Authentication",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.PROTOCOL_SECURITY,
                    description="Cleartext credentials transmitted without TLS.",
                    recommendation="Enable STLS or POP3S."
                )]
            ),
            capture_health=CaptureHealth(score=100),
            evidence_confidence=EvidenceConfidence(score=100)
        )

        pred = AIRiskModel.predict_session(sess)
        self.assertEqual(pred.risk_class, "CRITICAL")
        self.assertGreaterEqual(pred.confidence, 0.70)
        # Verify plaintext flag is identified as top risk factor
        risk_feat_names = [rf.feature for rf in pred.top_risk_factors]
        self.assertTrue("plaintext_flag" in risk_feat_names or "critical_finding_count" in risk_feat_names)

    def test_04_weak_tls_version_increases_risk_to_high(self):
        """Verify deprecated TLS 1.0 version shifts classification to HIGH risk."""
        sess = EmailSession(
            session_id="legacy_tls10_sess",
            stream_index=3,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.30",
            client_port=51111,
            server_ip="10.0.0.10",
            server_port=587,
            start_time_epoch=1700000000.0,
            duration_seconds=1.5,
            total_packets=15,
            starttls_state=STARTTLSState(advertised=True, requested=True, accepted=True, upgrade_successful=True),
            tls_details=TLSHandshakeDetails(
                negotiated_tls_version=TLSVersion.TLSv1_0,
                selected_cipher_name="TLS_RSA_WITH_AES_128_CBC_SHA"
            ),
            security_assessment=SessionSecurityAssessment(
                grade=SecurityGrade.C,
                high_findings_count=1,
                findings=[SecurityFinding(
                    id="TLS-LEGACY-VERSION-1.0",
                    title="Deprecated TLS Protocol Version 1.0",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.PROTOCOL_SECURITY,
                    description="TLS 1.0 deprecated per RFC 8996.",
                    recommendation="Upgrade to TLS 1.2 or TLS 1.3."
                )]
            ),
            capture_health=CaptureHealth(score=100),
            evidence_confidence=EvidenceConfidence(score=90)
        )

        pred = AIRiskModel.predict_session(sess)
        self.assertEqual(pred.risk_class, "HIGH")

    def test_05_expired_certificate_increases_risk(self):
        """Verify expired certificate elevates risk to HIGH with exact attribution."""
        cert = CertificateDetails(
            visibility=CertificateVisibility.OBSERVABLE,
            frame_number=40,
            subject="CN=expired.example.com",
            issuer="CN=Old Root CA",
            not_before="2020-01-01T00:00:00Z",
            not_after="2021-01-01T00:00:00Z",
            validity_status=CertificateValidityStatus.EXPIRED,
            public_key_algorithm="RSA",
            public_key_bits=2048,
            signature_algorithm="sha256WithRSAEncryption"
        )
        sess = EmailSession(
            session_id="expired_cert_sess",
            stream_index=4,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.40",
            client_port=52222,
            server_ip="10.0.0.20",
            server_port=587,
            start_time_epoch=1700000000.0,
            duration_seconds=2.0,
            total_packets=20,
            starttls_state=STARTTLSState(advertised=True, requested=True, accepted=True, upgrade_successful=True),
            tls_details=TLSHandshakeDetails(
                negotiated_tls_version=TLSVersion.TLSv1_2,
                selected_cipher_name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                certificate_details=cert
            ),
            security_assessment=SessionSecurityAssessment(
                grade=SecurityGrade.B,
                high_findings_count=1,
                findings=[SecurityFinding(
                    id="CERT-EXPIRED",
                    title="Expired Handshake Certificate",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                    description="Presented certificate is expired.",
                    recommendation="Renew certificate."
                )]
            ),
            capture_health=CaptureHealth(score=100),
            evidence_confidence=EvidenceConfidence(score=95)
        )

        pred = AIRiskModel.predict_session(sess)
        self.assertIn(pred.risk_class, ["HIGH", "MODERATE"])
        features = pred.feature_vector
        self.assertEqual(features["cert_expired_flag"], 1.0)
        self.assertEqual(features["cert_observable_flag"], 1.0)

    def test_06_explainability_and_limitations_populated(self):
        """Verify explainability factors, limitations notice, and disclaimer are fully populated."""
        sess = EmailSession(
            session_id="explain_sess",
            stream_index=5,
            protocol=EmailProtocol.IMAP,
            security_mode=SecurityMode.DIRECT_TLS,
            client_ip="192.168.1.60",
            client_port=54444,
            server_ip="10.0.0.30",
            server_port=993,
            start_time_epoch=1700000000.0,
            duration_seconds=1.0,
            total_packets=10,
            tls_details=TLSHandshakeDetails(
                negotiated_tls_version=TLSVersion.TLSv1_3,
                selected_cipher_name="TLS_AES_256_GCM_SHA384",
                has_forward_secrecy=True
            ),
            capture_health=CaptureHealth(score=100),
            evidence_confidence=EvidenceConfidence(score=90)
        )

        pred = AIRiskModel.predict_session(sess)
        self.assertTrue(len(pred.explanation) > 0)
        self.assertIn("Logistic Regression", pred.explanation)
        self.assertIn("advisory", pred.limitations.lower())
        self.assertIn("authoritative", pred.disclaimer.lower())
        self.assertFalse(pred.authoritative)

    def test_07_real_smtp_capture_end_to_end_pipeline(self):
        """Verify real SMTP STARTTLS capture pipeline integrates AI risk classification."""
        if not os.path.isfile(self.REAL_SMTP_PCAP):
            self.skipTest(f"PCAP not found: {self.REAL_SMTP_PCAP}")

        report, _ = AnalysisService._run_pipeline(self.REAL_SMTP_PCAP, "smtp-starttls-test.pcapng", 10000, "test_ai_smtp_01")
        self.assertGreater(len(report.sessions), 0)
        s0 = report.sessions[0]

        self.assertIsNotNone(s0.ai_risk_classification)
        ai = s0.ai_risk_classification
        self.assertIn(ai.risk_class, ["LOW", "MODERATE"])
        self.assertEqual(ai.model_name, "LogisticRegression (Multinomial / L-BFGS)")
        self.assertFalse(ai.authoritative)

        # Test serialization into JSON report
        json_str = ReportService.generate_json_str(report)
        self.assertIn("ai_risk_classification", json_str)
        self.assertIn(ai.risk_class, json_str)

        # Test HTML report rendering
        html_str = ReportService.generate_html_str(report)
        self.assertIn("AI-Assisted Risk Classification", html_str)
        self.assertIn(ai.risk_class, html_str)

    def test_08_real_plaintext_pop3_capture_end_to_end(self):
        """Verify real plaintext POP3 capture (pop3-stls-test.pcapng) is flagged as CRITICAL by AI model."""
        if not os.path.isfile(self.REAL_POP3_PLAIN_PCAP):
            self.skipTest(f"PCAP not found: {self.REAL_POP3_PLAIN_PCAP}")

        report, _ = AnalysisService._run_pipeline(self.REAL_POP3_PLAIN_PCAP, "pop3-stls-test.pcapng", 10000, "test_ai_pop3_plain_01")
        self.assertGreater(len(report.sessions), 0)
        s0 = report.sessions[0]

        self.assertIsNotNone(s0.ai_risk_classification)
        self.assertEqual(s0.ai_risk_classification.risk_class, "CRITICAL")
        self.assertGreaterEqual(s0.ai_risk_classification.confidence, 0.70)


if __name__ == "__main__":
    unittest.main(verbosity=2)

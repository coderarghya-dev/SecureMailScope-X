import os
import sys
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.schemas.forensic import (
    EmailSession, EmailProtocol, SecurityMode, TLSHandshakeDetails,
    TLSVersion, CipherSuiteInfo, SecurityStrength, CaptureHealth, EvidenceConfidence
)
from app.ml.risk_classifier import MLRiskClassifier


class TestMLTriage(unittest.TestCase):

    def _create_base_session(self) -> EmailSession:
        return EmailSession(
            session_id="stream_0_127.0.0.1_1000_127.0.0.1_25",
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="127.0.0.1",
            client_port=1000,
            server_ip="127.0.0.1",
            server_port=25,
            capture_health=CaptureHealth(score=100),
            evidence_confidence=EvidenceConfidence(score=95),
        )

    def test_01_plaintext_session_ml_triage_critical(self):
        """Plaintext session is triaged as CRITICAL with plaintext risk contributor."""
        session = self._create_base_session()
        session.security_mode = SecurityMode.PLAINTEXT
        session.observed_commands = [{"command": "AUTH LOGIN", "frame": 5}]

        triage = MLRiskClassifier.classify_session(session)
        self.assertIn(triage["advisory_risk_class"], ["CRITICAL", "HIGH"])
        self.assertGreater(triage["model_confidence"], 0.5)
        self.assertIn("Experimental ML triage model", triage["disclaimer"])
        self.assertTrue(any(c["feature"] == "has_plaintext_exposure" for c in triage["top_risk_contributors"]))

    def test_02_tls13_pqc_session_ml_triage_low(self):
        """TLS 1.3 with PQC is triaged as LOW risk with protective factors."""
        session = self._create_base_session()
        session.tls_details = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_group="X25519MLKEM768",
            cipher_info=CipherSuiteInfo(
                hex_code="0x1302",
                name="TLS_AES_256_GCM_SHA384",
                has_pfs=True,
                key_exchange="ML-KEM Hybrid",
                encryption="AES-256-GCM",
                hash_algorithm="SHA-384",
                strength=SecurityStrength.STATE_OF_THE_ART,
                is_post_quantum_safe=True,
            ),
            has_forward_secrecy=True,
        )

        triage = MLRiskClassifier.classify_session(session)
        self.assertEqual(triage["advisory_risk_class"], "LOW")
        self.assertTrue(len(triage["top_protective_factors"]) > 0)

    def test_03_xai_output_structure(self):
        """XAI explanation contains required attributes."""
        session = self._create_base_session()
        triage = MLRiskClassifier.classify_session(session)
        self.assertIn("features", triage)
        self.assertIn("top_risk_contributors", triage)
        self.assertIn("top_protective_factors", triage)
        self.assertIn("model_version", triage)


if __name__ == "__main__":
    unittest.main()

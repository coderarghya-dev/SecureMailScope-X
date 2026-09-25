"""
SecureMailScope X - ML-Assisted Risk Triage Service Tests
Phase 4.5 Validity & Explainability Audit Verification Suite.
Validates exact probability indexing, counterfactual perturbation XAI,
fallback mode truthfulness, and deterministic engine isolation.
"""

import os
import sys
import unittest
import json

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.schemas.forensic import (
    EmailSession,
    EmailProtocol,
    SecurityMode,
    TLSHandshakeDetails,
    TLSVersion,
    CipherSuiteInfo,
    SecurityStrength,
    CaptureHealth,
    EvidenceConfidence,
    SecurityGrade
)
from app.ml.risk_classifier import MLRiskClassifier, MODEL_METADATA_FILE
from app.ml.feature_extractor import MLFeatureExtractor, FEATURE_NAMES
from app.forensic.rule_engine import CryptographicRuleEngine
from app.forensic.pcap_reader import PCAPReader
from app.forensic.session_reconstructor import SessionReconstructor


class TestMLTriage(unittest.TestCase):
    SMTP_PCAP = r"D:\SecureMailScope\pcap_samples\smtp-starttls-test.pcapng"

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

    def test_01_risk_probability_matches_predicted_class_and_classes_array(self):
        """A. Returned probability matches exactly the probability of the returned class in model.classes_."""
        session = self._create_base_session()
        triage = MLRiskClassifier.classify_session(session)

        self.assertIn("class_probabilities", triage)
        pred_class = triage["advisory_risk_class"]
        risk_prob = triage["risk_probability"]

        # The selected probability must equal the class probability of the predicted class
        self.assertEqual(round(risk_prob, 4), round(triage["class_probabilities"][pred_class], 4))
        self.assertEqual(risk_prob, max(triage["class_probabilities"].values()))

    def test_02_deterministic_feature_reproducibility(self):
        """B. Identical structured forensic features yield strictly identical output."""
        session1 = self._create_base_session()
        session2 = self._create_base_session()

        t1 = MLRiskClassifier.classify_session(session1)
        t2 = MLRiskClassifier.classify_session(session2)

        self.assertEqual(t1["advisory_risk_class"], t2["advisory_risk_class"])
        self.assertEqual(t1["risk_probability"], t2["risk_probability"])
        self.assertEqual(t1["feature_vector"], t2["feature_vector"])
        self.assertEqual(t1["class_probabilities"], t2["class_probabilities"])

    def test_03_metadata_changes_do_not_affect_predictions(self):
        """C. Changes to IP, port, session_id, or frame timestamps do NOT change feature vector or ML prediction."""
        session1 = EmailSession(
            session_id="stream_0_10.0.0.1_1234_10.0.0.2_587",
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="10.0.0.1",
            client_port=1234,
            server_ip="10.0.0.2",
            server_port=587,
            capture_health=CaptureHealth(score=100),
            evidence_confidence=EvidenceConfidence(score=80)
        )
        session2 = EmailSession(
            session_id="stream_99_192.168.100.5_9999_192.168.100.6_587",
            stream_index=99,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.100.5",
            client_port=9999,
            server_ip="192.168.100.6",
            server_port=587,
            capture_health=CaptureHealth(score=100),
            evidence_confidence=EvidenceConfidence(score=80)
        )

        vec1 = MLFeatureExtractor.extract_features(session1)
        vec2 = MLFeatureExtractor.extract_features(session2)
        self.assertEqual(vec1, vec2)

        t1 = MLRiskClassifier.classify_session(session1)
        t2 = MLRiskClassifier.classify_session(session2)
        self.assertEqual(t1["advisory_risk_class"], t2["advisory_risk_class"])
        self.assertEqual(t1["risk_probability"], t2["risk_probability"])

    def test_04_fallback_mode_truthfulness(self):
        """D. Fallback mode cannot masquerade as ML_MODEL; explicitly identifies RuleBasedFallback."""
        features = {
            "tls_version_ord": -1.0,
            "cipher_strength_ord": -1.0,
            "security_mode_ord": 0.0,
            "has_forward_secrecy": 0.0,
            "has_post_quantum": 0.5,
            "has_plaintext_exposure": 1.0,
            "capture_confidence": 1.0,
            "capture_health": 1.0
        }
        fallback_resp = MLRiskClassifier._deterministic_fallback_response(features)
        self.assertEqual(fallback_resp["inference_mode"], "DETERMINISTIC_FALLBACK")
        self.assertEqual(fallback_resp["model_type"], "RuleBasedFallback")
        self.assertEqual(fallback_resp["explanation_method"], "DETERMINISTIC_FALLBACK_RULES")
        self.assertIn("Fallback rule-based triage", fallback_resp["disclaimer"])

    def test_05_explanation_method_truthfulness_and_no_fake_shap(self):
        """E & F. Explanation truthfully identifies ONE_FEATURE_PERTURBATION and does not claim SHAP."""
        session = self._create_base_session()
        triage = MLRiskClassifier.classify_session(session)

        self.assertEqual(triage["explanation_method"], "ONE_FEATURE_PERTURBATION")
        self.assertNotIn("SHAP", triage["explanation_method"])
        self.assertIn("Not Shapley / SHAP", triage["explanation_disclaimer"])
        self.assertIn("top_risk_contributors", triage)
        self.assertIn("top_protective_factors", triage)

    def test_06_missing_evidence_preserves_uncertainty(self):
        """G. Missing handshake evidence yields neutral feature values (0.5) without fabricating certainty."""
        session = self._create_base_session()
        session.tls_details = None
        session.security_mode = SecurityMode.STARTTLS_REQUESTED

        features = MLFeatureExtractor.extract_features(session)
        self.assertEqual(features["has_forward_secrecy"], 0.5)
        self.assertEqual(features["has_post_quantum"], 0.5)

    def test_07_ml_output_never_mutates_deterministic_state(self):
        """H. ML inference never mutates SecurityGrade, findings, Confidence, PFS, or PQC status."""
        session = self._create_base_session()
        session.tls_details = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            cipher_info=CipherSuiteInfo(
                hex_code="0x1302",
                name="TLS_AES_256_GCM_SHA384",
                key_exchange="Key Share (TLS 1.3)",
                encryption="AES-256-GCM",
                hash_algorithm="SHA-384",
                strength=SecurityStrength.STATE_OF_THE_ART,
                has_pfs=None
            )
        )

        det_before = CryptographicRuleEngine.evaluate_session(session)
        triage = MLRiskClassifier.classify_session(session)
        self.assertIsNotNone(triage)
        det_after = CryptographicRuleEngine.evaluate_session(session)

        self.assertEqual(det_after.grade, det_before.grade)
        self.assertEqual([f.id for f in det_after.findings], [f.id for f in det_before.findings])
        self.assertEqual(det_after.post_quantum_ready, det_before.post_quantum_ready)

    def test_08_training_metadata_explicitly_marks_synthetic_engineering_data(self):
        """J. Model metadata JSON explicitly declares synthetic engineering validation data."""
        self.assertTrue(os.path.exists(MODEL_METADATA_FILE), f"Metadata file must exist at {MODEL_METADATA_FILE}")
        with open(MODEL_METADATA_FILE, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.assertEqual(meta["model_version"], "v1.0.0")
        self.assertEqual(meta["random_state"], 42)
        self.assertEqual(meta["feature_names"], FEATURE_NAMES)
        self.assertIn("Synthetic validation dataset", meta["dataset_type"])
        self.assertIn("Engineering self-check only", meta["evaluation_metrics_disclaimer"])
        self.assertEqual(meta["class_distribution"], {"LOW": 6, "MEDIUM": 6, "HIGH": 6, "CRITICAL": 6})

    def test_09_real_smtp_capture_preserves_deterministic_posture(self):
        """Real Gmail capture ML inference preserves Security Grade A, Confidence 80, and PFS state."""
        if not os.path.exists(self.SMTP_PCAP):
            self.skipTest(f"PCAP not found: {self.SMTP_PCAP}")

        reader = PCAPReader(self.SMTP_PCAP)
        raw_packets = reader.read_packets()
        sessions = SessionReconstructor.reconstruct_sessions(raw_packets)
        self.assertEqual(len(sessions), 1)
        s = sessions[0]

        # Verify deterministic baseline
        self.assertEqual(s.security_assessment.grade, SecurityGrade.A)
        self.assertEqual(s.evidence_confidence.score, 80)
        self.assertIsNone(s.tls_details.has_forward_secrecy)

        # Run ML triage
        triage = MLRiskClassifier.classify_session(s)
        self.assertIn(triage["advisory_risk_class"], ["LOW", "MEDIUM"])
        self.assertFalse(triage["authoritative"])
        self.assertEqual(triage["inference_mode"], "ML_MODEL")

        # Deterministic assessment is unchanged
        self.assertEqual(s.security_assessment.grade, SecurityGrade.A)
        self.assertEqual(s.evidence_confidence.score, 80)
        self.assertIsNone(s.tls_details.has_forward_secrecy)


if __name__ == "__main__":
    unittest.main()

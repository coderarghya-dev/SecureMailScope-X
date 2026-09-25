import os
import sys
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.schemas.forensic import (
    EmailSession, EmailProtocol, SecurityMode, PacketEvidence, TLSHandshakeDetails, TLSVersion
)
from app.forensic.incident_correlator import IncidentCorrelator
from app.services.case_service import CaseService
from app.security.report_signer import ReportSigner
from app.security.notarization import NotarizationService, ExternalLedgerProvider


class TestAdvancedPhases(unittest.TestCase):

    def test_01_incident_correlation_repeated_plaintext(self):
        s1 = EmailSession(
            session_id="s1", stream_index=0, protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.PLAINTEXT, client_ip="10.0.0.1", client_port=5001,
            server_ip="192.168.1.10", server_port=25,
            evidence_packets=[PacketEvidence(1, 0.0, "", "10.0.0.1", 5001, "192.168.1.10", 25, "SMTP", 100, "")]
        )
        s2 = EmailSession(
            session_id="s2", stream_index=1, protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.PLAINTEXT, client_ip="10.0.0.2", client_port=5002,
            server_ip="192.168.1.10", server_port=25,
            evidence_packets=[PacketEvidence(10, 0.0, "", "10.0.0.2", 5002, "192.168.1.10", 25, "SMTP", 100, "")]
        )

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].incident_id, "INCIDENT-REPEATED-PLAINTEXT")
        self.assertEqual(incidents[0].severity, "CRITICAL")
        self.assertIn("s1", incidents[0].related_session_ids)
        self.assertIn("s2", incidents[0].related_session_ids)

    def test_02_case_service_crud_and_artifacts(self):
        case = CaseService.create_case(
            title="Investigate Phishing Incident #104",
            description="Analysis of captured SMTP streams",
            analyst_name="Special Agent Smith",
        )
        self.assertTrue(case.id.startswith("CASE-"))
        self.assertEqual(case.status, "OPEN")

        # Add artifact
        updated = CaseService.add_artifact_to_case(
            case_id=case.id,
            artifact_type="PCAP",
            filename="smtp_capture.pcap",
            sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            analysis_id="an_12345",
        )
        self.assertIsNotNone(updated)
        self.assertEqual(len(updated["artifacts"]), 1)
        self.assertIn("an_12345", updated["analysis_ids"])

        # Add note
        with_note = CaseService.add_note_to_case(
            case_id=case.id,
            author="Special Agent Smith",
            note_text="Primary suspect IP identified on port 25.",
        )
        self.assertEqual(len(with_note["analyst_notes"]), 1)

    def test_03_digital_report_signature_and_verification(self):
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        sig_result = ReportSigner.sign_hash(test_hash, analyst_name="Forensic Investigator")
        self.assertEqual(sig_result["signature_status"], "VALID_LOCAL_SIGNATURE")
        self.assertIn("RSA-PSS-2048", sig_result["algorithm"])

        # Verify signature
        is_valid = ReportSigner.verify_signature(
            sha256_hex=test_hash,
            signature_hex=sig_result["signature_hex"],
            public_key_pem=sig_result["public_key_pem"],
        )
        self.assertTrue(is_valid)

        # Tampered hash must fail verification
        tampered_hash = "f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertFalse(ReportSigner.verify_signature(
            sha256_hex=tampered_hash,
            signature_hex=sig_result["signature_hex"],
            public_key_pem=sig_result["public_key_pem"],
        ))

    def test_04_notarization_provider_not_configured_boundary(self):
        # Default local only
        proof = NotarizationService.notarize("abcdef1234567890")
        self.assertEqual(proof.status, "LOCAL_SEALED")

        # External unconfigured
        NotarizationService.set_provider(ExternalLedgerProvider())
        ext_proof = NotarizationService.notarize("abcdef1234567890")
        self.assertEqual(ext_proof.status, "NOT_CONFIGURED")
        self.assertIn("Not Configured", ext_proof.proof_details)


if __name__ == "__main__":
    unittest.main()

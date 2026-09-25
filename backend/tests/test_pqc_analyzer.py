import os
import sys
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.schemas.forensic import (
    EmailSession, EmailProtocol, SecurityMode, TLSHandshakeDetails,
    TLSVersion, CipherSuiteInfo, SecurityStrength
)
from app.forensic.pqc_analyzer import (
    PQCAnalyzer, PQCStatus, HNDLStatus
)


class TestPQCAnalyzer(unittest.TestCase):

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
        )

    def test_01_hybrid_x25519_mlkem768(self):
        """Observable X25519MLKEM768 group yields HYBRID_OBSERVED and LOW HNDL risk."""
        session = self._create_base_session()
        session.tls_details = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_group="X25519MLKEM768",
            server_hello_frame=15,
        )
        result = PQCAnalyzer.analyze_session(session)
        self.assertEqual(result.pqc_status, PQCStatus.HYBRID_OBSERVED)
        self.assertEqual(result.hndl_status, HNDLStatus.LOW)
        self.assertTrue(result.is_hybrid)
        self.assertEqual(result.evidence_frames, [15])

    def test_02_pure_kyber768(self):
        """Observable standalone Kyber768 group yields PQC_PROTECTED and LOW HNDL risk."""
        session = self._create_base_session()
        session.tls_details = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_group="Kyber768",
            server_hello_frame=20,
        )
        result = PQCAnalyzer.analyze_session(session)
        self.assertEqual(result.pqc_status, PQCStatus.PQC_PROTECTED)
        self.assertEqual(result.hndl_status, HNDLStatus.LOW)
        self.assertFalse(result.is_hybrid)

    def test_03_classical_x25519_only(self):
        """Observable classical X25519 key exchange yields CLASSICAL_ONLY and HIGH HNDL risk."""
        session = self._create_base_session()
        session.tls_details = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_group="x25519",
            cipher_info=CipherSuiteInfo(
                hex_code="0x1302",
                name="TLS_AES_256_GCM_SHA384",
                has_pfs=False,
                key_exchange="TLS 1.3 Key Share",
                encryption="AES-256-GCM",
                hash_algorithm="SHA-384",
                strength=SecurityStrength.STATE_OF_THE_ART,
            ),
            server_hello_frame=10,
        )
        result = PQCAnalyzer.analyze_session(session)
        self.assertEqual(result.pqc_status, PQCStatus.CLASSICAL_ONLY)
        self.assertEqual(result.hndl_status, HNDLStatus.HIGH)
        self.assertIn("x25519", result.summary)

    def test_04_unobserved_tls_details_incomplete(self):
        """Session with unobserved TLS handshake yields ASSESSMENT_INCOMPLETE."""
        session = self._create_base_session()
        session.security_mode = SecurityMode.PLAINTEXT
        result = PQCAnalyzer.analyze_session(session)
        self.assertEqual(result.pqc_status, PQCStatus.ASSESSMENT_INCOMPLETE)
        self.assertEqual(result.hndl_status, HNDLStatus.INCOMPLETE)


if __name__ == "__main__":
    unittest.main()

"""
SecureMailScope X - Post-Quantum Cryptography (PQC) & HNDL Analyzer Tests
Validates evidence-bounded PQC readiness and Harvest Now, Decrypt Later (HNDL) exposure assessments
against authoritative IANA TLS Supported Groups registry values.
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
    TLSHandshakeDetails,
    TLSVersion,
    CipherSuiteInfo,
    SecurityStrength,
    SecurityGrade
)
from app.forensic.pqc_analyzer import (
    PQCAnalyzer,
    PQCStatus,
    HNDLStatus,
    lookup_named_group
)
from app.forensic.rule_engine import CryptographicRuleEngine


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
        """Observable X25519MLKEM768 (0x11EC) yields HYBRID_OBSERVED and mitigated HNDL risk."""
        session = self._create_base_session()
        session.tls_details = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_group="0x11ec",
            server_hello_frame=15,
            client_hello_frame=11,
            has_forward_secrecy=True,
            pfs_status="Yes (Observable key_share: X25519MLKEM768)"
        )
        result = PQCAnalyzer.analyze_session(session)
        self.assertEqual(result.pqc_status, PQCStatus.HYBRID_OBSERVED)
        self.assertTrue(result.pqc_ready)
        self.assertTrue(result.hybrid_observed)
        self.assertTrue(result.is_hybrid)
        self.assertEqual(result.hndl_status, HNDLStatus.MITIGATED_BY_OBSERVED_HYBRID)
        self.assertIn(15, result.evidence_frames)
        self.assertIn(11, result.evidence_frames)
        self.assertIn("X25519MLKEM768", result.evidence_summary)

        # Rule engine evaluation should award Grade A+
        sec = CryptographicRuleEngine.evaluate_session(session)
        self.assertEqual(sec.grade, SecurityGrade.A_PLUS)
        self.assertTrue(sec.post_quantum_ready)
        self.assertTrue(any(f.id == "FINDING-PQC-HYBRID-VERIFIED" for f in sec.findings))

    def test_02_iana_hybrid_groups_resolution(self):
        """Authoritative IANA hybrid groups resolve correctly to their exact standardized definitions."""
        # 4587 / 0x11EB = SecP256r1MLKEM768
        g_11eb = lookup_named_group("0x11eb")
        self.assertIsNotNone(g_11eb)
        self.assertEqual(g_11eb.name, "SecP256r1MLKEM768")
        self.assertTrue(g_11eb.is_standard)
        self.assertEqual(g_11eb.group_type, "HYBRID")

        # 4588 / 0x11EC = X25519MLKEM768
        g_11ec = lookup_named_group("0x11ec")
        self.assertIsNotNone(g_11ec)
        self.assertEqual(g_11ec.name, "X25519MLKEM768")
        self.assertTrue(g_11ec.is_standard)
        self.assertEqual(g_11ec.group_type, "HYBRID")

        # 4589 / 0x11ED = SecP384r1MLKEM1024
        g_11ed = lookup_named_group("0x11ed")
        self.assertIsNotNone(g_11ed)
        self.assertEqual(g_11ed.name, "SecP384r1MLKEM1024")
        self.assertTrue(g_11ed.is_standard)
        self.assertEqual(g_11ed.group_type, "HYBRID")

    def test_03_iana_standalone_mlkem_groups(self):
        """Authoritative IANA standalone ML-KEM groups resolve to 0x0200, 0x0201, 0x0202."""
        # 512 / 0x0200 = MLKEM512
        g_0200 = lookup_named_group("0x0200")
        self.assertIsNotNone(g_0200)
        self.assertEqual(g_0200.name, "MLKEM512")
        self.assertTrue(g_0200.is_standard)
        self.assertEqual(g_0200.group_type, "PQC_STANDALONE")

        # 513 / 0x0201 = MLKEM768
        g_0201 = lookup_named_group("0x0201")
        self.assertIsNotNone(g_0201)
        self.assertEqual(g_0201.name, "MLKEM768")
        self.assertTrue(g_0201.is_standard)
        self.assertEqual(g_0201.group_type, "PQC_STANDALONE")

        # 514 / 0x0202 = MLKEM1024
        g_0202 = lookup_named_group("0x0202")
        self.assertIsNotNone(g_0202)
        self.assertEqual(g_0202.name, "MLKEM1024")
        self.assertTrue(g_0202.is_standard)
        self.assertEqual(g_0202.group_type, "PQC_STANDALONE")

    def test_04_obsolete_draft_kyber_groups_are_marked_non_standard(self):
        """Pre-standard draft Kyber codepoints (0x6399, 0x023a, 0x2f39) are marked non-standard and never yield PQC_PROTECTED."""
        for hex_code in ["0x6399", "0x639a", "0x2f39", "0x2f3a", "0x023a", "0x023c", "0x023d", "0x0239"]:
            grp = lookup_named_group(hex_code)
            self.assertIsNotNone(grp, f"Group {hex_code} must exist in registry")
            self.assertFalse(grp.is_standard, f"Group {hex_code} must NOT be labeled as current IANA standard")
            self.assertIn(grp.registry_status.value, ["IANA_OBSOLETE", "EXPERIMENTAL", "IMPLEMENTATION_SPECIFIC"])
            self.assertTrue(
                "draft" in grp.standard_ref.lower() or "obsolete" in grp.standard_ref.lower() or "experimental" in grp.standard_ref.lower() or "historical" in grp.standard_ref.lower(),
                f"Group {hex_code} reference must indicate draft/experimental/historical"
            )

            # Proving that observing this non-standard group never yields PQC_PROTECTED or HYBRID_OBSERVED
            session = self._create_base_session()
            session.tls_details = TLSHandshakeDetails(
                negotiated_tls_version=TLSVersion.TLSv1_3,
                selected_group=hex_code,
                server_hello_frame=50
            )
            res = PQCAnalyzer.analyze_session(session)
            self.assertEqual(res.pqc_status, PQCStatus.ASSESSMENT_INCOMPLETE)
            self.assertFalse(res.pqc_ready, f"Obsolete/draft group {hex_code} must not yield pqc_ready=True")
            self.assertFalse(res.hybrid_observed)

    def test_05_classical_x25519_only(self):
        """Observable classical X25519 key exchange yields CLASSICAL_ONLY and HNDL exposure."""
        session = self._create_base_session()
        session.tls_details = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_group="x25519",
            cipher_info=CipherSuiteInfo(
                hex_code="0x1302",
                name="TLS_AES_256_GCM_SHA384",
                key_exchange="Key Share (TLS 1.3)",
                encryption="AES-256-GCM",
                hash_algorithm="SHA-384",
                strength=SecurityStrength.STATE_OF_THE_ART,
                has_pfs=None
            ),
            server_hello_frame=10,
            has_forward_secrecy=True
        )
        result = PQCAnalyzer.analyze_session(session)
        self.assertEqual(result.pqc_status, PQCStatus.CLASSICAL_ONLY)
        self.assertFalse(result.pqc_ready)
        self.assertFalse(result.hybrid_observed)
        self.assertEqual(result.hndl_status, HNDLStatus.EXPOSURE_PRESENT)
        self.assertIn("x25519", result.summary.lower())

        # Rule engine evaluation should remain Grade A
        sec = CryptographicRuleEngine.evaluate_session(session)
        self.assertEqual(sec.grade, SecurityGrade.A)
        self.assertFalse(sec.post_quantum_ready)
        self.assertTrue(any(f.id == "FINDING-PQC-CLASSICAL-KEX-EXPOSURE" for f in sec.findings))

    def test_06_unobserved_tls_details_incomplete(self):
        """Session with unobserved TLS handshake yields ASSESSMENT_INCOMPLETE."""
        session = self._create_base_session()
        session.security_mode = SecurityMode.PLAINTEXT
        result = PQCAnalyzer.analyze_session(session)
        self.assertEqual(result.pqc_status, PQCStatus.ASSESSMENT_INCOMPLETE)
        self.assertEqual(result.hndl_status, HNDLStatus.INCOMPLETE)
        self.assertFalse(result.pqc_ready)

    def test_07_tls13_without_keyshare_is_incomplete(self):
        """TLS 1.3 with cipher 0x1302 alone (no observable key_share) must yield ASSESSMENT_INCOMPLETE."""
        session = self._create_base_session()
        session.tls_details = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_cipher_code="0x1302",
            selected_cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_info=CipherSuiteInfo(
                hex_code="0x1302",
                name="TLS_AES_256_GCM_SHA384",
                key_exchange="Key Share (TLS 1.3)",
                encryption="AES-256-GCM (AEAD)",
                hash_algorithm="SHA-384",
                strength=SecurityStrength.STATE_OF_THE_ART,
                has_pfs=None
            ),
            selected_group=None,
            server_hello_frame=2298,
            client_hello_frame=2295
        )
        result = PQCAnalyzer.analyze_session(session)
        self.assertEqual(result.pqc_status, PQCStatus.ASSESSMENT_INCOMPLETE)
        self.assertFalse(result.pqc_ready)
        self.assertFalse(result.hybrid_observed)
        self.assertEqual(result.hndl_status, HNDLStatus.INCOMPLETE)
        self.assertIn(2298, result.evidence_frames)
        self.assertIn(2295, result.evidence_frames)

    def test_08_unknown_or_private_group_is_unverified(self):
        """Unrecognized / private named group codepoint must NOT claim PQC protection."""
        session = self._create_base_session()
        session.tls_details = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_group="0x9999",  # Unassigned / private experimental group
            server_hello_frame=30
        )
        result = PQCAnalyzer.analyze_session(session)
        self.assertEqual(result.pqc_status, PQCStatus.ASSESSMENT_INCOMPLETE)
        self.assertFalse(result.pqc_ready)
        self.assertIn("0x9999", result.observed_groups)
        self.assertEqual(result.hndl_status, HNDLStatus.INCOMPLETE)

    def test_09_tls12_static_rsa_is_classical_only(self):
        """TLS 1.2 static RSA cipher suite establishes classical-only without PQC or PFS."""
        session = self._create_base_session()
        session.tls_details = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_2,
            cipher_info=CipherSuiteInfo(
                hex_code="0x009c",
                name="TLS_RSA_WITH_AES_128_GCM_SHA256",
                key_exchange="RSA (Static)",
                encryption="AES-128-GCM",
                hash_algorithm="SHA-256",
                strength=SecurityStrength.ACCEPTABLE,
                has_pfs=False
            ),
            server_hello_frame=40
        )
        result = PQCAnalyzer.analyze_session(session)
        self.assertEqual(result.pqc_status, PQCStatus.CLASSICAL_ONLY)
        self.assertFalse(result.pqc_ready)
        self.assertEqual(result.hndl_status, HNDLStatus.EXPOSURE_PRESENT)
        self.assertIn("Static RSA", result.evidence_summary)


if __name__ == "__main__":
    unittest.main()

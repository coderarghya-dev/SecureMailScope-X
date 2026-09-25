"""
SecureMailScope X - Phase 2 TLS Key Exchange & Perfect Forward Secrecy (PFS) Refinement Tests
Validates strict evidence boundaries for PFS across TLS 1.3 and TLS 1.2 handshakes.
"""

import os
import sys
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.tls.tls_dissector import TLSDissector
from app.tls.cipher_suites import lookup_cipher_suite
from app.schemas.forensic import TLSVersion, SecurityStrength, EmailSession, EmailProtocol, SecurityMode
from app.forensic.rule_engine import CryptographicRuleEngine
from app.forensic.confidence_scorer import ConfidenceScorer


class TestPFSRefinement(unittest.TestCase):

    def test_01_tls13_insufficient_key_exchange_evidence_yields_unknown(self):
        """TLS 1.3 without observable key_share extension must yield Unknown PFS (RFC 8446 boundary)."""
        details = TLSDissector.dissect_handshake(
            client_hello_frame=10,
            client_hello_time=1.0,
            server_hello_frame=14,
            server_hello_time=1.1,
            sni="smtp.example.com",
            alpn=None,
            raw_version="0x0303",
            supported_version_ext="0x0304",
            cipher_code="0x1302",
            cipher_name="TLS_AES_256_GCM_SHA384",
            key_share_group=None,
            server_share_group=None,
            key_share_observed=False,
            server_kx_observed=False
        )

        self.assertEqual(details.negotiated_tls_version, TLSVersion.TLSv1_3)
        self.assertIsNone(details.has_forward_secrecy, "PFS must not be inferred solely from TLS 1.3 cipher suite")
        self.assertEqual(details.pfs_status, "Unknown / insufficient passive evidence")
        self.assertIn("key_share", details.pfs_evidence.lower())

    def test_02_tls13_observable_key_share_yields_pfs_verified(self):
        """TLS 1.3 with observable key_share extension yields Verified PFS with named group."""
        details = TLSDissector.dissect_handshake(
            client_hello_frame=10,
            client_hello_time=1.0,
            server_hello_frame=14,
            server_hello_time=1.1,
            sni="smtp.example.com",
            alpn=None,
            raw_version="0x0303",
            supported_version_ext="0x0304",
            cipher_code="0x1301",
            cipher_name="TLS_AES_128_GCM_SHA256",
            key_share_group="x25519",
            server_share_group="x25519",
            key_share_observed=True,
            server_kx_observed=False
        )

        self.assertEqual(details.negotiated_tls_version, TLSVersion.TLSv1_3)
        self.assertTrue(details.has_forward_secrecy)
        self.assertIn("Observable key_share: x25519", details.pfs_status)
        self.assertEqual(details.selected_group, "x25519")

    def test_03_tls12_static_rsa_yields_no_pfs(self):
        """TLS 1.2 with static RSA cipher suite yields No PFS (has_forward_secrecy = False)."""
        details = TLSDissector.dissect_handshake(
            client_hello_frame=20,
            client_hello_time=2.0,
            server_hello_frame=22,
            server_hello_time=2.1,
            sni="pop.example.com",
            alpn=None,
            raw_version="0x0303",
            supported_version_ext=None,
            cipher_code="0x009c",
            cipher_name="TLS_RSA_WITH_AES_128_GCM_SHA256",
            key_share_group=None,
            server_share_group=None,
            key_share_observed=False,
            server_kx_observed=False
        )

        self.assertEqual(details.negotiated_tls_version, TLSVersion.TLSv1_2)
        self.assertFalse(details.has_forward_secrecy)
        self.assertIn("Static Key Exchange", details.pfs_status)

    def test_04_tls12_ecdhe_yields_pfs_verified(self):
        """TLS 1.2 with ECDHE cipher suite and ServerKeyExchange yields Verified PFS."""
        details = TLSDissector.dissect_handshake(
            client_hello_frame=30,
            client_hello_time=3.0,
            server_hello_frame=32,
            server_hello_time=3.1,
            sni="imap.example.com",
            alpn=None,
            raw_version="0x0303",
            supported_version_ext=None,
            cipher_code="0xc02f",
            cipher_name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_share_group=None,
            server_share_group=None,
            key_share_observed=False,
            server_kx_observed=True
        )

        self.assertEqual(details.negotiated_tls_version, TLSVersion.TLSv1_2)
        self.assertTrue(details.has_forward_secrecy)
        self.assertIn("ECDHE-RSA", details.pfs_status)

    def test_05_unknown_0x13xx_cipher_does_not_auto_infer_pfs(self):
        """Unmapped cipher suite codepoint starting with 0x13 must NOT automatically set has_pfs=True."""
        unmapped = lookup_cipher_suite("0x13fe")
        self.assertIsNotNone(unmapped)
        self.assertIsNone(unmapped.has_pfs, "Unmapped 0x13xx cipher must not be assumed to provide PFS without ECDHE/DHE in name")

    def test_06_rule_engine_tls13_without_keyshare_scores_grade_a(self):
        """TLS 1.3 without explicit key_share frame remains Grade A (RFC 8446 compliant) and does not falsely trigger No-PFS Grade C."""
        details = TLSDissector.dissect_handshake(
            client_hello_frame=1,
            client_hello_time=0.1,
            server_hello_frame=2,
            server_hello_time=0.2,
            sni="smtp.gmail.com",
            alpn=None,
            raw_version="0x0303",
            supported_version_ext="0x0304",
            cipher_code="0x1302",
            cipher_name="TLS_AES_256_GCM_SHA384",
            key_share_group=None,
            server_share_group=None
        )

        session = EmailSession(
            session_id="stream_test",
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.51",
            client_port=60778,
            server_ip="192.178.211.108",
            server_port=587,
            tls_details=details
        )

        assessment = CryptographicRuleEngine.evaluate_session(session)
        self.assertEqual(assessment.grade.value, "A")
        self.assertFalse(any(f.id == "FINDING-NO-FORWARD-SECRECY" for f in assessment.findings))

    def test_07_tls13_cipher_metadata_has_pfs_is_none(self):
        """TLS 1.3 symmetric cipher suites (0x1301-0x1304) have has_pfs is None."""
        for code in ["0x1301", "0x1302", "0x1303", "0x1304"]:
            info = lookup_cipher_suite(code)
            self.assertIsNotNone(info)
            self.assertIsNone(info.has_pfs, f"Cipher {code} has_pfs must be None")

    def test_08_tls13_confidence_score_80_without_keyshare(self):
        """TLS 1.3 session without observable key_share receives 80 confidence based strictly on observed evidence."""
        details = TLSDissector.dissect_handshake(
            client_hello_frame=2295,
            client_hello_time=0.061,
            server_hello_frame=2298,
            server_hello_time=0.074,
            sni="smtp.gmail.com",
            alpn=None,
            raw_version="0x0303",
            supported_version_ext="0x0304",
            cipher_code="0x1302",
            cipher_name="TLS_AES_256_GCM_SHA384",
            key_share_group=None,
            server_share_group=None,
            key_share_observed=False
        )
        conf = ConfidenceScorer.calculate_confidence(details, SecurityMode.STARTTLS_ACCEPTED)
        # Handshake: 35 + Version: 25 + Cipher: 20 + Key Exchange: 0 = 80
        self.assertEqual(conf.score, 80)
        self.assertEqual(conf.level.value, "HIGH")
        self.assertFalse(conf.key_exchange_observable)
        self.assertTrue(any("could not be verified" in f for f in conf.confidence_factors))

    def test_09_tls13_confidence_score_100_with_keyshare(self):
        """TLS 1.3 session with observable key_share earns full 100 confidence."""
        details = TLSDissector.dissect_handshake(
            client_hello_frame=2295,
            client_hello_time=0.061,
            server_hello_frame=2298,
            server_hello_time=0.074,
            sni="smtp.gmail.com",
            alpn=None,
            raw_version="0x0303",
            supported_version_ext="0x0304",
            cipher_code="0x1302",
            cipher_name="TLS_AES_256_GCM_SHA384",
            key_share_group="x25519",
            server_share_group="x25519",
            key_share_observed=True
        )
        conf = ConfidenceScorer.calculate_confidence(details, SecurityMode.STARTTLS_ACCEPTED)
        # Handshake: 35 + Version: 25 + Cipher: 20 + Key Exchange: 20 = 100
        self.assertEqual(conf.score, 100)
        self.assertEqual(conf.level.value, "HIGH")
        self.assertTrue(conf.key_exchange_observable)


if __name__ == "__main__":
    unittest.main(verbosity=2)

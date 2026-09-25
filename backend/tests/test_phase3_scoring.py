"""
SecureMailScope X - Phase 3 Core Forensics & Scoring Engine Unit & Real-Capture Tests
Validates Capture Health Scorer, Evidence Confidence Scorer, Cryptographic Rule Engine,
and Security Findings Assessment across deterministic fixtures and real PCAP captures.
"""

import os
import sys
import unittest

# Ensure backend root is in sys.path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from run_parser import analyze_pcap
from app.schemas.forensic import (
    EmailProtocol,
    SecurityMode,
    TLSVersion,
    SecurityStrength,
    HealthGrade,
    ConfidenceLevel,
    FindingSeverity,
    SecurityGrade,
    EmailSession,
    STARTTLSState,
    TLSHandshakeDetails,
    CipherSuiteInfo,
    PacketEvidence
)
from app.forensic.health_scorer import HealthScorer
from app.forensic.confidence_scorer import ConfidenceScorer
from app.forensic.rule_engine import CryptographicRuleEngine


class TestPhase3ScoringEngine(unittest.TestCase):
    SMTP_PCAP = r"D:\SecureMailScope\pcap_samples\smtp-starttls-test.pcapng"
    IMAP_PCAP = r"D:\SecureMailScope\pcap_samples\imap-tls-test.pcapng"
    POP3_PCAP = r"D:\SecureMailScope\pcap_samples\pop3-tls-test.pcapng"

    # ----------------------------------------------------------
    # 1. CAPTURE HEALTH SCORER TESTS
    # ----------------------------------------------------------
    def test_01_health_scorer_pristine_stream(self):
        """Complete stream with SYN, FIN, and no retransmissions yields 100 / EXCELLENT."""
        mock_packets = [
            {"frame_number": 1, "info": "50000 -> 587 [SYN]"},
            {"frame_number": 2, "info": "587 -> 50000 [SYN, ACK]"},
            {"frame_number": 3, "info": "50000 -> 587 [ACK]"},
            {"frame_number": 4, "info": "50000 -> 587 [FIN, ACK]"}
        ]
        health = HealthScorer.calculate_health(
            raw_packets=mock_packets,
            syn_observed=True,
            fin_rst_observed=True,
            duration_seconds=1.2
        )
        self.assertEqual(health.score, 100)
        self.assertEqual(health.grade, HealthGrade.EXCELLENT)
        self.assertEqual(len(health.deduction_reasons), 0)

    def test_02_health_scorer_missing_syn_and_fin(self):
        """Stream missing 3-way handshake and teardown gets deductions."""
        mock_packets = [
            {"frame_number": 10, "info": "SMTP 250-STARTTLS"},
            {"frame_number": 11, "info": "SMTP STARTTLS"},
            {"frame_number": 12, "info": "SMTP 220 Ready to start TLS"},
            {"frame_number": 13, "info": "TLSv1.3 Client Hello"}
        ]
        health = HealthScorer.calculate_health(
            raw_packets=mock_packets,
            syn_observed=False,
            fin_rst_observed=False,
            duration_seconds=0.8
        )
        self.assertLess(health.score, 100)
        self.assertEqual(health.score, 65)  # 100 - 20 (SYN) - 15 (FIN)
        self.assertEqual(health.grade, HealthGrade.FAIR)
        self.assertEqual(len(health.deduction_reasons), 2)

    # ----------------------------------------------------------
    # 2. EVIDENCE CONFIDENCE SCORER TESTS
    # ----------------------------------------------------------
    def test_03_confidence_scorer_plaintext(self):
        """Plaintext session has 100 confidence (unencrypted traffic directly inspectable)."""
        conf = ConfidenceScorer.calculate_confidence(
            tls_details=None,
            security_mode=SecurityMode.PLAINTEXT
        )
        self.assertEqual(conf.score, 100)
        self.assertEqual(conf.level, ConfidenceLevel.HIGH)
        self.assertIn("Plaintext", conf.observability_boundary)

    def test_04_confidence_scorer_tls13(self):
        """TLS 1.3 handshake with full observability respects RFC 8446 boundary."""
        tls = TLSHandshakeDetails(
            client_hello_frame=10,
            server_hello_frame=14,
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_cipher_name="TLS_AES_128_GCM_SHA256",
            selected_cipher_code="0x1301",
            has_forward_secrecy=True,
            pfs_status="Yes (Observable key_share)",
            key_share_observed=True,
            certificate_visibility="Unavailable from passive capture (TLS 1.3 encrypted handshake)"
        )
        conf = ConfidenceScorer.calculate_confidence(
            tls_details=tls,
            security_mode=SecurityMode.STARTTLS_ACCEPTED
        )
        self.assertEqual(conf.score, 100)
        self.assertEqual(conf.level, ConfidenceLevel.HIGH)
        self.assertTrue(conf.handshake_observable)
        self.assertTrue(conf.version_verifiable)
        self.assertTrue(conf.cipher_identifiable)
        self.assertIn("RFC 8446 Encrypted Handshake", conf.observability_boundary)

    # ----------------------------------------------------------
    # 3. CRYPTOGRAPHIC RULE ENGINE TESTS
    # ----------------------------------------------------------
    def test_05_rule_engine_plaintext_critical(self):
        """Plaintext session triggers CRITICAL finding and Grade F."""
        session = EmailSession(
            session_id="stream_0_192.168.1.100_50000_192.168.1.1_110",
            stream_index=0,
            protocol=EmailProtocol.POP3,
            security_mode=SecurityMode.PLAINTEXT,
            client_ip="192.168.1.100",
            client_port=50000,
            server_ip="192.168.1.1",
            server_port=110
        )
        sec = CryptographicRuleEngine.evaluate_session(session)
        self.assertEqual(sec.grade, SecurityGrade.F)
        self.assertGreaterEqual(sec.critical_findings_count, 1)
        critical_finding = next(f for f in sec.findings if f.severity == FindingSeverity.CRITICAL)
        self.assertEqual(critical_finding.id, "FINDING-PLAINTEXT-COMMUNICATION")

    def test_06_rule_engine_static_rsa_no_pfs(self):
        """TLS 1.2 with static RSA cipher triggers Grade C and NO_PFS finding."""
        cipher = CipherSuiteInfo(
            hex_code="0x009c",
            name="TLS_RSA_WITH_AES_128_GCM_SHA256",
            has_pfs=False,
            key_exchange="RSA (Static)",
            encryption="AES-128-GCM",
            hash_algorithm="SHA-256",
            strength=SecurityStrength.ACCEPTABLE
        )
        tls = TLSHandshakeDetails(
            client_hello_frame=1,
            server_hello_frame=2,
            negotiated_tls_version=TLSVersion.TLSv1_2,
            cipher_info=cipher,
            selected_cipher_name=cipher.name,
            has_forward_secrecy=False,
            pfs_status="No (RSA - Static Key Exchange)"
        )
        session = EmailSession(
            session_id="stream_1_192.168.1.100_50000_192.168.1.1_995",
            stream_index=1,
            protocol=EmailProtocol.POP3,
            security_mode=SecurityMode.DIRECT_TLS,
            client_ip="192.168.1.100",
            client_port=50000,
            server_ip="192.168.1.1",
            server_port=995,
            tls_details=tls
        )
        sec = CryptographicRuleEngine.evaluate_session(session)
        self.assertEqual(sec.grade, SecurityGrade.C)
        self.assertTrue(any(f.id == "FINDING-NO-FORWARD-SECRECY" for f in sec.findings))

    def test_07_rule_engine_tls13_state_of_the_art(self):
        """TLS 1.3 with AES-GCM and PFS yields Grade A with PQC readiness note."""
        cipher = CipherSuiteInfo(
            hex_code="0x1301",
            name="TLS_AES_128_GCM_SHA256",
            has_pfs=True,
            key_exchange="ECDHE/DHE (TLS 1.3)",
            encryption="AES-128-GCM",
            hash_algorithm="SHA-256",
            strength=SecurityStrength.STATE_OF_THE_ART,
            is_post_quantum_safe=False
        )
        tls = TLSHandshakeDetails(
            client_hello_frame=100,
            server_hello_frame=104,
            negotiated_tls_version=TLSVersion.TLSv1_3,
            cipher_info=cipher,
            selected_cipher_name=cipher.name,
            has_forward_secrecy=True,
            pfs_status="Yes (Observable key_share)"
        )
        session = EmailSession(
            session_id="stream_2_192.168.1.100_50000_192.168.1.1_587",
            stream_index=2,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.100",
            client_port=50000,
            server_ip="192.168.1.1",
            server_port=587,
            tls_details=tls
        )
        sec = CryptographicRuleEngine.evaluate_session(session)
        self.assertEqual(sec.grade, SecurityGrade.A)
        self.assertTrue(any(f.id == "FINDING-TLS13-STATE-OF-THE-ART" for f in sec.findings))
        self.assertTrue(any(f.id == "FINDING-PQC-CLASSICAL-KEX-EXPOSURE" for f in sec.findings))

    # ----------------------------------------------------------
    # 4. REAL PCAP CAPTURE SCORING TESTS
    # ----------------------------------------------------------
    def test_08_smtp_real_capture_phase3_scores(self):
        """Verify real Gmail SMTP STARTTLS capture scores Grade A and High Confidence."""
        if not os.path.isfile(self.SMTP_PCAP):
            self.skipTest(f"PCAP not found: {self.SMTP_PCAP}")

        report = analyze_pcap(self.SMTP_PCAP)
        smtp_sess = next(s for s in report["sessions"] if s["protocol"] == "SMTP")

        # Health - Real PCAP is a mid-stream trace (starts at Frame 2291 banner without SYN/FIN)
        health = smtp_sess["capture_health"]
        self.assertIsNotNone(health)
        self.assertGreaterEqual(health["score"], 50, "Real capture should maintain at least FAIR health (score >= 50)")
        self.assertIn(health["grade"], ["EXCELLENT", "GOOD", "FAIR"])

        # Confidence - TLS 1.3 handshake is fully observable
        conf = smtp_sess["evidence_confidence"]
        self.assertIsNotNone(conf)
        self.assertEqual(conf["level"], "HIGH")

        # Security Assessment - TLS 1.3 with PFS
        sec = smtp_sess["security_assessment"]
        self.assertIsNotNone(sec)
        self.assertEqual(sec["grade"], "A")
        self.assertTrue(len(sec["findings"]) > 0)
        print(f"[OK] Real SMTP Phase 3 Scoring: Grade {sec['grade']} | Health {health['score']}/100 ({health['grade']}) | Confidence {conf['score']}/100 ({conf['level']})")

    def test_09_imap_real_capture_phase3_scores(self):
        """Verify real Gmail IMAP Direct TLS capture scores Grade A and High Confidence."""
        if not os.path.isfile(self.IMAP_PCAP):
            self.skipTest(f"PCAP not found: {self.IMAP_PCAP}")

        report = analyze_pcap(self.IMAP_PCAP)
        imap_sess = next(s for s in report["sessions"] if s["protocol"] == "IMAP")

        health = imap_sess["capture_health"]
        self.assertIsNotNone(health)
        self.assertGreaterEqual(health["score"], 50)
        self.assertIn(health["grade"], ["EXCELLENT", "GOOD", "FAIR"])

        conf = imap_sess["evidence_confidence"]
        self.assertIsNotNone(conf)
        self.assertEqual(conf["level"], "HIGH")

        sec = imap_sess["security_assessment"]
        self.assertIsNotNone(sec)
        self.assertEqual(sec["grade"], "A")
        print(f"[OK] Real IMAP Phase 3 Scoring: Grade {sec['grade']} | Health {health['score']}/100 ({health['grade']}) | Confidence {conf['score']}/100 ({conf['level']})")

    def test_10_pop3s_real_capture_phase3_scores(self):
        """Verify real Gmail POP3S Direct TLS capture scores Grade A and High Confidence."""
        if not os.path.isfile(self.POP3_PCAP):
            self.skipTest(f"PCAP not found: {self.POP3_PCAP}")

        report = analyze_pcap(self.POP3_PCAP)
        pop_sess = next(s for s in report["sessions"] if s["protocol"] == "POP3")

        health = pop_sess["capture_health"]
        self.assertIsNotNone(health)
        self.assertGreaterEqual(health["score"], 50)
        self.assertIn(health["grade"], ["EXCELLENT", "GOOD", "FAIR"])

        conf = pop_sess["evidence_confidence"]
        self.assertIsNotNone(conf)
        self.assertEqual(conf["level"], "HIGH")

        sec = pop_sess["security_assessment"]
        self.assertIsNotNone(sec)
        self.assertEqual(sec["grade"], "A")
        print(f"[OK] Real POP3S Phase 3 Scoring: Grade {sec['grade']} | Health {health['score']}/100 ({health['grade']}) | Confidence {conf['score']}/100 ({conf['level']})")


if __name__ == "__main__":
    unittest.main(verbosity=2)

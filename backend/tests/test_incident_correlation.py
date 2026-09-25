"""
SecureMailScope X - Deterministic XAI & Multi-Session Incident Correlation Tests (Phase 5.5)
Verifies:
1. Repeated STARTTLS rejection does not automatically claim active stripping (emits STARTTLS_FAILURE_PATTERN).
2. STARTTLS advertised but unrequested emits STARTTLS_DOWNGRADE_PATTERN with evidence-bounded wording.
3. Certificate reuse requires actual fingerprint equality.
4. Same hostname/IP/subject without certificate fingerprint does NOT create CERTIFICATE_REUSE.
5. Incident confidence is correlation rule-match confidence, not attack probability.
6. ML output isolation (ML cannot create, remove, or modify incidents).
7. PQC / HNDL wording remains evidence-bounded without declaring inevitable decryption.
8. Two unrelated clean sessions remain uncorrelated.
9. Structured deterministic finding explanations preserve rule_id, evidence, confidence boundary, and standards refs.
10. Incident authority & evidence-backed semantics (evidence_backed=True, correlation_method='DETERMINISTIC_RULE_CORRELATION').
11. Multi-session capture summary computation correctness.
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
    PacketEvidence,
    STARTTLSState,
    TLSHandshakeDetails,
    TLSVersion,
    CipherSuiteInfo,
    SecurityStrength,
    FindingSeverity,
    FindingCategory
)
from app.forensic.rule_engine import CryptographicRuleEngine
from app.forensic.incident_correlator import IncidentCorrelator, CorrelatedIncident, MultiSessionSummary
from app.ml.risk_classifier import MLRiskClassifier


class TestIncidentCorrelationAndXAI(unittest.TestCase):

    def _create_clean_tls13_session(self, session_id: str, client_ip: str, client_port: int, server_ip: str, server_port: int) -> EmailSession:
        st = STARTTLSState(
            advertised=True, advertised_frame=10, advertised_text="250-STARTTLS",
            requested=True, requested_frame=12, requested_command="STARTTLS",
            accepted=True, accepted_frame=14, accepted_response="220 2.0.0 Ready to start TLS",
            upgrade_successful=True
        )
        tls = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_cipher_code="0x1302",
            selected_cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_info=CipherSuiteInfo(
                hex_code="0x1302", name="TLS_AES_256_GCM_SHA384",
                key_exchange="ECDHE", encryption="AES-256-GCM",
                hash_algorithm="SHA384", strength=SecurityStrength.STATE_OF_THE_ART,
                has_pfs=True
            ),
            has_forward_secrecy=True,
            pfs_status="Ephemeral key exchange (TLS 1.3 Key Share / ECDHE)",
            client_hello_frame=15,
            server_hello_frame=17,
            selected_group="SecP256r1MLKEM768 (0x11EB)",
            key_share_observed=True
        )
        sess = EmailSession(
            session_id=session_id,
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            starttls_state=st,
            tls_details=tls,
            evidence_packets=[
                PacketEvidence(10, 0.0, "", client_ip, client_port, server_ip, server_port, "SMTP", 80, "250-STARTTLS"),
                PacketEvidence(12, 0.1, "", client_ip, client_port, server_ip, server_port, "SMTP", 40, "STARTTLS"),
                PacketEvidence(14, 0.2, "", client_ip, client_port, server_ip, server_port, "SMTP", 50, "220 Ready"),
                PacketEvidence(15, 0.3, "", client_ip, client_port, server_ip, server_port, "TLS", 200, "Client Hello"),
                PacketEvidence(17, 0.4, "", client_ip, client_port, server_ip, server_port, "TLS", 180, "Server Hello")
            ]
        )
        sess.security_assessment = CryptographicRuleEngine.evaluate_session(sess)
        return sess

    def _create_starttls_failure_session(self, session_id: str, client_ip: str, client_port: int, server_ip: str, server_port: int, req_frame: int, fail_frame: int) -> EmailSession:
        st = STARTTLSState(
            requested=True, requested_frame=req_frame, requested_command="STARTTLS",
            failed=True, failure_frame=fail_frame, failure_reason="454 4.7.0 TLS not available"
        )
        sess = EmailSession(
            session_id=session_id,
            stream_index=1,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_FAILED,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            starttls_state=st,
            evidence_packets=[
                PacketEvidence(req_frame, 0.1, "", client_ip, client_port, server_ip, server_port, "SMTP", 40, "STARTTLS"),
                PacketEvidence(fail_frame, 0.2, "", client_ip, client_port, server_ip, server_port, "SMTP", 50, "454 TLS not available")
            ]
        )
        sess.security_assessment = CryptographicRuleEngine.evaluate_session(sess)
        return sess

    def _create_starttls_unrequested_session(self, session_id: str, client_ip: str, client_port: int, server_ip: str, server_port: int, adv_frame: int) -> EmailSession:
        st = STARTTLSState(
            advertised=True, advertised_frame=adv_frame, advertised_text="250-STARTTLS",
            requested=False
        )
        sess = EmailSession(
            session_id=session_id,
            stream_index=1,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.PLAINTEXT,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            starttls_state=st,
            evidence_packets=[
                PacketEvidence(adv_frame, 0.0, "", client_ip, client_port, server_ip, server_port, "SMTP", 80, "250-STARTTLS"),
                PacketEvidence(adv_frame + 2, 0.1, "", client_ip, client_port, server_ip, server_port, "SMTP", 60, "AUTH PLAIN")
            ]
        )
        sess.security_assessment = CryptographicRuleEngine.evaluate_session(sess)
        return sess

    def _create_static_rsa_session(self, session_id: str, client_ip: str, client_port: int, server_ip: str, server_port: int, sh_frame: int) -> EmailSession:
        tls = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_2,
            selected_cipher_code="0x0035",
            selected_cipher_name="TLS_RSA_WITH_AES_256_CBC_SHA",
            cipher_info=CipherSuiteInfo(
                hex_code="0x0035", name="TLS_RSA_WITH_AES_256_CBC_SHA",
                key_exchange="RSA", encryption="AES-256-CBC",
                hash_algorithm="SHA1", strength=SecurityStrength.DEPRECATED,
                has_pfs=False
            ),
            has_forward_secrecy=False,
            pfs_status="Static RSA Key Exchange (No Forward Secrecy)",
            client_hello_frame=sh_frame - 2,
            server_hello_frame=sh_frame
        )
        sess = EmailSession(
            session_id=session_id,
            stream_index=2,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.DIRECT_TLS,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            tls_details=tls,
            evidence_packets=[
                PacketEvidence(sh_frame - 2, 0.0, "", client_ip, client_port, server_ip, server_port, "TLS", 200, "Client Hello"),
                PacketEvidence(sh_frame, 0.1, "", client_ip, client_port, server_ip, server_port, "TLS", 180, "Server Hello")
            ]
        )
        sess.security_assessment = CryptographicRuleEngine.evaluate_session(sess)
        return sess

    def _create_classical_pqc_gap_session(self, session_id: str, client_ip: str, client_port: int, server_ip: str, server_port: int, sh_frame: int) -> EmailSession:
        tls = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_cipher_code="0x1302",
            selected_cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_info=CipherSuiteInfo(
                hex_code="0x1302", name="TLS_AES_256_GCM_SHA384",
                key_exchange="ECDHE", encryption="AES-256-GCM",
                hash_algorithm="SHA384", strength=SecurityStrength.STATE_OF_THE_ART,
                has_pfs=True
            ),
            has_forward_secrecy=True,
            pfs_status="Ephemeral key exchange (TLS 1.3 Key Share / ECDHE)",
            client_hello_frame=sh_frame - 2,
            server_hello_frame=sh_frame,
            selected_group="x25519 (0x001D)",
            key_share_observed=True
        )
        sess = EmailSession(
            session_id=session_id,
            stream_index=3,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.DIRECT_TLS,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            tls_details=tls,
            evidence_packets=[
                PacketEvidence(sh_frame - 2, 0.0, "", client_ip, client_port, server_ip, server_port, "TLS", 200, "Client Hello"),
                PacketEvidence(sh_frame, 0.1, "", client_ip, client_port, server_ip, server_port, "TLS", 180, "Server Hello")
            ]
        )
        sess.security_assessment = CryptographicRuleEngine.evaluate_session(sess)
        return sess

    # -----------------------------------------------------------------------
    # TEST 1: Repeated STARTTLS rejection does NOT claim active stripping
    # -----------------------------------------------------------------------
    def test_01_starttls_rejection_emits_failure_pattern_not_stripping(self):
        s1 = self._create_starttls_failure_session("sess_fail_1", "192.168.1.50", 40001, "192.0.2.10", 25, 103, 105)
        s2 = self._create_starttls_failure_session("sess_fail_2", "192.168.1.51", 40002, "192.0.2.10", 25, 203, 205)

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.incident_type, "STARTTLS_FAILURE_PATTERN")
        self.assertEqual(inc.severity, "HIGH")
        self.assertIn("sess_fail_1", inc.session_ids)
        self.assertIn("sess_fail_2", inc.session_ids)
        self.assertIn(105, inc.evidence_frames)
        self.assertIn(205, inc.evidence_frames)
        
        # Verify claim boundary: no claims of "stripping" or "active attacker" on server rejection
        for r in inc.correlation_reasons:
            self.assertNotIn("stripping", r.lower())
            self.assertNotIn("active attacker", r.lower())
        self.assertNotIn("stripping", inc.evidence_summary.lower())

    # -----------------------------------------------------------------------
    # TEST 2: Advertised but unrequested STARTTLS emits STARTTLS_DOWNGRADE_PATTERN
    # -----------------------------------------------------------------------
    def test_02_starttls_advertised_unrequested_emits_downgrade_pattern(self):
        s1 = self._create_starttls_unrequested_session("sess_adv_1", "192.168.1.50", 40001, "192.0.2.10", 25, 100)
        s2 = self._create_starttls_unrequested_session("sess_adv_2", "192.168.1.51", 40002, "192.0.2.10", 25, 200)

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        downgrade_incidents = [i for i in incidents if i.incident_type == "STARTTLS_DOWNGRADE_PATTERN"]
        self.assertEqual(len(downgrade_incidents), 1)
        inc = downgrade_incidents[0]
        self.assertEqual(inc.severity, "HIGH")
        self.assertIn("sess_adv_1", inc.session_ids)
        self.assertIn("sess_adv_2", inc.session_ids)
        self.assertIn(100, inc.evidence_frames)
        self.assertIn(200, inc.evidence_frames)

    # -----------------------------------------------------------------------
    # TEST 3: Certificate reuse requires actual fingerprint equality
    # -----------------------------------------------------------------------
    def test_03_certificate_reuse_requires_actual_fingerprint_equality(self):
        s1 = self._create_clean_tls13_session("cert_sess_1", "10.0.0.1", 5001, "192.0.2.50", 465)
        s1.tls_details.certificate_fingerprint_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        s2 = self._create_clean_tls13_session("cert_sess_2", "10.0.0.2", 5002, "192.0.2.50", 465)
        s2.tls_details.certificate_fingerprint_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        cert_incidents = [i for i in incidents if i.incident_type == "CERTIFICATE_REUSE"]
        self.assertEqual(len(cert_incidents), 1)
        inc = cert_incidents[0]
        self.assertEqual(inc.severity, "INFO")
        self.assertIn("cert_sess_1", inc.session_ids)
        self.assertIn("cert_sess_2", inc.session_ids)

    # -----------------------------------------------------------------------
    # TEST 4: Same IP / Subject / Hostname without fingerprint does NOT create CERTIFICATE_REUSE
    # -----------------------------------------------------------------------
    def test_04_same_subject_without_fingerprint_no_certificate_reuse(self):
        s1 = self._create_clean_tls13_session("no_fp_1", "10.0.0.1", 5001, "192.0.2.50", 465)
        s1.tls_details.certificate_subjects = ["CN=mail.example.com"]
        s1.tls_details.certificate_fingerprint_sha256 = None  # No verified fingerprint

        s2 = self._create_clean_tls13_session("no_fp_2", "10.0.0.2", 5002, "192.0.2.50", 465)
        s2.tls_details.certificate_subjects = ["CN=mail.example.com"]
        s2.tls_details.certificate_fingerprint_sha256 = None  # No verified fingerprint

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        cert_incidents = [i for i in incidents if i.incident_type == "CERTIFICATE_REUSE"]
        # Must not emit CERTIFICATE_REUSE without verified fingerprint hash equality
        self.assertEqual(len(cert_incidents), 0)

    # -----------------------------------------------------------------------
    # TEST 5: Correlation confidence is rule-match confidence, not attack probability
    # -----------------------------------------------------------------------
    def test_05_correlation_confidence_semantics(self):
        s1 = self._create_starttls_failure_session("s_f1", "10.0.0.1", 5001, "192.0.2.10", 25, 10, 12)
        s2 = self._create_starttls_failure_session("s_f2", "10.0.0.2", 5002, "192.0.2.10", 25, 20, 22)

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        # HIGH confidence means deterministic rule matched exact frames on the same endpoint
        self.assertEqual(inc.confidence, "HIGH")
        self.assertTrue(inc.evidence_backed)
        self.assertEqual(inc.correlation_method, "DETERMINISTIC_RULE_CORRELATION")

    # -----------------------------------------------------------------------
    # TEST 6: ML output cannot create or alter incidents
    # -----------------------------------------------------------------------
    def test_06_ml_cannot_create_or_modify_incidents(self):
        s1 = self._create_clean_tls13_session("clean_sess", "192.168.1.50", 40001, "192.0.2.10", 587)
        ml_triage = MLRiskClassifier.classify_session(s1)
        
        self.assertIn("advisory_risk_class", ml_triage)
        self.assertFalse(ml_triage["authoritative"])

        incidents = IncidentCorrelator.correlate_sessions([s1])
        # Clean session with no security anomalies produces 0 incidents regardless of ML
        self.assertEqual(len(incidents), 0)

    # -----------------------------------------------------------------------
    # TEST 7: PQC / HNDL wording remains evidence-bounded
    # -----------------------------------------------------------------------
    def test_07_pqc_hndl_wording_evidence_bounded(self):
        s1 = self._create_classical_pqc_gap_session("pqc_gap_1", "10.0.0.1", 50001, "192.0.2.40", 587, 50)
        s2 = self._create_classical_pqc_gap_session("pqc_gap_2", "10.0.0.2", 50002, "192.0.2.40", 587, 90)

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        pqc_incidents = [i for i in incidents if i.incident_type == "PQC_READINESS_GAP_CLUSTER"]
        self.assertEqual(len(pqc_incidents), 1)
        inc = pqc_incidents[0]
        self.assertEqual(inc.severity, "MEDIUM")
        self.assertIn("Classical-only key establishment was observed", inc.evidence_summary)
        self.assertNotIn("will be decrypted", inc.evidence_summary.lower())
        self.assertNotIn("broken encryption", inc.evidence_summary.lower())

    # -----------------------------------------------------------------------
    # TEST 8: Two unrelated clean sessions remain uncorrelated
    # -----------------------------------------------------------------------
    def test_08_two_clean_sessions_remain_uncorrelated(self):
        s1 = self._create_clean_tls13_session("clean_1", "192.168.1.50", 40001, "192.0.2.10", 587)
        s2 = self._create_clean_tls13_session("clean_2", "192.168.1.51", 40002, "192.0.2.20", 587)

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        self.assertEqual(len(incidents), 0)

        summary = IncidentCorrelator.generate_summary([s1, s2], incidents)
        self.assertEqual(summary.total_sessions, 2)
        self.assertEqual(summary.incident_count, 0)
        self.assertEqual(summary.uncorrelated_sessions_count, 2)

    # -----------------------------------------------------------------------
    # TEST 9: Structured deterministic finding explanations preserve rule_id and evidence
    # -----------------------------------------------------------------------
    def test_09_structured_deterministic_xai_explanations(self):
        s_pt = EmailSession(
            session_id="pt_1", stream_index=0, protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.PLAINTEXT, client_ip="10.0.0.1", client_port=5000,
            server_ip="10.0.0.2", server_port=25,
            evidence_packets=[PacketEvidence(55, 0.0, "", "10.0.0.1", 5000, "10.0.0.2", 25, "SMTP", 60, "")]
        )
        assessment = CryptographicRuleEngine.evaluate_session(s_pt)
        self.assertTrue(len(assessment.findings) > 0)
        f = assessment.findings[0]
        self.assertIsNotNone(f.explanation)
        self.assertEqual(f.explanation.finding_id, "FINDING-PLAINTEXT-COMMUNICATION")
        self.assertEqual(f.explanation.rule_id, "RULE-PLAINTEXT-TRAFFIC")
        self.assertEqual(f.explanation.evidence[0].frame, 55)
        self.assertIn("RFC 3207", f.explanation.standards_refs)

    # -----------------------------------------------------------------------
    # TEST 10: Incident authority & evidence-backed properties
    # -----------------------------------------------------------------------
    def test_10_incident_authority_and_evidence_backed(self):
        s1 = self._create_static_rsa_session("rsa_1", "10.0.0.1", 50001, "192.0.2.30", 465, 45)
        s2 = self._create_static_rsa_session("rsa_2", "10.0.0.2", 50002, "192.0.2.30", 465, 85)

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        self.assertTrue(len(incidents) >= 1)
        for inc in incidents:
            self.assertTrue(inc.authoritative)
            self.assertTrue(inc.evidence_backed)
            self.assertEqual(inc.correlation_method, "DETERMINISTIC_RULE_CORRELATION")

    # -----------------------------------------------------------------------
    # TEST 11: Multi-session summary computation
    # -----------------------------------------------------------------------
    def test_11_multi_session_summary_computation(self):
        s_fail1 = self._create_starttls_failure_session("f1", "10.0.0.1", 1001, "10.0.0.10", 25, 10, 12)
        s_fail2 = self._create_starttls_failure_session("f2", "10.0.0.2", 1002, "10.0.0.10", 25, 20, 22)
        s_clean = self._create_clean_tls13_session("c1", "10.0.0.3", 1003, "10.0.0.20", 587)

        sessions = [s_fail1, s_fail2, s_clean]
        incidents = IncidentCorrelator.correlate_sessions(sessions)
        summary = IncidentCorrelator.generate_summary(sessions, incidents)

        self.assertEqual(summary.total_sessions, 3)
        self.assertEqual(summary.sessions_with_findings, 2)
        self.assertEqual(summary.incident_count, 1)
        self.assertEqual(summary.critical_high_incident_count, 1)
        self.assertEqual(summary.repeated_pattern_count, 1)
        self.assertEqual(summary.uncorrelated_sessions_count, 1)


if __name__ == "__main__":
    unittest.main()

"""
SecureMailScope X - Evidence-Bounded X.509 Certificate Analyzer Tests (Phase 6 / 6.5)
Deterministic semantic verification tests:
1. Observable valid certificate -> parsed fields preserved.
2. Expired certificate -> CERTIFICATE_EXPIRED finding.
3. Not-yet-valid certificate -> CERTIFICATE_NOT_YET_VALID finding.
4. Weak RSA key (< 2048 bits) -> requires actual observable key size.
5. SHA-1 / MD5 deprecated signature -> uses signature algorithm evidence.
6. TLS 1.3 encrypted certificate -> UNOBSERVABLE_ENCRYPTED, no fake details.
7. Missing certificate in plaintext -> NOT_PRESENT, no fake vulnerability.
8. Incomplete chain -> chain_observed=True, chain_trust_status='NOT_VALIDATED'.
9. Self-issued without verification -> self_issued=True, self_signed=None, FINDING-CERTIFICATE-SELF-ISSUED.
10. Cryptographically self-signed -> self_signed=True, self_signature_verified=True, FINDING-CERTIFICATE-SELF-SIGNED.
11. SHA-256 fingerprint derived strictly from DER bytes (same DER -> same FP, different DER -> different FP).
12. Different certificate bytes never correlate as certificate reuse.
13. Identical DER fingerprints correlate as certificate reuse.
14. Same subject/hostname without identical fingerprint does NOT create CERTIFICATE_REUSE.
15. Real SMTP TLS 1.3 sample -> certificate visibility remains unavailable/encrypted.
16. Validity reference-time policy respects capture timestamp over current system clock.
17. Chain length represents number of actually observed certificates in captured stream.
"""

import os
import sys
import unittest
import hashlib
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
    FindingCategory,
    CertificateVisibility,
    CertificateValidityStatus,
    CertificateDetails
)
from app.forensic.certificate_analyzer import CertificateAnalyzer
from app.forensic.rule_engine import CryptographicRuleEngine
from app.forensic.incident_correlator import IncidentCorrelator
from app.services.analysis_service import AnalysisService


def _generate_test_der_certificate(
    subject_cn: str = "mail.example.org",
    issuer_cn: str = None,
    key_size: int = 2048,
    days_valid: int = 365,
    is_self_signed: bool = True
) -> bytes:
    """Generates real X.509 DER certificate bytes for deterministic cryptographic testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    issuer_name_str = issuer_cn if (issuer_cn and not is_self_signed) else subject_cn

    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name_str)])

    now = datetime.now(timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
    )

    cert = cert_builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


class TestCertificateAnalyzer(unittest.TestCase):

    def _create_session_with_tls(
        self,
        session_id: str = "sess_cert_1",
        version: TLSVersion = TLSVersion.TLSv1_2,
        server_ip: str = "192.0.2.10",
        server_port: int = 465,
        cert_subjects: list = None,
        cert_issuers: list = None,
        not_before: str = None,
        not_after: str = None,
        key_type: str = "RSA",
        key_size: int = 2048,
        sig_alg: str = "sha256WithRSAEncryption",
        fingerprint_sha256: str = None,
        der_bytes: bytes = None,
        cert_count: int = None,
        start_time_epoch: float = 1700000000.0  # 2023-11-14T22:13:20Z
    ) -> EmailSession:
        tls = TLSHandshakeDetails(
            negotiated_tls_version=version,
            selected_cipher_code="0xC02F",
            selected_cipher_name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            cipher_info=CipherSuiteInfo(
                hex_code="0xC02F", name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                key_exchange="ECDHE", encryption="AES-128-GCM",
                hash_algorithm="SHA256", strength=SecurityStrength.STRONG,
                has_pfs=True
            ),
            has_forward_secrecy=True,
            pfs_status="Ephemeral key exchange (ECDHE)",
            client_hello_frame=10,
            server_hello_frame=12,
            certificate_count=cert_count if cert_count is not None else (1 if (cert_subjects or der_bytes) else 0),
            certificate_subjects=cert_subjects or [],
            certificate_issuers=cert_issuers or [],
            certificate_not_before=not_before,
            certificate_not_after=not_after,
            certificate_key_type=key_type,
            certificate_key_size=key_size,
            certificate_sig_alg=sig_alg,
            certificate_fingerprint_sha256=fingerprint_sha256,
            certificate_der_bytes=der_bytes
        )
        sess = EmailSession(
            session_id=session_id,
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.DIRECT_TLS,
            client_ip="192.168.1.50",
            client_port=50000,
            server_ip=server_ip,
            server_port=server_port,
            start_time_epoch=start_time_epoch,
            tls_details=tls,
            evidence_packets=[
                PacketEvidence(10, 0.0, "", "192.168.1.50", 50000, server_ip, server_port, "TLS", 200, "Client Hello"),
                PacketEvidence(12, 0.1, "", "192.168.1.50", 50000, server_ip, server_port, "TLS", 180, "Server Hello")
            ]
        )
        return sess

    # -----------------------------------------------------------------------
    # TEST 1: Observable valid certificate -> parsed fields preserved
    # -----------------------------------------------------------------------
    def test_01_observable_valid_certificate(self):
        sess = self._create_session_with_tls(
            cert_subjects=["CN=mail.securemail.org, O=SecureMail Corp"],
            cert_issuers=["CN=Global Trust CA, O=Global Trust Inc"],
            not_before="2023-01-01T00:00:00Z",
            not_after="2024-01-01T00:00:00Z",
            key_type="RSA",
            key_size=2048,
            sig_alg="sha256WithRSAEncryption",
            fingerprint_sha256="a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
            start_time_epoch=1690000000.0  # 2023-07-22 (Valid in window)
        )
        cert = CertificateAnalyzer.analyze_session(sess)

        self.assertEqual(cert.visibility, CertificateVisibility.OBSERVABLE)
        self.assertEqual(cert.subject, "CN=mail.securemail.org, O=SecureMail Corp")
        self.assertEqual(cert.issuer, "CN=Global Trust CA, O=Global Trust Inc")
        self.assertEqual(cert.validity_status, CertificateValidityStatus.VALID)
        self.assertFalse(cert.self_issued)
        self.assertFalse(cert.self_signed)
        self.assertEqual(cert.public_key_bits, 2048)
        self.assertEqual(cert.signature_algorithm, "sha256WithRSAEncryption")
        self.assertEqual(cert.certificate_fingerprint_sha256, "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef")
        self.assertEqual(cert.chain_trust_status, "NOT_VALIDATED")

    # -----------------------------------------------------------------------
    # TEST 2: Expired certificate -> CERTIFICATE_EXPIRED finding
    # -----------------------------------------------------------------------
    def test_02_expired_certificate_finding(self):
        sess = self._create_session_with_tls(
            cert_subjects=["CN=expired.example.com"],
            cert_issuers=["CN=Example CA"],
            not_before="2020-01-01T00:00:00Z",
            not_after="2021-01-01T00:00:00Z",
            start_time_epoch=1680000000.0  # 2023-03-28 (Past expiration)
        )
        assessment = CryptographicRuleEngine.evaluate_session(sess)
        
        expired_finding = next((f for f in assessment.findings if f.id == "FINDING-CERTIFICATE-EXPIRED"), None)
        self.assertIsNotNone(expired_finding)
        self.assertEqual(expired_finding.severity, FindingSeverity.HIGH)
        self.assertIn("expired", expired_finding.description.lower())
        self.assertIsNotNone(expired_finding.explanation)
        self.assertEqual(expired_finding.explanation.rule_id, "RULE-CERT-EXPIRED")

    # -----------------------------------------------------------------------
    # TEST 3: Not-yet-valid certificate -> CERTIFICATE_NOT_YET_VALID finding
    # -----------------------------------------------------------------------
    def test_03_not_yet_valid_certificate_finding(self):
        sess = self._create_session_with_tls(
            cert_subjects=["CN=future.example.com"],
            cert_issuers=["CN=Example CA"],
            not_before="2025-01-01T00:00:00Z",
            not_after="2026-01-01T00:00:00Z",
            start_time_epoch=1680000000.0  # 2023-03-28 (Before not_before)
        )
        assessment = CryptographicRuleEngine.evaluate_session(sess)

        future_finding = next((f for f in assessment.findings if f.id == "FINDING-CERTIFICATE-NOT-YET-VALID"), None)
        self.assertIsNotNone(future_finding)
        self.assertEqual(future_finding.severity, FindingSeverity.HIGH)
        self.assertIn("not valid before", future_finding.description.lower())

    # -----------------------------------------------------------------------
    # TEST 4: Weak RSA key (< 2048 bits) -> requires actual observable key size
    # -----------------------------------------------------------------------
    def test_04_weak_rsa_key_finding_requires_actual_bits(self):
        sess = self._create_session_with_tls(
            cert_subjects=["CN=weak-rsa.example.com"],
            cert_issuers=["CN=Example CA"],
            not_before="2023-01-01T00:00:00Z",
            not_after="2024-01-01T00:00:00Z",
            key_type="RSA",
            key_size=1024,  # Actual observable weak key length
            start_time_epoch=1690000000.0
        )
        assessment = CryptographicRuleEngine.evaluate_session(sess)

        weak_rsa_finding = next((f for f in assessment.findings if f.id == "FINDING-CERTIFICATE-WEAK-RSA"), None)
        self.assertIsNotNone(weak_rsa_finding)
        self.assertEqual(weak_rsa_finding.severity, FindingSeverity.HIGH)
        self.assertIn("1024", weak_rsa_finding.description)

        # Confirm 2048-bit RSA does NOT trigger weak RSA finding
        sess_ok = self._create_session_with_tls(
            cert_subjects=["CN=ok-rsa.example.com"],
            cert_issuers=["CN=Example CA"],
            not_before="2023-01-01T00:00:00Z",
            not_after="2024-01-01T00:00:00Z",
            key_type="RSA",
            key_size=2048,
            start_time_epoch=1690000000.0
        )
        assess_ok = CryptographicRuleEngine.evaluate_session(sess_ok)
        self.assertIsNone(next((f for f in assess_ok.findings if f.id == "FINDING-CERTIFICATE-WEAK-RSA"), None))

    # -----------------------------------------------------------------------
    # TEST 5: SHA-1 / MD5 deprecated signature -> uses signature algorithm evidence
    # -----------------------------------------------------------------------
    def test_05_sha1_signature_algorithm_evidence_finding(self):
        # SHA-1 in signature algorithm
        sess_sha1 = self._create_session_with_tls(
            cert_subjects=["CN=sha1.example.com"],
            cert_issuers=["CN=Example CA"],
            not_before="2023-01-01T00:00:00Z",
            not_after="2024-01-01T00:00:00Z",
            sig_alg="sha1WithRSAEncryption",
            start_time_epoch=1690000000.0
        )
        assess_sha1 = CryptographicRuleEngine.evaluate_session(sess_sha1)
        sha1_f = next((f for f in assess_sha1.findings if f.id == "FINDING-CERTIFICATE-DEPRECATED-SIG"), None)
        self.assertIsNotNone(sha1_f)
        self.assertEqual(sha1_f.severity, FindingSeverity.HIGH)
        self.assertIn("sha1WithRSAEncryption", sha1_f.description)

        # MD5
        sess_md5 = self._create_session_with_tls(
            cert_subjects=["CN=md5.example.com"],
            cert_issuers=["CN=Example CA"],
            not_before="2023-01-01T00:00:00Z",
            not_after="2024-01-01T00:00:00Z",
            sig_alg="md5WithRSAEncryption",
            start_time_epoch=1690000000.0
        )
        assess_md5 = CryptographicRuleEngine.evaluate_session(sess_md5)
        md5_f = next((f for f in assess_md5.findings if f.id == "FINDING-CERTIFICATE-DEPRECATED-SIG"), None)
        self.assertIsNotNone(md5_f)
        self.assertEqual(md5_f.severity, FindingSeverity.CRITICAL)

    # -----------------------------------------------------------------------
    # TEST 6: TLS 1.3 encrypted certificate -> UNOBSERVABLE_ENCRYPTED, no fake details
    # -----------------------------------------------------------------------
    def test_06_tls13_encrypted_certificate_boundary(self):
        tls = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_cipher_code="0x1302",
            selected_cipher_name="TLS_AES_256_GCM_SHA384",
            client_hello_frame=15,
            server_hello_frame=17
        )
        sess = EmailSession(
            session_id="tls13_sess",
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.DIRECT_TLS,
            client_ip="192.168.1.50",
            client_port=50000,
            server_ip="192.0.2.10",
            server_port=465,
            tls_details=tls
        )
        cert = CertificateAnalyzer.analyze_session(sess)

        self.assertEqual(cert.visibility, CertificateVisibility.UNOBSERVABLE_ENCRYPTED)
        self.assertIsNone(cert.subject)
        self.assertIsNone(cert.issuer)
        self.assertIsNone(cert.not_after)
        self.assertIsNone(cert.certificate_fingerprint_sha256)
        self.assertIsNone(cert.self_issued)
        self.assertIsNone(cert.self_signed)
        self.assertTrue(len(cert.analysis_limitations) > 0)

        # Rule engine must NOT generate any fake certificate vulnerability findings
        assess = CryptographicRuleEngine.evaluate_session(sess)
        cert_findings = [f for f in assess.findings if "CERTIFICATE" in f.id]
        self.assertEqual(len(cert_findings), 0)

    # -----------------------------------------------------------------------
    # TEST 7: Missing certificate in plaintext -> NOT_PRESENT, no fake vulnerability
    # -----------------------------------------------------------------------
    def test_07_plaintext_session_certificate_not_present(self):
        sess = EmailSession(
            session_id="pt_sess",
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.PLAINTEXT,
            client_ip="10.0.0.1",
            client_port=5000,
            server_ip="10.0.0.2",
            server_port=25
        )
        cert = CertificateAnalyzer.analyze_session(sess)
        self.assertEqual(cert.visibility, CertificateVisibility.NOT_PRESENT)

        assess = CryptographicRuleEngine.evaluate_session(sess)
        cert_findings = [f for f in assess.findings if "CERTIFICATE" in f.id]
        self.assertEqual(len(cert_findings), 0)

    # -----------------------------------------------------------------------
    # TEST 8: Incomplete chain -> chain_observed=True, chain_trust_status='NOT_VALIDATED'
    # -----------------------------------------------------------------------
    def test_08_chain_trust_boundary_is_not_validated(self):
        sess = self._create_session_with_tls(
            cert_subjects=["CN=mail.corp.com"],
            cert_issuers=["CN=Corp Intermediate CA"],
            not_before="2023-01-01T00:00:00Z",
            not_after="2024-01-01T00:00:00Z",
            start_time_epoch=1690000000.0
        )
        cert = CertificateAnalyzer.analyze_session(sess)
        self.assertTrue(cert.chain_observed)
        self.assertEqual(cert.chain_trust_status, "NOT_VALIDATED")
        self.assertIn("NOT_VALIDATED", cert.analysis_limitations[0])

    # -----------------------------------------------------------------------
    # TEST 9: Self-issued metadata only -> self_issued=True, self_signed=None, FINDING-CERTIFICATE-SELF-ISSUED
    # -----------------------------------------------------------------------
    def test_09_self_issued_metadata_only_finding(self):
        # Subject == Issuer in metadata, but no raw DER signature bytes to verify self-signature
        sess = self._create_session_with_tls(
            cert_subjects=["CN=selfissued.local, O=Test Corp"],
            cert_issuers=["CN=selfissued.local, O=Test Corp"],
            not_before="2023-01-01T00:00:00Z",
            not_after="2024-01-01T00:00:00Z",
            der_bytes=None,
            start_time_epoch=1690000000.0
        )
        cert = CertificateAnalyzer.analyze_session(sess)
        self.assertTrue(cert.self_issued)
        self.assertIsNone(cert.self_signature_verified)
        self.assertIsNone(cert.self_signed)

        assess = CryptographicRuleEngine.evaluate_session(sess)
        # Must emit FINDING-CERTIFICATE-SELF-ISSUED, NOT FINDING-CERTIFICATE-SELF-SIGNED
        self_issued_f = next((f for f in assess.findings if f.id == "FINDING-CERTIFICATE-SELF-ISSUED"), None)
        self.assertIsNotNone(self_issued_f)
        self.assertEqual(self_issued_f.severity, FindingSeverity.LOW)
        self.assertNotIn("malicious", self_issued_f.description.lower())

        self_signed_f = next((f for f in assess.findings if f.id == "FINDING-CERTIFICATE-SELF-SIGNED"), None)
        self.assertIsNone(self_signed_f)

    # -----------------------------------------------------------------------
    # TEST 10: Cryptographically self-signed -> self_signed=True, self_signature_verified=True, FINDING-CERTIFICATE-SELF-SIGNED
    # -----------------------------------------------------------------------
    def test_10_cryptographically_self_signed_certificate(self):
        der_bytes = _generate_test_der_certificate(
            subject_cn="selfsigned-crypto.local",
            is_self_signed=True
        )
        sess = self._create_session_with_tls(
            der_bytes=der_bytes,
            start_time_epoch=datetime.now(timezone.utc).timestamp()
        )
        cert = CertificateAnalyzer.analyze_session(sess)

        self.assertTrue(cert.self_issued)
        self.assertTrue(cert.self_signature_verified)
        self.assertTrue(cert.self_signed)
        self.assertEqual(cert.subject, "CN=selfsigned-crypto.local")

        assess = CryptographicRuleEngine.evaluate_session(sess)
        self_signed_f = next((f for f in assess.findings if f.id == "FINDING-CERTIFICATE-SELF-SIGNED"), None)
        self.assertIsNotNone(self_signed_f)
        self.assertEqual(self_signed_f.severity, FindingSeverity.MEDIUM)
        self.assertIn("verified", self_signed_f.description.lower())

    # -----------------------------------------------------------------------
    # TEST 11: SHA-256 fingerprint derived strictly from DER bytes
    # -----------------------------------------------------------------------
    def test_11_fingerprint_der_derivation_deterministic(self):
        der_1 = _generate_test_der_certificate(subject_cn="cert1.domain.com")
        der_2 = _generate_test_der_certificate(subject_cn="cert2.domain.com")

        fp1_a = CertificateAnalyzer.compute_fingerprint_from_der(der_1)
        fp1_b = CertificateAnalyzer.compute_fingerprint_from_der(der_1)
        fp2 = CertificateAnalyzer.compute_fingerprint_from_der(der_2)

        # Same DER bytes -> same fingerprint
        self.assertEqual(fp1_a, fp1_b)
        self.assertEqual(fp1_a, hashlib.sha256(der_1).hexdigest().lower())

        # Different DER bytes -> different fingerprint
        self.assertNotEqual(fp1_a, fp2)

    # -----------------------------------------------------------------------
    # TEST 12: Different certificate bytes never correlate as certificate reuse
    # -----------------------------------------------------------------------
    def test_12_different_der_bytes_never_correlate_as_certificate_reuse(self):
        der_1 = _generate_test_der_certificate(subject_cn="shared.domain.com")
        der_2 = _generate_test_der_certificate(subject_cn="shared.domain.com")  # Different serial/key -> different bytes

        s1 = self._create_session_with_tls("s1", der_bytes=der_1)
        s2 = self._create_session_with_tls("s2", der_bytes=der_2)

        # Analyze sessions so fingerprints are extracted from DER bytes
        s1.tls_details.certificate_fingerprint_sha256 = CertificateAnalyzer.analyze_session(s1).certificate_fingerprint_sha256
        s2.tls_details.certificate_fingerprint_sha256 = CertificateAnalyzer.analyze_session(s2).certificate_fingerprint_sha256

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        cert_incidents = [i for i in incidents if i.incident_type == "CERTIFICATE_REUSE"]
        self.assertEqual(len(cert_incidents), 0)

    # -----------------------------------------------------------------------
    # TEST 13: Identical DER fingerprints correlate as certificate reuse
    # -----------------------------------------------------------------------
    def test_13_identical_der_fingerprints_correlate_as_certificate_reuse(self):
        der = _generate_test_der_certificate(subject_cn="reused.corp.com")
        fp = CertificateAnalyzer.compute_fingerprint_from_der(der)

        s1 = self._create_session_with_tls("s1", fingerprint_sha256=fp)
        s2 = self._create_session_with_tls("s2", fingerprint_sha256=fp)

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        cert_incidents = [i for i in incidents if i.incident_type == "CERTIFICATE_REUSE"]
        self.assertEqual(len(cert_incidents), 1)
        self.assertIn("s1", cert_incidents[0].session_ids)
        self.assertIn("s2", cert_incidents[0].session_ids)

    # -----------------------------------------------------------------------
    # TEST 14: Same subject without identical fingerprint does NOT create CERTIFICATE_REUSE
    # -----------------------------------------------------------------------
    def test_14_same_subject_without_identical_fingerprint_no_reuse(self):
        s1 = self._create_session_with_tls("s1", cert_subjects=["CN=mail.target.com"], fingerprint_sha256=None)
        s2 = self._create_session_with_tls("s2", cert_subjects=["CN=mail.target.com"], fingerprint_sha256=None)

        incidents = IncidentCorrelator.correlate_sessions([s1, s2])
        cert_incidents = [i for i in incidents if i.incident_type == "CERTIFICATE_REUSE"]
        self.assertEqual(len(cert_incidents), 0)

    # -----------------------------------------------------------------------
    # TEST 15: Real SMTP TLS 1.3 sample -> certificate visibility remains unavailable/encrypted
    # -----------------------------------------------------------------------
    def test_15_real_smtp_sample_certificate_visibility_encrypted(self):
        real_pcap = "D:/SecureMailScope/pcap_samples/smtp-starttls-test.pcapng"
        if os.path.exists(real_pcap):
            report = AnalysisService.process_local_pcap_path(real_pcap)
            self.assertTrue(len(report.sessions) > 0)
            primary_sess = report.sessions[0]
            self.assertIn("TLS 1.3", primary_sess.tls.negotiated_version)
            self.assertIn("encrypted", primary_sess.tls.certificate_visibility.lower())
            if primary_sess.certificate_details:
                self.assertEqual(primary_sess.certificate_details.visibility, "UNOBSERVABLE_ENCRYPTED")

    # -----------------------------------------------------------------------
    # TEST 16: Validity reference-time policy prefers capture timestamp over system clock
    # -----------------------------------------------------------------------
    def test_16_validity_reference_time_policy_uses_capture_timestamp(self):
        sess = self._create_session_with_tls(
            cert_subjects=["CN=historical.corp.org"],
            cert_issuers=["CN=Historical CA"],
            not_before="2020-01-01T00:00:00Z",
            not_after="2022-01-01T00:00:00Z",
            start_time_epoch=1620000000.0  # 2021-05-03T00:00:00Z (within validity window)
        )
        cert = CertificateAnalyzer.analyze_session(sess)
        self.assertEqual(cert.validity_status, CertificateValidityStatus.VALID)
        self.assertEqual(cert.reference_time_source, "CAPTURE_TIMESTAMP")
        self.assertIn("2021-05-03", cert.validity_reference_time)

    # -----------------------------------------------------------------------
    # TEST 17: Chain length reflects actual observed count without fabricated intermediates
    # -----------------------------------------------------------------------
    def test_17_chain_length_reflects_actual_observed_count(self):
        sess = self._create_session_with_tls(
            cert_subjects=["CN=leaf.mail.org", "CN=intermediate.ca.org"],
            cert_issuers=["CN=intermediate.ca.org", "CN=root.ca.org"],
            cert_count=2
        )
        cert = CertificateAnalyzer.analyze_session(sess)
        self.assertEqual(cert.chain_length, 2)
        self.assertTrue(cert.chain_observed)
        self.assertEqual(cert.chain_trust_status, "NOT_VALIDATED")

    # -----------------------------------------------------------------------
    # TEST 18: Real SMTP TLS 1.2 + X.509 Certificate sample extraction & validation
    # -----------------------------------------------------------------------
    def test_18_real_smtp_tls12_certificate_sample(self):
        real_pcap = r"D:\SecureMailScope\pcap_samples\smtp-tls12-cert.pcapng"
        if os.path.exists(real_pcap):
            report, sessions = AnalysisService._run_pipeline(
                real_pcap,
                "smtp-tls12-cert.pcapng",
                os.path.getsize(real_pcap),
                "test_analysis_cert_12_isolated"
            )
            self.assertTrue(len(report.sessions) > 0)
            primary_sess = report.sessions[0]
            self.assertEqual(primary_sess.tls.negotiated_version, "TLS 1.2")
            self.assertEqual(primary_sess.tls.cipher_name, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")

            cd = primary_sess.certificate_details
            self.assertIsNotNone(cd)
            self.assertEqual(cd.visibility, "OBSERVABLE")
            self.assertIn("mail.securemailscope.local", cd.subject)
            self.assertIn("SecureMailScope Forensics Lab", cd.issuer)
            self.assertIsNotNone(cd.serial_number)
            self.assertEqual(cd.certificate_fingerprint_sha256, "6434f3207ecc2499523296d3b1090febb59ab1a8fde625e0f13efdcf2d096627")
            self.assertEqual(cd.public_key_algorithm, "RSA")
            self.assertEqual(cd.public_key_bits, 2048)
            self.assertEqual(cd.signature_algorithm, "sha256WithRSAEncryption")
            self.assertEqual(cd.validity_status, "VALID")
            self.assertTrue(cd.self_issued)
            self.assertTrue(cd.self_signed)
            self.assertEqual(cd.chain_trust_status, "NOT_VALIDATED")
            self.assertIn("mail.securemailscope.local", cd.san_names)


if __name__ == "__main__":
    unittest.main()

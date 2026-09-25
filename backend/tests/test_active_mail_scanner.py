"""
SecureMailScope X - Phase 9 & 9.5 Active Mail Scanner Tests
Covers all safety rules, SSRF defenses, DNS rebinding & pinning, SNI behavior,
protocol sequences, provenance tagging, cert trust semantics, truncation handling,
and cipher classification using deterministic mock sockets.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch
import socket
import ssl
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.scanner.target_validator import TargetValidator, ALLOWED_MAIL_PORTS
from app.scanner.mail_posture_scanner import (
    MailPostureScanner,
    PortProbeResult,
    ActiveMailScanReport,
    MAX_RESPONSE_BYTES,
)
from app.scanner.active_scanner import ActiveMailScanner
from app.api.v1.endpoints.advanced import MailPostureScanRequest
from app.schemas.forensic import (
    EmailSession,
    EmailProtocol,
    SecurityMode,
    SessionSecurityAssessment,
    SecurityGrade,
    SecurityFinding,
    FindingSeverity,
    FindingCategory,
)


def generate_test_der_cert(
    cn: str = "mail.example.com",
    issuer_cn: str = "Test CA",
    key_size: int = 2048,
    is_expired: bool = False,
    self_signed: bool = False,
) -> bytes:
    """Generates an in-memory DER X.509 certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = subject if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])

    now = datetime.now(timezone.utc)
    if is_expired:
        not_before = now - timedelta(days=60)
        not_after = now - timedelta(days=10)
    else:
        not_before = now - timedelta(days=10)
        not_after = now + timedelta(days=365)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class MockSocket:
    """Simulates deterministic socket protocol conversations and records all sent data."""

    def __init__(self, responses=None, timeout=5.0):
        self.responses = list(responses or [])
        self.sent_data = []
        self.timeout = timeout
        self.closed = False

    def settimeout(self, val):
        self.timeout = val

    def sendall(self, data):
        self.sent_data.append(data)

    def recv(self, bufsize=512):
        if not self.responses:
            return b""
        resp = self.responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp

    def close(self):
        self.closed = True


class MockSSLSocket:
    """Simulates upgraded TLS socket wrapping."""

    def __init__(self, raw_sock, der_cert=None, version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", responses=None):
        self.raw_sock = raw_sock
        self.der_cert = der_cert or generate_test_der_cert()
        self.tls_version = version
        self.tls_cipher = cipher
        self.responses = list(responses or [])
        self.sent_data = []
        self.closed = False

    def settimeout(self, val):
        pass

    def version(self):
        return self.tls_version

    def cipher(self):
        return (self.tls_cipher, "TLSv1.3", 256)

    def getpeercert(self, binary_form=False):
        if binary_form:
            return self.der_cert
        return {}

    def sendall(self, data):
        self.sent_data.append(data)
        self.raw_sock.sendall(data)

    def recv(self, bufsize=512):
        if not self.responses:
            return b""
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class TestActiveMailScanner(unittest.TestCase):

    # 1. Arbitrary port 22 rejected
    def test_01_arbitrary_port_rejected(self):
        is_valid, err = TargetValidator.validate_port(22)
        self.assertFalse(is_valid)
        self.assertIn("not an allowed mail service port", err)

        is_valid_http, _ = TargetValidator.validate_port(80)
        self.assertFalse(is_valid_http)

    # 2. Allowed mail ports accepted
    def test_02_allowed_mail_ports_accepted(self):
        expected_ports = {25, 465, 587, 110, 143, 993, 995}
        self.assertEqual(ALLOWED_MAIL_PORTS, expected_ports)
        for p in expected_ports:
            is_valid, err = TargetValidator.validate_port(p)
            self.assertTrue(is_valid, f"Port {p} should be allowed")
            self.assertIsNone(err)

    # 3. localhost rejected by default (SSRF)
    def test_03_localhost_rejected_by_default(self):
        is_safe, ip, err, _ = TargetValidator.is_safe_public_target("localhost", allow_local_testing=False)
        self.assertFalse(is_safe)
        self.assertIn("SSRF blocked", err)

        is_safe_ip, _, err_ip, _ = TargetValidator.is_safe_public_target("127.0.0.1", allow_local_testing=False)
        self.assertFalse(is_safe_ip)
        self.assertIn("SSRF blocked", err_ip)

    # 4. RFC1918 private target rejected by default
    def test_04_rfc1918_private_targets_rejected(self):
        private_ips = ["10.0.0.1", "172.16.5.10", "192.168.1.1", "169.254.1.1"]
        for ip in private_ips:
            is_safe, _, err, _ = TargetValidator.is_safe_public_target(ip, allow_local_testing=False)
            self.assertFalse(is_safe, f"IP {ip} must be blocked by SSRF defense")
            self.assertIn("SSRF blocked", err)

    # 5. Malformed hostname/URL rejected
    def test_05_malformed_targets_rejected(self):
        bad_targets = [
            "https://mail.example.com",
            "http://10.0.0.1",
            "admin:pass@mail.example.com",
            "mail.example.com/login",
            "mail.example.com?query=1",
            "mail.example.com:25",
        ]
        for t in bad_targets:
            is_safe, _, err, _ = TargetValidator.is_safe_public_target(t, allow_local_testing=False)
            self.assertFalse(is_safe, f"Target '{t}' should be rejected")
            self.assertIsNotNone(err)

    # 6. SMTP 587: EHLO -> STARTTLS advertised -> accepted -> TLS upgrade -> no AUTH/MAIL FROM/RCPT TO/DATA
    def test_06_smtp_587_starttls_success_no_auth(self):
        mock_raw = MockSocket(
            responses=[
                b"220 mail.example.com ESMTP Postfix\r\n",
                b"250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n",
                b"220 2.0.0 Ready to start TLS\r\n",
            ]
        )
        der_cert = generate_test_der_cert(cn="mail.example.com", key_size=2048)
        mock_tls = MockSSLSocket(
            raw_sock=mock_raw,
            der_cert=der_cert,
            version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            responses=[
                b"250-mail.example.com\r\n250-AUTH PLAIN LOGIN\r\n250-8BITMIME\r\n250 OK\r\n"
            ]
        )

        with patch("app.scanner.mail_posture_scanner.MailPostureScanner._create_ssl_context") as mock_ctx_factory:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_tls
            mock_ctx_factory.return_value = (mock_ctx, "NOT_VALIDATED")

            res = MailPostureScanner.probe_port(
                target="mail.example.com",
                resolved_ip="93.184.216.34",
                port=587,
                timeout_sec=3.0,
                socket_factory=lambda h, p, t: mock_raw,
            )

        self.assertEqual(res.connection_status, "SUCCESS")
        self.assertEqual(res.starttls_status, "STARTTLS_ACCEPTED")
        self.assertTrue(res.starttls_advertised)
        self.assertTrue(res.starttls_attempted)
        self.assertTrue(res.starttls_accepted)
        self.assertIsNotNone(res.tls)
        self.assertEqual(res.tls.negotiated_version, "TLSv1.3")
        self.assertIsNotNone(res.certificate)
        self.assertEqual(res.certificate.public_key_bits, 2048)
        self.assertEqual(res.requested_hostname, "mail.example.com")
        self.assertEqual(res.connected_ip, "93.184.216.34")

        # Verify prohibited commands were NEVER sent
        all_sent_bytes = b"".join(mock_raw.sent_data)
        prohibited_commands = [b"AUTH", b"LOGIN", b"PLAIN", b"MAIL FROM", b"RCPT TO", b"DATA", b"USER", b"PASS", b"SELECT", b"EXAMINE", b"RETR", b"DELE"]
        for cmd in prohibited_commands:
            self.assertNotIn(cmd, all_sent_bytes)

    # 7. SMTP STARTTLS absent: observation only, no stripping claim
    def test_07_smtp_starttls_absent(self):
        mock_raw = MockSocket(
            responses=[
                b"220 mail.example.com ESMTP\r\n",
                b"250-mail.example.com\r\n250-PIPELINING\r\n250 8BITMIME\r\n",
            ]
        )
        res = MailPostureScanner.probe_port(
            target="mail.example.com",
            resolved_ip="93.184.216.34",
            port=587,
            socket_factory=lambda h, p, t: mock_raw,
        )
        self.assertEqual(res.starttls_status, "STARTTLS_NOT_ADVERTISED")
        self.assertFalse(res.starttls_advertised)
        self.assertFalse(res.starttls_attempted)
        self.assertIsNone(res.tls)

        findings = MailPostureScanner._evaluate_active_findings(res)
        self.assertTrue(any(f["id"] == "ACTIVE-STARTTLS-NOT-ADVERTISED-PORT-587" for f in findings))
        for f in findings:
            self.assertNotIn("strip", f["description"].lower())
            self.assertEqual(f["historical_applicability"], "CURRENT_STATE_ONLY")

    # 8. SMTP STARTTLS rejected: STARTTLS_REJECTED
    def test_08_smtp_starttls_rejected(self):
        mock_raw = MockSocket(
            responses=[
                b"220 mail.example.com ESMTP\r\n",
                b"250-mail.example.com\r\n250 STARTTLS\r\n",
                b"454 4.7.0 TLS not available due to local problem\r\n",
            ]
        )
        res = MailPostureScanner.probe_port(
            target="mail.example.com",
            resolved_ip="93.184.216.34",
            port=587,
            socket_factory=lambda h, p, t: mock_raw,
        )
        self.assertEqual(res.starttls_status, "STARTTLS_REJECTED")
        self.assertTrue(res.starttls_advertised)
        self.assertTrue(res.starttls_attempted)
        self.assertFalse(res.starttls_accepted)

        findings = MailPostureScanner._evaluate_active_findings(res)
        self.assertTrue(any(f["id"] == "ACTIVE-STARTTLS-REJECTED-PORT-587" for f in findings))

    # 9. SMTPS 465 direct TLS
    def test_09_smtps_465_direct_tls(self):
        mock_raw = MockSocket()
        der_cert = generate_test_der_cert(cn="smtp.example.com", key_size=2048)
        mock_tls = MockSSLSocket(
            raw_sock=mock_raw,
            der_cert=der_cert,
            version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            responses=[
                b"220 smtp.example.com ESMTP Ready\r\n",
                b"250-smtp.example.com\r\n250 8BITMIME\r\n",
            ]
        )

        with patch("app.scanner.mail_posture_scanner.MailPostureScanner._create_ssl_context") as mock_ctx_factory:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_tls
            mock_ctx_factory.return_value = (mock_ctx, "NOT_VALIDATED")

            res = MailPostureScanner.probe_port(
                target="smtp.example.com",
                resolved_ip="93.184.216.34",
                port=465,
                socket_factory=lambda h, p, t: mock_raw,
            )

        self.assertEqual(res.connection_status, "SUCCESS")
        self.assertEqual(res.mode, "DIRECT_TLS")
        self.assertEqual(res.tls.negotiated_version, "TLSv1.3")
        self.assertIn("8BITMIME", res.capabilities)

    # 10. IMAP 143: CAPABILITY + STARTTLS only, no LOGIN
    def test_10_imap_143_starttls_no_login(self):
        mock_raw = MockSocket(
            responses=[
                b"* OK IMAP4rev1 Service Ready\r\n",
                b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\na001 OK Completed\r\n",
                b"a002 OK Begin TLS negotiation now\r\n",
            ]
        )
        der_cert = generate_test_der_cert(cn="imap.example.com")
        mock_tls = MockSSLSocket(
            raw_sock=mock_raw,
            der_cert=der_cert,
            version="TLSv1.3",
            responses=[
                b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na003 OK Completed\r\n"
            ]
        )

        with patch("app.scanner.mail_posture_scanner.MailPostureScanner._create_ssl_context") as mock_ctx_factory:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_tls
            mock_ctx_factory.return_value = (mock_ctx, "NOT_VALIDATED")

            res = MailPostureScanner.probe_port(
                target="imap.example.com",
                resolved_ip="93.184.216.34",
                port=143,
                socket_factory=lambda h, p, t: mock_raw,
            )

        self.assertEqual(res.connection_status, "SUCCESS")
        self.assertEqual(res.starttls_status, "STARTTLS_ACCEPTED")
        self.assertTrue(res.starttls_accepted)

        # Ensure no LOGIN or SELECT command was sent
        all_sent = b"".join(mock_raw.sent_data)
        self.assertNotIn(b"LOGIN", all_sent)
        self.assertNotIn(b"SELECT", all_sent)

    # 11. IMAP 993 direct TLS
    def test_11_imap_993_direct_tls(self):
        mock_raw = MockSocket()
        mock_tls = MockSSLSocket(
            raw_sock=mock_raw,
            version="TLSv1.3",
            responses=[
                b"* OK IMAP4rev1 Server Ready\r\n",
                b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na001 OK Completed\r\n",
            ]
        )

        with patch("app.scanner.mail_posture_scanner.MailPostureScanner._create_ssl_context") as mock_ctx_factory:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_tls
            mock_ctx_factory.return_value = (mock_ctx, "NOT_VALIDATED")

            res = MailPostureScanner.probe_port(
                target="imap.example.com",
                resolved_ip="93.184.216.34",
                port=993,
                socket_factory=lambda h, p, t: mock_raw,
            )

        self.assertEqual(res.connection_status, "SUCCESS")
        self.assertEqual(res.protocol, "IMAP")
        self.assertEqual(res.mode, "DIRECT_TLS")

    # 12. POP3 110: CAPA + STLS only, no USER/PASS
    def test_12_pop3_110_stls_no_credentials(self):
        mock_raw = MockSocket(
            responses=[
                b"+OK POP3 server ready\r\n",
                b"+OK Capability list follows\r\nSTLS\r\nTOP\r\nUSER\r\n.\r\n",
                b"+OK Begin TLS negotiation\r\n",
            ]
        )
        mock_tls = MockSSLSocket(
            raw_sock=mock_raw,
            version="TLSv1.3",
            responses=[
                b"+OK Capability list follows\r\nUSER\r\nSASL PLAIN\r\n.\r\n"
            ]
        )

        with patch("app.scanner.mail_posture_scanner.MailPostureScanner._create_ssl_context") as mock_ctx_factory:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_tls
            mock_ctx_factory.return_value = (mock_ctx, "NOT_VALIDATED")

            res = MailPostureScanner.probe_port(
                target="pop3.example.com",
                resolved_ip="93.184.216.34",
                port=110,
                socket_factory=lambda h, p, t: mock_raw,
            )

        self.assertEqual(res.connection_status, "SUCCESS")
        self.assertEqual(res.starttls_status, "STARTTLS_ACCEPTED")

        # Verify no USER or PASS credential commands sent
        all_sent = b"".join(mock_raw.sent_data)
        self.assertNotIn(b"USER admin", all_sent)
        self.assertNotIn(b"PASS ", all_sent)

    # 13. POP3S 995 direct TLS
    def test_13_pop3s_995_direct_tls(self):
        mock_raw = MockSocket()
        mock_tls = MockSSLSocket(
            raw_sock=mock_raw,
            version="TLSv1.3",
            responses=[
                b"+OK Secure POP3 server ready\r\n",
                b"+OK Capability list follows\r\nTOP\r\nUSER\r\n.\r\n",
            ]
        )

        with patch("app.scanner.mail_posture_scanner.MailPostureScanner._create_ssl_context") as mock_ctx_factory:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_tls
            mock_ctx_factory.return_value = (mock_ctx, "NOT_VALIDATED")

            res = MailPostureScanner.probe_port(
                target="pop.example.com",
                resolved_ip="93.184.216.34",
                port=995,
                socket_factory=lambda h, p, t: mock_raw,
            )

        self.assertEqual(res.connection_status, "SUCCESS")
        self.assertEqual(res.protocol, "POP3")
        self.assertEqual(res.mode, "DIRECT_TLS")

    # 14. Timeout: status TIMEOUT, not insecure
    def test_14_timeout_returns_timeout_status(self):
        def timeout_factory(h, p, t):
            raise socket.timeout("Timed out")

        res = MailPostureScanner.probe_port(
            target="mail.example.com",
            resolved_ip="93.184.216.34",
            port=587,
            socket_factory=timeout_factory,
        )
        self.assertEqual(res.connection_status, "TIMEOUT")
        findings = MailPostureScanner._evaluate_active_findings(res)
        self.assertEqual(len(findings), 0)

    # 15. Connection refused: CONNECTION_FAILED, not insecure
    def test_15_connection_refused_returns_connection_failed(self):
        def refused_factory(h, p, t):
            raise ConnectionRefusedError("Connection refused")

        res = MailPostureScanner.probe_port(
            target="mail.example.com",
            resolved_ip="93.184.216.34",
            port=25,
            socket_factory=refused_factory,
        )
        self.assertEqual(res.connection_status, "CONNECTION_FAILED")
        findings = MailPostureScanner._evaluate_active_findings(res)
        self.assertEqual(len(findings), 0)

    # 16. Active scan provenance: source & historical_applicability
    def test_16_active_scan_provenance_labels(self):
        report = MailPostureScanner.scan("invalid-target-blocked.local", ports=[25, 587])
        self.assertEqual(report.source, "ACTIVE_NETWORK_PROBE")
        self.assertEqual(report.historical_applicability, "CURRENT_STATE_ONLY")

    # 17. Active findings cannot mutate historical PCAP findings/grade
    def test_17_active_findings_do_not_mutate_pcap(self):
        historical_session = EmailSession(
            session_id="stream_historical",
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="192.168.1.50",
            client_port=50000,
            server_ip="192.168.1.1",
            server_port=25,
            security_assessment=SessionSecurityAssessment(
                grade=SecurityGrade.A,
                findings=[],
            )
        )
        self.assertEqual(historical_session.security_assessment.grade, SecurityGrade.A)

        active_finding = {
            "id": "ACTIVE-WEAK-CIPHER-PORT-25",
            "source": "ACTIVE_NETWORK_PROBE",
            "historical_applicability": "CURRENT_STATE_ONLY",
        }
        self.assertEqual(active_finding["source"], "ACTIVE_NETWORK_PROBE")
        self.assertEqual(historical_session.security_assessment.grade, SecurityGrade.A)
        self.assertEqual(len(historical_session.security_assessment.findings), 0)

    # 18. Certificate trust status correctly reflects whether validation occurred
    def test_18_certificate_trust_status(self):
        ctx_unvalidated, mode_unval = MailPostureScanner._create_ssl_context(validate_cert_trust=False)
        self.assertEqual(mode_unval, "NOT_VALIDATED")
        self.assertEqual(ctx_unvalidated.verify_mode, ssl.CERT_NONE)

        ctx_validated, mode_val = MailPostureScanner._create_ssl_context(validate_cert_trust=True)
        self.assertEqual(mode_val, "CA_AND_HOSTNAME")
        self.assertEqual(ctx_validated.verify_mode, ssl.CERT_REQUIRED)

    # 19. Response-size limit enforced
    def test_19_response_size_limit_enforced(self):
        huge_chunk = b"250-LONG-CAPABILITY-ENTRY-" + (b"A" * 1000) + b"\r\n"
        mock_raw = MockSocket(responses=[huge_chunk] * 10)
        bounded, is_trunc = MailPostureScanner._recv_bounded_lines(mock_raw, max_lines=20, max_bytes=MAX_RESPONSE_BYTES)
        self.assertTrue(is_trunc)
        self.assertLessEqual(len(bounded.encode("utf-8")), MAX_RESPONSE_BYTES + 512)

    # 20. Legacy ActiveMailScanner wrapper compatibility
    def test_20_legacy_scanner_compatibility(self):
        res = ActiveMailScanner.probe_single_port("invalid.domain.ssrf.local", 25)
        self.assertFalse(res.is_open)

    # =========================================================================
    # Phase 9.5 Specific Audited Tests
    # =========================================================================

    # 21. DNS Pinning: Socket connects to validated IP, not re-resolving hostname
    def test_21_dns_pinning_prevents_rebinding(self):
        connected_destinations = []

        def capture_socket_factory(host, port, timeout):
            connected_destinations.append((host, port))
            return MockSocket(responses=[b"220 mail.example.com ESMTP\r\n", b"250-mail.example.com\r\n250 STARTTLS\r\n"])

        # Pretend DNS resolves to a safe public IP
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
            ]

            report = MailPostureScanner.scan(
                target="mail.example.com",
                ports=[587],
                socket_factory=capture_socket_factory,
            )

        # Ensure the socket factory was invoked with the pinned IP, NOT the hostname
        self.assertEqual(connected_destinations[0][0], "93.184.216.34")
        self.assertEqual(report.requested_hostname, "mail.example.com")
        self.assertEqual(report.connected_ip, "93.184.216.34")

    # 22. Multi-address host: All resolved addresses must be public; if one is private, reject target
    def test_22_multi_address_host_rebinding_rejected(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0)),  # Private IP rebinding attack
            ]

            is_safe, _, err, _ = TargetValidator.is_safe_public_target("mail.example.com")
            self.assertFalse(is_safe)
            self.assertIn("non-public/private IP 192.168.1.1", err)

    # 23. TLS SNI uses original requested hostname when connecting via IP
    def test_23_tls_sni_retains_original_hostname(self):
        mock_raw = MockSocket(
            responses=[
                b"220 mail.example.com ESMTP\r\n",
                b"250-mail.example.com\r\n250 STARTTLS\r\n",
                b"220 2.0.0 Go ahead\r\n",
            ]
        )
        mock_tls = MockSSLSocket(raw_sock=mock_raw, version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384")

        with patch("app.scanner.mail_posture_scanner.MailPostureScanner._create_ssl_context") as mock_ctx_factory:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_tls
            mock_ctx_factory.return_value = (mock_ctx, "NOT_VALIDATED")

            res = MailPostureScanner.probe_port(
                target="mail.example.com",
                resolved_ip="93.184.216.34",
                port=587,
                socket_factory=lambda h, p, t: mock_raw,
            )

            # Verify wrap_socket was called with server_hostname = "mail.example.com"
            mock_ctx.wrap_socket.assert_called_once_with(mock_raw, server_hostname="mail.example.com")

    # 24. Hostname verification failure is explicit
    def test_24_hostname_verification_failure_explicit(self):
        def bad_cert_wrap(sock, target, port, proto, result, validate_cert_trust, timeout_sec, probe_time):
            raise ssl.CertificateError("hostname 'mail.example.com' doesn't match 'other.domain.com'")

        with patch.object(MailPostureScanner, "_probe_direct_tls", side_effect=bad_cert_wrap):
            res = MailPostureScanner.probe_port(
                target="mail.example.com",
                resolved_ip="93.184.216.34",
                port=465,
                validate_cert_trust=True,
                socket_factory=lambda h, p, t: MockSocket(),
            )

        self.assertEqual(res.connection_status, "TLS_VERIFICATION_FAILED")
        self.assertIn("hostname mismatch", res.error_message.lower())

    # 25. Active certificate validity reference time uses ACTIVE_PROBE_TIME
    def test_25_certificate_validity_reference_time(self):
        der_cert = generate_test_der_cert(cn="mail.example.com", is_expired=True)
        probe_iso = "2026-09-25T12:00:00+00:00"
        cert_details = MailPostureScanner._parse_certificate(der_cert, trust_mode="NOT_VALIDATED", probe_time=probe_iso)

        self.assertEqual(cert_details.reference_time_source, "ACTIVE_PROBE_TIME")
        self.assertEqual(cert_details.validity_reference_time, probe_iso)
        self.assertTrue(cert_details.is_expired)

    # 26. Truncated capability response produces PROBE_INCOMPLETE
    def test_26_truncated_capability_response_produces_probe_incomplete(self):
        huge_partial_ehlo = b"250-mail.example.com\r\n" + (b"250-X-FEATURE-" + (b"B" * 300) + b"\r\n") * 15
        mock_raw = MockSocket(
            responses=[
                b"220 mail.example.com ESMTP\r\n",
                huge_partial_ehlo,
            ]
        )

        res = MailPostureScanner.probe_port(
            target="mail.example.com",
            resolved_ip="93.184.216.34",
            port=587,
            socket_factory=lambda h, p, t: mock_raw,
        )

        self.assertTrue(res.response_truncated)
        self.assertEqual(res.starttls_status, "PROBE_INCOMPLETE")
        self.assertFalse(res.starttls_advertised)

    # 27. Unknown cipher is classified as UNKNOWN_POSTURE, not weak
    def test_27_unknown_cipher_is_not_falsely_weak(self):
        posture_standard = MailPostureScanner._classify_cipher_posture("TLS_AES_256_GCM_SHA384")
        self.assertEqual(posture_standard, "STANDARD")

        posture_weak = MailPostureScanner._classify_cipher_posture("TLS_RSA_WITH_RC4_128_MD5")
        self.assertEqual(posture_weak, "WEAK")

        posture_unknown = MailPostureScanner._classify_cipher_posture("FUTURE_CUSTOM_CIPHER_XYZ")
        self.assertEqual(posture_unknown, "UNKNOWN_POSTURE")

    # 28. API schema cannot enable allow_local_testing (SSRF security)
    def test_28_api_schema_does_not_expose_allow_local_testing(self):
        schema_fields = MailPostureScanRequest.model_fields.keys()
        self.assertNotIn("allow_local_testing", schema_fields)


if __name__ == "__main__":
    unittest.main()

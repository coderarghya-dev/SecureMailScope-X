import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from app.tls.cert_analyzer import CertificateAnalyzer


class TestCertificateAnalyzer(unittest.TestCase):

    def _generate_test_cert(self, days_before=1, days_after=30, key_size=2048, sig_hash=hashes.SHA256(), cn="mail.example.com", san="mail.example.com") -> bytes:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=days_before))
            .not_valid_after(now + timedelta(days=days_after))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
            .sign(private_key, sig_hash)
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_01_valid_cert_parsed(self):
        der = self._generate_test_cert(days_before=1, days_after=90, key_size=2048)
        info = CertificateAnalyzer.parse_der(der, target_hostname="mail.example.com")
        self.assertEqual(info.subject_cn, "mail.example.com")
        self.assertEqual(info.key_size_bits, 2048)
        self.assertFalse(info.is_expired)

    def test_02_expired_cert_detected(self):
        der = self._generate_test_cert(days_before=60, days_after=-5, key_size=2048)
        info = CertificateAnalyzer.parse_der(der)
        self.assertTrue(info.is_expired)
        self.assertTrue(any(f["id"] == "FINDING-CERT-EXPIRED" for f in info.findings))

    def test_03_weak_rsa_key_detected(self):
        der = self._generate_test_cert(days_before=1, days_after=30, key_size=1024)
        info = CertificateAnalyzer.parse_der(der)
        self.assertEqual(info.key_size_bits, 1024)
        self.assertTrue(any(f["id"] == "FINDING-CERT-WEAK-RSA-KEY" for f in info.findings))

    def test_04_hostname_mismatch_detected(self):
        der = self._generate_test_cert(days_before=1, days_after=30, cn="mail.other.com", san="mail.other.com")
        info = CertificateAnalyzer.parse_der(der, target_hostname="mail.secure.com")
        self.assertTrue(any(f["id"] == "FINDING-CERT-HOSTNAME-MISMATCH" for f in info.findings))


if __name__ == "__main__":
    unittest.main()

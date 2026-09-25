"""
SecureMailScope X - X.509 Certificate Forensic Analyzer
Analyzes observable X.509 certificates from TLS handshakes or active scans.
Adheres strictly to evidence boundaries (TLS 1.3 certificates are encrypted passively).
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa


@dataclass
class CertificateInfo:
    subject_cn: Optional[str] = None
    subject_raw: str = ""
    issuer_cn: Optional[str] = None
    issuer_raw: str = ""
    san_list: List[str] = field(default_factory=list)
    serial_number_hex: str = ""
    not_before_iso: str = ""
    not_after_iso: str = ""
    is_expired: bool = False
    days_until_expiration: int = 0
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    key_size_bits: Optional[int] = None
    ec_curve_name: Optional[str] = None
    is_self_signed: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject_cn": self.subject_cn,
            "subject_raw": self.subject_raw,
            "issuer_cn": self.issuer_cn,
            "issuer_raw": self.issuer_raw,
            "san_list": self.san_list,
            "serial_number_hex": self.serial_number_hex,
            "not_before_iso": self.not_before_iso,
            "not_after_iso": self.not_after_iso,
            "is_expired": self.is_expired,
            "days_until_expiration": self.days_until_expiration,
            "signature_algorithm": self.signature_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
            "key_size_bits": self.key_size_bits,
            "ec_curve_name": self.ec_curve_name,
            "is_self_signed": self.is_self_signed,
            "findings": self.findings,
        }


class CertificateAnalyzer:
    """Parses DER or PEM X.509 certificates and checks forensic security criteria."""

    @classmethod
    def parse_der(cls, der_bytes: bytes, target_hostname: Optional[str] = None) -> CertificateInfo:
        cert = x509.load_der_x509_certificate(der_bytes)
        return cls._analyze_cert_object(cert, target_hostname)

    @classmethod
    def parse_pem(cls, pem_bytes: bytes, target_hostname: Optional[str] = None) -> CertificateInfo:
        cert = x509.load_pem_x509_certificate(pem_bytes)
        return cls._analyze_cert_object(cert, target_hostname)

    @classmethod
    def _analyze_cert_object(cls, cert: x509.Certificate, target_hostname: Optional[str] = None) -> CertificateInfo:
        now = datetime.now(timezone.utc)
        
        # Subject and Issuer
        subject_cn = None
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                subject_cn = str(attr.value)
                break
        
        issuer_cn = None
        for attr in cert.issuer:
            if attr.oid == x509.NameOID.COMMON_NAME:
                issuer_cn = str(attr.value)
                break

        # SAN
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                san_list.append(str(name.value))
        except Exception:
            pass

        # Validity
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        is_expired = now > not_after or now < not_before
        days_until_expiration = (not_after - now).days

        # Public Key details
        pub_key = cert.public_key()
        pub_key_alg = type(pub_key).__name__
        key_size = None
        curve_name = None

        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key_alg = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key_alg = "ECDSA / EC"
            curve_name = pub_key.curve.name
            key_size = pub_key.curve.key_size
        elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub_key_alg = "EdDSA"
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_key_alg = "DSA"
            key_size = pub_key.key_size

        sig_alg = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)
        is_self_signed = cert.subject == cert.issuer

        info = CertificateInfo(
            subject_cn=subject_cn,
            subject_raw=cert.subject.rfc4514_string(),
            issuer_cn=issuer_cn,
            issuer_raw=cert.issuer.rfc4514_string(),
            san_list=san_list,
            serial_number_hex=hex(cert.serial_number),
            not_before_iso=not_before.isoformat(),
            not_after_iso=not_after.isoformat(),
            is_expired=is_expired,
            days_until_expiration=days_until_expiration,
            signature_algorithm=sig_alg,
            public_key_algorithm=pub_key_alg,
            key_size_bits=key_size,
            ec_curve_name=curve_name,
            is_self_signed=is_self_signed,
        )

        # Forensic findings on certificate
        if is_expired:
            info.findings.append({
                "id": "FINDING-CERT-EXPIRED",
                "title": "X.509 Certificate Expired or Not Yet Valid",
                "severity": "CRITICAL",
                "description": f"Certificate expired on {not_after.isoformat()} (Validity: {not_before.isoformat()} to {not_after.isoformat()}).",
            })
        elif days_until_expiration < 14:
            info.findings.append({
                "id": "FINDING-CERT-EXPIRING-SOON",
                "title": "X.509 Certificate Expiring Imminently",
                "severity": "MEDIUM",
                "description": f"Certificate expires in {days_until_expiration} days.",
            })

        if key_size and pub_key_alg == "RSA" and key_size < 2048:
            info.findings.append({
                "id": "FINDING-CERT-WEAK-RSA-KEY",
                "title": f"Weak RSA Key Size ({key_size} bits)",
                "severity": "HIGH",
                "description": f"RSA key length of {key_size} bits is cryptographically weak. Enforce minimum 2048-bit RSA.",
            })

        if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
            info.findings.append({
                "id": "FINDING-CERT-WEAK-SIG-ALGO",
                "title": f"Weak Certificate Signature Algorithm ({sig_alg})",
                "severity": "HIGH",
                "description": f"Certificate is signed using deprecated digest {sig_alg}. Vulnerable to collision attacks.",
            })

        if is_self_signed and not is_expired:
            info.findings.append({
                "id": "FINDING-CERT-SELF-SIGNED",
                "title": "Self-Signed Certificate Detected",
                "severity": "MEDIUM",
                "description": "Certificate is self-signed and not issued by a recognized public or enterprise CA.",
            })

        # Hostname verification if target hostname provided
        if target_hostname:
            matched = False
            clean_target = target_hostname.strip().lower()
            all_names = [subject_cn.lower()] if subject_cn else []
            all_names.extend([s.lower() for s in san_list])

            for name in all_names:
                if name.startswith("*."):
                    domain_suffix = name[2:]
                    if clean_target.endswith(domain_suffix) and clean_target.count('.') == name.count('.'):
                        matched = True
                        break
                elif name == clean_target:
                    matched = True
                    break

            if not matched and all_names:
                info.findings.append({
                    "id": "FINDING-CERT-HOSTNAME-MISMATCH",
                    "title": f"Certificate Hostname Mismatch ({target_hostname})",
                    "severity": "HIGH",
                    "description": f"Target hostname '{target_hostname}' does not match certificate CN '{subject_cn}' or SANs ({', '.join(san_list)}).",
                })

        return info

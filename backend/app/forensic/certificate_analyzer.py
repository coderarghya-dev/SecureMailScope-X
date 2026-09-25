"""
SecureMailScope X - Evidence-Bounded X.509 Certificate Analyzer (Phase 6 / 6.5)
Evaluates observable X.509 certificate metadata, validity boundaries, key strengths,
and signature algorithms from passive captures while enforcing strict visibility limits for TLS 1.3.

Core Principles:
1. Never fabricate certificate details.
2. TLS 1.3 encrypted handshakes return UNOBSERVABLE_ENCRYPTED without fake subjects/issuers/validity.
3. Passive PCAP does not validate trust stores -> chain_trust_status is strictly NOT_VALIDATED.
4. Validity reference time uses capture timestamp when available; analysis time as explicit fallback.
5. Certificate reuse strictly requires identical observable SHA-256 certificate fingerprints derived from DER bytes.
6. Subject == Issuer proves only SELF-ISSUED; cryptographically verified self-signature is required for SELF-SIGNED.
"""

from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
import hashlib
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

from app.schemas.forensic import (
    EmailSession,
    SecurityMode,
    TLSVersion,
    CertificateVisibility,
    CertificateValidityStatus,
    CertificateDetails
)


class CertificateAnalyzer:
    """Evidence-bounded passive certificate analyzer."""

    @staticmethod
    def compute_fingerprint_from_der(der_bytes: bytes) -> str:
        """
        Computes SHA-256 certificate fingerprint strictly from raw DER-encoded bytes.
        Does not use metadata strings, PEM normalization, or subject text.
        """
        return hashlib.sha256(der_bytes).hexdigest().lower()

    @staticmethod
    def _parse_timestamp(dt_str: Optional[str]) -> Optional[datetime]:
        """Parses common X.509 validity date string formats to UTC datetime."""
        if not dt_str:
            return None
        s = str(dt_str).strip()
        
        # Formats to attempt
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%SZ",
            "%b %d %H:%M:%S %Y GMT",
            "%b %d %H:%M:%S %Y",
            "%Y-%m-%d",
            "%Y%m%d%H%M%SZ",
            "%y%m%d%H%M%SZ"
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(s, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
                
        # Try ISO fromisoformat fallback
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    @classmethod
    def verify_self_signature_from_der(cls, der_bytes: bytes) -> Tuple[bool, Optional[bool]]:
        """
        Parses DER certificate bytes and performs cryptographic self-signature verification.
        Returns:
            (self_issued: bool, self_signature_verified: Optional[bool])
        """
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
            self_issued = (cert.subject == cert.issuer)
            if not self_issued:
                return False, False
            
            try:
                cert.verify_directly_issued_by(cert)
                return True, True
            except Exception:
                return True, False
        except Exception:
            return False, None

    @classmethod
    def parse_der_certificate(
        cls,
        der_bytes: bytes,
        ref_dt: Optional[datetime] = None,
        frame_number: Optional[int] = None
    ) -> CertificateDetails:
        """
        Parses raw DER certificate bytes into a fully validated CertificateDetails model.
        """
        if not ref_dt:
            ref_dt = datetime.now(timezone.utc)
            ref_source = "ANALYSIS_TIMESTAMP"
        else:
            ref_source = "CAPTURE_TIMESTAMP"

        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception as e:
            return CertificateDetails(
                visibility=CertificateVisibility.INCOMPLETE,
                frame_number=frame_number,
                chain_observed=False,
                chain_trust_status="NOT_VALIDATED",
                analysis_limitations=[f"Failed to parse observable DER certificate bytes: {str(e)}"]
            )

        # Subject and Issuer
        subj = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        serial_str = str(cert.serial_number)

        # Validity dates
        try:
            not_before_dt = cert.not_valid_before_utc
            not_after_dt = cert.not_valid_after_utc
        except AttributeError:
            not_before_dt = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after_dt = cert.not_valid_after.replace(tzinfo=timezone.utc)

        not_before_raw = not_before_dt.isoformat()
        not_after_raw = not_after_dt.isoformat()

        validity_status = CertificateValidityStatus.UNKNOWN
        days_until_exp: Optional[int] = None
        if not_before_dt and not_after_dt:
            days_until_exp = (not_after_dt - ref_dt).days
            if ref_dt < not_before_dt:
                validity_status = CertificateValidityStatus.NOT_YET_VALID
            elif ref_dt > not_after_dt:
                validity_status = CertificateValidityStatus.EXPIRED
            else:
                validity_status = CertificateValidityStatus.VALID

        # Public Key details
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = f"ECDSA ({pub_key.curve.name})"
            key_size = pub_key.curve.key_size
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            key_type = "Ed25519"
            key_size = 256
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            key_type = "Ed448"
            key_size = 448
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type = "DSA"
            key_size = pub_key.key_size
        else:
            key_type = pub_key.__class__.__name__
            key_size = getattr(pub_key, "key_size", None)

        # Signature algorithm
        sig_alg = cert.signature_algorithm_oid._name

        # Fingerprint strictly from DER bytes
        fp_sha256 = cls.compute_fingerprint_from_der(der_bytes)

        # SAN names
        san_list: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                san_list.append(str(name.value))
        except Exception:
            pass

        # Self-issued vs self-signed verification
        self_issued = (cert.subject == cert.issuer)
        self_sig_verified: Optional[bool] = None
        self_signed: Optional[bool] = None

        if self_issued:
            try:
                cert.verify_directly_issued_by(cert)
                self_sig_verified = True
                self_signed = True
            except Exception:
                self_sig_verified = False
                self_signed = False
        else:
            self_sig_verified = False
            self_signed = False

        return CertificateDetails(
            visibility=CertificateVisibility.OBSERVABLE,
            frame_number=frame_number,
            subject=subj,
            issuer=issuer,
            serial_number=serial_str,
            not_before=not_before_raw,
            not_after=not_after_raw,
            validity_status=validity_status,
            days_until_expiry=days_until_exp,
            validity_reference_time=ref_dt.isoformat(),
            reference_time_source=ref_source,
            self_issued=self_issued,
            self_signature_verified=self_sig_verified,
            self_signed=self_signed,
            signature_algorithm=sig_alg,
            public_key_algorithm=key_type,
            public_key_bits=key_size,
            certificate_fingerprint_sha256=fp_sha256,
            san_names=san_list,
            chain_length=1,
            chain_observed=True,
            chain_trust_status="NOT_VALIDATED",
            analysis_limitations=[
                "Passive capture analysis cannot establish root trust store validation; certificate chain is NOT_VALIDATED."
            ]
        )

    @classmethod
    def analyze_session(cls, session: EmailSession) -> CertificateDetails:
        """
        Extracts and evaluates certificate evidence strictly from observed session facts.
        """
        tls = session.tls_details

        # -------------------------------------------------------------------
        # 1. Plaintext / No TLS -> NOT_PRESENT
        # -------------------------------------------------------------------
        if not tls or session.security_mode == SecurityMode.PLAINTEXT:
            return CertificateDetails(
                visibility=CertificateVisibility.NOT_PRESENT,
                chain_observed=False,
                chain_trust_status="NOT_APPLICABLE",
                analysis_limitations=["No transport-layer security or certificate exchange in cleartext session."]
            )

        # -------------------------------------------------------------------
        # 2. TLS 1.3 Encrypted Certificate Handshake -> UNOBSERVABLE_ENCRYPTED
        # -------------------------------------------------------------------
        # In TLS 1.3, Certificate messages are sent encrypted under handshake keys (RFC 8446 Section 4.4.2).
        # Unless explicit unencrypted raw certificate bytes were passed, visibility is strictly encrypted.
        if tls.negotiated_tls_version == TLSVersion.TLSv1_3:
            # Check if any non-standard unencrypted cert facts were supplied
            has_observable_cert = bool(
                tls.certificate_der_bytes or tls.certificate_fingerprint_sha256 or (
                    tls.certificate_subjects and tls.certificate_not_after
                )
            )
            if not has_observable_cert:
                return CertificateDetails(
                    visibility=CertificateVisibility.UNOBSERVABLE_ENCRYPTED,
                    frame_number=tls.server_hello_frame,
                    chain_observed=False,
                    chain_trust_status="NOT_VALIDATED",
                    analysis_limitations=[
                        "Certificate properties unavailable from passive capture because the TLS 1.3 certificate message is encrypted (RFC 8446 Section 4.4.2)."
                    ]
                )

        # -------------------------------------------------------------------
        # Reference-Time Determination
        # -------------------------------------------------------------------
        if session.start_time_epoch and session.start_time_epoch > 0:
            ref_dt = datetime.fromtimestamp(session.start_time_epoch, tz=timezone.utc)
            ref_source = "CAPTURE_TIMESTAMP"
        elif session.evidence_packets and session.evidence_packets[0].timestamp_epoch > 0:
            ref_dt = datetime.fromtimestamp(session.evidence_packets[0].timestamp_epoch, tz=timezone.utc)
            ref_source = "CAPTURE_TIMESTAMP"
        else:
            ref_dt = datetime.now(timezone.utc)
            ref_source = "ANALYSIS_TIMESTAMP"

        # -------------------------------------------------------------------
        # 3. If raw DER bytes are available, parse directly
        # -------------------------------------------------------------------
        if tls.certificate_der_bytes:
            cert_details = cls.parse_der_certificate(
                tls.certificate_der_bytes,
                ref_dt=ref_dt,
                frame_number=tls.server_hello_frame
            )
            if tls.certificate_count and tls.certificate_count > 1:
                cert_details.chain_length = tls.certificate_count
            return cert_details

        # -------------------------------------------------------------------
        # 4. Check for Observable Certificate Metadata in TLS 1.2 / Direct Handshake
        # -------------------------------------------------------------------
        subj = tls.certificate_subjects[0] if tls.certificate_subjects else None
        issuer = tls.certificate_issuers[0] if tls.certificate_issuers else None
        not_before_raw = tls.certificate_not_before
        not_after_raw = tls.certificate_not_after
        fp_sha256 = tls.certificate_fingerprint_sha256
        key_type = tls.certificate_key_type
        key_size = tls.certificate_key_size
        sig_alg = tls.certificate_sig_alg
        cert_count = tls.certificate_count or (len(tls.certificate_subjects) if tls.certificate_subjects else 0)

        # If no certificate attributes are observed at all
        if not subj and not issuer and not not_after_raw and not fp_sha256:
            return CertificateDetails(
                visibility=CertificateVisibility.UNKNOWN,
                frame_number=tls.server_hello_frame,
                chain_observed=False,
                chain_trust_status="NOT_VALIDATED",
                analysis_limitations=["Certificate handshake frames were not observed or captured in stream."]
            )

        # -------------------------------------------------------------------
        # 5. Validity Assessment
        # -------------------------------------------------------------------
        not_before_dt = cls._parse_timestamp(not_before_raw)
        not_after_dt = cls._parse_timestamp(not_after_raw)

        validity_status = CertificateValidityStatus.UNKNOWN
        days_until_exp: Optional[int] = None

        if not_before_dt and not_after_dt:
            days_until_exp = (not_after_dt - ref_dt).days
            if ref_dt < not_before_dt:
                validity_status = CertificateValidityStatus.NOT_YET_VALID
            elif ref_dt > not_after_dt:
                validity_status = CertificateValidityStatus.EXPIRED
            else:
                validity_status = CertificateValidityStatus.VALID
        elif not_after_dt:
            days_until_exp = (not_after_dt - ref_dt).days
            if ref_dt > not_after_dt:
                validity_status = CertificateValidityStatus.EXPIRED
            else:
                validity_status = CertificateValidityStatus.VALID

        # -------------------------------------------------------------------
        # 6. Self-Issued vs Self-Signed Assessment (Metadata only)
        # -------------------------------------------------------------------
        # Subject == Issuer alone proves only SELF-ISSUED.
        # Without raw signature bytes to verify with the public key,
        # self_signed remains Unknown (None), and self_signature_verified is None.
        self_issued = None
        if subj and issuer:
            self_issued = (subj.strip().lower() == issuer.strip().lower())

        self_sig_verified = None
        self_signed = None

        # -------------------------------------------------------------------
        # 7. Chain Observability & Trust Boundary
        # -------------------------------------------------------------------
        chain_len = cert_count if cert_count > 0 else (1 if (subj or fp_sha256) else 0)
        chain_obs = (chain_len > 0)

        limitations: List[str] = [
            "Passive capture analysis cannot establish root trust store validation; certificate chain is NOT_VALIDATED."
        ]
        if not fp_sha256:
            limitations.append("Raw DER certificate bytes were not observable; SHA-256 fingerprint unavailable.")
        if self_issued and self_sig_verified is None:
            limitations.append("Certificate is self-issued; raw signature bytes were unavailable to verify self-signature.")

        return CertificateDetails(
            visibility=CertificateVisibility.OBSERVABLE,
            frame_number=tls.server_hello_frame,
            subject=subj,
            issuer=issuer,
            serial_number=None,
            not_before=not_before_raw,
            not_after=not_after_raw,
            validity_status=validity_status,
            days_until_expiry=days_until_exp,
            validity_reference_time=ref_dt.isoformat(),
            reference_time_source=ref_source,
            self_issued=self_issued,
            self_signature_verified=self_sig_verified,
            self_signed=self_signed,
            signature_algorithm=sig_alg,
            public_key_algorithm=key_type,
            public_key_bits=key_size,
            certificate_fingerprint_sha256=fp_sha256,
            san_names=[],
            chain_length=chain_len,
            chain_observed=chain_obs,
            chain_trust_status="NOT_VALIDATED",
            analysis_limitations=limitations
        )

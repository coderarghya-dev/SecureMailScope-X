"""
SecureMailScope X - Explainable AI-Ready TLS Anomaly Detection Engine (Phase 26)
Evaluates observed session features against heuristic, statistical, and security baselines
to flag cryptographic regressions, STARTTLS stripping, cipher/version downgrades,
and certificate anomalies with full evidence bounding and frame anchors.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from ..schemas.forensic import EmailSession, SecurityMode, TLSVersion, CertificateVisibility, CertificateValidityStatus


@dataclass
class TLSAnomaly:
    anomaly_id: str
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    anomaly_score: float  # 0.0 - 100.0
    confidence: float  # 0.0 - 100.0
    category: str
    observed_evidence: Dict[str, Any] = field(default_factory=dict)
    frame_anchors: List[int] = field(default_factory=list)
    explanation: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "title": self.title,
            "severity": self.severity,
            "anomaly_score": self.anomaly_score,
            "confidence": self.confidence,
            "category": self.category,
            "observed_evidence": self.observed_evidence,
            "frame_anchors": self.frame_anchors,
            "explanation": self.explanation,
            "remediation": self.remediation,
        }


@dataclass
class SessionAnomalyReport:
    session_id: str
    total_anomalies: int
    overall_anomaly_score: float  # 0.0 - 100.0
    highest_severity: str
    anomalies: List[TLSAnomaly] = field(default_factory=list)
    detection_method: str = "EXPLAINABLE_FEATURE_ANOMALY_ENGINE"
    disclaimer: str = "Explainable heuristic anomaly scoring — deterministic, evidence-driven feature evaluation without opaque black-box models."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "total_anomalies": self.total_anomalies,
            "overall_anomaly_score": self.overall_anomaly_score,
            "highest_severity": self.highest_severity,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "detection_method": self.detection_method,
            "disclaimer": self.disclaimer,
        }


class TLSAnomalyDetector:
    """Explainable anomaly detection engine evaluating multi-dimensional session features."""

    @classmethod
    def detect_session_anomalies(cls, session: EmailSession) -> SessionAnomalyReport:
        anomalies: List[TLSAnomaly] = []
        tls = getattr(session, "tls_details", None)
        st = getattr(session, "starttls_state", None)
        cert = getattr(session, "certificate_details", None) or (getattr(session.tls_details, "certificate_details", None) if tls else None)
        ev_pkts = getattr(session, "evidence_packets", []) or []

        # 1. Cleartext / Plaintext Traffic on Secure/Standard Ports
        if session.security_mode == SecurityMode.PLAINTEXT or not tls:
            frames = [ep.frame_number for ep in ev_pkts[:5]] if ev_pkts else []
            remed_text = "Enforce mandatory TLS encryption via STLS (POP3 port 110) or Direct TLS (port 995)." if session.protocol.value == "POP3" else (
                "Enforce mandatory TLS encryption via STARTTLS (SMTP port 587) or Direct TLS (port 465)." if session.protocol.value == "SMTP" else (
                    "Enforce mandatory TLS encryption via STARTTLS (IMAP port 143) or Direct TLS (port 993)."
                )
            )
            anomalies.append(TLSAnomaly(
                anomaly_id="ANOMALY-PLAINTEXT-UNENCRYPTED",
                title="Unencrypted Cleartext Email Session",
                severity="CRITICAL",
                anomaly_score=95.0,
                confidence=100.0,
                category="CLEARText_EXPOSURE",
                observed_evidence={
                    "protocol": session.protocol.value,
                    "server_port": session.server_port,
                    "security_mode": "PLAINTEXT",
                    "tls_negotiated": False
                },
                frame_anchors=frames,
                explanation=f"Plaintext transport may expose authentication credentials, headers, and payloads over port {session.server_port} with no TLS encryption negotiated.",
                remediation=remed_text
            ))

        # 2. STARTTLS Stripping / Downgrade: Advertised but Not Requested
        if st and st.advertised and not st.requested and session.security_mode != SecurityMode.DIRECT_TLS:
            adv_f = [st.advertised_frame] if st.advertised_frame else []
            anomalies.append(TLSAnomaly(
                anomaly_id="ANOMALY-STARTTLS-UNREQUESTED",
                title="Potential STARTTLS Stripping / Upgrade Bypass",
                severity="HIGH",
                anomaly_score=85.0,
                confidence=90.0,
                category="DOWNGRADE_ATTACK",
                observed_evidence={
                    "advertised": True,
                    "advertised_frame": st.advertised_frame,
                    "requested": False
                },
                frame_anchors=adv_f,
                explanation="Server advertised STARTTLS capability, but the client did not issue an upgrade request before sending payload data. Indicates possible MitM stripping or misconfigured client.",
                remediation="Configure client email agent to require mandatory TLS upgrade (STARTTLS) before authentication."
            ))

        # 3. STARTTLS Failure / Rejection
        if st and st.failed:
            f_frame = [st.failure_frame] if st.failure_frame else ([st.requested_frame] if st.requested_frame else [])
            anomalies.append(TLSAnomaly(
                anomaly_id="ANOMALY-STARTTLS-REJECTED",
                title="STARTTLS Upgrade Command Rejected by Server",
                severity="HIGH",
                anomaly_score=80.0,
                confidence=95.0,
                category="PROTOCOL_STATE",
                observed_evidence={
                    "requested": True,
                    "failed": True,
                    "failure_reason": st.failure_reason
                },
                frame_anchors=f_frame,
                explanation=f"Client requested STARTTLS upgrade, but server rejected or failed the command: {st.failure_reason or 'Non-OK response'}.",
                remediation="Inspect server mail log for TLS certificate errors, cipher configuration mismatches, or rate limits."
            ))

        # 4. Deprecated Legacy TLS Protocol Version (TLS 1.0, 1.1, SSLv3, SSLv2)
        if tls and tls.negotiated_tls_version in [TLSVersion.TLSv1_0, TLSVersion.TLSv1_1, TLSVersion.SSLv3, TLSVersion.SSLv2]:
            sh_frame = [tls.server_hello_frame] if tls.server_hello_frame else []
            anomalies.append(TLSAnomaly(
                anomaly_id="ANOMALY-LEGACY-TLS-VERSION",
                title=f"Deprecated TLS Protocol Version ({tls.negotiated_tls_version.value})",
                severity="HIGH",
                anomaly_score=85.0,
                confidence=100.0,
                category="DEPRECATED_PROTOCOL",
                observed_evidence={
                    "negotiated_version": tls.negotiated_tls_version.value,
                    "server_hello_frame": tls.server_hello_frame
                },
                frame_anchors=sh_frame,
                explanation=f"Negotiated {tls.negotiated_tls_version.value} is deprecated per RFC 8996 due to known cryptographic weaknesses (POODLE, BEAST, CRIME).",
                remediation="Disable TLS 1.0/1.1 in mail server configuration. Enforce TLS 1.2 and TLS 1.3 only."
            ))

        # 5. Weak or Deprecated Cipher Suites (RC4, 3DES, Static RSA without PFS, NULL/Export)
        if tls and tls.cipher_info:
            ci = tls.cipher_info
            if ci.has_pfs is False or "3des" in ci.name.lower() or "rc4" in ci.name.lower() or "null" in ci.name.lower():
                sh_frame = [tls.server_hello_frame] if tls.server_hello_frame else []
                anomalies.append(TLSAnomaly(
                    anomaly_id="ANOMALY-WEAK-CIPHER-SUITE",
                    title=f"Insecure Cipher Suite ({ci.name})",
                    severity="HIGH" if ("3des" in ci.name.lower() or "rc4" in ci.name.lower()) else "MEDIUM",
                    anomaly_score=75.0,
                    confidence=95.0,
                    category="WEAK_CRYPTOGRAPHY",
                    observed_evidence={
                        "cipher_name": ci.name,
                        "has_pfs": ci.has_pfs,
                        "key_exchange": ci.key_exchange,
                        "strength": ci.strength.value if hasattr(ci.strength, "value") else str(ci.strength)
                    },
                    frame_anchors=sh_frame,
                    explanation=f"Cipher suite {ci.name} uses {ci.key_exchange} key exchange without Forward Secrecy or deprecated legacy symmetric ciphers.",
                    remediation="Configure server cipher suite list to prefer ECDHE-based AEAD ciphers (AES-GCM / CHACHA20-POLY1305)."
                ))

        # 6. Certificate Anomalies (Expired, Weak RSA, Self-Signed)
        if cert and cert.visibility == CertificateVisibility.OBSERVABLE:
            cert_f = [cert.frame_number] if cert.frame_number else ([tls.server_hello_frame] if tls and tls.server_hello_frame else [])
            if cert.validity_status == CertificateValidityStatus.EXPIRED:
                anomalies.append(TLSAnomaly(
                    anomaly_id="ANOMALY-CERTIFICATE-EXPIRED",
                    title="Expired X.509 Server Certificate in Handshake",
                    severity="HIGH",
                    anomaly_score=85.0,
                    confidence=100.0,
                    category="CERTIFICATE_ANOMALY",
                    observed_evidence={
                        "subject": cert.subject,
                        "not_after": cert.not_after,
                        "validity_reference_time": cert.validity_reference_time
                    },
                    frame_anchors=cert_f,
                    explanation=f"Server presented an expired certificate (notAfter: {cert.not_after}).",
                    remediation="Renew and deploy an active X.509 certificate from a trusted CA."
                ))
            if cert.public_key_bits and cert.public_key_bits < 2048 and (not cert.public_key_algorithm or "rsa" in cert.public_key_algorithm.lower()):
                anomalies.append(TLSAnomaly(
                    anomaly_id="ANOMALY-CERTIFICATE-WEAK-RSA",
                    title=f"Sub-2048 Bit RSA Certificate Key Length ({cert.public_key_bits} bits)",
                    severity="HIGH",
                    anomaly_score=75.0,
                    confidence=100.0,
                    category="CERTIFICATE_ANOMALY",
                    observed_evidence={
                        "public_key_algorithm": cert.public_key_algorithm,
                        "public_key_bits": cert.public_key_bits
                    },
                    frame_anchors=cert_f,
                    explanation=f"Certificate uses a {cert.public_key_bits}-bit RSA key below the NIST SP 800-57 2048-bit minimum threshold.",
                    remediation="Reissue certificate with at least 2048-bit RSA or 256-bit ECDSA."
                ))
            if cert.signature_algorithm and any(weak_alg in cert.signature_algorithm.lower() for weak_alg in ["sha1", "md5", "sha-1", "md2"]):
                anomalies.append(TLSAnomaly(
                    anomaly_id="ANOMALY-CERTIFICATE-WEAK-SIGNATURE",
                    title=f"Deprecated Digest in Certificate Signature ({cert.signature_algorithm})",
                    severity="HIGH",
                    anomaly_score=80.0,
                    confidence=100.0,
                    category="CERTIFICATE_ANOMALY",
                    observed_evidence={
                        "signature_algorithm": cert.signature_algorithm,
                        "subject": cert.subject
                    },
                    frame_anchors=cert_f,
                    explanation=f"Certificate is signed with deprecated collision-vulnerable algorithm {cert.signature_algorithm}.",
                    remediation="Reissue certificate using SHA-256 (e.g., sha256WithRSAEncryption or ecdsa-with-SHA256) or stronger."
                ))

        # 7. Abnormal Protocol / Port Transport Incongruity
        # Dedicated implicit TLS ports (465, 993, 995) running unencrypted cleartext
        if session.server_port in [465, 993, 995] and session.security_mode == SecurityMode.PLAINTEXT:
            anomalies.append(TLSAnomaly(
                anomaly_id="ANOMALY-IMPLICIT-PORT-CLEARTEXT",
                title=f"Unencrypted Plaintext on Implicit TLS Port {session.server_port}",
                severity="CRITICAL",
                anomaly_score=95.0,
                confidence=100.0,
                category="PORT_INCONGRUITY",
                observed_evidence={
                    "server_port": session.server_port,
                    "expected_mode": "DIRECT_TLS",
                    "observed_mode": "PLAINTEXT"
                },
                frame_anchors=[ep.frame_number for ep in ev_pkts[:3]] if ev_pkts else [],
                explanation=f"Port {session.server_port} is standard for direct implicit TLS, but cleartext commands were observed without encryption.",
                remediation=f"Ensure mail service listening on port {session.server_port} mandates immediate TLS handshake negotiation."
            ))

        # Compute overall anomaly score
        if not anomalies:
            overall_score = 0.0
            highest_sev = "NOMINAL"
        else:
            overall_score = min(100.0, max(a.anomaly_score for a in anomalies))
            sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            highest_sev = "INFO"
            for s in sev_order:
                if any(a.severity == s for a in anomalies):
                    highest_sev = s
                    break

        return SessionAnomalyReport(
            session_id=session.session_id,
            total_anomalies=len(anomalies),
            overall_anomaly_score=round(overall_score, 1),
            highest_severity=highest_sev,
            anomalies=anomalies
        )

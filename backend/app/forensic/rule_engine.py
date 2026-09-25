"""
SecureMailScope X - Cryptographic Rule Engine & Security Assessment
Evaluates deterministic forensic rules against email sessions, computes risk grades,
and produces frame-backed security findings and actionable mitigations.
"""

from typing import List, Optional
from ..schemas.forensic import (
    EmailSession,
    SecurityFinding,
    SessionSecurityAssessment,
    FindingSeverity,
    FindingCategory,
    SecurityGrade,
    SecurityMode,
    TLSVersion,
    SecurityStrength
)


class CryptographicRuleEngine:
    @classmethod
    def evaluate_session(cls, session: EmailSession) -> SessionSecurityAssessment:
        """
        Execute deterministic security rules against reconstructed session evidence.
        """
        findings: List[SecurityFinding] = []
        tls = session.tls_details
        st = session.starttls_state

        # Evidence frame collection helper
        def get_frames(*frames: Optional[int]) -> List[int]:
            return [f for f in frames if f is not None]

        # ----------------------------------------------------------
        # RULE 1: PLAINTEXT COMMUNICATION (CRITICAL)
        # ----------------------------------------------------------
        if session.security_mode == SecurityMode.PLAINTEXT:
            findings.append(SecurityFinding(
                id="FINDING-PLAINTEXT-COMMUNICATION",
                title="Unencrypted Cleartext Email Session",
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.PROTOCOL_SECURITY,
                description=(
                    f"Email session on {session.protocol.value} ({session.server_ip}:{session.server_port}) "
                    "was conducted entirely in plaintext without cryptographic encryption. Authentication credentials, "
                    "headers, and email payloads are exposed to passive eavesdropping and MITM tampering."
                ),
                evidence_frames=[p.frame_number for p in session.evidence_packets[:5]],
                recommendation="Enforce mandatory TLS encryption via STARTTLS (SMTP 587, POP3 110, IMAP 143) or Direct TLS (SMTPS 465, IMAPS 993, POP3S 995)."
            ))

        # ----------------------------------------------------------
        # RULE 2: STARTTLS STRIPPING & TRANSITION FAILURES (HIGH)
        # ----------------------------------------------------------
        if st.advertised and not st.requested and session.security_mode != SecurityMode.DIRECT_TLS:
            findings.append(SecurityFinding(
                id="FINDING-STARTTLS-STRIPPING-RISK",
                title="STARTTLS Capability Advertised but Never Requested",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.PROTOCOL_SECURITY,
                description=(
                    f"Server advertised STARTTLS capability on frame {st.advertised_frame}, but the client never issued "
                    "a STARTTLS command. This behavior is a signature of active STARTTLS stripping attacks or client misconfiguration."
                ),
                evidence_frames=get_frames(st.advertised_frame),
                recommendation="Configure client with mandatory TLS / strict transport security (MTA-STS / DANE) to prevent plaintext fallbacks."
            ))

        if st.failed:
            findings.append(SecurityFinding(
                id="FINDING-STARTTLS-UPGRADE-FAILED",
                title="STARTTLS Upgrade Rejected by Server",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.PROTOCOL_SECURITY,
                description=f"STARTTLS upgrade command was rejected by the server: {st.failure_reason or 'Unknown failure'}.",
                evidence_frames=get_frames(st.requested_frame, st.failure_frame),
                recommendation="Audit server configuration and certificates to resolve STARTTLS rejection cause."
            ))

        # ----------------------------------------------------------
        # RULE 3: PROTOCOL VERSION SECURITY (CRITICAL / HIGH / INFO)
        # ----------------------------------------------------------
        if tls:
            ver = tls.negotiated_tls_version

            if ver in [TLSVersion.SSLv2, TLSVersion.SSLv3]:
                findings.append(SecurityFinding(
                    id="FINDING-INSECURE-LEGACY-SSL",
                    title=f"Insecure Legacy Protocol Negotiated ({ver.value})",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                    description=f"{ver.value} is cryptographically broken and vulnerable to POODLE, DROWN, and padding oracle attacks.",
                    evidence_frames=get_frames(tls.client_hello_frame, tls.server_hello_frame),
                    recommendation="Immediately disable SSLv2 and SSLv3. Require TLS 1.2 or TLS 1.3 minimum."
                ))
            elif ver in [TLSVersion.TLSv1_0, TLSVersion.TLSv1_1]:
                findings.append(SecurityFinding(
                    id="FINDING-DEPRECATED-TLS-VERSION",
                    title=f"Deprecated TLS Version Negotiated ({ver.value})",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                    description=f"{ver.value} was formally deprecated by IETF (RFC 8996) due to weak cryptographic primitives and known attacks (BEAST, Lucky13).",
                    evidence_frames=get_frames(tls.client_hello_frame, tls.server_hello_frame),
                    recommendation="Disable TLS 1.0 and TLS 1.1 across all mail server configurations. Enforce TLS 1.2 and TLS 1.3."
                ))
            elif ver == TLSVersion.TLSv1_2:
                findings.append(SecurityFinding(
                    id="FINDING-TLS12-ACCEPTABLE",
                    title="TLS 1.2 Protocol Negotiated",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                    description="TLS 1.2 negotiated. Valid standard, though TLS 1.3 is strongly recommended for enhanced security and zero plaintext handshake parameters.",
                    evidence_frames=get_frames(tls.client_hello_frame, tls.server_hello_frame),
                    recommendation="Plan upgrade to TLS 1.3 to benefit from modern AEAD ciphers and encrypted certificate handshakes."
                ))
            elif ver == TLSVersion.TLSv1_3:
                findings.append(SecurityFinding(
                    id="FINDING-TLS13-STATE-OF-THE-ART",
                    title="State-of-the-Art TLS 1.3 Negotiated",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                    description="TLS 1.3 successfully negotiated with modern AEAD encryption and encrypted handshake extensions (RFC 8446).",
                    evidence_frames=get_frames(tls.client_hello_frame, tls.server_hello_frame),
                    recommendation="Maintain TLS 1.3 configuration."
                ))

            # ------------------------------------------------------
            # RULE 4: CIPHER SUITE & STRENGTH EVALUATION
            # ------------------------------------------------------
            cipher = tls.cipher_info
            if cipher:
                if cipher.strength == SecurityStrength.INSECURE:
                    findings.append(SecurityFinding(
                        id="FINDING-INSECURE-CIPHER-SUITE",
                        title=f"Insecure Cipher Suite Negotiated: {cipher.name}",
                        severity=FindingSeverity.CRITICAL,
                        category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                        description=f"Cipher suite {cipher.name} uses obsolete or broken cryptographic algorithms (RC4, 3DES, NULL, or DES).",
                        evidence_frames=get_frames(tls.server_hello_frame),
                        recommendation="Remove obsolete ciphers from server cipher suite configuration."
                    ))
                elif cipher.strength == SecurityStrength.DEPRECATED:
                    findings.append(SecurityFinding(
                        id="FINDING-DEPRECATED-CIPHER-SUITE",
                        title=f"Deprecated Cipher Suite Negotiated: {cipher.name}",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                        description=f"Cipher suite {cipher.name} uses legacy CBC mode encryption or SHA-1 MAC.",
                        evidence_frames=get_frames(tls.server_hello_frame),
                        recommendation="Enforce modern AEAD cipher suites (AES-GCM or ChaCha20-Poly1305)."
                    ))

            # ------------------------------------------------------
            # RULE 5: FORWARD SECRECY (PFS) EVALUATION
            # ------------------------------------------------------
            if tls.has_forward_secrecy is False or (ver == TLSVersion.TLSv1_2 and cipher and cipher.has_pfs is False):
                findings.append(SecurityFinding(
                    id="FINDING-NO-FORWARD-SECRECY",
                    title="No Perfect Forward Secrecy (Static Key Exchange)",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.FORWARD_SECRECY,
                    description=(
                        "The session negotiated a static RSA key exchange without Forward Secrecy. "
                        "If the server private key is compromised in the future, all previously recorded sessions can be retroactively decrypted."
                    ),
                    evidence_frames=get_frames(tls.server_hello_frame),
                    recommendation="Disable static RSA cipher suites (TLS_RSA_WITH_*). Enforce ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) or DHE."
                ))
            elif tls.has_forward_secrecy is True:
                findings.append(SecurityFinding(
                    id="FINDING-FORWARD-SECRECY-VERIFIED",
                    title="Perfect Forward Secrecy (PFS) Verified",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FORWARD_SECRECY,
                    description=f"Session protects past traffic from retroactive decryption: {tls.pfs_status}.",
                    evidence_frames=get_frames(tls.server_hello_frame),
                    recommendation=None
                ))

            # ------------------------------------------------------
            # RULE 6: POST-QUANTUM CRYPTOGRAPHY (PQC) READINESS
            # ------------------------------------------------------
            if ver in [TLSVersion.TLSv1_3, TLSVersion.TLSv1_2]:
                is_pqc = bool(cipher and cipher.is_post_quantum_safe)
                if not is_pqc:
                    findings.append(SecurityFinding(
                        id="FINDING-PQC-CLASSICAL-KEX-EXPOSURE",
                        title="Vulnerable to Harvest Now, Decrypt Later (HNDL)",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.POST_QUANTUM_READINESS,
                        description=(
                            "No verified post-quantum key-establishment evidence was observed in the passive capture. "
                            "The specific classical key-exchange mechanism could not be established with sufficient passive evidence; "
                            "therefore HNDL exposure remains an incomplete evidence-bounded assessment."
                        ),
                        evidence_frames=get_frames(tls.client_hello_frame, tls.server_hello_frame),
                        recommendation="Consider hybrid key establishment combining classical key exchange with ML-KEM, where appropriate. ML-KEM is standardized in NIST FIPS 203."
                    ))

        # ----------------------------------------------------------
        # OVERALL SECURITY GRADE CALCULATION
        # ----------------------------------------------------------
        critical_cnt = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        high_cnt = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        med_cnt = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
        low_cnt = sum(1 for f in findings if f.severity == FindingSeverity.LOW)
        info_cnt = sum(1 for f in findings if f.severity == FindingSeverity.INFO)

        if session.security_mode == SecurityMode.PLAINTEXT or critical_cnt > 0:
            grade = SecurityGrade.F
            rationale = "Unencrypted plaintext traffic or critical cryptographic vulnerabilities detected."
        elif tls and tls.negotiated_tls_version in [TLSVersion.TLSv1_0, TLSVersion.TLSv1_1]:
            grade = SecurityGrade.D
            rationale = "Deprecated TLS 1.0/1.1 version negotiated (RFC 8996 violation)."
        elif tls and (tls.has_forward_secrecy is False or (tls.negotiated_tls_version == TLSVersion.TLSv1_2 and tls.cipher_info and tls.cipher_info.has_pfs is False)):
            grade = SecurityGrade.C
            rationale = "TLS 1.2 negotiated but lacks Forward Secrecy (static RSA key exchange)."
        elif tls and tls.negotiated_tls_version == TLSVersion.TLSv1_2:
            grade = SecurityGrade.B
            rationale = "TLS 1.2 with Forward Secrecy verified. Modern, but upgrade to TLS 1.3 recommended."
        elif tls and tls.negotiated_tls_version == TLSVersion.TLSv1_3:
            is_pqc = bool(tls.cipher_info and tls.cipher_info.is_post_quantum_safe)
            if is_pqc:
                grade = SecurityGrade.A_PLUS
                rationale = "TLS 1.3 negotiated with Forward Secrecy and Post-Quantum hybrid protection."
            else:
                grade = SecurityGrade.A
                rationale = "TLS 1.3 negotiated (State-of-the-Art Classical security)."
        else:
            grade = SecurityGrade.F
            rationale = "Unknown or unverified security posture."

        pqc_summary = (
            "Classical Key Exchange (Vulnerable to Quantum Decryption)"
            if not (tls and tls.cipher_info and tls.cipher_info.is_post_quantum_safe)
            else "Post-Quantum Protected (ML-KEM Hybrid)"
        )

        return SessionSecurityAssessment(
            grade=grade,
            grade_rationale=rationale,
            findings=findings,
            critical_findings_count=critical_cnt,
            high_findings_count=high_cnt,
            medium_findings_count=med_cnt,
            low_findings_count=low_cnt,
            info_findings_count=info_cnt,
            post_quantum_ready=bool(tls and tls.cipher_info and tls.cipher_info.is_post_quantum_safe),
            post_quantum_summary=pqc_summary
        )

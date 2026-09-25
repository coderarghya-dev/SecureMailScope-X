"""
SecureMailScope X - Cryptographic Rule Engine & Security Assessment
Evaluates deterministic forensic rules against email sessions, computes risk grades,
and produces frame-backed security findings and actionable mitigations.
"""

from typing import List, Optional
from ..schemas.forensic import (
    EmailSession,
    SecurityFinding,
    FindingEvidenceItem,
    FindingExplanation,
    SessionSecurityAssessment,
    FindingSeverity,
    FindingCategory,
    SecurityGrade,
    SecurityMode,
    TLSVersion,
    SecurityStrength
)
from .pqc_analyzer import PQCAnalyzer, PQCStatus, HNDLStatus


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
            pt_frames = [p.frame_number for p in session.evidence_packets[:5]]
            pt_evidence = [
                FindingEvidenceItem(
                    type="PROTOCOL_SECURITY",
                    frame=p.frame_number,
                    field="security_mode",
                    observed_value="PLAINTEXT"
                )
                for p in session.evidence_packets[:5]
            ]
            if not pt_evidence:
                pt_evidence = [
                    FindingEvidenceItem(
                        type="PROTOCOL_SECURITY",
                        frame=None,
                        field="security_mode",
                        observed_value="PLAINTEXT (Unencrypted session stream)"
                    )
                ]

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
                evidence_frames=pt_frames,
                recommendation="Enforce mandatory TLS encryption via STARTTLS (SMTP 587, POP3 110, IMAP 143) or Direct TLS (SMTPS 465, IMAPS 993, POP3S 995).",
                explanation=FindingExplanation(
                    finding_id="FINDING-PLAINTEXT-COMMUNICATION",
                    rule_id="RULE-PLAINTEXT-TRAFFIC",
                    why_triggered="Email session conducted entirely in cleartext without TLS or STARTTLS cryptographic wrapping.",
                    evidence=pt_evidence,
                    confidence_boundary="Direct frame inspection of packet payload and unencrypted commands.",
                    standards_refs=["RFC 3207", "RFC 8314"]
                )
            ))

        # ----------------------------------------------------------
        # RULE 2: STARTTLS STRIPPING & TRANSITION FAILURES (HIGH)
        # ----------------------------------------------------------
        if st.advertised and not st.requested and session.security_mode != SecurityMode.DIRECT_TLS:
            adv_frames = get_frames(st.advertised_frame)
            adv_evidence = [
                FindingEvidenceItem(
                    type="PROTOCOL_COMMAND",
                    frame=st.advertised_frame,
                    field="starttls_advertised",
                    observed_value=st.advertised_text or "STARTTLS capability advertised"
                )
            ]
            findings.append(SecurityFinding(
                id="FINDING-STARTTLS-STRIPPING-RISK",
                title="STARTTLS Capability Advertised but Never Requested",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.PROTOCOL_SECURITY,
                description=(
                    f"Server advertised STARTTLS capability on frame {st.advertised_frame}, but the client never issued "
                    "a STARTTLS command. This behavior is a signature of active STARTTLS stripping attacks or client misconfiguration."
                ),
                evidence_frames=adv_frames,
                recommendation="Configure client with mandatory TLS / strict transport security (MTA-STS / DANE) to prevent plaintext fallbacks.",
                explanation=FindingExplanation(
                    finding_id="FINDING-STARTTLS-STRIPPING-RISK",
                    rule_id="RULE-STARTTLS-STRIPPING",
                    why_triggered="Server advertised STARTTLS capability, but client failed to request it before issuing plaintext transaction commands.",
                    evidence=adv_evidence,
                    confidence_boundary="Direct protocol command stream observation.",
                    standards_refs=["RFC 3207", "RFC 7435"]
                )
            ))

        if st.failed:
            fail_frames = get_frames(st.requested_frame, st.failure_frame)
            fail_evidence = []
            if st.requested_frame is not None:
                fail_evidence.append(FindingEvidenceItem(
                    type="PROTOCOL_COMMAND",
                    frame=st.requested_frame,
                    field="requested_command",
                    observed_value=st.requested_command or "STARTTLS"
                ))
            if st.failure_frame is not None:
                fail_evidence.append(FindingEvidenceItem(
                    type="PROTOCOL_RESPONSE",
                    frame=st.failure_frame,
                    field="failure_reason",
                    observed_value=st.failure_reason or "STARTTLS rejected by server"
                ))
            if not fail_evidence:
                fail_evidence.append(FindingEvidenceItem(
                    type="PROTOCOL_RESPONSE",
                    frame=None,
                    field="failure_reason",
                    observed_value=st.failure_reason or "STARTTLS failed"
                ))

            findings.append(SecurityFinding(
                id="FINDING-STARTTLS-UPGRADE-FAILED",
                title="STARTTLS Upgrade Rejected by Server",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.PROTOCOL_SECURITY,
                description=f"STARTTLS upgrade command was rejected by the server: {st.failure_reason or 'Unknown failure'}.",
                evidence_frames=fail_frames,
                recommendation="Audit server configuration and certificates to resolve STARTTLS rejection cause.",
                explanation=FindingExplanation(
                    finding_id="FINDING-STARTTLS-UPGRADE-FAILED",
                    rule_id="RULE-STARTTLS-FAILURE",
                    why_triggered="STARTTLS upgrade command was rejected by the server response.",
                    evidence=fail_evidence,
                    confidence_boundary="Direct protocol response code inspection.",
                    standards_refs=["RFC 3207"]
                )
            ))

        # ----------------------------------------------------------
        # RULE 3: PROTOCOL VERSION SECURITY (CRITICAL / HIGH / INFO)
        # ----------------------------------------------------------
        if tls:
            ver = tls.negotiated_tls_version
            tls_frames = get_frames(tls.client_hello_frame, tls.server_hello_frame)
            server_frame = tls.server_hello_frame or tls.client_hello_frame

            if ver in [TLSVersion.SSLv2, TLSVersion.SSLv3]:
                findings.append(SecurityFinding(
                    id="FINDING-INSECURE-LEGACY-SSL",
                    title=f"Insecure Legacy Protocol Negotiated ({ver.value})",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                    description=f"{ver.value} is cryptographically broken and vulnerable to POODLE, DROWN, and padding oracle attacks.",
                    evidence_frames=tls_frames,
                    recommendation="Immediately disable SSLv2 and SSLv3. Require TLS 1.2 or TLS 1.3 minimum.",
                    explanation=FindingExplanation(
                        finding_id="FINDING-INSECURE-LEGACY-SSL",
                        rule_id="RULE-LEGACY-SSL-VERSION",
                        why_triggered=f"{ver.value} is cryptographically broken and vulnerable to POODLE, DROWN, and padding oracle attacks.",
                        evidence=[
                            FindingEvidenceItem(
                                type="TLS_VERSION",
                                frame=server_frame,
                                field="negotiated_tls_version",
                                observed_value=ver.value
                            )
                        ],
                        confidence_boundary="TLS Record layer and ServerHello version byte dissection.",
                        standards_refs=["RFC 6176", "RFC 7568"]
                    )
                ))
            elif ver in [TLSVersion.TLSv1_0, TLSVersion.TLSv1_1]:
                findings.append(SecurityFinding(
                    id="FINDING-DEPRECATED-TLS-VERSION",
                    title=f"Deprecated TLS Version Negotiated ({ver.value})",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                    description=f"{ver.value} was formally deprecated by IETF (RFC 8996) due to weak cryptographic primitives and known attacks (BEAST, Lucky13).",
                    evidence_frames=tls_frames,
                    recommendation="Disable TLS 1.0 and TLS 1.1 across all mail server configurations. Enforce TLS 1.2 and TLS 1.3.",
                    explanation=FindingExplanation(
                        finding_id="FINDING-DEPRECATED-TLS-VERSION",
                        rule_id="RULE-DEPRECATED-TLS-VERSION",
                        why_triggered=f"{ver.value} was formally deprecated by IETF (RFC 8996) due to weak cryptographic primitives.",
                        evidence=[
                            FindingEvidenceItem(
                                type="TLS_VERSION",
                                frame=server_frame,
                                field="negotiated_tls_version",
                                observed_value=ver.value
                            )
                        ],
                        confidence_boundary="TLS ServerHello Record and Handshake version verification.",
                        standards_refs=["RFC 8996"]
                    )
                ))
            elif ver == TLSVersion.TLSv1_2:
                findings.append(SecurityFinding(
                    id="FINDING-TLS12-ACCEPTABLE",
                    title="TLS 1.2 Protocol Negotiated",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                    description="TLS 1.2 negotiated. Valid standard, though TLS 1.3 is strongly recommended for enhanced security and zero plaintext handshake parameters.",
                    evidence_frames=tls_frames,
                    recommendation="Plan upgrade to TLS 1.3 to benefit from modern AEAD ciphers and encrypted certificate handshakes.",
                    explanation=FindingExplanation(
                        finding_id="FINDING-TLS12-ACCEPTABLE",
                        rule_id="RULE-TLS12-BASELINE",
                        why_triggered="TLS 1.2 negotiated. Valid standard, though TLS 1.3 is strongly recommended.",
                        evidence=[
                            FindingEvidenceItem(
                                type="TLS_VERSION",
                                frame=server_frame,
                                field="negotiated_tls_version",
                                observed_value="TLS 1.2"
                            )
                        ],
                        confidence_boundary="TLS ServerHello version field.",
                        standards_refs=["RFC 5246"]
                    )
                ))
            elif ver == TLSVersion.TLSv1_3:
                findings.append(SecurityFinding(
                    id="FINDING-TLS13-STATE-OF-THE-ART",
                    title="State-of-the-Art TLS 1.3 Negotiated",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                    description="TLS 1.3 successfully negotiated with modern AEAD encryption and encrypted handshake extensions (RFC 8446).",
                    evidence_frames=tls_frames,
                    recommendation="Maintain TLS 1.3 configuration.",
                    explanation=FindingExplanation(
                        finding_id="FINDING-TLS13-STATE-OF-THE-ART",
                        rule_id="RULE-TLS13-MODERN",
                        why_triggered="TLS 1.3 successfully negotiated with modern AEAD encryption and encrypted handshake extensions.",
                        evidence=[
                            FindingEvidenceItem(
                                type="TLS_VERSION",
                                frame=server_frame,
                                field="negotiated_tls_version",
                                observed_value="TLS 1.3"
                            )
                        ],
                        confidence_boundary="TLS 1.3 supported_versions extension (RFC 8446 Section 4.2.1).",
                        standards_refs=["RFC 8446"]
                    )
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
                        recommendation="Remove obsolete ciphers from server cipher suite configuration.",
                        explanation=FindingExplanation(
                            finding_id="FINDING-INSECURE-CIPHER-SUITE",
                            rule_id="RULE-INSECURE-CIPHER",
                            why_triggered=f"Cipher suite {cipher.name} uses obsolete or broken cryptographic algorithms.",
                            evidence=[
                                FindingEvidenceItem(
                                    type="CIPHER_SUITE",
                                    frame=tls.server_hello_frame,
                                    field="selected_cipher_name",
                                    observed_value=f"{cipher.name} ({cipher.hex_code})"
                                )
                            ],
                            confidence_boundary="TLS ServerHello cipher suite code mapping.",
                            standards_refs=["RFC 7465", "RFC 8446"]
                        )
                    ))
                elif cipher.strength == SecurityStrength.DEPRECATED:
                    findings.append(SecurityFinding(
                        id="FINDING-DEPRECATED-CIPHER-SUITE",
                        title=f"Deprecated Cipher Suite Negotiated: {cipher.name}",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                        description=f"Cipher suite {cipher.name} uses legacy CBC mode encryption or SHA-1 MAC.",
                        evidence_frames=get_frames(tls.server_hello_frame),
                        recommendation="Enforce modern AEAD cipher suites (AES-GCM or ChaCha20-Poly1305).",
                        explanation=FindingExplanation(
                            finding_id="FINDING-DEPRECATED-CIPHER-SUITE",
                            rule_id="RULE-DEPRECATED-CIPHER",
                            why_triggered=f"Cipher suite {cipher.name} uses legacy CBC mode encryption or SHA-1 MAC.",
                            evidence=[
                                FindingEvidenceItem(
                                    type="CIPHER_SUITE",
                                    frame=tls.server_hello_frame,
                                    field="selected_cipher_name",
                                    observed_value=f"{cipher.name} ({cipher.hex_code})"
                                )
                            ],
                            confidence_boundary="TLS ServerHello cipher suite code mapping.",
                            standards_refs=["RFC 8996", "RFC 5246"]
                        )
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
                    recommendation="Disable static RSA cipher suites (TLS_RSA_WITH_*). Enforce ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) or DHE.",
                    explanation=FindingExplanation(
                        finding_id="FINDING-NO-FORWARD-SECRECY",
                        rule_id="RULE-STATIC-RSA-NO-PFS",
                        why_triggered="The session negotiated a static RSA key exchange without Forward Secrecy.",
                        evidence=[
                            FindingEvidenceItem(
                                type="FORWARD_SECRECY",
                                frame=tls.server_hello_frame,
                                field="key_exchange",
                                observed_value=cipher.key_exchange if cipher else "Static RSA"
                            )
                        ],
                        confidence_boundary="Passive key exchange mechanism identification from negotiated cipher suite.",
                        standards_refs=["RFC 5246", "RFC 8446"]
                    )
                ))
            elif tls.has_forward_secrecy is True:
                findings.append(SecurityFinding(
                    id="FINDING-FORWARD-SECRECY-VERIFIED",
                    title="Perfect Forward Secrecy (PFS) Verified",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FORWARD_SECRECY,
                    description=f"Session protects past traffic from retroactive decryption: {tls.pfs_status}.",
                    evidence_frames=get_frames(tls.server_hello_frame),
                    recommendation=None,
                    explanation=FindingExplanation(
                        finding_id="FINDING-FORWARD-SECRECY-VERIFIED",
                        rule_id="RULE-PFS-VERIFIED",
                        why_triggered=f"Session protects past traffic from retroactive decryption: {tls.pfs_status}.",
                        evidence=[
                            FindingEvidenceItem(
                                type="FORWARD_SECRECY",
                                frame=tls.server_hello_frame,
                                field="pfs_status",
                                observed_value=tls.pfs_status
                            )
                        ],
                        confidence_boundary="Observable ECDHE / DHE or TLS 1.3 key share evidence.",
                        standards_refs=["RFC 8446", "RFC 7919"]
                    )
                ))

            # ------------------------------------------------------
            # RULE 6: POST-QUANTUM CRYPTOGRAPHY (PQC) READINESS
            # ------------------------------------------------------
            pqc_result = PQCAnalyzer.analyze_session(session)
            if ver in [TLSVersion.TLSv1_3, TLSVersion.TLSv1_2]:
                if pqc_result.pqc_status == PQCStatus.HYBRID_OBSERVED:
                    findings.append(SecurityFinding(
                        id="FINDING-PQC-HYBRID-VERIFIED",
                        title="Post-Quantum Hybrid Key Exchange Verified (ML-KEM)",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.POST_QUANTUM_READINESS,
                        description=pqc_result.evidence_summary,
                        evidence_frames=pqc_result.evidence_frames,
                        recommendation=pqc_result.recommendation,
                        explanation=FindingExplanation(
                            finding_id="FINDING-PQC-HYBRID-VERIFIED",
                            rule_id="RULE-PQC-HYBRID-KEM",
                            why_triggered="Post-Quantum hybrid key exchange verified with standardized ML-KEM algorithm.",
                            evidence=[
                                FindingEvidenceItem(
                                    type="PQC_KEY_SHARE",
                                    frame=f,
                                    field="selected_group",
                                    observed_value=tls.selected_group or "Standardized Hybrid ML-KEM"
                                )
                                for f in (pqc_result.evidence_frames or get_frames(tls.server_hello_frame))
                            ],
                            confidence_boundary="Direct observation of IANA-standardized hybrid NamedGroup in TLS KeyShare.",
                            standards_refs=["NIST FIPS 203", "draft-ietf-tls-hybrid-design"]
                        )
                    ))
                elif pqc_result.pqc_status == PQCStatus.PQC_PROTECTED:
                    findings.append(SecurityFinding(
                        id="FINDING-PQC-PROTECTED",
                        title="Post-Quantum Key Exchange Verified",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.POST_QUANTUM_READINESS,
                        description=pqc_result.evidence_summary,
                        evidence_frames=pqc_result.evidence_frames,
                        recommendation=pqc_result.recommendation,
                        explanation=FindingExplanation(
                            finding_id="FINDING-PQC-PROTECTED",
                            rule_id="RULE-PQC-STANDALONE-KEM",
                            why_triggered="Standalone Post-quantum key exchange verified.",
                            evidence=[
                                FindingEvidenceItem(
                                    type="PQC_KEY_SHARE",
                                    frame=f,
                                    field="selected_group",
                                    observed_value=tls.selected_group or "Standardized Standalone ML-KEM"
                                )
                                for f in (pqc_result.evidence_frames or get_frames(tls.server_hello_frame))
                            ],
                            confidence_boundary="Direct observation of IANA-standardized standalone ML-KEM NamedGroup.",
                            standards_refs=["NIST FIPS 203"]
                        )
                    ))
                elif pqc_result.pqc_status == PQCStatus.CLASSICAL_ONLY:
                    findings.append(SecurityFinding(
                        id="FINDING-PQC-CLASSICAL-KEX-EXPOSURE",
                        title="Vulnerable to Harvest Now, Decrypt Later (HNDL)",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.POST_QUANTUM_READINESS,
                        description=pqc_result.evidence_summary,
                        evidence_frames=pqc_result.evidence_frames,
                        recommendation=pqc_result.recommendation,
                        explanation=FindingExplanation(
                            finding_id="FINDING-PQC-CLASSICAL-KEX-EXPOSURE",
                            rule_id="RULE-PQC-HNDL-EXPOSURE",
                            why_triggered="Session relies purely on classical discrete log/factoring key exchange, exposing session to Harvest Now, Decrypt Later (HNDL).",
                            evidence=[
                                FindingEvidenceItem(
                                    type="PQC_ASSESSMENT",
                                    frame=f,
                                    field="key_exchange_posture",
                                    observed_value=tls.selected_group or (tls.cipher_info.key_exchange if tls.cipher_info else "Classical Key Exchange")
                                )
                                for f in (pqc_result.evidence_frames or get_frames(tls.server_hello_frame))
                            ],
                            confidence_boundary="Passive observation confirmed absence of post-quantum key shares.",
                            standards_refs=["NIST FIPS 203", "NIST SP 800-227"]
                        )
                    ))
                elif pqc_result.pqc_status == PQCStatus.ASSESSMENT_INCOMPLETE:
                    pqc_ev_frames = pqc_result.evidence_frames or get_frames(tls.client_hello_frame, tls.server_hello_frame)
                    findings.append(SecurityFinding(
                        id="FINDING-PQC-CLASSICAL-KEX-EXPOSURE",
                        title="Vulnerable to Harvest Now, Decrypt Later (HNDL)",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.POST_QUANTUM_READINESS,
                        description=(
                            "Post-quantum readiness could not be fully established from observable passive evidence. "
                            "No verified post-quantum key-establishment evidence was observed in the passive capture; "
                            "therefore HNDL exposure remains an incomplete evidence-bounded assessment."
                        ),
                        evidence_frames=pqc_ev_frames,
                        recommendation="Consider hybrid key establishment combining classical key exchange with ML-KEM, where appropriate. ML-KEM is standardized in NIST FIPS 203.",
                        explanation=FindingExplanation(
                            finding_id="FINDING-PQC-CLASSICAL-KEX-EXPOSURE",
                            rule_id="RULE-PQC-HNDL-EXPOSURE",
                            why_triggered="Post-quantum readiness could not be fully established from observable passive evidence; HNDL exposure assessment is incomplete.",
                            evidence=[
                                FindingEvidenceItem(
                                    type="PQC_ASSESSMENT",
                                    frame=f,
                                    field="pqc_readiness_state",
                                    observed_value="ASSESSMENT_INCOMPLETE (No observable PQC KeyShare)"
                                )
                                for f in pqc_ev_frames
                            ],
                            confidence_boundary="Passive observation bounds; KeyShare extension unobserved.",
                            standards_refs=["NIST FIPS 203"]
                        )
                    ))

            # ------------------------------------------------------
            # RULE 7: X.509 CERTIFICATE SECURITY & VALIDITY (PHASE 6)
            # ------------------------------------------------------
            from .certificate_analyzer import CertificateAnalyzer, CertificateValidityStatus, CertificateVisibility
            cert_details = CertificateAnalyzer.analyze_session(session)
            tls.certificate_details = cert_details
            cert_frames = get_frames(cert_details.frame_number or tls.server_hello_frame)

            if cert_details.visibility == CertificateVisibility.OBSERVABLE:
                # 7a. Expired Certificate
                if cert_details.validity_status == CertificateValidityStatus.EXPIRED:
                    findings.append(SecurityFinding(
                        id="FINDING-CERTIFICATE-EXPIRED",
                        title="Expired X.509 Server Certificate",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                        description=f"Server certificate expired on {cert_details.not_after} (reference timestamp: {cert_details.validity_reference_time}).",
                        evidence_frames=cert_frames,
                        recommendation="Renew and deploy an active X.509 certificate from a trusted Certificate Authority.",
                        explanation=FindingExplanation(
                            finding_id="FINDING-CERTIFICATE-EXPIRED",
                            rule_id="RULE-CERT-EXPIRED",
                            why_triggered=f"Server certificate expired on {cert_details.not_after}.",
                            evidence=[
                                FindingEvidenceItem(
                                    type="CERTIFICATE_VALIDITY",
                                    frame=cert_details.frame_number,
                                    field="not_after",
                                    observed_value=str(cert_details.not_after)
                                )
                            ],
                            confidence_boundary="Direct parsing of observable X.509 Validity.notAfter field against session reference time.",
                            standards_refs=["RFC 5280"]
                        )
                    ))
                # 7b. Not Yet Valid Certificate
                elif cert_details.validity_status == CertificateValidityStatus.NOT_YET_VALID:
                    findings.append(SecurityFinding(
                        id="FINDING-CERTIFICATE-NOT-YET-VALID",
                        title="Not-Yet-Valid X.509 Server Certificate",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                        description=f"Server certificate is not valid before {cert_details.not_before} (reference timestamp: {cert_details.validity_reference_time}).",
                        evidence_frames=cert_frames,
                        recommendation="Verify server clock synchronization and certificate validity timeframe.",
                        explanation=FindingExplanation(
                            finding_id="FINDING-CERTIFICATE-NOT-YET-VALID",
                            rule_id="RULE-CERT-NOT-YET-VALID",
                            why_triggered=f"Server certificate is not yet valid (notBefore: {cert_details.not_before}).",
                            evidence=[
                                FindingEvidenceItem(
                                    type="CERTIFICATE_VALIDITY",
                                    frame=cert_details.frame_number,
                                    field="not_before",
                                    observed_value=str(cert_details.not_before)
                                )
                            ],
                            confidence_boundary="Direct parsing of observable X.509 Validity.notBefore field against session reference time.",
                            standards_refs=["RFC 5280"]
                        )
                    ))

                # 7c. Weak RSA Key Size (< 2048 bits)
                if (
                    cert_details.public_key_bits is not None
                    and cert_details.public_key_bits < 2048
                    and (not cert_details.public_key_algorithm or "rsa" in cert_details.public_key_algorithm.lower())
                ):
                    findings.append(SecurityFinding(
                        id="FINDING-CERTIFICATE-WEAK-RSA",
                        title=f"Weak RSA Certificate Key Length ({cert_details.public_key_bits} bits)",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                        description=f"Server certificate uses an insecure RSA key length of {cert_details.public_key_bits} bits. Industry baseline is 2048 bits minimum (NIST SP 800-57).",
                        evidence_frames=cert_frames,
                        recommendation="Re-issue certificate with a minimum 2048-bit RSA key or 256-bit ECDSA key.",
                        explanation=FindingExplanation(
                            finding_id="FINDING-CERTIFICATE-WEAK-RSA",
                            rule_id="RULE-CERT-WEAK-RSA",
                            why_triggered=f"Certificate uses {cert_details.public_key_bits}-bit RSA key, below the 2048-bit minimum threshold.",
                            evidence=[
                                FindingEvidenceItem(
                                    type="CERTIFICATE_KEY",
                                    frame=cert_details.frame_number,
                                    field="public_key_bits",
                                    observed_value=str(cert_details.public_key_bits)
                                )
                            ],
                            confidence_boundary="Observable SubjectPublicKeyInfo modulus bit length.",
                            standards_refs=["NIST SP 800-57", "RFC 5280"]
                        )
                    ))

                # 7d. Deprecated Signature Algorithm (MD5 / SHA-1)
                if cert_details.signature_algorithm:
                    sig_lower = cert_details.signature_algorithm.lower()
                    if "md5" in sig_lower or "md2" in sig_lower:
                        findings.append(SecurityFinding(
                            id="FINDING-CERTIFICATE-DEPRECATED-SIG",
                            title=f"Insecure Certificate Signature Algorithm ({cert_details.signature_algorithm})",
                            severity=FindingSeverity.CRITICAL,
                            category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                            description=f"Server certificate was signed using broken MD5 hash algorithm ({cert_details.signature_algorithm}), vulnerable to collision attacks.",
                            evidence_frames=cert_frames,
                            recommendation="Re-issue certificate with modern SHA-256 or SHA-384 signature algorithm.",
                            explanation=FindingExplanation(
                                finding_id="FINDING-CERTIFICATE-DEPRECATED-SIG",
                                rule_id="RULE-CERT-DEPRECATED-SIG",
                                why_triggered=f"Certificate signature algorithm uses broken hash ({cert_details.signature_algorithm}).",
                                evidence=[
                                    FindingEvidenceItem(
                                        type="CERTIFICATE_SIGNATURE",
                                        frame=cert_details.frame_number,
                                        field="signature_algorithm",
                                        observed_value=cert_details.signature_algorithm
                                    )
                                ],
                                confidence_boundary="Observable X.509 signatureAlgorithm OID dissection.",
                                standards_refs=["RFC 6151", "RFC 5280"]
                            )
                        ))
                    elif "sha1" in sig_lower or "sha-1" in sig_lower:
                        findings.append(SecurityFinding(
                            id="FINDING-CERTIFICATE-DEPRECATED-SIG",
                            title=f"Deprecated Certificate Signature Algorithm ({cert_details.signature_algorithm})",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                            description=f"Server certificate was signed using deprecated SHA-1 hash algorithm ({cert_details.signature_algorithm}).",
                            evidence_frames=cert_frames,
                            recommendation="Re-issue certificate with modern SHA-256 or SHA-384 signature algorithm.",
                            explanation=FindingExplanation(
                                finding_id="FINDING-CERTIFICATE-DEPRECATED-SIG",
                                rule_id="RULE-CERT-DEPRECATED-SIG",
                                why_triggered=f"Certificate signature algorithm uses deprecated SHA-1 ({cert_details.signature_algorithm}).",
                                evidence=[
                                    FindingEvidenceItem(
                                        type="CERTIFICATE_SIGNATURE",
                                        frame=cert_details.frame_number,
                                        field="signature_algorithm",
                                        observed_value=cert_details.signature_algorithm
                                    )
                                ],
                                confidence_boundary="Observable X.509 signatureAlgorithm OID dissection.",
                                standards_refs=["RFC 9155", "RFC 5280"]
                            )
                        ))

                # 7e. Cryptographically Self-Signed vs Self-Issued
                if cert_details.self_signed is True:
                    findings.append(SecurityFinding(
                        id="FINDING-CERTIFICATE-SELF-SIGNED",
                        title="Cryptographically Self-Signed X.509 Certificate",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                        description=f"Server certificate is cryptographically self-signed (signature verified using its own public key; Subject matches Issuer: {cert_details.subject or 'Unknown'}). May be expected for internal staging/test systems, but requires manual trust verification in production.",
                        evidence_frames=cert_frames,
                        recommendation="Deploy certificates issued by a recognized public or enterprise Certificate Authority (CA).",
                        explanation=FindingExplanation(
                            finding_id="FINDING-CERTIFICATE-SELF-SIGNED",
                            rule_id="RULE-CERT-SELF-SIGNED",
                            why_triggered="Certificate signature cryptographically verified using its own public key.",
                            evidence=[
                                FindingEvidenceItem(
                                    type="CERTIFICATE_IDENTITY",
                                    frame=cert_details.frame_number,
                                    field="self_signature_verified",
                                    observed_value="True"
                                )
                            ],
                            confidence_boundary="Cryptographic public-key signature verification.",
                            standards_refs=["RFC 5280"]
                        )
                    ))
                elif cert_details.self_issued is True:
                    findings.append(SecurityFinding(
                        id="FINDING-CERTIFICATE-SELF-ISSUED",
                        title="Self-Issued X.509 Server Certificate",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                        description=f"Server certificate appears self-issued (Subject matches Issuer: {cert_details.subject or 'Unknown'}). Cryptographic self-signature verification was not performed or raw signature bytes were unavailable.",
                        evidence_frames=cert_frames,
                        recommendation="Deploy certificates issued by a recognized public or enterprise Certificate Authority (CA).",
                        explanation=FindingExplanation(
                            finding_id="FINDING-CERTIFICATE-SELF-ISSUED",
                            rule_id="RULE-CERT-SELF-ISSUED",
                            why_triggered="Subject and Issuer DNs are identical, but self-signature was not cryptographically verified.",
                            evidence=[
                                FindingEvidenceItem(
                                    type="CERTIFICATE_IDENTITY",
                                    frame=cert_details.frame_number,
                                    field="self_issued",
                                    observed_value="True"
                                )
                            ],
                            confidence_boundary="Direct comparison of observable Subject and Issuer Distinguished Names.",
                            standards_refs=["RFC 5280"]
                        )
                    ))

        # ----------------------------------------------------------
        # OVERALL SECURITY GRADE CALCULATION
        # ----------------------------------------------------------
        critical_cnt = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        high_cnt = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        med_cnt = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
        low_cnt = sum(1 for f in findings if f.severity == FindingSeverity.LOW)
        info_cnt = sum(1 for f in findings if f.severity == FindingSeverity.INFO)

        pqc_result = PQCAnalyzer.analyze_session(session)

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
            if pqc_result.pqc_ready and tls.has_forward_secrecy is True:
                grade = SecurityGrade.A_PLUS
                rationale = "TLS 1.3 negotiated with Forward Secrecy and Post-Quantum hybrid protection."
            else:
                grade = SecurityGrade.A
                rationale = "TLS 1.3 negotiated (State-of-the-Art Classical security)."
        else:
            grade = SecurityGrade.F
            rationale = "Unknown or unverified security posture."

        return SessionSecurityAssessment(
            grade=grade,
            grade_rationale=rationale,
            findings=findings,
            critical_findings_count=critical_cnt,
            high_findings_count=high_cnt,
            medium_findings_count=med_cnt,
            low_findings_count=low_cnt,
            info_findings_count=info_cnt,
            post_quantum_ready=pqc_result.pqc_ready,
            post_quantum_summary=pqc_result.evidence_summary
        )

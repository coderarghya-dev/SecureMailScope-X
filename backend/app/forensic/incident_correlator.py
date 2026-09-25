"""
SecureMailScope X - Evidence-Bounded Multi-Session Incident Correlator
Correlates forensic evidence across multiple TCP streams to identify systemic protocol weaknesses,
repeated downgrade anomalies, plaintext exposure, static RSA clusters, and PQC readiness gaps.

Authoritative & Claim-Boundary Principles:
1. Deterministic findings remain authoritative (non-ML generated).
2. Correlation confidence (HIGH/MEDIUM/LOW) describes the precision of the deterministic rule match,
   NOT the probability of malicious activity or attack attribution.
3. Incident correlation does not imply proven causal certainty or attack attribution.
4. Repeated STARTTLS failures are classified under STARTTLS_FAILURE_PATTERN unless explicit
   downgrade behavior is observed (STARTTLS_DOWNGRADE_PATTERN). Active stripping is only claimed
   when explicit tampering evidence is present.
5. PQC/HNDL analysis states observable facts (classical-only key exchange observed without hybrid mitigation),
   without claiming traffic "will be decrypted" or is compromised.
6. Certificate reuse correlation strictly requires matching observable certificate fingerprints,
   never subject names, hostnames, or IP addresses alone.
"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from app.schemas.forensic import (
    EmailSession, SecurityMode, TLSVersion, FindingSeverity, SecurityGrade
)


@dataclass
class CorrelatedIncident:
    """
    Evidence-linked multi-session security incident.
    
    Attributes:
        incident_id: Canonical incident identifier
        incident_type: Specific incident classification (e.g. STARTTLS_FAILURE_PATTERN, STARTTLS_DOWNGRADE_PATTERN, REPEATED_PLAINTEXT_EXPOSURE, WEAK_TLS_CLUSTER, STATIC_RSA_CLUSTER, CERTIFICATE_REUSE, PQC_READINESS_GAP_CLUSTER)
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
        session_ids: Explicit list of correlated session IDs
        finding_ids: Explicit list of underlying deterministic finding IDs
        evidence_frames: Native frame numbers supporting the correlation
        correlation_reasons: Descriptive observable rationale for grouping
        confidence: Correlation confidence (HIGH/MEDIUM/LOW) indicating rule-match certainty, NOT attack probability
        authoritative: True indicates deterministic evidence-backed derivation (not ML-generated); does NOT imply proven causal adversary attribution
        evidence_backed: True when backed by observable packet facts
        correlation_method: Exact correlation strategy employed
    """
    incident_id: str
    incident_type: str
    severity: str
    session_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    evidence_frames: List[int] = field(default_factory=list)
    correlation_reasons: List[str] = field(default_factory=list)
    confidence: str = "HIGH"
    authoritative: bool = True
    evidence_backed: bool = True
    correlation_method: str = "DETERMINISTIC_RULE_CORRELATION"
    pattern_name: Optional[str] = None
    endpoint: Optional[str] = None
    evidence_summary: Optional[str] = None
    recommendation: Optional[str] = None

    @property
    def related_session_ids(self) -> List[str]:
        return self.session_ids

    @property
    def relevant_frames(self) -> List[int]:
        return self.evidence_frames

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "session_ids": self.session_ids,
            "related_session_ids": self.session_ids,
            "finding_ids": self.finding_ids,
            "evidence_frames": self.evidence_frames,
            "relevant_frames": self.evidence_frames,
            "correlation_reasons": self.correlation_reasons,
            "confidence": self.confidence,
            "authoritative": self.authoritative,
            "evidence_backed": self.evidence_backed,
            "correlation_method": self.correlation_method,
            "pattern_name": self.pattern_name or self.incident_type,
            "endpoint": self.endpoint or "",
            "evidence_summary": self.evidence_summary or "",
            "recommendation": self.recommendation or "",
        }


@dataclass
class MultiSessionSummary:
    """Capture-level summary of sessions, findings, and correlated incidents."""
    total_sessions: int = 0
    sessions_with_findings: int = 0
    incident_count: int = 0
    critical_high_incident_count: int = 0
    repeated_pattern_count: int = 0
    uncorrelated_sessions_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_sessions": self.total_sessions,
            "sessions_with_findings": self.sessions_with_findings,
            "incident_count": self.incident_count,
            "critical_high_incident_count": self.critical_high_incident_count,
            "repeated_pattern_count": self.repeated_pattern_count,
            "uncorrelated_sessions_count": self.uncorrelated_sessions_count,
        }


class IncidentCorrelator:
    """
    Evidence-bounded incident correlation engine.
    Correlates multiple sessions into unified security incidents only when backed by
    deterministic finding signatures and observable frame evidence.
    """

    @classmethod
    def correlate_sessions(cls, sessions: List[EmailSession]) -> List[CorrelatedIncident]:
        incidents: List[CorrelatedIncident] = []
        if not sessions:
            return incidents

        correlated_session_ids: Set[str] = set()

        def get_matching_finding_ids(sess_list: List[EmailSession], target_finding_prefixes: List[str]) -> List[str]:
            f_ids = []
            for s in sess_list:
                if s.security_assessment:
                    for f in s.security_assessment.findings:
                        if any(f.id.startswith(pfx) or f.id == pfx for pfx in target_finding_prefixes):
                            f_ids.append(f.id)
            return sorted(list(set(f_ids)))

        # -------------------------------------------------------------------
        # 1a. Repeated STARTTLS Failure Pattern (Rejections / Negotiation Failures)
        # -------------------------------------------------------------------
        failed_sessions = [
            s for s in sessions
            if s.security_mode == SecurityMode.STARTTLS_FAILED or (
                s.security_assessment and any(f.id == "FINDING-STARTTLS-UPGRADE-FAILED" for f in s.security_assessment.findings)
            )
        ]

        if len(failed_sessions) >= 2:
            sess_ids = [s.session_id for s in failed_sessions]
            frames: List[int] = []
            endpoints = set()
            for s in failed_sessions:
                endpoints.add(f"{s.server_ip}:{s.server_port}")
                if s.starttls_state.requested_frame:
                    frames.append(s.starttls_state.requested_frame)
                if s.starttls_state.failure_frame:
                    frames.append(s.starttls_state.failure_frame)
                if s.security_assessment:
                    for f in s.security_assessment.findings:
                        if f.id == "FINDING-STARTTLS-UPGRADE-FAILED":
                            frames.extend(f.evidence_frames)

            clean_frames = sorted(list(set([f for f in frames if f is not None])))
            finding_ids = get_matching_finding_ids(failed_sessions, ["FINDING-STARTTLS-UPGRADE-FAILED"])
            primary_ep = ", ".join(sorted(endpoints))

            conf = "HIGH" if len(endpoints) == 1 else "MEDIUM"

            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-STARTTLS-FAILURE-PATTERN",
                incident_type="STARTTLS_FAILURE_PATTERN",
                severity="HIGH",
                session_ids=sess_ids,
                finding_ids=finding_ids,
                evidence_frames=clean_frames,
                correlation_reasons=[
                    f"Observed {len(failed_sessions)} sessions where STARTTLS handshake was rejected or failed on {primary_ep}.",
                    f"Session evidence frames ({', '.join(map(str, clean_frames[:6]))}) record server rejection response codes."
                ],
                confidence=conf,
                authoritative=True,
                evidence_backed=True,
                correlation_method="DETERMINISTIC_RULE_CORRELATION",
                pattern_name="Repeated STARTTLS Failure Pattern",
                endpoint=primary_ep,
                evidence_summary=f"Observed {len(failed_sessions)} sessions where STARTTLS handshake was rejected or failed.",
                recommendation="Investigate whether server configuration, intermediary behavior, or client policy caused repeated STARTTLS failures."
            ))
            correlated_session_ids.update(sess_ids)

        elif len(failed_sessions) == 1:
            s = failed_sessions[0]
            frames = []
            if s.starttls_state.requested_frame:
                frames.append(s.starttls_state.requested_frame)
            if s.starttls_state.failure_frame:
                frames.append(s.starttls_state.failure_frame)
            if s.security_assessment:
                for f in s.security_assessment.findings:
                    if f.id == "FINDING-STARTTLS-UPGRADE-FAILED":
                        frames.extend(f.evidence_frames)

            clean_frames = sorted(list(set([f for f in frames if f is not None])))
            finding_ids = get_matching_finding_ids([s], ["FINDING-STARTTLS-UPGRADE-FAILED"])

            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-STARTTLS-FAILURE-PATTERN",
                incident_type="STARTTLS_FAILURE_PATTERN",
                severity="HIGH",
                session_ids=[s.session_id],
                finding_ids=finding_ids,
                evidence_frames=clean_frames,
                correlation_reasons=[
                    f"STARTTLS negotiation failure observed in session {s.session_id} on {s.server_ip}:{s.server_port}."
                ],
                confidence="HIGH",
                authoritative=True,
                evidence_backed=True,
                correlation_method="DETERMINISTIC_RULE_CORRELATION",
                pattern_name="Isolated STARTTLS Negotiation Failure",
                endpoint=f"{s.server_ip}:{s.server_port}",
                evidence_summary=f"Observed STARTTLS handshake rejection on stream {s.stream_index}.",
                recommendation="Investigate whether server configuration, intermediary behavior, or client policy caused repeated STARTTLS failures."
            ))
            correlated_session_ids.add(s.session_id)

        # -------------------------------------------------------------------
        # 1b. Repeated STARTTLS Downgrade / Stripping Risk (Advertised but Unused)
        # -------------------------------------------------------------------
        downgrade_sessions = [
            s for s in sessions
            if s.security_assessment and any(f.id == "FINDING-STARTTLS-STRIPPING-RISK" for f in s.security_assessment.findings)
        ]

        if len(downgrade_sessions) >= 2:
            sess_ids = [s.session_id for s in downgrade_sessions]
            frames = []
            endpoints = set()
            for s in downgrade_sessions:
                endpoints.add(f"{s.server_ip}:{s.server_port}")
                if s.starttls_state.advertised_frame:
                    frames.append(s.starttls_state.advertised_frame)
                if s.security_assessment:
                    for f in s.security_assessment.findings:
                        if f.id == "FINDING-STARTTLS-STRIPPING-RISK":
                            frames.extend(f.evidence_frames)

            clean_frames = sorted(list(set([f for f in frames if f is not None])))
            finding_ids = get_matching_finding_ids(downgrade_sessions, ["FINDING-STARTTLS-STRIPPING-RISK"])
            primary_ep = ", ".join(sorted(endpoints))

            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-STARTTLS-DOWNGRADE-PATTERN",
                incident_type="STARTTLS_DOWNGRADE_PATTERN",
                severity="HIGH",
                session_ids=sess_ids,
                finding_ids=finding_ids,
                evidence_frames=clean_frames,
                correlation_reasons=[
                    f"Observed {len(downgrade_sessions)} sessions where STARTTLS was advertised by {primary_ep} but unrequested by the client."
                ],
                confidence="HIGH" if len(endpoints) == 1 else "MEDIUM",
                authoritative=True,
                evidence_backed=True,
                correlation_method="DETERMINISTIC_RULE_CORRELATION",
                pattern_name="Repeated STARTTLS Capability Advertised but Unused (Possible Downgrade)",
                endpoint=primary_ep,
                evidence_summary=f"Detected {len(downgrade_sessions)} sessions where server advertised STARTTLS capability but client proceeded in cleartext without requesting TLS.",
                recommendation="Investigate client transport security configuration and mail server policy to verify strict TLS requirements (MTA-STS / DANE)."
            ))
            correlated_session_ids.update(sess_ids)

        elif len(downgrade_sessions) == 1 and len(failed_sessions) == 0:
            s = downgrade_sessions[0]
            frames = []
            if s.starttls_state.advertised_frame:
                frames.append(s.starttls_state.advertised_frame)
            if s.security_assessment:
                for f in s.security_assessment.findings:
                    if f.id == "FINDING-STARTTLS-STRIPPING-RISK":
                        frames.extend(f.evidence_frames)

            clean_frames = sorted(list(set([f for f in frames if f is not None])))
            finding_ids = get_matching_finding_ids([s], ["FINDING-STARTTLS-STRIPPING-RISK"])

            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-STARTTLS-DOWNGRADE-PATTERN",
                incident_type="STARTTLS_DOWNGRADE_PATTERN",
                severity="HIGH",
                session_ids=[s.session_id],
                finding_ids=finding_ids,
                evidence_frames=clean_frames,
                correlation_reasons=[
                    f"Server advertised STARTTLS capability on frame {s.starttls_state.advertised_frame}, but client did not request it."
                ],
                confidence="HIGH",
                authoritative=True,
                evidence_backed=True,
                correlation_method="DETERMINISTIC_RULE_CORRELATION",
                pattern_name="Isolated STARTTLS Unrequested Capability (Possible Downgrade)",
                endpoint=f"{s.server_ip}:{s.server_port}",
                evidence_summary="Observed session where STARTTLS capability was advertised but unrequested.",
                recommendation="Investigate client transport security configuration to enforce strict TLS requirements."
            ))
            correlated_session_ids.add(s.session_id)

        # -------------------------------------------------------------------
        # 2. Repeated Plaintext Exposure
        # -------------------------------------------------------------------
        plaintext_sessions = [s for s in sessions if s.security_mode == SecurityMode.PLAINTEXT]
        if len(plaintext_sessions) >= 2:
            sess_ids = [s.session_id for s in plaintext_sessions]
            frames = []
            endpoints = set()
            for s in plaintext_sessions:
                endpoints.add(f"{s.server_ip}:{s.server_port}")
                frames.extend([p.frame_number for p in s.evidence_packets[:3]])
                if s.security_assessment:
                    for f in s.security_assessment.findings:
                        if f.id == "FINDING-PLAINTEXT-COMMUNICATION":
                            frames.extend(f.evidence_frames)

            clean_frames = sorted(list(set([f for f in frames if f is not None])))
            finding_ids = get_matching_finding_ids(plaintext_sessions, ["FINDING-PLAINTEXT-COMMUNICATION"])
            primary_ep = ", ".join(sorted(endpoints))

            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-REPEATED-PLAINTEXT",
                incident_type="REPEATED_PLAINTEXT_EXPOSURE",
                severity="CRITICAL",
                session_ids=sess_ids,
                finding_ids=finding_ids,
                evidence_frames=clean_frames,
                correlation_reasons=[
                    f"Identified {len(plaintext_sessions)} independent email sessions transmitting entirely in cleartext.",
                    f"Endpoints involved: {primary_ep}. Authentication credentials and payloads exposed."
                ],
                confidence="HIGH",
                authoritative=True,
                evidence_backed=True,
                correlation_method="DETERMINISTIC_RULE_CORRELATION",
                pattern_name="Repeated Cleartext Protocol Session Transmission",
                endpoint=primary_ep,
                evidence_summary=f"Observed {len(plaintext_sessions)} distinct plaintext sessions transmitting unencrypted mail traffic across {primary_ep}.",
                recommendation="Enforce mandatory transport-layer encryption (STARTTLS or Direct TLS) across all mail endpoints."
            ))
            correlated_session_ids.update(sess_ids)

        # -------------------------------------------------------------------
        # 3. Static RSA Cluster (No Forward Secrecy)
        # -------------------------------------------------------------------
        static_rsa_sessions: List[EmailSession] = []
        for s in sessions:
            if s.security_assessment:
                if any(f.id == "FINDING-NO-FORWARD-SECRECY" for f in s.security_assessment.findings):
                    static_rsa_sessions.append(s)

        if len(static_rsa_sessions) >= 2:
            sess_ids = [s.session_id for s in static_rsa_sessions]
            frames = []
            endpoints = set()
            for s in static_rsa_sessions:
                endpoints.add(f"{s.server_ip}:{s.server_port}")
                if s.tls_details and s.tls_details.server_hello_frame:
                    frames.append(s.tls_details.server_hello_frame)
                if s.security_assessment:
                    for f in s.security_assessment.findings:
                        if f.id == "FINDING-NO-FORWARD-SECRECY":
                            frames.extend(f.evidence_frames)

            clean_frames = sorted(list(set([f for f in frames if f is not None])))
            finding_ids = get_matching_finding_ids(static_rsa_sessions, ["FINDING-NO-FORWARD-SECRECY"])
            primary_ep = ", ".join(sorted(endpoints))

            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-STATIC-RSA-CLUSTER",
                incident_type="STATIC_RSA_CLUSTER",
                severity="HIGH",
                session_ids=sess_ids,
                finding_ids=finding_ids,
                evidence_frames=clean_frames,
                correlation_reasons=[
                    f"Observed {len(static_rsa_sessions)} sessions negotiating static RSA cipher suites without Perfect Forward Secrecy.",
                    f"Target endpoints: {primary_ep}."
                ],
                confidence="HIGH",
                authoritative=True,
                evidence_backed=True,
                correlation_method="DETERMINISTIC_RULE_CORRELATION",
                pattern_name="Repeated Static RSA Key Exchange (No Forward Secrecy)",
                endpoint=primary_ep,
                evidence_summary=f"Observed {len(static_rsa_sessions)} sessions negotiating static RSA cipher suites lacking Perfect Forward Secrecy.",
                recommendation="Disable static RSA cipher suites (TLS_RSA_WITH_*). Enforce ECDHE or DHE key exchange."
            ))
            correlated_session_ids.update(sess_ids)

        # -------------------------------------------------------------------
        # 4. Weak / Deprecated TLS Cluster
        # -------------------------------------------------------------------
        weak_tls_sessions: List[EmailSession] = []
        for s in sessions:
            if s.security_assessment:
                if any(
                    f.id in [
                        "FINDING-DEPRECATED-TLS-VERSION",
                        "FINDING-INSECURE-LEGACY-SSL",
                        "FINDING-INSECURE-CIPHER-SUITE",
                        "FINDING-DEPRECATED-CIPHER-SUITE"
                    ]
                    for f in s.security_assessment.findings
                ):
                    weak_tls_sessions.append(s)

        if len(weak_tls_sessions) >= 2:
            sess_ids = [s.session_id for s in weak_tls_sessions]
            frames = []
            endpoints = set()
            for s in weak_tls_sessions:
                endpoints.add(f"{s.server_ip}:{s.server_port}")
                if s.tls_details and s.tls_details.server_hello_frame:
                    frames.append(s.tls_details.server_hello_frame)
                if s.security_assessment:
                    for f in s.security_assessment.findings:
                        if f.id in [
                            "FINDING-DEPRECATED-TLS-VERSION",
                            "FINDING-INSECURE-LEGACY-SSL",
                            "FINDING-INSECURE-CIPHER-SUITE",
                            "FINDING-DEPRECATED-CIPHER-SUITE"
                        ]:
                            frames.extend(f.evidence_frames)

            clean_frames = sorted(list(set([f for f in frames if f is not None])))
            finding_ids = get_matching_finding_ids(
                weak_tls_sessions,
                [
                    "FINDING-DEPRECATED-TLS-VERSION",
                    "FINDING-INSECURE-LEGACY-SSL",
                    "FINDING-INSECURE-CIPHER-SUITE",
                    "FINDING-DEPRECATED-CIPHER-SUITE"
                ]
            )
            primary_ep = ", ".join(sorted(endpoints))

            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-WEAK-TLS-CLUSTER",
                incident_type="WEAK_TLS_CLUSTER",
                severity="HIGH",
                session_ids=sess_ids,
                finding_ids=finding_ids,
                evidence_frames=clean_frames,
                correlation_reasons=[
                    f"Observed {len(weak_tls_sessions)} sessions negotiating deprecated TLS versions (RFC 8996) or legacy ciphers.",
                    f"Impacted endpoints: {primary_ep}."
                ],
                confidence="HIGH",
                authoritative=True,
                evidence_backed=True,
                correlation_method="DETERMINISTIC_RULE_CORRELATION",
                pattern_name="Repeated Legacy TLS Version / Insecure Cipher Usage",
                endpoint=primary_ep,
                evidence_summary=f"Observed {len(weak_tls_sessions)} sessions negotiating deprecated TLS versions (RFC 8996) or legacy ciphers.",
                recommendation="Disable TLS 1.0 and 1.1 globally. Require TLS 1.2 and TLS 1.3 with modern AEAD ciphers."
            ))
            correlated_session_ids.update(sess_ids)

        # -------------------------------------------------------------------
        # 5. PQC Readiness Gap Cluster (Harvest Now, Decrypt Later)
        # -------------------------------------------------------------------
        pqc_gap_sessions: List[EmailSession] = []
        for s in sessions:
            if s.security_assessment:
                if any(f.id == "FINDING-PQC-CLASSICAL-KEX-EXPOSURE" for f in s.security_assessment.findings):
                    pqc_gap_sessions.append(s)

        if len(pqc_gap_sessions) >= 2:
            sess_ids = [s.session_id for s in pqc_gap_sessions]
            frames = []
            endpoints = set()
            for s in pqc_gap_sessions:
                endpoints.add(f"{s.server_ip}:{s.server_port}")
                if s.tls_details and s.tls_details.server_hello_frame:
                    frames.append(s.tls_details.server_hello_frame)
                if s.security_assessment:
                    for f in s.security_assessment.findings:
                        if f.id == "FINDING-PQC-CLASSICAL-KEX-EXPOSURE":
                            frames.extend(f.evidence_frames)

            clean_frames = sorted(list(set([f for f in frames if f is not None])))
            finding_ids = get_matching_finding_ids(pqc_gap_sessions, ["FINDING-PQC-CLASSICAL-KEX-EXPOSURE"])
            primary_ep = ", ".join(sorted(endpoints))

            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-PQC-READINESS-GAP-CLUSTER",
                incident_type="PQC_READINESS_GAP_CLUSTER",
                severity="MEDIUM",
                session_ids=sess_ids,
                finding_ids=finding_ids,
                evidence_frames=clean_frames,
                correlation_reasons=[
                    f"Classical-only key establishment was observed, and no hybrid/PQC mitigation was observed for future quantum-decryption risk across {len(pqc_gap_sessions)} sessions.",
                    f"Impacted endpoints: {primary_ep}."
                ],
                confidence="MEDIUM",
                authoritative=True,
                evidence_backed=True,
                correlation_method="DETERMINISTIC_RULE_CORRELATION",
                pattern_name="Classical-Only Key Establishment Posture Cluster",
                endpoint=primary_ep,
                evidence_summary=f"Classical-only key establishment was observed, and no hybrid/PQC mitigation was observed for future quantum-decryption risk across {len(pqc_gap_sessions)} sessions.",
                recommendation="Consider deploying hybrid classical + post-quantum key exchange (e.g. X25519MLKEM768 / SecP256r1MLKEM768 under NIST FIPS 203) where appropriate for long-term confidentiality protection."
            ))
            correlated_session_ids.update(sess_ids)

        # -------------------------------------------------------------------
        # 6. Observable Certificate Reuse (Strict Fingerprint Equality Only)
        # -------------------------------------------------------------------
        cert_fingerprints: Dict[str, List[EmailSession]] = {}
        for s in sessions:
            if s.tls_details and s.tls_details.certificate_fingerprint_sha256:
                fp = s.tls_details.certificate_fingerprint_sha256.strip().lower()
                if fp:
                    cert_fingerprints.setdefault(fp, []).append(s)

        for fp, c_sessions in cert_fingerprints.items():
            if len(c_sessions) >= 2:
                sess_ids = [s.session_id for s in c_sessions]
                frames = [s.tls_details.server_hello_frame for s in c_sessions if s.tls_details and s.tls_details.server_hello_frame]
                primary_ep = ", ".join(sorted(set(f"{s.server_ip}:{s.server_port}" for s in c_sessions)))
                incidents.append(CorrelatedIncident(
                    incident_id="INCIDENT-CERTIFICATE-REUSE",
                    incident_type="CERTIFICATE_REUSE",
                    severity="INFO",
                    session_ids=sess_ids,
                    finding_ids=[],
                    evidence_frames=sorted(list(set([f for f in frames if f is not None]))),
                    correlation_reasons=[
                        f"Observed identical verified certificate SHA-256 fingerprint ({fp[:16]}...) reused across {len(c_sessions)} distinct connections on {primary_ep}."
                    ],
                    confidence="HIGH",
                    authoritative=True,
                    evidence_backed=True,
                    correlation_method="DETERMINISTIC_RULE_CORRELATION",
                    pattern_name="Observed Identical Certificate Fingerprint Reuse",
                    endpoint=primary_ep,
                    evidence_summary=f"Identical certificate SHA-256 fingerprint observed across {len(c_sessions)} connections.",
                    recommendation="Monitor certificate lifecycle and renewal schedules."
                ))
                correlated_session_ids.update(sess_ids)

        return incidents

    @classmethod
    def generate_summary(cls, sessions: List[EmailSession], incidents: List[CorrelatedIncident]) -> MultiSessionSummary:
        """
        Computes capture-level summary metrics across sessions and correlated incidents.
        """
        total = len(sessions)
        with_findings = 0
        all_correlated_sessions: Set[str] = set()

        for s in sessions:
            has_actionable_findings = False
            if s.security_assessment:
                non_info = [f for f in s.security_assessment.findings if f.severity != FindingSeverity.INFO]
                if non_info:
                    has_actionable_findings = True
            if has_actionable_findings or s.security_mode in [SecurityMode.PLAINTEXT, SecurityMode.STARTTLS_FAILED]:
                with_findings += 1

        for inc in incidents:
            if inc.incident_type != "UNCORRELATED":
                all_correlated_sessions.update(inc.session_ids)

        crit_high = sum(1 for inc in incidents if inc.severity in ["CRITICAL", "HIGH"])
        repeated = sum(1 for inc in incidents if len(inc.session_ids) >= 2)
        uncorrelated = max(0, total - len(all_correlated_sessions))

        return MultiSessionSummary(
            total_sessions=total,
            sessions_with_findings=with_findings,
            incident_count=len(incidents),
            critical_high_incident_count=crit_high,
            repeated_pattern_count=repeated,
            uncorrelated_sessions_count=uncorrelated
        )

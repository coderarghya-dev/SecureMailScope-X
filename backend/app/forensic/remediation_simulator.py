"""
SecureMailScope X - Evidence-Preserving Remediation Simulator (Phase 10 & 10.5)
Simulates what-if security posture changes under specific policy remediations
without mutating or replacing authoritative observed forensic evidence.

CORE FORENSIC BOUNDARIES:
1. Observed analysis remains immutable; original evidence, frames, and findings are never modified.
2. Provenance is strictly labeled:
   - source = "SIMULATED_REMEDIATION"
   - authoritative = False
   - historical_applicability = "HYPOTHETICAL"
   - observed_state_preserved = True
   - projected_score_method = "DETERMINISTIC_RULE_ENGINE"
3. Never fabricates packet frames, key_share bytes, or synthetic X.509 certificates.
4. Shares identical deterministic grade calculation function with CryptographicRuleEngine.
"""

from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
import copy

from app.schemas.forensic import (
    EmailSession,
    SessionSecurityAssessment,
    SecurityGrade,
    SecurityFinding,
    FindingSeverity,
    FindingCategory,
    SecurityMode,
    TLSVersion,
)
from app.forensic.rule_engine import CryptographicRuleEngine


SUPPORTED_REMEDIATIONS: Set[str] = {
    "DISABLE_DEPRECATED_TLS",
    "REQUIRE_STARTTLS",
    "ENABLE_FORWARD_SECRECY",
    "REPLACE_WEAK_CIPHER",
    "RENEW_CERTIFICATE",
    "UPGRADE_RSA_KEY",
    "ENABLE_HYBRID_PQC",
    "ENABLE_DMARC_POLICY",
    "FIX_DMARC_CONFIGURATION",
    "ENABLE_SPF_POLICY",
    "FIX_SPF_CONFIGURATION",
    "ENABLE_MTA_STS",
}


@dataclass
class ObservedSummary:
    session_id: str
    security_mode: str
    security_grade: str
    score: int
    findings_count: int
    findings: List[Dict[str, Any]]
    post_quantum_ready: bool
    evidence_confidence_score: Optional[int] = None
    evidence_confidence_level: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "security_mode": self.security_mode,
            "security_grade": self.security_grade,
            "score": self.score,
            "findings_count": self.findings_count,
            "findings": self.findings,
            "post_quantum_ready": self.post_quantum_ready,
            "evidence_confidence_score": self.evidence_confidence_score,
            "evidence_confidence_level": self.evidence_confidence_level,
        }


@dataclass
class SimulatedSummary:
    projected_security_grade: str
    projected_score: int
    projected_score_method: str = "DETERMINISTIC_RULE_ENGINE"
    projected_findings_count: int = 0
    projected_pqc_readiness: str = "CLASSICAL_ONLY"  # "OBSERVED", "PROJECTED", "CLASSICAL_ONLY"
    projected_pqc_status: str = "CLASSICAL_ONLY"  # "OBSERVED_PQC", "HYBRID_POLICY_ASSUMED", "CLASSICAL_ONLY", "ALREADY_PQC_READY"
    projected_validity_status: Optional[str] = None  # "ASSUMED_VALID_AFTER_RENEWAL"
    projected_policy_state: Optional[str] = None
    projected_evidence_confidence: str = "NOT_APPLICABLE"
    disclaimer: str = (
        "PROJECTED POSTURE — Simulation only. Hypothetical policy projection that does not alter verified historical PCAP evidence."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "projected_security_grade": self.projected_security_grade,
            "projected_score": self.projected_score,
            "projected_score_method": self.projected_score_method,
            "projected_findings_count": self.projected_findings_count,
            "projected_pqc_readiness": self.projected_pqc_readiness,
            "projected_pqc_status": self.projected_pqc_status,
            "projected_validity_status": self.projected_validity_status,
            "projected_policy_state": self.projected_policy_state,
            "projected_evidence_confidence": self.projected_evidence_confidence,
            "disclaimer": self.disclaimer,
        }


@dataclass
class RemediationSimulationReport:
    source: str = "SIMULATED_REMEDIATION"
    authoritative: bool = False
    historical_applicability: str = "HYPOTHETICAL"
    observed_state_preserved: bool = True
    session_id: str = ""
    observed_summary: Optional[ObservedSummary] = None
    simulated_summary: Optional[SimulatedSummary] = None
    remediation_status_map: Dict[str, str] = field(default_factory=dict)  # Action -> APPLIED / NOT_APPLICABLE / INSUFFICIENT_EVIDENCE / UNSUPPORTED
    applied_remediations: List[str] = field(default_factory=list)
    not_applicable_remediations: List[str] = field(default_factory=list)
    insufficient_evidence_remediations: List[str] = field(default_factory=list)
    unsupported_remediations: List[str] = field(default_factory=list)
    projected_findings_removed: List[Dict[str, Any]] = field(default_factory=list)
    projected_findings_remaining: List[Dict[str, Any]] = field(default_factory=list)
    projected_findings_added: List[Dict[str, Any]] = field(default_factory=list)
    projection_confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    assumptions: List[str] = field(default_factory=list)
    projection_limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "authoritative": self.authoritative,
            "historical_applicability": self.historical_applicability,
            "observed_state_preserved": self.observed_state_preserved,
            "session_id": self.session_id,
            "observed_summary": self.observed_summary.to_dict() if self.observed_summary else None,
            "simulated_summary": self.simulated_summary.to_dict() if self.simulated_summary else None,
            "remediation_status_map": self.remediation_status_map,
            "applied_remediations": self.applied_remediations,
            "not_applicable_remediations": self.not_applicable_remediations,
            "insufficient_evidence_remediations": self.insufficient_evidence_remediations,
            "unsupported_remediations": self.unsupported_remediations,
            "projected_findings_removed": self.projected_findings_removed,
            "projected_findings_remaining": self.projected_findings_remaining,
            "projected_findings_added": self.projected_findings_added,
            "projection_confidence": self.projection_confidence,
            "assumptions": self.assumptions,
            "projection_limitations": self.projection_limitations,
        }


class RemediationSimulator:
    """Calculates deterministic projected risk posture under hypothetical security hardening."""

    @classmethod
    def simulate(
        cls,
        session: EmailSession,
        remediations: Optional[List[str]] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> RemediationSimulationReport:
        """
        Runs an evidence-preserving simulation against an observed email session.
        Guarantees zero mutation of session or any nested objects.
        """
        remed_list = remediations or []
        params = parameters or {}

        # 1. Build immutable observed summary
        assessment = session.security_assessment
        obs_grade = assessment.grade.value if assessment else "F"
        obs_findings = [
            f.model_dump() if hasattr(f, "model_dump") else f.__dict__
            for f in (assessment.findings if assessment else [])
        ]
        obs_pqc_ready = assessment.post_quantum_ready if assessment else False
        obs_score = cls._calculate_score(assessment.findings if assessment else [])

        conf_obj = getattr(session, "evidence_confidence", None) or getattr(session, "confidence_assessment", None)
        conf_score = conf_obj.score if conf_obj else None
        conf_level = (
            conf_obj.level.value
            if conf_obj and hasattr(conf_obj.level, "value")
            else (str(conf_obj.level) if conf_obj else None)
        )

        observed_sum = ObservedSummary(
            session_id=session.session_id,
            security_mode=session.security_mode.value if hasattr(session.security_mode, "value") else str(session.security_mode),
            security_grade=obs_grade,
            score=obs_score,
            findings_count=len(obs_findings),
            findings=obs_findings,
            post_quantum_ready=obs_pqc_ready,
            evidence_confidence_score=conf_score,
            evidence_confidence_level=conf_level,
        )

        # 2. Categorize requested remediations
        status_map: Dict[str, str] = {}
        applied: List[str] = []
        not_applicable: List[str] = []
        insufficient_evidence: List[str] = []
        unsupported: List[str] = []
        assumptions: List[str] = []
        limitations: List[str] = [
            "Simulation represents HYPOTHETICAL policy projection only.",
            "Authoritative PCAP packet capture and forensic custody hashes remain untouched.",
            "No synthetic packet frames, key_share extensions, or X.509 certificates were created.",
        ]

        # Tracking finding removals
        current_findings_objects = list(assessment.findings) if assessment else []
        remaining_findings: List[SecurityFinding] = []
        removed_findings: List[SecurityFinding] = []

        # Parse requested actions
        requested_actions_clean = []
        for r in remed_list:
            r_clean = r.strip().upper()
            if r_clean not in SUPPORTED_REMEDIATIONS:
                unsupported.append(r)
                status_map[r] = "UNSUPPORTED"
            else:
                if r_clean not in requested_actions_clean:
                    requested_actions_clean.append(r_clean)

        # 3. Evaluate each finding against requested actions
        projected_validity_status = None

        for f in current_findings_objects:
            f_id = f.id.upper()
            eliminated = False

            # DISABLE_DEPRECATED_TLS
            if "DISABLE_DEPRECATED_TLS" in requested_actions_clean and any(
                k in f_id for k in ["DEPRECATED-TLS", "TLS-1-0", "TLS-1-1", "TLS-DEPRECATED", "TLS10", "TLS11"]
            ):
                eliminated = True
                if "DISABLE_DEPRECATED_TLS" not in applied:
                    applied.append("DISABLE_DEPRECATED_TLS")
                    status_map["DISABLE_DEPRECATED_TLS"] = "APPLIED"
                    assumptions.append("Assumes TLS 1.0 and TLS 1.1 are disabled in server configuration.")

            # REQUIRE_STARTTLS
            elif "REQUIRE_STARTTLS" in requested_actions_clean and any(
                k in f_id for k in ["PLAINTEXT", "CLEAR-TEXT", "UNENCRYPTED", "STRIPPING", "STARTTLS-STRIPPING", "TRANSITION-FAILED"]
            ):
                eliminated = True
                if "REQUIRE_STARTTLS" not in applied:
                    applied.append("REQUIRE_STARTTLS")
                    status_map["REQUIRE_STARTTLS"] = "APPLIED"
                    assumptions.append("Assumes mandatory STARTTLS / Direct TLS transport encryption is configured and enforced; does not claim previous historical failure cause was repaired.")

            # ENABLE_FORWARD_SECRECY
            elif "ENABLE_FORWARD_SECRECY" in requested_actions_clean and any(
                k in f_id for k in ["NO-FORWARD-SECRECY", "STATIC-RSA", "NO-PFS", "NO_PFS", "STATIC_RSA"]
            ):
                eliminated = True
                if "ENABLE_FORWARD_SECRECY" not in applied:
                    applied.append("ENABLE_FORWARD_SECRECY")
                    status_map["ENABLE_FORWARD_SECRECY"] = "APPLIED"
                    assumptions.append("Assumes static RSA key exchange is replaced by ECDHE / DHE ephemeral key exchange.")

            # REPLACE_WEAK_CIPHER
            elif "REPLACE_WEAK_CIPHER" in requested_actions_clean and any(
                k in f_id for k in ["DEPRECATED-CIPHER", "WEAK-CIPHER", "CIPHER-CBC", "CIPHER-RC4", "CIPHER-3DES", "3DES", "RC4"]
            ):
                eliminated = True
                if "REPLACE_WEAK_CIPHER" not in applied:
                    applied.append("REPLACE_WEAK_CIPHER")
                    status_map["REPLACE_WEAK_CIPHER"] = "APPLIED"
                    assumptions.append("Assumes legacy ciphers (CBC, 3DES, RC4) are replaced by modern AEAD (AES-GCM / ChaCha20-Poly1305).")

            # RENEW_CERTIFICATE
            elif "RENEW_CERTIFICATE" in requested_actions_clean and any(
                k in f_id for k in ["CERT-EXPIRED", "CERTIFICATE-EXPIRED", "NOT-YET-VALID", "EXPIRING-SOON"]
            ):
                eliminated = True
                projected_validity_status = "ASSUMED_VALID_AFTER_RENEWAL"
                if "RENEW_CERTIFICATE" not in applied:
                    applied.append("RENEW_CERTIFICATE")
                    status_map["RENEW_CERTIFICATE"] = "APPLIED"
                    assumptions.append("Assumes expired X.509 certificate has been renewed with a valid validity period; no synthetic certificate fields are generated.")

            # UPGRADE_RSA_KEY
            elif "UPGRADE_RSA_KEY" in requested_actions_clean and any(
                k in f_id for k in ["WEAK-RSA", "CERT-WEAK-RSA", "KEY-SIZE"]
            ):
                eliminated = True
                if "UPGRADE_RSA_KEY" not in applied:
                    applied.append("UPGRADE_RSA_KEY")
                    status_map["UPGRADE_RSA_KEY"] = "APPLIED"
                    target_bits = params.get("rsa_key_bits")
                    if target_bits:
                        assumptions.append(f"Assumes RSA public key length is upgraded to {target_bits} bits.")
                    else:
                        assumptions.append("Assumes RSA public key is upgraded to modern secure key standards without fabricating key bytes.")

            # ENABLE_DMARC_POLICY (handles missing or p=none policy)
            elif "ENABLE_DMARC_POLICY" in requested_actions_clean and any(
                k in f_id for k in ["DMARC-POLICY-NONE", "DMARC-POLICY-ABSENT", "DMARC-ABSENT", "DMARC-NONE"]
            ):
                eliminated = True
                if "ENABLE_DMARC_POLICY" not in applied:
                    applied.append("ENABLE_DMARC_POLICY")
                    status_map["ENABLE_DMARC_POLICY"] = "APPLIED"
                    assumptions.append("Assumes DMARC policy is upgraded to 'p=quarantine' or 'p=reject' (policy assumption; no synthetic DNS TXT record created).")

            # FIX_DMARC_CONFIGURATION (handles syntax/misconfiguration errors)
            elif "FIX_DMARC_CONFIGURATION" in requested_actions_clean and any(
                k in f_id for k in ["DMARC-SYNTAX", "DMARC-ERROR", "DMARC-CONFIG"]
            ):
                eliminated = True
                if "FIX_DMARC_CONFIGURATION" not in applied:
                    applied.append("FIX_DMARC_CONFIGURATION")
                    status_map["FIX_DMARC_CONFIGURATION"] = "APPLIED"
                    assumptions.append("Assumes DMARC configuration syntax and tags are corrected.")

            # ENABLE_SPF_POLICY (handles missing SPF only; does NOT remove PERMERROR)
            elif "ENABLE_SPF_POLICY" in requested_actions_clean and any(
                k in f_id for k in ["SPF-POLICY-ABSENT", "SPF-ABSENT"]
            ):
                eliminated = True
                if "ENABLE_SPF_POLICY" not in applied:
                    applied.append("ENABLE_SPF_POLICY")
                    status_map["ENABLE_SPF_POLICY"] = "APPLIED"
                    assumptions.append("Assumes valid SPF record (v=spf1 ... -all) is published (policy assumption).")

            # FIX_SPF_CONFIGURATION (specifically handles SPF PERMERROR and syntax errors)
            elif "FIX_SPF_CONFIGURATION" in requested_actions_clean and any(
                k in f_id for k in ["SPF-PERMERROR", "SPF-SYNTAX", "SPF-LOOKUP-LIMIT"]
            ):
                eliminated = True
                if "FIX_SPF_CONFIGURATION" not in applied:
                    applied.append("FIX_SPF_CONFIGURATION")
                    status_map["FIX_SPF_CONFIGURATION"] = "APPLIED"
                    assumptions.append("Assumes SPF record syntax, includes, and lookup limits are corrected.")

            # ENABLE_MTA_STS
            elif "ENABLE_MTA_STS" in requested_actions_clean and any(
                k in f_id for k in ["MTA-STS-TESTING", "MTA-STS-ABSENT"]
            ):
                eliminated = True
                if "ENABLE_MTA_STS" not in applied:
                    applied.append("ENABLE_MTA_STS")
                    status_map["ENABLE_MTA_STS"] = "APPLIED"
                    assumptions.append("Assumes MTA-STS policy mode is transitioned to 'enforce' (policy assumption).")

            # ENABLE_HYBRID_PQC
            elif "ENABLE_HYBRID_PQC" in requested_actions_clean and any(
                k in f_id for k in ["PQC-CLASSICAL-KEX", "HNDL-RISK", "PQC-READINESS"]
            ):
                eliminated = True
                if "ENABLE_HYBRID_PQC" not in applied:
                    applied.append("ENABLE_HYBRID_PQC")
                    status_map["ENABLE_HYBRID_PQC"] = "APPLIED"
                    assumptions.append("Assumes NIST FIPS 203 Post-Quantum hybrid key encapsulation is deployed without inventing raw key_share bytes.")

            if eliminated:
                removed_findings.append(f)
            else:
                remaining_findings.append(f)

        # 4. Handle PQC State Transformation
        projected_pqc_readiness = "OBSERVED" if obs_pqc_ready else "CLASSICAL_ONLY"
        projected_pqc_status = "OBSERVED_PQC" if obs_pqc_ready else "CLASSICAL_ONLY"

        if "ENABLE_HYBRID_PQC" in requested_actions_clean:
            if not obs_pqc_ready:
                if "ENABLE_HYBRID_PQC" not in applied:
                    applied.append("ENABLE_HYBRID_PQC")
                    status_map["ENABLE_HYBRID_PQC"] = "APPLIED"
                    assumptions.append("Assumes NIST FIPS 203 Post-Quantum hybrid key encapsulation is deployed without inventing raw key_share bytes.")
                projected_pqc_readiness = "PROJECTED"
                projected_pqc_status = "HYBRID_POLICY_ASSUMED"
            else:
                projected_pqc_status = "ALREADY_PQC_READY"
                status_map["ENABLE_HYBRID_PQC"] = "NOT_APPLICABLE"

        # 5. Populate not_applicable list for any remaining unapplied actions
        for req_act in requested_actions_clean:
            if req_act not in applied:
                if req_act not in not_applicable:
                    not_applicable.append(req_act)
                    status_map[req_act] = "NOT_APPLICABLE"

        # 6. Recalculate projected SecurityGrade using shared CryptographicRuleEngine
        projected_grade = cls._calculate_projected_grade_shared(
            session=session,
            remaining_findings=remaining_findings,
            applied=applied,
            projected_pqc_ready=(projected_pqc_readiness in ["OBSERVED", "PROJECTED"]),
            parameters=params,
        )
        projected_score = cls._calculate_score(remaining_findings)

        # 7. Evaluate projection confidence
        proj_conf = cls._calculate_projection_confidence(applied, requested_actions_clean)

        simulated_sum = SimulatedSummary(
            projected_security_grade=projected_grade.value,
            projected_score=projected_score,
            projected_score_method="DETERMINISTIC_RULE_ENGINE",
            projected_findings_count=len(remaining_findings),
            projected_pqc_readiness=projected_pqc_readiness,
            projected_pqc_status=projected_pqc_status,
            projected_validity_status=projected_validity_status,
            projected_policy_state="HYPOTHETICAL_HARDENED" if applied else "NO_CHANGE",
            projected_evidence_confidence="NOT_APPLICABLE",
        )

        return RemediationSimulationReport(
            session_id=session.session_id,
            observed_summary=observed_sum,
            simulated_summary=simulated_sum,
            remediation_status_map=status_map,
            applied_remediations=applied,
            not_applicable_remediations=not_applicable,
            insufficient_evidence_remediations=insufficient_evidence,
            unsupported_remediations=unsupported,
            projected_findings_removed=[
                f.model_dump() if hasattr(f, "model_dump") else f.__dict__ for f in removed_findings
            ],
            projected_findings_remaining=[
                f.model_dump() if hasattr(f, "model_dump") else f.__dict__ for f in remaining_findings
            ],
            projected_findings_added=[],
            projection_confidence=proj_conf,
            assumptions=assumptions,
            projection_limitations=limitations,
        )

    @classmethod
    def _calculate_projected_grade_shared(
        cls,
        session: EmailSession,
        remaining_findings: List[SecurityFinding],
        applied: List[str],
        projected_pqc_ready: bool,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> SecurityGrade:
        """
        Calculates projected SecurityGrade using the EXACT SAME CryptographicRuleEngine.compute_security_grade.
        """
        params = parameters or {}
        critical_cnt = sum(
            1 for f in remaining_findings
            if f.severity == FindingSeverity.CRITICAL and f.category != FindingCategory.DOMAIN_AUTHENTICATION
        )
        high_cnt = sum(1 for f in remaining_findings if f.severity == FindingSeverity.HIGH)

        # Determine projected security mode
        proj_sec_mode = session.security_mode
        if session.security_mode == SecurityMode.PLAINTEXT and "REQUIRE_STARTTLS" in applied:
            proj_sec_mode = SecurityMode.STARTTLS_ACCEPTED

        # Determine projected TLS version
        tls = session.tls_details
        proj_tls_ver = tls.negotiated_tls_version if tls else None
        if params.get("projected_tls_version"):
            proj_tls_ver = params.get("projected_tls_version")
        elif params.get("require_tls13"):
            proj_tls_ver = TLSVersion.TLSv1_3
        elif "DISABLE_DEPRECATED_TLS" in applied:
            if proj_tls_ver in [TLSVersion.TLSv1_0, TLSVersion.TLSv1_1, None, TLSVersion.UNKNOWN]:
                proj_tls_ver = TLSVersion.TLSv1_3

        # Determine projected PFS
        proj_pfs = None
        if tls:
            if tls.has_forward_secrecy is not None:
                proj_pfs = tls.has_forward_secrecy
            elif tls.cipher_info and tls.cipher_info.has_pfs is not None:
                proj_pfs = tls.cipher_info.has_pfs

        if "ENABLE_FORWARD_SECRECY" in applied:
            proj_pfs = True

        if proj_tls_ver == TLSVersion.TLSv1_3:
            proj_pfs = True

        # Call the authoritative shared pure grade calculation function
        grade, _ = CryptographicRuleEngine.compute_security_grade(
            security_mode=proj_sec_mode,
            tls_version=proj_tls_ver,
            has_pfs=proj_pfs,
            pqc_ready=projected_pqc_ready,
            critical_findings_count=critical_cnt,
            high_findings_count=high_cnt,
        )
        return grade

    @classmethod
    def _calculate_score(cls, findings: List[SecurityFinding]) -> int:
        """Calculates a deterministic 0-100 score based on findings severity deductions."""
        score = 100
        for f in findings:
            if f.severity == FindingSeverity.CRITICAL:
                score -= 40
            elif f.severity == FindingSeverity.HIGH:
                score -= 20
            elif f.severity == FindingSeverity.MEDIUM:
                score -= 10
            elif f.severity == FindingSeverity.LOW:
                score -= 5
        return max(0, min(100, score))

    @classmethod
    def _calculate_projection_confidence(
        cls,
        applied: List[str],
        requested: List[str],
    ) -> str:
        """
        Evaluates projection confidence.
        HIGH: Direct 1-to-1 deterministic mapping for all applied actions.
        MEDIUM: Complex composite policy assumptions made.
        LOW: Unclear or composite actions.
        """
        if not applied:
            return "HIGH"
        if "ENABLE_HYBRID_PQC" in applied and len(applied) > 3:
            return "MEDIUM"
        return "HIGH"

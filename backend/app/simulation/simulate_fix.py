"""
SecureMailScope X - Deterministic 'What If / Simulate Fix' Engine
Projects posture changes under remediation actions without modifying authoritative packet evidence.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from app.schemas.forensic import (
    EmailSession, SecurityGrade, FindingSeverity, SecurityFinding, TLSVersion
)


@dataclass
class SimulationAction:
    action_id: str
    title: str
    description: str
    enabled: bool = True


@dataclass
class ProjectedPosture:
    session_id: str
    current_grade: str
    projected_grade: str
    current_findings_count: int
    projected_findings_count: int
    eliminated_findings: List[str] = field(default_factory=list)
    remaining_findings: List[str] = field(default_factory=list)
    applied_remediations: List[str] = field(default_factory=list)
    disclaimer: str = "PROJECTED POSTURE — Simulation only. Does not alter verified forensic evidence."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "current_grade": self.current_grade,
            "projected_grade": self.projected_grade,
            "current_findings_count": self.current_findings_count,
            "projected_findings_count": self.projected_findings_count,
            "eliminated_findings": self.eliminated_findings,
            "remaining_findings": self.remaining_findings,
            "applied_remediations": self.applied_remediations,
            "disclaimer": self.disclaimer,
        }


class SimulateFixEngine:
    """Calculates deterministic projected risk posture under hypothetical security hardening."""

    @classmethod
    def simulate(
        cls,
        session: EmailSession,
        require_tls13: bool = False,
        require_tls12_plus: bool = True,
        remove_static_rsa: bool = True,
        remove_deprecated_ciphers: bool = True,
        enable_pqc_hybrid: bool = False,
        enforce_starttls_mandatory: bool = True,
    ) -> ProjectedPosture:
        assessment = session.security_assessment
        current_grade = assessment.grade.value if assessment else "F"
        current_findings = assessment.findings if assessment else []

        eliminated = []
        remaining = []
        applied = []

        # Evaluate simulated actions against current findings
        for f in current_findings:
            eliminated_flag = False

            if "FINDING-PLAINTEXT" in f.id or "FINDING-CLEAR-TEXT" in f.id or "FINDING-UNENCRYPTED" in f.id:
                if enforce_starttls_mandatory:
                    eliminated_flag = True
                    applied.append("Enforced mandatory STARTTLS / Direct TLS")
            
            elif "FINDING-DEPRECATED-TLS" in f.id:
                if require_tls12_plus or require_tls13:
                    eliminated_flag = True
                    applied.append("Disabled TLS 1.0 / TLS 1.1")

            elif "FINDING-NO-FORWARD-SECRECY" in f.id:
                if remove_static_rsa or require_tls13:
                    eliminated_flag = True
                    applied.append("Disabled static RSA key exchange (enforced ECDHE/DHE)")

            elif "FINDING-DEPRECATED-CIPHER" in f.id:
                if remove_deprecated_ciphers or require_tls13:
                    eliminated_flag = True
                    applied.append("Removed legacy CBC/3DES/RC4 cipher suites")

            elif "FINDING-PQC-CLASSICAL-KEX" in f.id:
                if enable_pqc_hybrid:
                    eliminated_flag = True
                    applied.append("Enabled NIST FIPS 203 ML-KEM hybrid key exchange (X25519MLKEM768)")

            if eliminated_flag:
                eliminated.append(f"{f.id}: {f.title}")
            else:
                remaining.append(f"{f.id}: {f.title}")

        # Recalculate projected grade
        if require_tls13 and enable_pqc_hybrid and not remaining:
            projected_grade = SecurityGrade.A_PLUS.value
        elif require_tls13 and not remaining:
            projected_grade = SecurityGrade.A.value
        elif require_tls12_plus and remove_static_rsa and not any("CRITICAL" in r or "DEPRECATED" in r for r in remaining):
            projected_grade = SecurityGrade.B.value
        elif any("FINDING-PLAINTEXT" in r for r in remaining):
            projected_grade = SecurityGrade.F.value
        else:
            projected_grade = SecurityGrade.B.value

        return ProjectedPosture(
            session_id=session.session_id,
            current_grade=current_grade,
            projected_grade=projected_grade,
            current_findings_count=len(current_findings),
            projected_findings_count=len(remaining),
            eliminated_findings=eliminated,
            remaining_findings=remaining,
            applied_remediations=list(set(applied)),
        )

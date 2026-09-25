"""
SecureMailScope X - Deterministic 'What If / Simulate Fix' Engine (Phase 10 Bridge)
Maintains backward compatibility while delegating to the evidence-preserving RemediationSimulator.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from app.schemas.forensic import EmailSession
from app.forensic.remediation_simulator import RemediationSimulator, RemediationSimulationReport


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
    disclaimer: str = (
        "PROJECTED POSTURE — Simulation only. Hypothetical policy projection that does not alter verified historical PCAP evidence."
    )
    simulation_report: Optional[Dict[str, Any]] = None

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
            "simulation_report": self.simulation_report,
        }


class SimulateFixEngine:
    """Legacy wrapper for RemediationSimulator."""

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
        remediations: Optional[List[str]] = None,
    ) -> ProjectedPosture:
        """Translates legacy flags into remediation action tokens and executes RemediationSimulator."""
        actions: List[str] = []
        if remediations:
            actions.extend(remediations)
        else:
            if enforce_starttls_mandatory:
                actions.append("REQUIRE_STARTTLS")
            if require_tls12_plus or require_tls13:
                actions.append("DISABLE_DEPRECATED_TLS")
            if remove_static_rsa:
                actions.append("ENABLE_FORWARD_SECRECY")
            if remove_deprecated_ciphers:
                actions.append("REPLACE_WEAK_CIPHER")
            if enable_pqc_hybrid:
                actions.append("ENABLE_HYBRID_PQC")

        report = RemediationSimulator.simulate(
            session=session,
            remediations=actions,
            parameters={"require_tls13": require_tls13},
        )

        eliminated_str = [
            f"{f.get('id')}: {f.get('title')}" for f in report.projected_findings_removed
        ]
        remaining_str = [
            f"{f.get('id')}: {f.get('title')}" for f in report.projected_findings_remaining
        ]

        obs_grade = report.observed_summary.security_grade if report.observed_summary else "F"
        proj_grade = report.simulated_summary.projected_security_grade if report.simulated_summary else "F"
        obs_cnt = report.observed_summary.findings_count if report.observed_summary else 0
        proj_cnt = report.simulated_summary.projected_findings_count if report.simulated_summary else 0

        return ProjectedPosture(
            session_id=session.session_id,
            current_grade=obs_grade,
            projected_grade=proj_grade,
            current_findings_count=obs_cnt,
            projected_findings_count=proj_cnt,
            eliminated_findings=eliminated_str,
            remaining_findings=remaining_str,
            applied_remediations=report.applied_remediations,
            simulation_report=report.to_dict(),
        )

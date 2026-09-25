"""
SecureMailScope X - Multi-Session Incident Correlator
Correlates evidence across multiple TCP streams to identify systemic protocol weaknesses,
downgrade anomalies, repeated plaintext sessions, or repeated cryptographic flaws.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from app.schemas.forensic import (
    EmailSession, SecurityMode, TLSVersion, FindingSeverity, SecurityGrade
)


@dataclass
class CorrelatedIncident:
    incident_id: str
    pattern_name: str
    severity: str
    related_session_ids: List[str] = field(default_factory=list)
    relevant_frames: List[int] = field(default_factory=list)
    endpoint: str = ""
    evidence_summary: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "pattern_name": self.pattern_name,
            "severity": self.severity,
            "related_session_ids": self.related_session_ids,
            "relevant_frames": self.relevant_frames,
            "endpoint": self.endpoint,
            "evidence_summary": self.evidence_summary,
            "recommendation": self.recommendation,
        }


class IncidentCorrelator:
    """Detects multi-stream forensic anomalies and security incidents."""

    @classmethod
    def correlate_sessions(cls, sessions: List[EmailSession]) -> List[CorrelatedIncident]:
        incidents: List[CorrelatedIncident] = []
        if not sessions:
            return incidents

        # Group sessions by endpoint (server IP:port)
        endpoint_groups: Dict[str, List[EmailSession]] = {}
        for s in sessions:
            ep = f"{s.server_ip}:{s.server_port}"
            endpoint_groups.setdefault(ep, []).append(s)

        # 1. Check Repeated Plaintext Sessions
        plaintext_sessions = [s for s in sessions if s.security_mode == SecurityMode.PLAINTEXT]
        if len(plaintext_sessions) >= 2:
            frames = []
            for s in plaintext_sessions:
                frames.extend([p.frame_number for p in s.evidence_packets[:3]])
            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-REPEATED-PLAINTEXT",
                pattern_name="Systemic Cleartext Email Transmission",
                severity="CRITICAL",
                related_session_ids=[s.session_id for s in plaintext_sessions],
                relevant_frames=sorted(list(set(frames))),
                endpoint=f"{plaintext_sessions[0].server_ip}:{plaintext_sessions[0].server_port}",
                evidence_summary=f"Detected {len(plaintext_sessions)} independent unencrypted email streams transmitting plaintext commands/credentials.",
                recommendation="Enforce mandatory transport-layer encryption (STARTTLS or Direct TLS) across all mail endpoints.",
            ))

        # 2. Check Repeated STARTTLS Failures
        failed_sessions = [s for s in sessions if s.security_mode == SecurityMode.STARTTLS_FAILED]
        if failed_sessions:
            frames = []
            for s in failed_sessions:
                if s.starttls_state.failure_frame:
                    frames.append(s.starttls_state.failure_frame)
            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-STARTTLS-DOWNGRADE-ANOMALY",
                pattern_name="Repeated STARTTLS Negotiation Failure / Downgrade Indicator",
                severity="HIGH",
                related_session_ids=[s.session_id for s in failed_sessions],
                relevant_frames=sorted(list(set(frames))),
                endpoint=f"{failed_sessions[0].server_ip}:{failed_sessions[0].server_port}",
                evidence_summary=f"Observed {len(failed_sessions)} sessions where STARTTLS handshake was rejected or failed. Potential STRIPTLS attack or misconfiguration.",
                recommendation="Investigate network intermediaries for active STARTTLS stripping. Enforce MTA-STS and DANE.",
            ))

        # 3. Check Deprecated TLS versions across endpoints
        deprecated_sessions = [
            s for s in sessions
            if s.tls_details and s.tls_details.negotiated_tls_version in [TLSVersion.TLSv1_0, TLSVersion.TLSv1_1]
        ]
        if len(deprecated_sessions) >= 1:
            frames = [s.tls_details.server_hello_frame for s in deprecated_sessions if s.tls_details.server_hello_frame]
            incidents.append(CorrelatedIncident(
                incident_id="INCIDENT-SYSTEMIC-LEGACY-TLS",
                pattern_name="Systemic Legacy TLS Protocol Usage (RFC 8996)",
                severity="HIGH",
                related_session_ids=[s.session_id for s in deprecated_sessions],
                relevant_frames=sorted(list(set(frames))),
                endpoint=f"{deprecated_sessions[0].server_ip}:{deprecated_sessions[0].server_port}",
                evidence_summary=f"Observed {len(deprecated_sessions)} sessions negotiating obsolete TLS 1.0/1.1 protocols.",
                recommendation="Disable TLS 1.0 and TLS 1.1 globally on all mail server daemons.",
            ))

        return incidents

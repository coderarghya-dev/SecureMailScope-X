"""
SecureMailScope X - Phase 10 & 10.5 Remediation Simulator Tests
Verifies evidence-preserving simulation, hypothetical projections, immutability of
observed state, shared grade calculation consistency, action applicability, and
explicit projection metadata.
"""

import os
import sys
import unittest
import copy
from typing import List

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.schemas.forensic import (
    EmailSession,
    EmailProtocol,
    SecurityMode,
    SessionSecurityAssessment,
    SecurityGrade,
    SecurityFinding,
    FindingSeverity,
    FindingCategory,
    TLSVersion,
    TLSHandshakeDetails,
    EvidenceConfidence,
    ConfidenceLevel,
    STARTTLSState,
)
from app.forensic.rule_engine import CryptographicRuleEngine
from app.forensic.remediation_simulator import (
    RemediationSimulator,
    RemediationSimulationReport,
    SUPPORTED_REMEDIATIONS,
)
from app.simulation.simulate_fix import SimulateFixEngine
from app.services.analysis_service import AnalysisService


def create_sample_session(
    session_id: str = "stream_01",
    grade: SecurityGrade = SecurityGrade.C,
    security_mode: SecurityMode = SecurityMode.STARTTLS_ACCEPTED,
    tls_version: TLSVersion = TLSVersion.TLSv1_2,
    findings: List[SecurityFinding] = None,
) -> EmailSession:
    """Helper to build a deterministic test session."""
    return EmailSession(
        session_id=session_id,
        stream_index=0,
        protocol=EmailProtocol.SMTP,
        security_mode=security_mode,
        client_ip="192.168.1.50",
        client_port=54321,
        server_ip="93.184.216.34",
        server_port=587,
        starttls_state=STARTTLSState(advertised=True, requested=True, accepted=True),
        tls_details=TLSHandshakeDetails(
            client_hello_frame=10,
            server_hello_frame=12,
            negotiated_tls_version=tls_version,
            selected_cipher_name="TLS_RSA_WITH_AES_128_CBC_SHA",
            has_forward_secrecy=False,
            key_share_observed=False,
        ),
        evidence_confidence=EvidenceConfidence(
            score=80,
            level=ConfidenceLevel.HIGH,
            handshake_observable=True,
            version_verifiable=True,
            cipher_identifiable=True,
            key_exchange_observable=True,
        ),
        security_assessment=SessionSecurityAssessment(
            grade=grade,
            grade_rationale="Observed test assessment",
            findings=findings or [],
            critical_findings_count=sum(1 for f in (findings or []) if f.severity == FindingSeverity.CRITICAL),
            high_findings_count=sum(1 for f in (findings or []) if f.severity == FindingSeverity.HIGH),
            medium_findings_count=sum(1 for f in (findings or []) if f.severity == FindingSeverity.MEDIUM),
            low_findings_count=sum(1 for f in (findings or []) if f.severity == FindingSeverity.LOW),
            post_quantum_ready=False,
        ),
    )


class TestRemediationSimulator(unittest.TestCase):

    # 1. Original assessment object remains completely unchanged after simulation
    def test_01_original_assessment_remains_immutable(self):
        finding = SecurityFinding(
            id="FINDING-NO-FORWARD-SECRECY",
            title="Static RSA Key Exchange",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.FORWARD_SECRECY,
            description="Lacks PFS",
        )
        session = create_sample_session(grade=SecurityGrade.C, findings=[finding])
        original_grade = session.security_assessment.grade
        original_findings_count = len(session.security_assessment.findings)

        report = RemediationSimulator.simulate(
            session=session,
            remediations=["ENABLE_FORWARD_SECRECY"],
        )

        # Ensure original session object was not mutated
        self.assertEqual(session.security_assessment.grade, original_grade)
        self.assertEqual(len(session.security_assessment.findings), original_findings_count)
        self.assertEqual(session.security_assessment.findings[0].id, "FINDING-NO-FORWARD-SECRECY")

        # But projected report reflects elimination (TLS 1.2 with PFS reaches Grade B)
        self.assertEqual(report.observed_summary.security_grade, "C")
        self.assertEqual(report.simulated_summary.projected_security_grade, "B")
        self.assertEqual(len(report.projected_findings_removed), 1)

    # 2. Deprecated TLS finding + DISABLE_DEPRECATED_TLS -> projected finding removed
    def test_02_disable_deprecated_tls(self):
        finding = SecurityFinding(
            id="FINDING-DEPRECATED-TLS-1-0",
            title="Deprecated TLS 1.0 Negotiated",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.PROTOCOL_SECURITY,
            description="Obsolete TLS version",
        )
        session = create_sample_session(grade=SecurityGrade.D, tls_version=TLSVersion.TLSv1_0, findings=[finding])

        report = RemediationSimulator.simulate(
            session=session,
            remediations=["DISABLE_DEPRECATED_TLS"],
        )

        self.assertIn("DISABLE_DEPRECATED_TLS", report.applied_remediations)
        self.assertEqual(len(report.projected_findings_removed), 1)
        self.assertEqual(len(report.projected_findings_remaining), 0)
        self.assertEqual(report.simulated_summary.projected_security_grade, "A")

    # 3. No-PFS finding + ENABLE_FORWARD_SECRECY -> projected finding removed
    def test_03_enable_forward_secrecy(self):
        finding = SecurityFinding(
            id="FINDING-STATIC-RSA-NO-PFS",
            title="Static RSA Lacks Forward Secrecy",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.FORWARD_SECRECY,
            description="Static RSA",
        )
        session = create_sample_session(grade=SecurityGrade.C, findings=[finding])

        report = RemediationSimulator.simulate(
            session=session,
            remediations=["ENABLE_FORWARD_SECRECY"],
        )

        self.assertIn("ENABLE_FORWARD_SECRECY", report.applied_remediations)
        self.assertEqual(len(report.projected_findings_removed), 1)
        self.assertEqual(report.simulated_summary.projected_security_grade, "B")

    # 4. Expired certificate + RENEW_CERTIFICATE -> projected expiry finding removed
    def test_04_renew_certificate(self):
        finding = SecurityFinding(
            id="FINDING-CERTIFICATE-EXPIRED",
            title="X.509 Certificate Expired",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
            description="Certificate expired",
        )
        session = create_sample_session(grade=SecurityGrade.F, findings=[finding])

        report = RemediationSimulator.simulate(
            session=session,
            remediations=["RENEW_CERTIFICATE"],
        )

        self.assertIn("RENEW_CERTIFICATE", report.applied_remediations)
        self.assertEqual(len(report.projected_findings_removed), 1)
        self.assertEqual(report.simulated_summary.projected_security_grade, "C")
        self.assertEqual(report.simulated_summary.projected_validity_status, "ASSUMED_VALID_AFTER_RENEWAL")

    # 5. Weak RSA key + UPGRADE_RSA_KEY -> projected weak-key finding removed
    def test_05_upgrade_rsa_key(self):
        finding = SecurityFinding(
            id="FINDING-CERTIFICATE-WEAK-RSA-KEY",
            title="Weak 1024-bit RSA Key",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
            description="1024-bit RSA",
        )
        session = create_sample_session(grade=SecurityGrade.B, findings=[finding])

        report = RemediationSimulator.simulate(
            session=session,
            remediations=["UPGRADE_RSA_KEY"],
        )

        self.assertIn("UPGRADE_RSA_KEY", report.applied_remediations)
        self.assertEqual(len(report.projected_findings_removed), 1)

    # 6. PQC readiness gap + ENABLE_HYBRID_PQC -> projected gap reduced, no fake key_share
    def test_06_enable_hybrid_pqc_no_fake_keyshare(self):
        finding = SecurityFinding(
            id="FINDING-PQC-CLASSICAL-KEX",
            title="Classical-Only Key Exchange Subject to HNDL Risk",
            severity=FindingSeverity.LOW,
            category=FindingCategory.POST_QUANTUM_READINESS,
            description="No PQC hybrid key encapsulation",
        )
        session = create_sample_session(grade=SecurityGrade.A, tls_version=TLSVersion.TLSv1_3, findings=[finding])

        report = RemediationSimulator.simulate(
            session=session,
            remediations=["ENABLE_HYBRID_PQC"],
        )

        self.assertIn("ENABLE_HYBRID_PQC", report.applied_remediations)
        self.assertEqual(report.simulated_summary.projected_pqc_readiness, "PROJECTED")
        self.assertEqual(report.simulated_summary.projected_pqc_status, "HYBRID_POLICY_ASSUMED")
        self.assertEqual(report.simulated_summary.projected_security_grade, "A+")

        # Ensure NO fake key_share or raw frame was added to session or report
        self.assertIsNone(session.tls_details.selected_group)
        self.assertFalse(session.tls_details.key_share_observed)

    # 7. Irrelevant remediation -> not_applicable_remediations
    def test_07_irrelevant_remediation_marked_not_applicable(self):
        session = create_sample_session(grade=SecurityGrade.A, findings=[])
        session.security_assessment.post_quantum_ready = True

        report = RemediationSimulator.simulate(
            session=session,
            remediations=["RENEW_CERTIFICATE"],
        )

        self.assertNotIn("RENEW_CERTIFICATE", report.applied_remediations)
        self.assertIn("RENEW_CERTIFICATE", report.not_applicable_remediations)
        self.assertEqual(report.remediation_status_map.get("RENEW_CERTIFICATE"), "NOT_APPLICABLE")

    # 8. Unsupported remediation -> explicit unsupported_remediations
    def test_08_unsupported_remediation(self):
        session = create_sample_session(grade=SecurityGrade.A, findings=[])

        report = RemediationSimulator.simulate(
            session=session,
            remediations=["INSTALL_AI_FIREWALL_MAGIC"],
        )

        self.assertIn("INSTALL_AI_FIREWALL_MAGIC", report.unsupported_remediations)
        self.assertEqual(report.remediation_status_map.get("INSTALL_AI_FIREWALL_MAGIC"), "UNSUPPORTED")

    # 9. EvidenceConfidence remains identical in observed state
    def test_09_evidence_confidence_preserved(self):
        session = create_sample_session(grade=SecurityGrade.C, findings=[])
        orig_conf_score = session.evidence_confidence.score

        report = RemediationSimulator.simulate(
            session=session,
            remediations=["ENABLE_FORWARD_SECRECY"],
        )

        self.assertEqual(session.evidence_confidence.score, orig_conf_score)
        self.assertEqual(report.observed_summary.evidence_confidence_score, orig_conf_score)

    # 10. projected_evidence_confidence = NOT_APPLICABLE and score method is explicit
    def test_10_projected_evidence_confidence_and_method(self):
        session = create_sample_session(grade=SecurityGrade.C, findings=[])
        report = RemediationSimulator.simulate(session=session, remediations=["ENABLE_FORWARD_SECRECY"])
        self.assertEqual(report.simulated_summary.projected_evidence_confidence, "NOT_APPLICABLE")
        self.assertEqual(report.simulated_summary.projected_score_method, "DETERMINISTIC_RULE_ENGINE")

    # 11. No raw frame/evidence list is mutated
    def test_11_no_raw_frames_mutated(self):
        session = create_sample_session(grade=SecurityGrade.C, findings=[])
        orig_tls = copy.deepcopy(session.tls_details)

        RemediationSimulator.simulate(session=session, remediations=["ENABLE_FORWARD_SECRECY", "ENABLE_HYBRID_PQC"])

        self.assertEqual(session.tls_details.client_hello_frame, orig_tls.client_hello_frame)
        self.assertEqual(session.tls_details.server_hello_frame, orig_tls.server_hello_frame)
        self.assertEqual(session.tls_details.has_forward_secrecy, orig_tls.has_forward_secrecy)

    # 12. Projection never replaces original grade
    def test_12_projection_never_replaces_original_grade(self):
        finding = SecurityFinding(
            id="FINDING-PLAINTEXT-COMMUNICATION",
            title="Cleartext Traffic",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.PROTOCOL_SECURITY,
            description="Cleartext",
        )
        session = create_sample_session(grade=SecurityGrade.F, security_mode=SecurityMode.PLAINTEXT, findings=[finding])

        report = RemediationSimulator.simulate(session=session, remediations=["REQUIRE_STARTTLS"])

        self.assertEqual(session.security_assessment.grade, SecurityGrade.F)
        self.assertEqual(report.observed_summary.security_grade, "F")
        # Deterministic grade for TLS 1.2 without PFS is C
        self.assertEqual(report.simulated_summary.projected_security_grade, "C")

    # 13. Same input -> same projected result (determinism)
    def test_13_deterministic_reproducibility(self):
        finding = SecurityFinding(
            id="FINDING-NO-FORWARD-SECRECY",
            title="Static RSA",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.FORWARD_SECRECY,
            description="Static RSA",
        )
        session = create_sample_session(grade=SecurityGrade.C, findings=[finding])

        report1 = RemediationSimulator.simulate(session, remediations=["ENABLE_FORWARD_SECRECY"])
        report2 = RemediationSimulator.simulate(session, remediations=["ENABLE_FORWARD_SECRECY"])

        self.assertEqual(report1.simulated_summary.projected_security_grade, report2.simulated_summary.projected_security_grade)
        self.assertEqual(report1.simulated_summary.projected_score, report2.simulated_summary.projected_score)
        self.assertEqual(report1.applied_remediations, report2.applied_remediations)

    # 14. Domain Authentication policy simulation (SPF Absent vs SPF PermError)
    def test_14_domain_auth_spf_permerror_distinction(self):
        spf_absent = SecurityFinding(
            id="FINDING-SPF-POLICY-ABSENT",
            title="Missing SPF Record",
            severity=FindingSeverity.LOW,
            category=FindingCategory.DOMAIN_AUTHENTICATION,
            description="No SPF",
        )
        spf_permerror = SecurityFinding(
            id="FINDING-SPF-PERMERROR",
            title="SPF Permanent Error",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.DOMAIN_AUTHENTICATION,
            description="SPF PermError in syntax",
        )
        session = create_sample_session(grade=SecurityGrade.A, findings=[spf_absent, spf_permerror])

        # Requesting only ENABLE_SPF_POLICY should remove absent SPF, but NOT permerror
        report1 = RemediationSimulator.simulate(session, remediations=["ENABLE_SPF_POLICY"])
        self.assertEqual(len(report1.projected_findings_removed), 1)
        self.assertEqual(report1.projected_findings_removed[0]["id"], "FINDING-SPF-POLICY-ABSENT")
        self.assertEqual(len(report1.projected_findings_remaining), 1)
        self.assertEqual(report1.projected_findings_remaining[0]["id"], "FINDING-SPF-PERMERROR")

        # Requesting FIX_SPF_CONFIGURATION should remove the PERMERROR
        report2 = RemediationSimulator.simulate(session, remediations=["ENABLE_SPF_POLICY", "FIX_SPF_CONFIGURATION"])
        self.assertEqual(len(report2.projected_findings_removed), 2)
        self.assertEqual(len(report2.projected_findings_remaining), 0)

    # 15. Shared grade calculation consistency with CryptographicRuleEngine
    def test_15_shared_grade_calculation_consistency(self):
        # Grade computation on identical cryptographic parameters
        auth_grade, _ = CryptographicRuleEngine.compute_security_grade(
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            tls_version=TLSVersion.TLSv1_3,
            has_pfs=True,
            pqc_ready=True,
            critical_findings_count=0,
            high_findings_count=0,
        )
        self.assertEqual(auth_grade, SecurityGrade.A_PLUS)

        # Simulation on session with PQC enabled
        session = create_sample_session(grade=SecurityGrade.A, tls_version=TLSVersion.TLSv1_3, findings=[])
        report = RemediationSimulator.simulate(session, remediations=["ENABLE_HYBRID_PQC"])
        self.assertEqual(report.simulated_summary.projected_security_grade, auth_grade.value)

    # 16. Legacy SimulateFixEngine bridge compatibility
    def test_16_legacy_simulate_fix_engine_bridge(self):
        finding = SecurityFinding(
            id="FINDING-NO-FORWARD-SECRECY",
            title="Static RSA",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.FORWARD_SECRECY,
            description="Static RSA",
        )
        session = create_sample_session(grade=SecurityGrade.C, findings=[finding])

        projected = SimulateFixEngine.simulate(
            session=session,
            remove_static_rsa=True,
            require_tls13=True,
            enable_pqc_hybrid=True,
        )

        self.assertEqual(projected.current_grade, "C")
        self.assertEqual(projected.projected_grade, "A+")
        self.assertIn("PROJECTED POSTURE", projected.disclaimer)
        self.assertIsNotNone(projected.simulation_report)


if __name__ == "__main__":
    unittest.main()

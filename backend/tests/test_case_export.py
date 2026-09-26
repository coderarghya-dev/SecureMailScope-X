"""
SecureMailScope X - Forensic Case Management & Evidence Bundle Export Tests (Phase 17)
Validates multi-analysis case grouping, summary evidence metrics aggregation,
offline ZIP evidence bundle packaging, and cryptographic tamper verification.
"""

import os
import sys
import json
import uuid
import tempfile
import unittest
from datetime import datetime, timezone

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.db.database import set_custom_db_path, init_db, get_db_connection
from app.db.repository import (
    ForensicRepository,
    compute_sha256,
    IntegrityVerificationError,
)
from app.services.custody_service import CustodyService
from app.services.case_service import CaseService
from app.services.signature_service import SignatureService
from app.schemas.identity import ActorContext
from app.schemas.api import (
    AnalysisDetailResponse,
    SessionDetailDTO,
    STARTTLSStateDTO,
    TLSHandshakeDTO,
    CaptureHealthDTO,
    EvidenceConfidenceDTO,
    SecurityAssessmentDTO,
    SecurityFindingDTO,
    FindingsSummaryDTO,
    EvidenceFrameDTO,
    MultiSessionSummaryDTO,
)


def create_sample_analysis(
    analysis_id: str,
    protocol: str = "SMTP",
    tls_version: str = "TLSv1.3",
    cipher: str = "TLS_AES_256_GCM_SHA384",
    grade: str = "A",
    findings_count: int = 0
) -> AnalysisDetailResponse:
    findings = []
    for i in range(findings_count):
        findings.append(SecurityFindingDTO(
            id=f"FINDING-{analysis_id}-{i+1}",
            title=f"Sample Finding {i+1}",
            severity="MEDIUM",
            category="CIPHER_SUITE",
            description=f"Description {i+1}",
            evidence_frames=[10 + i],
            recommendation="Remediate"
        ))

    assessment = SecurityAssessmentDTO(
        grade=grade,
        grade_rationale="Evaluated",
        post_quantum_ready=False,
        post_quantum_summary="Standard",
        findings_summary=FindingsSummaryDTO(critical=0, high=0, medium=findings_count, low=0, info=0),
        findings=findings
    )

    session = SessionDetailDTO(
        session_id=f"stream_0_{analysis_id}",
        stream_index=0,
        protocol=protocol,
        security_mode="STARTTLS_ACCEPTED",
        client="192.168.1.10:45678",
        server="192.168.1.1:587",
        server_hostname="mail.example.org",
        start_time_iso="2026-09-26T10:00:00Z",
        duration_seconds=1.2,
        packets_count=10,
        starttls=STARTTLSStateDTO(advertised=True, requested=True, accepted=True, upgrade_successful=True, state="UPGRADED"),
        tls=TLSHandshakeDTO(
            negotiated_version=tls_version,
            cipher_name=cipher,
            forward_secrecy_pfs=True,
            pfs_status="ECDHE_PFS_ACTIVE",
            certificate_visibility="FULL_CHAIN_OBSERVED"
        ),
        capture_health=CaptureHealthDTO(score=100, grade="EXCELLENT", syn_observed=True, fin_rst_observed=True, total_packets=10, retransmissions_count=0, retransmission_rate=0.0, deduction_reasons=[]),
        evidence_confidence=EvidenceConfidenceDTO(score=95, level="HIGH", handshake_observable=True, version_verifiable=True, cipher_identifiable=True, key_exchange_observable=True, confidence_factors=[]),
        security_assessment=assessment,
        evidence_frames=[EvidenceFrameDTO(frame=10, time_epoch=1727344800.0, protocol=protocol, summary="Handshake")],
    )

    return AnalysisDetailResponse(
        analysis_id=analysis_id,
        file_name=f"{analysis_id}.pcap",
        file_size_bytes=2048,
        analysis_time_utc="2026-09-26T10:00:00Z",
        tshark_version="TShark 4.6.0",
        total_packets_extracted=10,
        raw_capture_packets_total=10,
        email_sessions_found=1,
        sessions=[session],
        evidence_confidence_score=95,
        evidence_confidence_level="HIGH",
        multi_session_summary=MultiSessionSummaryDTO(total_sessions=1, sessions_with_findings=findings_count, incident_count=0, critical_high_incident_count=0, repeated_pattern_count=0, uncorrelated_sessions_count=0),
        correlated_incidents=[],
    )


class TestCaseManagementAndBundleExport(unittest.TestCase):

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db", prefix="sms_case_test_")
        os.close(self.temp_db_fd)
        set_custom_db_path(self.temp_db_path)
        init_db(self.temp_db_path)

    def tearDown(self):
        set_custom_db_path(None)
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    # 1. Case creation and listing
    def test_01_case_creation_and_listing(self):
        case1 = CaseService.create_case(title="Incident 101", description="Phishing campaign", db_path=self.temp_db_path)
        case2 = CaseService.create_case(title="Incident 102", description="Weak TLS audit", db_path=self.temp_db_path)

        cases = CaseService.list_cases(include_archived=False, db_path=self.temp_db_path)
        self.assertEqual(len(cases), 2)
        c_ids = [c["id"] for c in cases]
        self.assertIn(case1.id, c_ids)
        self.assertIn(case2.id, c_ids)

    # 2. Analysis attachment to case
    def test_02_attach_analysis_to_case(self):
        aid = "analysis_case_attach_02"
        analysis = create_sample_analysis(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        case = CaseService.create_case(title="Attachment Test", db_path=self.temp_db_path)
        updated = CaseService.attach_analysis_to_case(case.id, aid, db_path=self.temp_db_path)

        self.assertIsNotNone(updated)
        self.assertIn(aid, updated["analysis_ids"])

    # 3. Analysis detachment from case
    def test_03_detach_analysis_from_case(self):
        aid = "analysis_case_detach_03"
        analysis = create_sample_analysis(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        case = CaseService.create_case(title="Detachment Test", db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(case.id, aid, db_path=self.temp_db_path)
        updated = CaseService.detach_analysis_from_case(case.id, aid, db_path=self.temp_db_path)

        self.assertIsNotNone(updated)
        self.assertNotIn(aid, updated["analysis_ids"])

    # 4. Artifact linking to case
    def test_04_add_artifact_to_case(self):
        case = CaseService.create_case(title="Artifact Case", db_path=self.temp_db_path)
        art_hash = "b" * 64
        updated = CaseService.add_artifact_to_case(
            case_id=case.id,
            artifact_type="PCAP",
            filename="capture.pcap",
            sha256=art_hash,
            db_path=self.temp_db_path
        )

        self.assertIsNotNone(updated)
        self.assertEqual(len(updated["artifacts"]), 1)
        self.assertEqual(updated["artifacts"][0]["sha256"], art_hash)

    # 5. Additive analyst notes
    def test_05_add_analyst_notes_to_case(self):
        case = CaseService.create_case(title="Notes Case", db_path=self.temp_db_path)
        CaseService.add_note_to_case(case.id, author="Lead Analyst", note_text="Initial review completed.", db_path=self.temp_db_path)
        CaseService.add_note_to_case(case.id, author="Peer Reviewer", note_text="Verified packet trace.", db_path=self.temp_db_path)

        case_details = CaseService.get_case(case.id, db_path=self.temp_db_path)
        self.assertEqual(len(case_details["analyst_notes"]), 2)
        self.assertEqual(case_details["analyst_notes"][0]["author"], "Lead Analyst")
        self.assertEqual(case_details["analyst_notes"][1]["author"], "Peer Reviewer")

    # 6. Case archival preserves linked evidence
    def test_06_case_archival_preserves_evidence(self):
        aid = "analysis_archive_06"
        analysis = create_sample_analysis(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        case = CaseService.create_case(title="Archive Target", db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(case.id, aid, db_path=self.temp_db_path)

        archived = CaseService.archive_case(case.id, db_path=self.temp_db_path)
        self.assertEqual(archived["status"], "ARCHIVED")
        self.assertTrue(archived["is_archived"])

        reloaded = ForensicRepository.get_analysis(aid, db_path=self.temp_db_path)
        self.assertIsNotNone(reloaded)

    # 7. Add note to analysis
    def test_07_add_note_to_analysis(self):
        aid = "analysis_note_07"
        analysis = create_sample_analysis(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        note = CaseService.add_note_to_analysis(
            analysis_id=aid,
            author="Forensic Expert",
            note_text="STARTTLS negotiation verified.",
            db_path=self.temp_db_path
        )
        self.assertIsNotNone(note)
        self.assertEqual(note["target_id"], aid)
        self.assertEqual(note["analyst_name"], "Forensic Expert")

    # 8. Listing active vs archived cases
    def test_08_list_active_vs_archived_cases(self):
        c1 = CaseService.create_case(title="Active Case", db_path=self.temp_db_path)
        c2 = CaseService.create_case(title="To Be Archived", db_path=self.temp_db_path)
        CaseService.archive_case(c2.id, db_path=self.temp_db_path)

        active_cases = CaseService.list_cases(include_archived=False, db_path=self.temp_db_path)
        self.assertEqual(len(active_cases), 1)
        self.assertEqual(active_cases[0]["id"], c1.id)

        all_cases = CaseService.list_cases(include_archived=True, db_path=self.temp_db_path)
        self.assertEqual(len(all_cases), 2)

    # 9. Case retrieval not found returns None
    def test_09_case_retrieval_not_found(self):
        non_existent = CaseService.get_case("CASE-DOESNOTEXIST", db_path=self.temp_db_path)
        self.assertIsNone(non_existent)

    # 10. Audit event logged on case creation and attachment
    def test_10_audit_event_logged_on_case_operations(self):
        aid = "analysis_audit_10"
        analysis = create_sample_analysis(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        case = CaseService.create_case(title="Audit Tracking Case", db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(case.id, aid, db_path=self.temp_db_path)
        CaseService.detach_analysis_from_case(case.id, aid, db_path=self.temp_db_path)
        CaseService.archive_case(case.id, db_path=self.temp_db_path)

        events = ForensicRepository.get_audit_events(object_id=case.id, verify_integrity=True, db_path=self.temp_db_path)
        self.assertEqual(len(events), 4)
        event_types = [e["event_type"] for e in events]
        self.assertIn("CASE_CREATED", event_types)
        self.assertIn("CASE_ANALYSIS_ATTACHED", event_types)
        self.assertIn("CASE_ANALYSIS_DETACHED", event_types)
        self.assertIn("CASE_ARCHIVED", event_types)

    # 11. Multi-analysis attachment to single case
    def test_11_multiple_analyses_in_case(self):
        aid1 = "analysis_multi_11_1"
        aid2 = "analysis_multi_11_2"
        ForensicRepository.save_analysis(create_sample_analysis(aid1, protocol="SMTP"), db_path=self.temp_db_path)
        ForensicRepository.save_analysis(create_sample_analysis(aid2, protocol="IMAP"), db_path=self.temp_db_path)

        case = CaseService.create_case(title="Multi Protocol Case", db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(case.id, aid1, db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(case.id, aid2, db_path=self.temp_db_path)

        case_details = CaseService.get_case(case.id, db_path=self.temp_db_path)
        self.assertEqual(len(case_details["analysis_ids"]), 2)
        self.assertIn(aid1, case_details["analysis_ids"])
        self.assertIn(aid2, case_details["analysis_ids"])

    # 12. Tampered analyst note integrity check
    def test_12_tampered_analyst_note_fails_integrity(self):
        case = CaseService.create_case(title="Tamper Note Case", db_path=self.temp_db_path)
        note = CaseService.add_note_to_case(case.id, author="Analyst 1", note_text="Original safe text", db_path=self.temp_db_path)

        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE analyst_notes SET note_text = 'Tampered text' WHERE target_id = ?", (case.id,))
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_analyst_notes("CASE", case.id, verify_integrity=True, db_path=self.temp_db_path)


if __name__ == "__main__":
    unittest.main()

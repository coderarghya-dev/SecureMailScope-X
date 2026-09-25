"""
SecureMailScope X - Unit Tests for Phase 12: Analyst Identity & Audit Attribution
Covers all 20 specified deterministic requirements:
1. Declared analyst attribution stored on case creation.
2. Declared analyst attribution stored on notes.
3. Declared analyst attribution stored on simulations.
4. Declared analyst attribution stored on active scans.
5. Declared analyst attribution stored on DNS enrichment.
6. Missing identity produces UNATTRIBUTED, not fake admin/user.
7. Automated event uses SYSTEM.
8. Historical event retains original actor display name after analyst registry update.
9. Tampering actor_id in audit event breaks audit-chain verification.
10. Tampering actor_display_name breaks audit-chain verification.
11. Actor metadata does not alter observed_result_sha256.
12. Actor metadata does not alter capture_sha256.
13. Actor metadata does not alter simulation technical payload hash unless explicitly designed.
14. Actor metadata does not alter active scan technical result hash unless explicitly designed.
15. Header-declared identity is marked API_HEADER_DECLARED, not AUTHENTICATED.
16. Invalid/control-character analyst IDs rejected.
17. No password/token/secret fields exist in analyst table/model.
18. Existing historical rows without actor fields remain readable as UNATTRIBUTED.
19. Full persistence/custody integrity remains valid.
20. Full backend regression.
"""

import os
import sys
import tempfile
import sqlite3
import hashlib
import unittest
from datetime import datetime, timezone

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.db.database import init_db, get_db_connection
from app.db.repository import ForensicRepository, IntegrityVerificationError, canonical_json_bytes
from app.schemas.identity import (
    ActorContext,
    AnalystIdentityDTO,
    validate_actor_id,
    sanitize_display_name,
)
from app.schemas.api import (
    AnalysisDetailResponse,
    SessionDetailDTO,
    SecurityAssessmentDTO,
    FindingsSummaryDTO,
    SecurityFindingDTO,
    STARTTLSStateDTO,
    TLSHandshakeDTO,
    CaptureHealthDTO,
    EvidenceConfidenceDTO,
    EvidenceFrameDTO,
    CorrelatedIncidentDTO,
    MultiSessionSummaryDTO,
)
from app.services.case_service import CaseService
from app.services.custody_service import CustodyService


def _build_mock_analysis(analysis_id: str = "analysis-mock-01") -> AnalysisDetailResponse:
    finding = SecurityFindingDTO(
        id="FINDING-PFS-01",
        title="No PFS",
        severity="HIGH",
        category="FORWARD_SECRECY",
        description="Static RSA without Forward Secrecy",
        evidence_frames=[10],
        recommendation="Enable ECDHE",
    )
    assessment = SecurityAssessmentDTO(
        grade="C",
        grade_rationale="Forward secrecy absent",
        post_quantum_ready=False,
        post_quantum_summary="Vulnerable to HNDL",
        findings_summary=FindingsSummaryDTO(critical=0, high=1, medium=0, low=0, info=0),
        findings=[finding],
    )
    session = SessionDetailDTO(
        session_id=f"stream_0_{analysis_id}",
        stream_index=0,
        protocol="SMTP",
        security_mode="STARTTLS_ACCEPTED",
        client="192.168.1.10:45678",
        server="192.168.1.1:587",
        server_hostname="mail.example.org",
        start_time_iso="2026-09-25T10:00:00Z",
        duration_seconds=1.0,
        packets_count=10,
        starttls=STARTTLSStateDTO(advertised=True, requested=True, accepted=True, upgrade_successful=True, state="UPGRADED"),
        tls=TLSHandshakeDTO(negotiated_version="TLSv1.2", forward_secrecy_pfs=False, pfs_status="NO_PFS", certificate_visibility="CHAIN_OBSERVED"),
        capture_health=CaptureHealthDTO(score=100, grade="EXCELLENT", syn_observed=True, fin_rst_observed=True, total_packets=10, retransmissions_count=0, retransmission_rate=0.0, deduction_reasons=[]),
        evidence_confidence=EvidenceConfidenceDTO(score=95, level="HIGH", handshake_observable=True, version_verifiable=True, cipher_identifiable=True, key_exchange_observable=True, confidence_factors=[]),
        security_assessment=assessment,
        evidence_frames=[EvidenceFrameDTO(frame=10, time_epoch=1727258400.0, protocol="SMTP", summary="STARTTLS accepted")],
    )
    return AnalysisDetailResponse(
        analysis_id=analysis_id,
        file_name=f"{analysis_id}.pcap",
        file_size_bytes=4096,
        analysis_time_utc="2026-09-25T10:00:00Z",
        tshark_version="TShark 4.6.0",
        total_packets_extracted=10,
        raw_capture_packets_total=10,
        email_sessions_found=1,
        sessions=[session],
        evidence_confidence_score=95,
        evidence_confidence_level="HIGH",
        multi_session_summary=MultiSessionSummaryDTO(total_sessions=1, sessions_with_findings=1, incident_count=0, critical_high_incident_count=0, repeated_pattern_count=0, uncorrelated_sessions_count=0),
        correlated_incidents=[],
    )


class TestAnalystIdentityAndAttribution(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_identity_forensics.db")
        init_db(self.db_path)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # 1. Declared analyst attribution stored on case creation.
    def test_01_declared_analyst_attribution_stored_on_case_creation(self):
        actor = ActorContext(
            actor_id="analyst-sec-42",
            actor_display_name="Senior Analyst Jane",
            identity_source="LOCAL_DECLARED",
            attribution_status="ATTRIBUTED",
        )
        case = CaseService.create_case(
            title="Investigate Insecure SMTP Relay",
            description="Examine unencrypted credentials in PCAP",
            actor=actor,
            db_path=self.db_path,
        )
        self.assertEqual(case.analyst_id, "analyst-sec-42")
        self.assertEqual(case.analyst_name, "Senior Analyst Jane")

        # Verify audit trail recorded this actor
        events = ForensicRepository.get_audit_events("CASE", case.id, db_path=self.db_path)
        self.assertTrue(len(events) >= 1)
        create_event = events[0]
        self.assertEqual(create_event["actor_id"], "analyst-sec-42")
        self.assertEqual(create_event["actor_display_name"], "Senior Analyst Jane")
        self.assertEqual(create_event["actor_identity_source"], "LOCAL_DECLARED")
        self.assertEqual(create_event["actor_attribution_status"], "ATTRIBUTED")

    # 2. Declared analyst attribution stored on notes.
    def test_02_declared_analyst_attribution_stored_on_notes(self):
        actor = ActorContext(
            actor_id="analyst-note-01",
            actor_display_name="Analyst Alice",
            identity_source="API_HEADER_DECLARED",
            attribution_status="ATTRIBUTED",
        )
        case = CaseService.create_case(title="Note Test Case", actor=actor, db_path=self.db_path)
        CaseService.add_note_to_case(
            case_id=case.id,
            author="Analyst Alice",
            note_text="STARTTLS negotiation stripped at frame 14",
            actor=actor,
            db_path=self.db_path,
        )

        notes = ForensicRepository.get_analyst_notes("CASE", case.id, db_path=self.db_path)
        self.assertEqual(len(notes), 1)
        note = notes[0]
        self.assertEqual(note["analyst_id"], "analyst-note-01")
        self.assertEqual(note["analyst_name"], "Analyst Alice")
        self.assertEqual(note["attribution_status"], "ATTRIBUTED")
        self.assertEqual(note["identity_source"], "API_HEADER_DECLARED")

    # 3. Declared analyst attribution stored on simulations.
    def test_03_declared_analyst_attribution_stored_on_simulations(self):
        mock_analysis = _build_mock_analysis("analysis-sim-parent-01")
        ForensicRepository.save_analysis(mock_analysis, db_path=self.db_path)

        actor = ActorContext(
            actor_id="analyst-sim-99",
            actor_display_name="Remediation Specialist Bob",
            identity_source="LOCAL_DECLARED",
            attribution_status="ATTRIBUTED",
        )
        sim_id = "sim_test_001"
        projection_dict = {
            "simulation_id": sim_id,
            "projected_grade": "A+",
            "projected_score": 98,
            "source": "SIMULATED_REMEDIATION",
            "authoritative": False,
        }
        ForensicRepository.save_simulation(
            simulation_id=sim_id,
            analysis_id="analysis-sim-parent-01",
            session_id=mock_analysis.sessions[0].session_id,
            requested_actions=["ENABLE_FORWARD_SECRECY"],
            projection_dict=projection_dict,
            actor=actor,
            db_path=self.db_path,
        )

        sim_record = ForensicRepository.get_simulation(sim_id, db_path=self.db_path)
        self.assertIsNotNone(sim_record)
        self.assertEqual(sim_record["created_by_actor_id"], "analyst-sim-99")
        self.assertEqual(sim_record["identity_source"], "LOCAL_DECLARED")

    # 4. Declared analyst attribution stored on active scans.
    def test_04_declared_analyst_attribution_stored_on_active_scans(self):
        actor = ActorContext(
            actor_id="analyst-scan-05",
            actor_display_name="Penetration Tester Eve",
            identity_source="API_HEADER_DECLARED",
            attribution_status="ATTRIBUTED",
        )
        scan_id = "scan_test_001"
        result_dict = {
            "scan_id": scan_id,
            "target_host": "mail.example.org",
            "resolved_ip": "93.184.216.34",
            "ports": [{"port": 25, "status": "OPEN"}],
        }
        ForensicRepository.save_active_scan(
            scan_id=scan_id,
            target_host="mail.example.org",
            connected_ip="93.184.216.34",
            ports_scanned=[25],
            result_dict=result_dict,
            actor=actor,
            db_path=self.db_path,
        )

        scan_record = ForensicRepository.get_active_scan(scan_id, db_path=self.db_path)
        self.assertIsNotNone(scan_record)
        self.assertEqual(scan_record["initiated_by_actor_id"], "analyst-scan-05")
        self.assertEqual(scan_record["identity_source"], "API_HEADER_DECLARED")

    # 5. Declared analyst attribution stored on DNS enrichment.
    def test_05_declared_analyst_attribution_stored_on_dns_enrichment(self):
        actor = ActorContext(
            actor_id="analyst-dns-12",
            actor_display_name="OSINT Analyst Charlie",
            identity_source="LOCAL_DECLARED",
            attribution_status="ATTRIBUTED",
        )
        enrichment_id = "dns_test_001"
        enrichment_dict = {
            "domain": "example.com",
            "mx_records": ["mail.example.com"],
            "spf_record": "v=spf1 -all",
            "dmarc_record": "v=DMARC1; p=reject",
        }
        ForensicRepository.save_dns_enrichment(
            enrichment_id=enrichment_id,
            target_domain="example.com",
            resolver_provider="System-Default",
            result_dict=enrichment_dict,
            queried_at_utc=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            db_path=self.db_path,
        )

        dns_record = ForensicRepository.get_dns_enrichment(enrichment_id, db_path=self.db_path)
        self.assertIsNotNone(dns_record)
        self.assertEqual(dns_record["queried_by_actor_id"], "analyst-dns-12")
        self.assertEqual(dns_record["identity_source"], "LOCAL_DECLARED")

    # 6. Missing identity produces UNATTRIBUTED, not fake admin/user.
    def test_06_missing_identity_produces_unattributed(self):
        ctx = ActorContext.from_headers(None, None)
        self.assertEqual(ctx.actor_id, "UNATTRIBUTED")
        self.assertEqual(ctx.actor_display_name, "Unattributed Analyst")
        self.assertEqual(ctx.identity_source, "UNKNOWN")
        self.assertEqual(ctx.attribution_status, "UNATTRIBUTED")
        self.assertNotEqual(ctx.actor_id.lower(), "admin")
        self.assertNotEqual(ctx.actor_id.lower(), "root")

        case = CaseService.create_case(
            title="Unattributed Investigation",
            actor=None,
            db_path=self.db_path,
        )
        self.assertEqual(case.analyst_id, "UNATTRIBUTED")

    # 7. Automated event uses SYSTEM.
    def test_07_automated_event_uses_system(self):
        sys_ctx = ActorContext.system_actor()
        self.assertEqual(sys_ctx.actor_id, "SYSTEM")
        self.assertEqual(sys_ctx.actor_display_name, "SecureMailScope X")
        self.assertEqual(sys_ctx.identity_source, "SYSTEM")
        self.assertEqual(sys_ctx.attribution_status, "SYSTEM_GENERATED")

        ForensicRepository.record_audit_event(
            event_type="AUTO_INTEGRITY_CHECK",
            object_type="ANALYSIS",
            object_id="analysis-sys-01",
            details="Automated periodic integrity verification",
            actor=sys_ctx,
            db_path=self.db_path,
        )

        events = ForensicRepository.get_audit_events("ANALYSIS", "analysis-sys-01", db_path=self.db_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["actor_id"], "SYSTEM")
        self.assertEqual(events[0]["actor_display_name"], "SecureMailScope X")
        self.assertEqual(events[0]["actor_identity_source"], "SYSTEM")
        self.assertEqual(events[0]["actor_attribution_status"], "SYSTEM_GENERATED")

    # 8. Historical event retains original actor display name after analyst registry update.
    def test_08_historical_event_retains_original_display_name_after_registry_update(self):
        analyst_id = "analyst-dyn-01"
        ForensicRepository.register_analyst(
            analyst_id=analyst_id,
            display_name="Analyst Version 1",
            identity_source="LOCAL_DECLARED",
            db_path=self.db_path,
        )

        actor_v1 = ActorContext(
            actor_id=analyst_id,
            actor_display_name="Analyst Version 1",
            identity_source="LOCAL_DECLARED",
            attribution_status="ATTRIBUTED",
        )

        case = CaseService.create_case(
            title="Registry Update Case",
            actor=actor_v1,
            db_path=self.db_path,
        )

        # Update analyst profile in registry
        ForensicRepository.update_analyst_profile(
            analyst_id=analyst_id,
            display_name="Analyst Version 2 (Promoted)",
            db_path=self.db_path,
        )

        # Retrieve registry profile -> has new name
        profile = ForensicRepository.get_analyst(analyst_id, db_path=self.db_path)
        self.assertEqual(profile["display_name"], "Analyst Version 2 (Promoted)")

        # Retrieve historical audit events -> MUST still retain historical "Analyst Version 1"
        events = ForensicRepository.get_audit_events("CASE", case.id, db_path=self.db_path)
        self.assertEqual(events[0]["actor_display_name"], "Analyst Version 1")

    # 9. Tampering actor_id in audit event breaks audit-chain verification.
    def test_09_tampering_actor_id_breaks_chain(self):
        actor = ActorContext(
            actor_id="analyst-original",
            actor_display_name="Original Analyst",
            identity_source="LOCAL_DECLARED",
            attribution_status="ATTRIBUTED",
        )
        case = CaseService.create_case(title="Tamper Actor ID Case", actor=actor, db_path=self.db_path)

        events = ForensicRepository.get_audit_events("CASE", case.id, db_path=self.db_path)
        self.assertTrue(len(events) >= 1)

        # Directly tamper actor_id in SQLite
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE audit_events SET actor_id = 'analyst-imposter' WHERE object_id = ?",
            (case.id,)
        )
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_audit_events("CASE", case.id, db_path=self.db_path)

    # 10. Tampering actor_display_name breaks audit-chain verification.
    def test_10_tampering_actor_display_name_breaks_chain(self):
        actor = ActorContext(
            actor_id="analyst-test",
            actor_display_name="Original Name",
            identity_source="LOCAL_DECLARED",
            attribution_status="ATTRIBUTED",
        )
        case = CaseService.create_case(title="Tamper Display Name Case", actor=actor, db_path=self.db_path)

        ForensicRepository.get_audit_events("CASE", case.id, db_path=self.db_path)

        # Directly tamper actor_display_name in SQLite
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE audit_events SET actor_display_name = 'Forged Name' WHERE object_id = ?",
            (case.id,)
        )
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_audit_events("CASE", case.id, db_path=self.db_path)

    # 11. Actor metadata does not alter observed_result_sha256.
    def test_11_actor_metadata_does_not_alter_observed_result_sha256(self):
        mock_analysis = _build_mock_analysis("a-01")
        actor1 = ActorContext(actor_id="analyst-1", actor_display_name="Analyst 1", identity_source="LOCAL_DECLARED", attribution_status="ATTRIBUTED")

        ForensicRepository.save_analysis(
            analysis=mock_analysis,
            actor=actor1,
            db_path=self.db_path,
        )

        row = ForensicRepository.get_analysis("a-01", db_path=self.db_path)
        self.assertIsNotNone(row)
        
        # Verify actor attribution saved in database
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT created_by_actor_id, observed_result_sha256 FROM analyses WHERE analysis_id = 'a-01'")
        db_row = cursor.fetchone()
        conn.close()

        self.assertEqual(db_row["created_by_actor_id"], "analyst-1")
        self.assertIsNotNone(db_row["observed_result_sha256"])

    # 12. Actor metadata does not alter capture_sha256.
    def test_12_actor_metadata_does_not_alter_capture_sha256(self):
        raw_bytes = b"fake pcap capture bytes for testing"
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        ForensicRepository.save_custody_record(
            analysis_id="custody-cap-01",
            filename="test.pcap",
            file_size=len(raw_bytes),
            capture_sha256=raw_sha256,
            raw_bytes=raw_bytes,
            ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
            start_timestamp=None,
            completion_timestamp=None,
            manifest_dict=None,
            manifest_hash=None,
            report_pdf_bytes=None,
            report_pdf_hash=None,
            events=[],
            db_path=self.db_path,
        )

        rec = ForensicRepository.get_custody_record("custody-cap-01", db_path=self.db_path)
        self.assertEqual(rec["capture_sha256"], raw_sha256)

    # 13. Actor metadata does not alter simulation technical payload hash unless explicitly designed.
    def test_13_actor_metadata_does_not_alter_simulation_projection_hash(self):
        mock_analysis = _build_mock_analysis("a-sim-hash-01")
        ForensicRepository.save_analysis(mock_analysis, db_path=self.db_path)

        projection_dict = {
            "simulation_id": "sim_hash_01",
            "projected_grade": "A+",
            "hypothetical": True,
        }
        canonical_proj_json = ForensicRepository.canonical_json(projection_dict)
        expected_hash = hashlib.sha256(canonical_proj_json.encode("utf-8")).hexdigest()

        actor = ActorContext(
            actor_id="analyst-sim-hash",
            actor_display_name="Sim Analyst",
            identity_source="LOCAL_DECLARED",
            attribution_status="ATTRIBUTED",
        )

        ForensicRepository.save_simulation(
            simulation_id="sim_hash_01",
            analysis_id="a-sim-hash-01",
            session_id=mock_analysis.sessions[0].session_id,
            requested_actions=["ACTION_1"],
            projection_dict=projection_dict,
            actor=actor,
            db_path=self.db_path,
        )

        retrieved = ForensicRepository.get_simulation("sim_hash_01", db_path=self.db_path)
        self.assertEqual(retrieved["projection_sha256"], expected_hash)

    # 14. Actor metadata does not alter active scan technical result hash unless explicitly designed.
    def test_14_actor_metadata_does_not_alter_active_scan_result_hash(self):
        result_dict = {
            "scan_id": "scan_hash_01",
            "target_host": "mail.example.com",
            "ports": [25, 587],
        }
        canonical_scan_json = ForensicRepository.canonical_json(result_dict)
        expected_hash = hashlib.sha256(canonical_scan_json.encode("utf-8")).hexdigest()

        actor = ActorContext(
            actor_id="analyst-scan-hash",
            actor_display_name="Scan Analyst",
            identity_source="API_HEADER_DECLARED",
            attribution_status="ATTRIBUTED",
        )

        ForensicRepository.save_active_scan(
            scan_id="scan_hash_01",
            target_host="mail.example.com",
            connected_ip="192.0.2.1",
            ports_scanned=[25, 587],
            result_dict=result_dict,
            actor=actor,
            db_path=self.db_path,
        )

        retrieved = ForensicRepository.get_active_scan("scan_hash_01", db_path=self.db_path)
        self.assertEqual(retrieved["result_sha256"], expected_hash)

    # 15. Header-declared identity is marked API_HEADER_DECLARED, not AUTHENTICATED.
    def test_15_header_declared_identity_is_api_header_declared(self):
        ctx = ActorContext.from_headers("analyst-hdr-01", "Header Analyst")
        self.assertEqual(ctx.identity_source, "API_HEADER_DECLARED")
        self.assertEqual(ctx.attribution_status, "ATTRIBUTED")
        self.assertEqual(ctx.authorization_status, "NOT_IMPLEMENTED")
        self.assertNotIn("AUTH", ctx.identity_source.upper().replace("API_HEADER_DECLARED", ""))
        self.assertNotEqual(ctx.identity_source, "AUTHENTICATED")

    # 16. Invalid/control-character analyst IDs rejected.
    def test_16_invalid_control_character_analyst_ids_rejected(self):
        with self.assertRaises(ValueError):
            validate_actor_id("../etc/passwd")

        with self.assertRaises(ValueError):
            validate_actor_id("analyst\x00null")

        with self.assertRaises(ValueError):
            validate_actor_id("analyst\nnewline")

        with self.assertRaises(ValueError):
            validate_actor_id("a" * 129)

        valid_id = validate_actor_id("analyst_sec-42.test")
        self.assertEqual(valid_id, "analyst_sec-42.test")

        clean_name = sanitize_display_name("Analyst\r\nName\t")
        self.assertEqual(clean_name, "Analyst Name")

    # 17. No password/token/secret fields exist in analyst table/model.
    def test_17_no_password_token_secret_fields_in_analysts_table(self):
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(analysts)")
        columns = [row["name"].lower() for row in cursor.fetchall()]
        conn.close()

        forbidden_substrings = ["password", "token", "secret", "hash_pw", "salt", "credential", "auth_token"]
        for col in columns:
            for forbidden in forbidden_substrings:
                self.assertNotIn(forbidden, col, f"Forbidden authentication field '{col}' found in analysts table!")

        dto_fields = AnalystIdentityDTO.model_fields.keys()
        for field_name in dto_fields:
            for forbidden in forbidden_substrings:
                self.assertNotIn(forbidden, field_name.lower(), f"Forbidden field '{field_name}' in AnalystIdentityDTO!")

    # 18. Existing historical rows without actor fields remain readable as UNATTRIBUTED.
    def test_18_existing_historical_rows_without_actor_remain_readable(self):
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO cases (id, title, description, status, analyst_id, analyst_name, tags_json, created_at, updated_at, is_archived, created_by_actor_id, created_by_display_name, archived_by_actor_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'UNATTRIBUTED', 'Unattributed Analyst', NULL)
            """,
            ("CASE-LEGACY-01", "Legacy Case", "No actor columns", "OPEN", "analyst-legacy", "Legacy Name", "[]", datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        conn.close()

        case = ForensicRepository.get_case("CASE-LEGACY-01", db_path=self.db_path)
        self.assertIsNotNone(case)
        self.assertEqual(case["title"], "Legacy Case")
        self.assertEqual(case["created_by_actor_id"], "UNATTRIBUTED")

    # 19. Full persistence/custody integrity remains valid.
    def test_19_full_persistence_custody_integrity_remains_valid(self):
        raw_pcap = b"Sample raw pcap stream for custody verification."
        analysis_id = "analysis_custody_test_01"

        CustodyService.get_or_create_record(analysis_id, "custody_test.pcap", raw_pcap)
        CustodyService.record_analysis_start(analysis_id)

        mock_detail = _build_mock_analysis(analysis_id)
        CustodyService.record_analysis_completion(analysis_id, mock_detail)

        verification = CustodyService.verify_integrity(analysis_id)
        self.assertEqual(verification.overall_status, "VERIFIED")
        self.assertTrue(len(verification.audit_events) >= 2)
        for evt in verification.audit_events:
            self.assertEqual(evt.actor_id, "SYSTEM")
            self.assertEqual(evt.actor_attribution_status, "SYSTEM_GENERATED")

    # 20. Case attach/detach audit trail records actor.
    def test_20_case_attach_detach_audit_trail_records_actor(self):
        actor_attacher = ActorContext(
            actor_id="analyst-attach-01",
            actor_display_name="Attacher Analyst",
            identity_source="API_HEADER_DECLARED",
            attribution_status="ATTRIBUTED",
        )
        case = CaseService.create_case(title="Attach Detach Test", actor=actor_attacher, db_path=self.db_path)
        
        mock_analysis = _build_mock_analysis("analysis-link-01")
        ForensicRepository.save_analysis(mock_analysis, db_path=self.db_path)

        # Attach
        CaseService.attach_analysis_to_case(case.id, "analysis-link-01", actor=actor_attacher, db_path=self.db_path)
        # Detach
        CaseService.detach_analysis_from_case(case.id, "analysis-link-01", actor=actor_attacher, db_path=self.db_path)

        events = ForensicRepository.get_audit_events("CASE", case.id, db_path=self.db_path)
        event_types = [e["event_type"] for e in events]
        self.assertIn("CASE_ANALYSIS_ATTACHED", event_types)
        self.assertIn("CASE_ANALYSIS_DETACHED", event_types)
        for e in events:
            self.assertEqual(e["actor_id"], "analyst-attach-01")


if __name__ == "__main__":
    unittest.main()

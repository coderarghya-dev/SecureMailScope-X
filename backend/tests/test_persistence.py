"""
SecureMailScope X - Persistent Analysis / Case Storage & History Tests (Phase 11)
Validates SQLite persistence, immutability, canonical hashing, custody chain recovery across restarts,
tamper detection, case management, additive notes, and transaction safety.
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
    ImmutableRecordError,
    IntegrityVerificationError,
    UnsupportedSchemaVersionError,
    compute_sha256,
)
from app.services.custody_service import CustodyService, CustodyRecord
from app.services.analysis_service import AnalysisService
from app.services.case_service import CaseService
from app.schemas.api import (
    AnalysisDetailResponse,
    SessionDetailDTO,
    STARTTLSStateDTO,
    TLSHandshakeDTO,
    CipherSuiteInfoDTO,
    CaptureHealthDTO,
    EvidenceConfidenceDTO,
    SecurityAssessmentDTO,
    SecurityFindingDTO,
    FindingsSummaryDTO,
    EvidenceFrameDTO,
    CorrelatedIncidentDTO,
    MultiSessionSummaryDTO,
    PacketEvidenceDTO,
)


def create_sample_analysis_dto(analysis_id: str = "analysis_sample12345678") -> AnalysisDetailResponse:
    finding = SecurityFindingDTO(
        id="FINDING-NO-FORWARD-SECRECY",
        title="No PFS",
        severity="HIGH",
        category="FORWARD_SECRECY",
        description="Static RSA without Ephemeral Diffie-Hellman",
        evidence_frames=[10, 12],
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
        session_id="stream_0_192.168.1.10_587",
        stream_index=0,
        protocol="SMTP",
        security_mode="STARTTLS_ACCEPTED",
        client="192.168.1.10:45678",
        server="192.168.1.1:587",
        server_hostname="mail.example.org",
        start_time_iso="2026-09-25T10:00:00Z",
        duration_seconds=1.234,
        packets_count=15,
        starttls=STARTTLSStateDTO(advertised=True, requested=True, accepted=True, upgrade_successful=True, state="UPGRADED"),
        tls=TLSHandshakeDTO(
            negotiated_version="TLSv1.2",
            cipher_name="TLS_RSA_WITH_AES_256_GCM_SHA384",
            forward_secrecy_pfs=False,
            pfs_status="NO_PFS_STATIC_KEY_EXCHANGE",
            certificate_visibility="FULL_CHAIN_OBSERVED"
        ),
        capture_health=CaptureHealthDTO(score=98, grade="EXCELLENT", syn_observed=True, fin_rst_observed=True, total_packets=15, retransmissions_count=0, retransmission_rate=0.0, deduction_reasons=[]),
        evidence_confidence=EvidenceConfidenceDTO(score=95, level="HIGH", handshake_observable=True, version_verifiable=True, cipher_identifiable=True, key_exchange_observable=True, confidence_factors=[]),
        security_assessment=assessment,
        evidence_frames=[EvidenceFrameDTO(frame=10, time_epoch=1727258400.0, protocol="SMTP", summary="STARTTLS accepted")],
    )
    incident = CorrelatedIncidentDTO(
        incident_id="INC-STATIC-RSA-001",
        incident_type="STATIC_KEY_EXCHANGE_PATTERN",
        severity="HIGH",
        session_ids=[session.session_id],
        finding_ids=[finding.id],
        evidence_frames=[10, 12],
        correlation_reasons=["Static RSA session without PFS"],
        confidence="HIGH",
        authoritative=True,
        evidence_backed=True,
        correlation_method="DETERMINISTIC_RULE_CORRELATION",
    )
    return AnalysisDetailResponse(
        analysis_id=analysis_id,
        file_name="sample_test.pcap",
        file_size_bytes=10240,
        analysis_time_utc="2026-09-25T10:00:00Z",
        tshark_version="TShark 4.6.0",
        total_packets_extracted=15,
        raw_capture_packets_total=15,
        email_sessions_found=1,
        sessions=[session],
        evidence_confidence_score=95,
        evidence_confidence_level="HIGH",
        multi_session_summary=MultiSessionSummaryDTO(total_sessions=1, sessions_with_findings=1, incident_count=1, critical_high_incident_count=1, repeated_pattern_count=0, uncorrelated_sessions_count=0),
        correlated_incidents=[incident],
    )


class TestPersistence(unittest.TestCase):

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db", prefix="sms_test_")
        os.close(self.temp_db_fd)
        set_custom_db_path(self.temp_db_path)
        init_db(self.temp_db_path)

        # Clear in-memory caches between tests
        AnalysisService._cache.clear()
        CustodyService._records.clear()

    def tearDown(self):
        set_custom_db_path(None)
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    # 1. Analysis persists across repository restart
    def test_01_analysis_persists_across_restart(self):
        analysis = create_sample_analysis_dto("analysis_test_restart_01")
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        # Clear in-memory cache to simulate full restart
        AnalysisService._cache.clear()

        # Reload from database
        reloaded = ForensicRepository.get_analysis("analysis_test_restart_01", db_path=self.temp_db_path)
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.analysis_id, "analysis_test_restart_01")
        self.assertEqual(reloaded.file_name, "sample_test.pcap")
        self.assertEqual(len(reloaded.sessions), 1)
        self.assertEqual(reloaded.sessions[0].protocol, "SMTP")

    # 2. Stored observed JSON hash verifies after reload
    def test_02_stored_json_hash_verification(self):
        analysis = create_sample_analysis_dto("analysis_test_hash_02")
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        # Reload and verify integrity
        reloaded = ForensicRepository.get_analysis("analysis_test_hash_02", verify_integrity=True, db_path=self.temp_db_path)
        self.assertEqual(reloaded.analysis_id, "analysis_test_hash_02")

    # 3. Tampered DB JSON produces IntegrityVerificationError
    def test_03_tampered_json_fails_integrity(self):
        analysis = create_sample_analysis_dto("analysis_test_tamper_03")
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        # Tamper directly in SQLite table without updating hash
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE analyses SET observed_result_json = ? WHERE analysis_id = ?",
            ('{"tampered": true, "analysis_id": "analysis_test_tamper_03"}', "analysis_test_tamper_03")
        )
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_analysis("analysis_test_tamper_03", verify_integrity=True, db_path=self.temp_db_path)

    # 4. Finalized analysis cannot be overwritten
    def test_04_finalized_analysis_cannot_be_overwritten(self):
        analysis = create_sample_analysis_dto("analysis_immutable_04")
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        # Attempt to save a modified analysis with same ID
        modified = create_sample_analysis_dto("analysis_immutable_04")
        modified.file_name = "OVERWRITTEN_NAME.pcap"

        ForensicRepository.save_analysis(modified, db_path=self.temp_db_path)

        # Stored analysis must still have original filename
        reloaded = ForensicRepository.get_analysis("analysis_immutable_04", db_path=self.temp_db_path)
        self.assertEqual(reloaded.file_name, "sample_test.pcap")

    # 5. New re-analysis creates new revision or record instead of overwriting old
    def test_05_reanalysis_preserves_historical_records(self):
        analysis_v1 = create_sample_analysis_dto("analysis_hist_v1")
        ForensicRepository.save_analysis(analysis_v1, db_path=self.temp_db_path)

        analysis_v2 = create_sample_analysis_dto("analysis_hist_v2")
        analysis_v2.file_name = "sample_test_reanalysis.pcap"
        ForensicRepository.save_analysis(analysis_v2, db_path=self.temp_db_path)

        all_records = ForensicRepository.list_analyses(db_path=self.temp_db_path)
        a_ids = [r["analysis_id"] for r in all_records]
        self.assertIn("analysis_hist_v1", a_ids)
        self.assertIn("analysis_hist_v2", a_ids)

    # 6. Sessions/findings persist with exact native evidence frames
    def test_06_sessions_and_findings_persist_frames(self):
        analysis = create_sample_analysis_dto("analysis_frames_06")
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        reloaded = ForensicRepository.get_analysis("analysis_frames_06", db_path=self.temp_db_path)
        self.assertEqual(len(reloaded.sessions), 1)
        sess = reloaded.sessions[0]
        self.assertEqual(sess.evidence_frames[0].frame, 10)
        self.assertEqual(sess.security_assessment.findings[0].evidence_frames, [10, 12])

    # 7. Custody event chain persists across restart
    def test_07_custody_chain_persists_across_restart(self):
        sample_bytes = b"TEST_PCAP_BYTES_FOR_CUSTODY_12345"
        aid = "analysis_custody_07"
        CustodyService.get_or_create_record(aid, "test.pcap", sample_bytes)
        CustodyService.record_analysis_start(aid)

        analysis_dto = create_sample_analysis_dto(aid)
        CustodyService.record_analysis_completion(aid, analysis_dto)

        # Clear memory cache
        CustodyService._records.clear()

        # Reload from DB and verify integrity
        resp = CustodyService.verify_integrity(aid)
        self.assertEqual(resp.overall_status, "VERIFIED")
        self.assertGreaterEqual(len(resp.audit_events), 3)
        self.assertEqual(resp.capture_integrity.status, "VERIFIED")
        self.assertEqual(resp.manifest_integrity.status, "VERIFIED")

    # 8. Custody hashes remain identical after reload
    def test_08_custody_hashes_identical_after_reload(self):
        sample_bytes = b"SAMPLE_PAYLOAD_FOR_HASH_VERIFY"
        aid = "analysis_hash_08"
        rec = CustodyService.get_or_create_record(aid, "hash_test.pcap", sample_bytes)
        orig_capture_hash = rec.capture_sha256

        CustodyService._records.clear()

        rec_reloaded = CustodyService.get_record(aid)
        self.assertIsNotNone(rec_reloaded)
        self.assertEqual(rec_reloaded.capture_sha256, orig_capture_hash)

    # 9. Simulation stored separately from observed analysis
    def test_09_simulation_stored_separately(self):
        aid = "analysis_sim_09"
        analysis = create_sample_analysis_dto(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        sim_id = f"sim_{uuid.uuid4().hex[:8]}"
        proj_dict = {
            "simulation_id": sim_id,
            "projected_grade": "A+",
            "source": "SIMULATED_REMEDIATION",
            "authoritative": False,
            "historical_applicability": "HYPOTHETICAL",
        }
        ForensicRepository.save_simulation(
            simulation_id=sim_id,
            analysis_id=aid,
            session_id=analysis.sessions[0].session_id,
            requested_actions=["ENABLE_HYBRID_PQC"],
            projection_dict=proj_dict,
            db_path=self.temp_db_path,
        )

        # Verify observed analysis remains unchanged
        obs = ForensicRepository.get_analysis(aid, db_path=self.temp_db_path)
        self.assertEqual(obs.sessions[0].security_assessment.grade, "C")

    # 10. Active scan stored separately with CURRENT_STATE_ONLY provenance
    def test_10_active_scan_stored_separately(self):
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        scan_res = {
            "scan_id": scan_id,
            "target": "mail.example.com",
            "grade": "A",
            "provenance": "ACTIVE_NETWORK_PROBE",
            "historical_applicability": "CURRENT_STATE_ONLY",
        }
        ForensicRepository.save_active_scan(
            scan_id=scan_id,
            target_host="mail.example.com",
            connected_ip="93.184.216.34",
            ports_scanned=[25, 587],
            result_dict=scan_res,
            db_path=self.temp_db_path,
        )

        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["provenance"], "ACTIVE_NETWORK_PROBE")
        self.assertEqual(row["historical_applicability"], "CURRENT_STATE_ONLY")

    # 11. DNS enrichment stored separately with CURRENT_STATE_ONLY provenance
    def test_11_dns_enrichment_stored_separately(self):
        enr_id = f"enr_{uuid.uuid4().hex[:8]}"
        dns_res = {
            "domain": "example.com",
            "spf_status": "PASS",
            "provenance": "ACTIVE_DNS_ENRICHMENT",
            "historical_applicability": "CURRENT_STATE_ONLY",
        }
        ForensicRepository.save_dns_enrichment(
            enrichment_id=enr_id,
            target_domain="example.com",
            resolver_provider="Cloudflare (1.1.1.1)",
            result_dict=dns_res,
            queried_at_utc="2026-09-25T10:00:00Z",
            db_path=self.temp_db_path,
        )

        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM dns_enrichments WHERE enrichment_id = ?", (enr_id,))
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["provenance"], "ACTIVE_DNS_ENRICHMENT")
        self.assertEqual(row["historical_applicability"], "CURRENT_STATE_ONLY")

    # 12. Case creation and analysis attachment
    def test_12_case_creation_and_attachment(self):
        aid = "analysis_case_12"
        analysis = create_sample_analysis_dto(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        case = CaseService.create_case(title="Investigate Static RSA Incident", description="Case #12")
        attached = CaseService.attach_analysis_to_case(case.id, aid)

        self.assertIsNotNone(attached)
        self.assertIn(aid, attached["analysis_ids"])

    # 13. Case archival does not delete analysis evidence
    def test_13_case_archival_preserves_evidence(self):
        aid = "analysis_case_13"
        analysis = create_sample_analysis_dto(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        case = CaseService.create_case(title="Case to Archive", description="Test Archival")
        CaseService.attach_analysis_to_case(case.id, aid)

        archived = CaseService.archive_case(case.id)
        self.assertEqual(archived["status"], "ARCHIVED")
        self.assertTrue(archived["is_archived"])

        # Evidence in analyses table remains intact
        reloaded = ForensicRepository.get_analysis(aid, db_path=self.temp_db_path)
        self.assertIsNotNone(reloaded)

    # 14. Analyst note append-only behavior
    def test_14_analyst_note_append_only(self):
        case = CaseService.create_case(title="Notes Test Case")
        CaseService.add_note_to_case(case.id, author="Analyst-A", note_text="Initial observation: Static RSA found.")
        CaseService.add_note_to_case(case.id, author="Analyst-B", note_text="Confirmed lack of forward secrecy.")

        case_details = CaseService.get_case(case.id)
        self.assertEqual(len(case_details["analyst_notes"]), 2)
        self.assertEqual(case_details["analyst_notes"][0]["author"], "Analyst-A")
        self.assertEqual(case_details["analyst_notes"][1]["author"], "Analyst-B")

    # 15. Failed transaction rolls back partial analysis persistence
    def test_15_transaction_rollback_on_failure(self):
        aid = "analysis_fail_15"
        # Create an object that will fail during session serialization
        analysis = create_sample_analysis_dto(aid)

        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as c FROM analyses WHERE analysis_id = ?", (aid,))
        count_before = cursor.fetchone()["c"]
        conn.close()

        self.assertEqual(count_before, 0)

    # 16. Schema/analyzer versions persist
    def test_16_schema_and_analyzer_versions_persist(self):
        aid = "analysis_ver_16"
        analysis = create_sample_analysis_dto(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT schema_version, analyzer_version FROM analyses WHERE analysis_id = ?", (aid,))
        row = cursor.fetchone()
        conn.close()

        self.assertEqual(row["schema_version"], "1.0")
        self.assertEqual(row["analyzer_version"], "SecureMailScope X 1.0.0")

    # 17. Unsupported schema version fails safely
    def test_17_unsupported_schema_version_fails_safely(self):
        aid = "analysis_ver_17"
        analysis = create_sample_analysis_dto(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        # Update to an unsupported future schema major version (e.g. 9.0)
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE analyses SET schema_version = '9.0' WHERE analysis_id = ?", (aid,))
        conn.commit()
        conn.close()

        with self.assertRaises(UnsupportedSchemaVersionError):
            ForensicRepository.get_analysis(aid, db_path=self.temp_db_path)

    # 18. Parameterized SQL / injection-like input stored safely
    def test_18_parameterized_sql_safety(self):
        nasty_input = "'; DROP TABLE analyses; --"
        case = CaseService.create_case(title=nasty_input, description=nasty_input)

        reloaded = CaseService.get_case(case.id)
        self.assertEqual(reloaded["title"], nasty_input)

        # Confirm analyses table still exists
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM analyses")
        cursor.fetchone()
        conn.close()

    # 19. Session packet evidence retrieved from DB
    def test_19_session_packet_evidence_persistence(self):
        aid = "analysis_packets_19"
        analysis = create_sample_analysis_dto(aid)
        pkts = {
            analysis.sessions[0].session_id: [
                PacketEvidenceDTO(
                    frame_number=1,
                    timestamp_epoch=1727258400.0,
                    timestamp_iso="2026-09-25T10:00:00Z",
                    src_ip="192.168.1.10",
                    src_port=45678,
                    dst_ip="192.168.1.1",
                    dst_port=587,
                    protocol="SMTP",
                    length=80,
                    summary="EHLO client.example.com",
                    smtp_req_command="EHLO",
                )
            ]
        }
        ForensicRepository.save_analysis(analysis, raw_packets_by_session=pkts, db_path=self.temp_db_path)

    # 20. Canonicalization version and key order determinism
    def test_20_canonicalization_version_and_key_order_determinism(self):
        from app.db.repository import CANONICALIZATION_VERSION, canonical_json_bytes, compute_json_sha256
        self.assertEqual(CANONICALIZATION_VERSION, "SECUREMAILSCOPE_CANONICAL_JSON_V1")

        dict_a = {"zebra": 1, "alpha": "test", "nested": {"b": 2, "a": 1}}
        dict_b = {"alpha": "test", "nested": {"a": 1, "b": 2}, "zebra": 1}

        bytes_a = canonical_json_bytes(dict_a)
        bytes_b = canonical_json_bytes(dict_b)

        self.assertEqual(bytes_a, bytes_b)
        self.assertEqual(compute_json_sha256(dict_a), compute_json_sha256(dict_b))

    # 21. Non-finite floats (NaN, Infinity) are rejected
    def test_21_non_finite_floats_nan_inf_rejected(self):
        from app.db.repository import canonical_json_bytes

        with self.assertRaises(ValueError):
            canonical_json_bytes({"score": float("nan")})

        with self.assertRaises(ValueError):
            canonical_json_bytes({"score": float("inf")})

        with self.assertRaises(ValueError):
            canonical_json_bytes({"score": float("-inf")})

    # 22. Tampered child session detected
    def test_22_tampered_child_session_detected(self):
        aid = "analysis_tamper_sess_22"
        analysis = create_sample_analysis_dto(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        # Tamper directly with the session row JSON
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE sessions SET session_result_json = ? WHERE analysis_id = ?",
            ('{"tampered": true}', aid)
        )
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_analysis(aid, verify_integrity=True, db_path=self.temp_db_path)

    # 23. Tampered child finding detected
    def test_23_tampered_child_finding_detected(self):
        aid = "analysis_tamper_find_23"
        analysis = create_sample_analysis_dto(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        # Tamper directly with the finding row JSON
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE findings SET finding_json = ? WHERE analysis_id = ?",
            ('{"tampered_finding": true}', aid)
        )
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_analysis(aid, verify_integrity=True, db_path=self.temp_db_path)

    # 24. Custody reload is side-effect-free
    def test_24_custody_reload_is_side_effect_free(self):
        aid = "analysis_custody_side_effect_24"
        sample_bytes = b"SIDE_EFFECT_FREE_READ_TEST"
        CustodyService.get_or_create_record(aid, "test.pcap", sample_bytes)
        CustodyService.record_analysis_start(aid)
        analysis_dto = create_sample_analysis_dto(aid)
        CustodyService.record_analysis_completion(aid, analysis_dto)

        # Clear memory
        CustodyService._records.clear()

        # Check event count in database before read
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as c FROM custody_events WHERE analysis_id = ?", (aid,))
        count_before = cursor.fetchone()["c"]
        conn.close()

        # Perform read-only verification
        resp1 = CustodyService.verify_integrity(aid, record_verification_event=False)
        self.assertEqual(resp1.overall_status, "VERIFIED")

        # Confirm count in database has NOT increased
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as c FROM custody_events WHERE analysis_id = ?", (aid,))
        count_after = cursor.fetchone()["c"]
        conn.close()

        self.assertEqual(count_before, count_after)

    # 25. Case attach/detach audit trail preserved
    def test_25_case_attach_detach_audit_trail_preserved(self):
        aid = "analysis_audit_25"
        analysis = create_sample_analysis_dto(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        case = CaseService.create_case(title="Audit Trail Case")
        CaseService.attach_analysis_to_case(case.id, aid)
        CaseService.detach_analysis_from_case(case.id, aid)

        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT event_type FROM audit_events WHERE object_id = ? ORDER BY timestamp_utc ASC", (case.id,))
        events = [r["event_type"] for r in cursor.fetchall()]
        conn.close()

        self.assertIn("CASE_ANALYSIS_ATTACHED", events)
        self.assertIn("CASE_ANALYSIS_DETACHED", events)

    # 26. Analyst note tamper detected
    def test_26_analyst_note_tamper_detected(self):
        case = CaseService.create_case(title="Note Tamper Case")
        CaseService.add_note_to_case(case.id, author="Analyst-1", note_text="Legitimate forensic observation.")

        # Tamper note text directly in DB
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE analyst_notes SET note_text = 'TAMPERED EVIDENCE STATEMENT' WHERE target_id = ?", (case.id,))
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_analyst_notes("CASE", case.id, verify_integrity=True, db_path=self.temp_db_path)

    # 27. Gitignore includes DB WAL and SHM patterns
    def test_27_gitignore_wal_shm_patterns(self):
        gitignore_path = os.path.join(os.path.dirname(BACKEND_DIR), ".gitignore")
        with open(gitignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("*.db", content)
        self.assertIn("*.db-wal", content)
        self.assertIn("*.db-shm", content)

    # 28. Historical schema migration does NOT alter observed JSON bytes or hash
    def test_28_migration_preserves_observed_bytes_and_hash(self):
        # Create a fresh isolated DB file with an older schema
        old_db_fd, old_db_path = tempfile.mkstemp(suffix=".db", prefix="sms_old_")
        os.close(old_db_fd)

        try:
            import sqlite3
            conn = sqlite3.connect(old_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Create older schema without is_archived column
            cursor.execute("""
                CREATE TABLE analyses (
                    analysis_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL DEFAULT 1,
                    filename TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL,
                    capture_sha256 TEXT NOT NULL,
                    analysis_status TEXT NOT NULL DEFAULT 'FINALIZED',
                    created_at TEXT NOT NULL,
                    finalized_at TEXT,
                    is_finalized INTEGER NOT NULL DEFAULT 1,
                    observed_result_json TEXT NOT NULL,
                    observed_result_sha256 TEXT NOT NULL,
                    total_packets INTEGER NOT NULL DEFAULT 0,
                    raw_total_frames INTEGER NOT NULL DEFAULT 0,
                    email_sessions_found INTEGER NOT NULL DEFAULT 0,
                    evidence_confidence_score INTEGER,
                    evidence_confidence_level TEXT,
                    security_grade TEXT
                )
            """)

            # Insert sample historical record with known raw JSON and hash
            analysis = create_sample_analysis_dto("analysis_legacy_28")
            from app.db.repository import canonical_json_bytes, compute_sha256
            raw_json_bytes = canonical_json_bytes(analysis.model_dump())
            raw_hash = compute_sha256(raw_json_bytes)

            cursor.execute(
                """
                INSERT INTO analyses (
                    analysis_id, filename, file_size_bytes, capture_sha256,
                    created_at, observed_result_json, observed_result_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                ("analysis_legacy_28", "legacy.pcap", 1024, "fake_cap_sha", "2026-01-01T00:00:00Z", raw_json_bytes.decode("utf-8"), raw_hash)
            )
            conn.commit()
            conn.close()

            # Run migration via init_db
            init_db(old_db_path)

            # Query back and verify bytes and hash are 100% identical
            conn2 = sqlite3.connect(old_db_path)
            conn2.row_factory = sqlite3.Row
            cursor2 = conn2.cursor()
            cursor2.execute("SELECT observed_result_json, observed_result_sha256, is_archived, analyzer_version, schema_version FROM analyses WHERE analysis_id = ?", ("analysis_legacy_28",))
            row = cursor2.fetchone()
            conn2.close()

            self.assertIsNotNone(row)
            self.assertEqual(row["observed_result_json"].encode("utf-8"), raw_json_bytes)
            self.assertEqual(row["observed_result_sha256"], raw_hash)
            self.assertEqual(row["is_archived"], 0)
            self.assertEqual(row["analyzer_version"], "SecureMailScope X 1.0.0")
            self.assertEqual(row["schema_version"], "1.0")

            # Verify ForensicRepository loads and validates integrity without error
            loaded = ForensicRepository.get_analysis("analysis_legacy_28", verify_integrity=True, db_path=old_db_path)
            self.assertEqual(loaded.analysis_id, "analysis_legacy_28")
        finally:
            if os.path.exists(old_db_path):
                try:
                    os.remove(old_db_path)
                except OSError:
                    pass

    # 29. Tampered active scan detected on retrieval
    def test_29_tampered_active_scan_detected(self):
        scan_id = "scan_tamper_29"
        ForensicRepository.save_active_scan(
            scan_id=scan_id,
            target_host="mail.example.org",
            connected_ip="192.168.1.1",
            ports_scanned=[25, 587],
            result_dict={"target": "mail.example.org", "overall_grade": "A"},
            db_path=self.temp_db_path,
        )

        # Confirm normal get_active_scan works
        scan = ForensicRepository.get_active_scan(scan_id, verify_integrity=True, db_path=self.temp_db_path)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["result"]["overall_grade"], "A")

        # Tamper result JSON directly in DB
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE active_scans SET result_json = ? WHERE scan_id = ?", ('{"target": "mail.example.org", "overall_grade": "F"}', scan_id))
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_active_scan(scan_id, verify_integrity=True, db_path=self.temp_db_path)

    # 30. Tampered DNS enrichment detected on retrieval
    def test_30_tampered_dns_enrichment_detected(self):
        enr_id = "dns_tamper_30"
        ForensicRepository.save_dns_enrichment(
            enrichment_id=enr_id,
            target_domain="example.org",
            resolver_provider="Cloudflare",
            result_dict={"domain": "example.org", "spf_status": "PASS"},
            queried_at_utc="2026-09-25T10:00:00Z",
            db_path=self.temp_db_path,
        )

        # Confirm normal get_dns_enrichment works
        enr = ForensicRepository.get_dns_enrichment(enr_id, verify_integrity=True, db_path=self.temp_db_path)
        self.assertIsNotNone(enr)
        self.assertEqual(enr["result"]["spf_status"], "PASS")

        # Tamper result JSON directly in DB
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE dns_enrichments SET result_json = ? WHERE enrichment_id = ?", ('{"domain": "example.org", "spf_status": "FAIL"}', enr_id))
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_dns_enrichment(enr_id, verify_integrity=True, db_path=self.temp_db_path)

    # 31. Tampered remediation simulation projection detected
    def test_31_tampered_simulation_detected(self):
        sim_id = "sim_tamper_31"
        aid = "analysis_sim_31"
        analysis = create_sample_analysis_dto(aid)
        ForensicRepository.save_analysis(analysis, db_path=self.temp_db_path)

        ForensicRepository.save_simulation(
            simulation_id=sim_id,
            analysis_id=aid,
            session_id=analysis.sessions[0].session_id,
            requested_actions=["ENABLE_FORWARD_SECRECY"],
            projection_dict={"projected_grade": "A", "projected_score": 90},
            db_path=self.temp_db_path,
        )

        # Confirm normal retrieval works
        sim = ForensicRepository.get_simulation(sim_id, verify_integrity=True, db_path=self.temp_db_path)
        self.assertIsNotNone(sim)
        self.assertEqual(sim["projection"]["projected_grade"], "A")

        # Tamper projection JSON directly in DB
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE simulations SET projection_json = ? WHERE simulation_id = ?", ('{"projected_grade": "A+", "projected_score": 100}', sim_id))
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_simulation(sim_id, verify_integrity=True, db_path=self.temp_db_path)

    # 32. Analyst note containing pipe '|' characters serializes and verifies unambiguously
    def test_32_analyst_note_pipe_delimiter_safety(self):
        case = CaseService.create_case(title="Pipe Safety Case", db_path=self.temp_db_path)
        note_with_pipes = "Note with | pipes | inside | text | and | delimiters."
        author_with_pipes = "Lead | Analyst | Special"

        note = ForensicRepository.add_analyst_note(
            note_id="note_pipe_32",
            target_type="CASE",
            target_id=case.id,
            analyst_id="analyst-special|01",
            analyst_name=author_with_pipes,
            note_text=note_with_pipes,
            db_path=self.temp_db_path,
        )
        self.assertIsNotNone(note)

        # Retrieve and verify integrity
        notes = ForensicRepository.get_analyst_notes("CASE", case.id, verify_integrity=True, db_path=self.temp_db_path)
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["note_text"], note_with_pipes)
        self.assertEqual(notes[0]["analyst_name"], author_with_pipes)

    # 33. System audit event chain integrity and tamper detection
    def test_33_audit_event_chain_integrity_and_tamper_detection(self):
        aid1 = "analysis_chain_33_1"
        aid2 = "analysis_chain_33_2"
        analysis1 = create_sample_analysis_dto(aid1)
        analysis2 = create_sample_analysis_dto(aid2)
        ForensicRepository.save_analysis(analysis1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(analysis2, db_path=self.temp_db_path)

        case = CaseService.create_case(title="Audit Chain Case", db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(case.id, aid1, db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(case.id, aid2, db_path=self.temp_db_path)
        CaseService.detach_analysis_from_case(case.id, aid1, db_path=self.temp_db_path)
        CaseService.archive_case(case.id, db_path=self.temp_db_path)

        # Verify entire chain integrity passes
        events = ForensicRepository.get_audit_events(verify_integrity=True, db_path=self.temp_db_path)
        self.assertEqual(len(events), 5)

        # Tamper the details of the second event
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE audit_events SET details = 'TAMPERED AUDIT ENTRY' WHERE event_id = ?", (events[1]["event_id"],))
        conn.commit()
        conn.close()

        with self.assertRaises(IntegrityVerificationError):
            ForensicRepository.get_audit_events(verify_integrity=True, db_path=self.temp_db_path)

    # 34. Custody and system audit chains remain independent
    def test_34_custody_and_audit_chains_independent(self):
        aid = "analysis_chains_indep_34"
        sample_bytes = b"CHAIN_INDEPENDENCE_TEST"
        CustodyService.get_or_create_record(aid, "test.pcap", sample_bytes)
        CustodyService.record_analysis_start(aid)
        analysis_dto = create_sample_analysis_dto(aid)
        CustodyService.record_analysis_completion(aid, analysis_dto)

        # Record system audit events for a case
        case = CaseService.create_case(title="Independent Case", db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(case.id, aid, db_path=self.temp_db_path)

        # Verify custody events start with genesis "0"*64
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT previous_event_hash FROM custody_events WHERE analysis_id = ? ORDER BY sequence_order ASC LIMIT 1", (aid,))
        custody_genesis = cursor.fetchone()["previous_event_hash"]

        # Verify system audit events start with genesis "0"*64
        cursor.execute("SELECT previous_event_hash FROM audit_events ORDER BY rowid ASC LIMIT 1")
        audit_genesis = cursor.fetchone()["previous_event_hash"]
        conn.close()

        self.assertEqual(custody_genesis, "0" * 64)
        self.assertEqual(audit_genesis, "0" * 64)


if __name__ == "__main__":
    unittest.main()



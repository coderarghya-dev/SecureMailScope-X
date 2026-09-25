"""
SecureMailScope X - Immutable Manifest Versioning & Report Artifact Persistence Tests (Phase 13)
Validates immutable custody manifest versioning, report artifact records, report regeneration history,
manifest hash chaining, report-to-manifest linkage, tamper verification, actor attribution freezing,
transaction safety, and legacy custody compatibility.
"""

import os
import sys
import json
import uuid
import tempfile
import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.db.database import set_custom_db_path, init_db, get_db_connection
from app.db.repository import (
    ForensicRepository,
    ImmutableRecordError,
    IntegrityVerificationError,
    canonical_json_bytes,
    canonical_json_str,
    compute_sha256,
    compute_json_sha256,
)
from app.services.custody_service import (
    CustodyService,
    CustodyRecord,
    compute_legacy_event_hash,
    compute_event_hash_v2,
    GENESIS_PREV_HASH,
)
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportService
from app.schemas.identity import (
    ActorContext,
    IDENTITY_SOURCE_LOCAL_DECLARED,
    ATTRIBUTION_STATUS_ATTRIBUTED,
)
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
    CustodyEventDTO,
)
from app.main import app


def _build_test_analysis_dto(analysis_id: str) -> AnalysisDetailResponse:
    finding = SecurityFindingDTO(
        id="FINDING-TLS-1",
        title="Plaintext Fallback Risk",
        severity="HIGH",
        category="TLS_CONFIGURATION",
        description="STARTTLS not enforced strictly",
        evidence_frames=[1, 2],
        recommendation="Require TLS 1.3",
    )
    assessment = SecurityAssessmentDTO(
        grade="B",
        grade_rationale="Adequate transport security",
        post_quantum_ready=False,
        post_quantum_summary="Classical key exchange only",
        findings_summary=FindingsSummaryDTO(critical=0, high=1, medium=0, low=0, info=0),
        findings=[finding],
    )
    session = SessionDetailDTO(
        session_id=f"stream_0_{analysis_id}",
        stream_index=0,
        protocol="SMTP",
        security_mode="STARTTLS_ACCEPTED",
        client="10.0.0.1:45000",
        server="10.0.0.2:587",
        server_hostname="smtp.test.local",
        start_time_iso="2026-09-25T12:00:00Z",
        duration_seconds=0.5,
        packets_count=10,
        starttls=STARTTLSStateDTO(advertised=True, requested=True, accepted=True, upgrade_successful=True, state="UPGRADED"),
        tls=TLSHandshakeDTO(
            negotiated_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            forward_secrecy_pfs=True,
            pfs_status="PFS_SUPPORTED",
            certificate_visibility="UNOBSERVED"
        ),
        capture_health=CaptureHealthDTO(score=100, grade="EXCELLENT", syn_observed=True, fin_rst_observed=True, total_packets=10, retransmissions_count=0, retransmission_rate=0.0, deduction_reasons=[]),
        evidence_confidence=EvidenceConfidenceDTO(score=95, level="HIGH", handshake_observable=True, version_verifiable=True, cipher_identifiable=True, key_exchange_observable=True, confidence_factors=[]),
        security_assessment=assessment,
        evidence_frames=[EvidenceFrameDTO(frame=1, time_epoch=1727258400.0, protocol="SMTP", summary="STARTTLS offer")],
    )

    return AnalysisDetailResponse(
        analysis_id=analysis_id,
        file_name="test_sample.pcap",
        file_size_bytes=1024,
        analysis_time_utc="2026-09-25T12:00:00Z",
        tshark_version="TShark 4.0.0",
        total_packets_extracted=10,
        raw_capture_packets_total=10,
        email_sessions_found=1,
        sessions=[session],
        multi_session_summary=None,
        correlated_incidents=[],
        unhandled_transports=[],
        dns_enrichment=None,
    )


class TestManifestVersioning(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sms_manifest_test_")
        self.db_path = os.path.join(self.temp_dir, "test_manifest.db")
        set_custom_db_path(self.db_path)
        init_db(self.db_path)
        # Clear CustodyService in-memory records
        CustodyService._records.clear()
        self.client = TestClient(app)

    def tearDown(self):
        CustodyService._records.clear()
        set_custom_db_path(None)
        if os.path.exists(self.temp_dir):
            try:
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass

    # 1. Analysis finalization creates manifest version 1
    def test_01_analysis_finalization_creates_manifest_version_1(self):
        aid = "analysis_test_v1_001"
        pcap_bytes = b"\xd4\xc3\xb2\xa1" + b"\x00" * 60
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_start(aid)
        CustodyService.record_analysis_completion(aid, dto)

        versions = ForensicRepository.get_manifest_versions(aid, db_path=self.db_path)
        self.assertEqual(len(versions), 1)
        v1 = versions[0]
        self.assertEqual(v1["version_number"], 1)
        self.assertEqual(v1["manifest_type"], "ANALYSIS_FINALIZATION_MANIFEST")
        self.assertEqual(v1["previous_manifest_sha256"], GENESIS_PREV_HASH)
        self.assertTrue(v1["sealed"])

        # Check payload does not contain mutable report_pdf_hash
        m_dict = v1["manifest_dict"]
        self.assertNotIn("report_pdf_hash", m_dict)
        self.assertEqual(m_dict["linked_report_artifacts"], [])

    # 2. V1 is sealed and immutable
    def test_02_v1_is_sealed_and_immutable(self):
        aid = "analysis_test_v1_002"
        pcap_bytes = b"test bytes"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        v1 = ForensicRepository.get_manifest_version(aid, 1, db_path=self.db_path)
        self.assertIsNotNone(v1)
        self.assertTrue(v1["sealed"])

        # Attempting to re-save / overwrite version 1 must raise ImmutableRecordError
        with self.assertRaises(ImmutableRecordError):
            ForensicRepository.save_manifest_version(
                manifest_version_id="cmv_duplicate_v1",
                analysis_id=aid,
                version_number=1,
                manifest_type="ANALYSIS_FINALIZATION_MANIFEST",
                previous_manifest_sha256=GENESIS_PREV_HASH,
                manifest_json="{}",
                manifest_sha256="0"*64,
                db_path=self.db_path,
            )

    # 3. Generating first report creates report artifact v1
    def test_03_generating_first_report_creates_report_artifact_v1(self):
        aid = "analysis_test_rep_003"
        pcap_bytes = b"sample pcap bytes 3"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        pdf_bytes = b"%PDF-1.4 sample pdf content version 1"
        pdf_sha = CustodyService.record_report_generation(aid, pdf_bytes)

        reports = ForensicRepository.get_report_artifacts(aid, db_path=self.db_path)
        self.assertEqual(len(reports), 1)
        rep1 = reports[0]
        self.assertEqual(rep1["report_version"], 1)
        self.assertEqual(rep1["artifact_sha256"], pdf_sha)
        self.assertEqual(rep1["status"], "GENERATED")

    # 4. Generating first report creates manifest version 2
    def test_04_generating_first_report_creates_manifest_version_2(self):
        aid = "analysis_test_rep_004"
        pcap_bytes = b"sample pcap bytes 4"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        pdf_bytes = b"%PDF-1.4 report v1"
        pdf_sha = CustodyService.record_report_generation(aid, pdf_bytes)

        versions = ForensicRepository.get_manifest_versions(aid, db_path=self.db_path)
        self.assertEqual(len(versions), 2)
        v2 = versions[1]
        self.assertEqual(v2["version_number"], 2)
        self.assertEqual(v2["manifest_type"], "REPORT_LINKAGE_MANIFEST")
        self.assertEqual(len(v2["linked_report_artifacts"]), 1)
        self.assertEqual(v2["linked_report_artifacts"][0]["artifact_sha256"], pdf_sha)

    # 5. Manifest v1 JSON remains byte-for-byte unchanged
    def test_05_manifest_v1_json_remains_byte_for_byte_unchanged(self):
        aid = "analysis_test_v1_immut_005"
        pcap_bytes = b"sample bytes 5"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        v1_before = ForensicRepository.get_manifest_version(aid, 1, db_path=self.db_path)
        json_before = v1_before["manifest_json"]

        # Generate report
        CustodyService.record_report_generation(aid, b"%PDF-1.4 report content")

        v1_after = ForensicRepository.get_manifest_version(aid, 1, db_path=self.db_path)
        json_after = v1_after["manifest_json"]

        self.assertEqual(json_before, json_after)

    # 6. Manifest v1 hash remains unchanged
    def test_06_manifest_v1_hash_remains_unchanged(self):
        aid = "analysis_test_v1_immut_006"
        pcap_bytes = b"sample bytes 6"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        v1_before = ForensicRepository.get_manifest_version(aid, 1, db_path=self.db_path)
        hash_before = v1_before["manifest_sha256"]

        # Generate multiple reports
        CustodyService.record_report_generation(aid, b"%PDF-1.4 report v1")
        CustodyService.record_report_generation(aid, b"%PDF-1.4 report v2")

        v1_after = ForensicRepository.get_manifest_version(aid, 1, db_path=self.db_path)
        self.assertEqual(hash_before, v1_after["manifest_sha256"])

    # 7. v2.previous_manifest_sha256 == v1.manifest_sha256
    def test_07_v2_previous_manifest_sha256_equals_v1_hash(self):
        aid = "analysis_test_chain_007"
        pcap_bytes = b"sample bytes 7"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)
        CustodyService.record_report_generation(aid, b"%PDF-1.4 report v1")

        v1 = ForensicRepository.get_manifest_version(aid, 1, db_path=self.db_path)
        v2 = ForensicRepository.get_manifest_version(aid, 2, db_path=self.db_path)

        self.assertEqual(v2["previous_manifest_sha256"], v1["manifest_sha256"])

    # 8. Report regeneration creates report artifact v2
    def test_08_report_regeneration_creates_report_artifact_v2(self):
        aid = "analysis_test_regen_008"
        pcap_bytes = b"sample bytes 8"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        CustodyService.record_report_generation(aid, b"%PDF-1.4 report v1 bytes")
        pdf2_sha = CustodyService.record_report_generation(aid, b"%PDF-1.4 report v2 bytes regenerated")

        reports = ForensicRepository.get_report_artifacts(aid, db_path=self.db_path)
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0]["report_version"], 1)
        self.assertEqual(reports[0]["status"], "SUPERSEDED")
        self.assertEqual(reports[1]["report_version"], 2)
        self.assertEqual(reports[1]["status"], "GENERATED")
        self.assertEqual(reports[1]["artifact_sha256"], pdf2_sha)

    # 9. Report regeneration creates manifest version 3
    def test_09_report_regeneration_creates_manifest_version_3(self):
        aid = "analysis_test_regen_009"
        pcap_bytes = b"sample bytes 9"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)
        CustodyService.record_report_generation(aid, b"%PDF-1.4 report v1")
        CustodyService.record_report_generation(aid, b"%PDF-1.4 report v2")

        versions = ForensicRepository.get_manifest_versions(aid, db_path=self.db_path)
        self.assertEqual(len(versions), 3)
        self.assertEqual(versions[0]["version_number"], 1)
        self.assertEqual(versions[1]["version_number"], 2)
        self.assertEqual(versions[2]["version_number"], 3)
        self.assertEqual(versions[2]["previous_manifest_sha256"], versions[1]["manifest_sha256"])

    # 10. Old report artifact/hash remains preserved
    def test_10_old_report_artifact_and_hash_remains_preserved(self):
        aid = "analysis_test_preserv_010"
        pcap_bytes = b"sample bytes 10"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        sha1 = CustodyService.record_report_generation(aid, b"%PDF-1.4 report first edition")
        CustodyService.record_report_generation(aid, b"%PDF-1.4 report second edition")

        reports = ForensicRepository.get_report_artifacts(aid, db_path=self.db_path)
        self.assertEqual(reports[0]["artifact_sha256"], sha1)

    # 11. Old manifest versions remain preserved
    def test_11_old_manifest_versions_remain_preserved(self):
        aid = "analysis_test_preserv_011"
        pcap_bytes = b"sample bytes 11"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)
        CustodyService.record_report_generation(aid, b"%PDF-1.4 v1")
        CustodyService.record_report_generation(aid, b"%PDF-1.4 v2")
        CustodyService.record_report_generation(aid, b"%PDF-1.4 v3")

        versions = ForensicRepository.get_manifest_versions(aid, db_path=self.db_path)
        self.assertEqual(len(versions), 4)

    # 12. Tampering manifest JSON fails verification
    def test_12_tampering_manifest_json_fails_verification(self):
        aid = "analysis_test_tamper_012"
        pcap_bytes = b"sample bytes 12"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        # Tamper manifest v1 json directly in DB
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE custody_manifest_versions
            SET manifest_json = '{"analysis_id": "analysis_test_tamper_012", "findings_count": 999}'
            WHERE analysis_id = ? AND version_number = 1
            """,
            (aid,)
        )
        conn.commit()
        conn.close()

        res = ForensicRepository.verify_manifest_chain(aid, db_path=self.db_path)
        self.assertEqual(res["overall_status"], "INTEGRITY_FAILED")
        self.assertIn("mismatch", res["details"].lower())

    # 13. Tampering previous_manifest_sha256 breaks chain
    def test_13_tampering_previous_manifest_sha256_breaks_chain(self):
        aid = "analysis_test_tamper_013"
        pcap_bytes = b"sample bytes 13"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)
        CustodyService.record_report_generation(aid, b"%PDF-1.4 v1")

        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE custody_manifest_versions
            SET previous_manifest_sha256 = 'f' * 64
            WHERE analysis_id = ? AND version_number = 2
            """,
            (aid,)
        )
        conn.commit()
        conn.close()

        res = ForensicRepository.verify_manifest_chain(aid, db_path=self.db_path)
        self.assertEqual(res["overall_status"], "INTEGRITY_FAILED")
        self.assertIn("link broken", res["details"].lower())

    # 14. Tampering report bytes causes INTEGRITY_FAILED
    def test_14_tampering_report_bytes_causes_integrity_failed(self):
        aid = "analysis_test_tamper_014"
        pcap_bytes = b"sample bytes 14"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)
        CustodyService.record_report_generation(aid, b"%PDF-1.4 valid report bytes")

        # Mutate raw_bytes of report artifact in DB
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE report_artifacts
            SET raw_bytes = ?
            WHERE analysis_id = ? AND report_version = 1
            """,
            (b"%PDF-1.4 TAMPERED BYTES", aid)
        )
        conn.commit()
        conn.close()

        res = ForensicRepository.verify_manifest_chain(aid, db_path=self.db_path)
        self.assertEqual(res["overall_status"], "INTEGRITY_FAILED")
        self.assertIn("tampered", res["details"].lower())

    # 15. Missing report artifact returns INCOMPLETE
    def test_15_missing_report_artifact_returns_incomplete(self):
        aid = "analysis_test_tamper_015"
        pcap_bytes = b"sample bytes 15"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)
        CustodyService.record_report_generation(aid, b"%PDF-1.4 valid report bytes")

        # Delete report artifact row from DB
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM report_artifacts WHERE analysis_id = ?", (aid,))
        conn.commit()
        conn.close()

        res = ForensicRepository.verify_manifest_chain(aid, db_path=self.db_path)
        self.assertEqual(res["overall_status"], "INCOMPLETE")
        self.assertIn("not found", res["details"].lower())

    # 16. capture_sha256 unchanged across all manifest versions
    def test_16_capture_sha256_unchanged_across_all_versions(self):
        aid = "analysis_test_cap_016"
        pcap_bytes = b"immutable pcap capture 16"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)
        CustodyService.record_report_generation(aid, b"%PDF-1.4 v1")
        CustodyService.record_report_generation(aid, b"%PDF-1.4 v2")

        versions = ForensicRepository.get_manifest_versions(aid, db_path=self.db_path)
        expected_cap_sha = compute_sha256(pcap_bytes)
        for v in versions:
            self.assertEqual(v["manifest_dict"]["capture_sha256"], expected_cap_sha)

    # 17. observed_result_sha256 unchanged across same-analysis versions
    def test_17_observed_result_sha256_unchanged_across_versions(self):
        aid = "analysis_test_obs_017"
        pcap_bytes = b"immutable pcap 17"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)
        CustodyService.record_report_generation(aid, b"%PDF-1.4 v1")
        CustodyService.record_report_generation(aid, b"%PDF-1.4 v2")

        versions = ForensicRepository.get_manifest_versions(aid, db_path=self.db_path)
        v1_obs = versions[0]["manifest_dict"]["observed_result_sha256"]
        for v in versions:
            self.assertEqual(v["manifest_dict"]["observed_result_sha256"], v1_obs)

    # 18. Actor metadata frozen in historical manifest version
    def test_18_actor_metadata_frozen_in_historical_manifest(self):
        aid = "analysis_test_actor_018"
        pcap_bytes = b"immutable pcap 18"
        dto = _build_test_analysis_dto(aid)

        analyst_actor = ActorContext.local_declared("analyst-jones", "Agent Jones")
        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes, actor=analyst_actor)
        CustodyService.record_analysis_completion(aid, dto, actor=analyst_actor)

        v1 = ForensicRepository.get_manifest_version(aid, 1, db_path=self.db_path)
        self.assertEqual(v1["created_by_actor_id"], "analyst-jones")
        self.assertEqual(v1["created_by_actor_display_name"], "Agent Jones")
        self.assertEqual(v1["actor_identity_source"], IDENTITY_SOURCE_LOCAL_DECLARED)
        self.assertEqual(v1["actor_attribution_status"], ATTRIBUTION_STATUS_ATTRIBUTED)

    # 19. Analyst profile update does not alter old manifest actor data
    def test_19_analyst_profile_update_does_not_alter_old_manifest_actor(self):
        aid = "analysis_test_actor_019"
        pcap_bytes = b"immutable pcap 19"
        dto = _build_test_analysis_dto(aid)

        ForensicRepository.register_analyst("analyst-smith", "Agent Smith", db_path=self.db_path)
        actor = ActorContext.local_declared("analyst-smith", "Agent Smith")

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes, actor=actor)
        CustodyService.record_analysis_completion(aid, dto, actor=actor)

        # Update analyst profile in registry
        ForensicRepository.update_analyst_profile("analyst-smith", display_name="Senior Director Smith", db_path=self.db_path)

        # Old manifest v1 must still have original frozen actor display name
        v1 = ForensicRepository.get_manifest_version(aid, 1, db_path=self.db_path)
        self.assertEqual(v1["created_by_actor_display_name"], "Agent Smith")

    # 20. Sealed manifest update attempt raises ImmutableRecordError or equivalent
    def test_20_sealed_manifest_update_attempt_raises_immutable_error(self):
        aid = "analysis_test_seal_020"
        pcap_bytes = b"immutable pcap 20"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        with self.assertRaises(ImmutableRecordError):
            ForensicRepository.save_manifest_version(
                manifest_version_id="cmv_attempt_overwrite",
                analysis_id=aid,
                version_number=1,
                manifest_type="ANALYSIS_FINALIZATION_MANIFEST",
                previous_manifest_sha256=GENESIS_PREV_HASH,
                manifest_json="{}",
                manifest_sha256="0"*64,
                db_path=self.db_path,
            )

    # 21. Read-only verification appends zero new custody events
    def test_21_read_only_verification_appends_zero_custody_events(self):
        aid = "analysis_test_readonly_021"
        pcap_bytes = b"immutable pcap 21"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        rec_before = CustodyService.get_record(aid)
        event_count_before = len(rec_before.events)

        # Run read-only integrity verifications
        CustodyService.verify_integrity(aid, record_verification_event=False)
        ForensicRepository.verify_manifest_chain(aid, db_path=self.db_path)

        rec_after = CustodyService.get_record(aid)
        self.assertEqual(len(rec_after.events), event_count_before)

    # 22. Report + manifest transaction rollback on injected failure
    def test_22_report_and_manifest_transaction_rollback_on_injected_failure(self):
        aid = "analysis_test_rollback_022"
        pcap_bytes = b"immutable pcap 22"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)

        v1 = ForensicRepository.get_manifest_version(aid, 1, db_path=self.db_path)
        rep_art = {
            "report_artifact_id": "rep_fail_test",
            "analysis_id": aid,
            "report_type": "PDF",
            "report_version": 1,
            "filename": "fail_test.pdf",
            "media_type": "application/pdf",
            "artifact_sha256": "0"*64,
            "artifact_size_bytes": 100,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_manifest_version_id": v1["manifest_version_id"],
        }
        man_ver = {
            "manifest_version_id": "cmv_fail_test",
            "analysis_id": aid,
            "version_number": 2,
            "manifest_type": "REPORT_LINKAGE_MANIFEST",
            "parent_manifest_version_id": v1["manifest_version_id"],
            "previous_manifest_sha256": v1["manifest_sha256"],
            "manifest_json": "{}",
            "manifest_sha256": "0"*64,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        with self.assertRaises(RuntimeError):
            ForensicRepository.save_report_artifact_and_manifest_version(
                report_artifact=rep_art,
                manifest_version=man_ver,
                db_path=self.db_path,
                inject_failure_after_artifact=True,
            )

        # Verify no orphaned report artifact row exists
        reports = ForensicRepository.get_report_artifacts(aid, db_path=self.db_path)
        self.assertEqual(len(reports), 0)
        # Verify no orphaned manifest v2 exists
        versions = ForensicRepository.get_manifest_versions(aid, db_path=self.db_path)
        self.assertEqual(len(versions), 1)

    # 23. Legacy single-manifest custody record remains readable
    def test_23_legacy_single_manifest_custody_record_remains_readable(self):
        aid = "analysis_legacy_023"
        now_iso = datetime.now(timezone.utc).isoformat()
        manifest_payload = {
            "analysis_id": aid,
            "findings_count": 2,
            "raw_pcap_frame_count": 10,
        }
        m_bytes = canonical_json_bytes(manifest_payload)
        m_hash = compute_sha256(m_bytes)

        # Directly insert a legacy custody record without custody_manifest_versions row
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO custody_records (
                analysis_id, filename, file_size, capture_sha256, ingestion_timestamp,
                manifest_dict_json, manifest_hash, is_sealed, overall_status,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'VERIFIED', ?, ?)
            """,
            (aid, "legacy.pcap", 100, "a"*64, now_iso, json.dumps(manifest_payload), m_hash, now_iso, now_iso)
        )
        conn.commit()
        conn.close()

        rec = ForensicRepository.get_custody_record(aid, db_path=self.db_path)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["manifest_hash"], m_hash)

        # Manifest chain verification should gracefully verify legacy record
        res = ForensicRepository.verify_manifest_chain(aid, db_path=self.db_path)
        self.assertEqual(res["overall_status"], "VERIFIED")

    # 24. Legacy manifest hash is not silently recomputed
    def test_24_legacy_manifest_hash_is_not_silently_recomputed(self):
        aid = "analysis_legacy_024"
        now_iso = datetime.now(timezone.utc).isoformat()
        original_hash = "1234567890abcdef" * 4

        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO custody_records (
                analysis_id, filename, file_size, capture_sha256, ingestion_timestamp,
                manifest_dict_json, manifest_hash, is_sealed, overall_status,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'VERIFIED', ?, ?)
            """,
            (aid, "legacy24.pcap", 100, "b"*64, now_iso, '{"legacy": true}', original_hash, now_iso, now_iso)
        )
        conn.commit()
        conn.close()

        rec = ForensicRepository.get_custody_record(aid, db_path=self.db_path)
        self.assertEqual(rec["manifest_hash"], original_hash)

    # 25. Legacy custody-event hash remains verifiable
    def test_25_legacy_custody_event_hash_remains_verifiable(self):
        aid = "analysis_legacy_evt_025"
        evt_id = "evt_legacy_01"
        now_iso = datetime.now(timezone.utc).isoformat()
        cap_sha = "c" * 64

        # Compute legacy pipe hash
        leg_hash = compute_legacy_event_hash(
            event_id=evt_id,
            analysis_id=aid,
            timestamp_utc=now_iso,
            event_type="CAPTURE_INGESTED",
            artifact_hash=cap_sha,
            previous_event_hash=GENESIS_PREV_HASH,
        )

        legacy_evt = CustodyEventDTO(
            event_id=evt_id,
            analysis_id=aid,
            timestamp_utc=now_iso,
            event_type="CAPTURE_INGESTED",
            artifact_hash=cap_sha,
            previous_event_hash=GENESIS_PREV_HASH,
            current_event_hash=leg_hash,
            details="Legacy capture ingested",
            hash_format_version="LEGACY_PIPE_V1"
        )

        rec = CustodyRecord(aid, "legacy.pcap", b"raw bytes", initial_events=[legacy_evt])
        CustodyService._records[aid] = rec
        CustodyService._persist_record(rec)

        res = CustodyService.verify_integrity(aid)
        self.assertEqual(res.overall_status, "VERIFIED")

    # 26. New custody-event details tampering is detected
    def test_26_new_custody_event_details_tampering_is_detected(self):
        aid = "analysis_evt_tamper_026"
        pcap_bytes = b"pcap 26"
        CustodyService.get_or_create_record(aid, "test26.pcap", pcap_bytes)

        rec = CustodyService.get_record(aid)
        # Tamper details in first event
        rec.events[0].details = "Tampered detail string that was never in original hash"

        res = CustodyService.verify_integrity(aid)
        self.assertEqual(res.overall_status, "FAILED")
        self.assertIn("tampered content detected", res.verification_details.lower())

    # 27. New custody-event actor tampering is detected
    def test_27_new_custody_event_actor_tampering_is_detected(self):
        aid = "analysis_evt_actor_027"
        pcap_bytes = b"pcap 27"
        actor = ActorContext.local_declared("analyst-original", "Original Analyst")
        CustodyService.get_or_create_record(aid, "test27.pcap", pcap_bytes, actor=actor)

        rec = CustodyService.get_record(aid)
        # Tamper actor_id in first event
        rec.events[0].actor_id = "analyst-imposter"

        res = CustodyService.verify_integrity(aid)
        self.assertEqual(res.overall_status, "FAILED")
        self.assertIn("tampered content detected", res.verification_details.lower())

    # 28. Generated report files remain Git-ignored
    def test_28_generated_report_files_remain_git_ignored(self):
        gitignore_path = os.path.join(BACKEND_DIR, "..", ".gitignore")
        self.assertTrue(os.path.isfile(gitignore_path))
        with open(gitignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("*.pdf", content)
        self.assertIn("reports/", content)

    # 29. REST API endpoints for manifest versions and reports
    def test_29_manifest_and_report_rest_api_endpoints(self):
        aid = "analysis_api_029"
        pcap_bytes = b"api test pcap bytes"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "test.pcap", pcap_bytes)
        CustodyService.record_analysis_completion(aid, dto)
        CustodyService.record_report_generation(aid, b"%PDF-1.4 report v1")
        CustodyService.record_report_generation(aid, b"%PDF-1.4 report v2")

        # Mock AnalysisService.get_analysis
        AnalysisService._cache[aid] = (dto, [])

        # 1. GET /api/v1/analyses/{aid}/manifests
        res = self.client.get(f"/api/v1/analyses/{aid}/manifests")
        self.assertEqual(res.status_code, 200)
        manifests_data = res.json()
        self.assertEqual(len(manifests_data), 3)

        # 2. GET /api/v1/analyses/{aid}/manifests/verify
        res_v = self.client.get(f"/api/v1/analyses/{aid}/manifests/verify")
        self.assertEqual(res_v.status_code, 200)
        verify_data = res_v.json()
        self.assertEqual(verify_data["overall_status"], "VERIFIED")
        self.assertEqual(verify_data["versions_count"], 3)

        # 3. GET /api/v1/analyses/{aid}/manifests/1
        res_m1 = self.client.get(f"/api/v1/analyses/{aid}/manifests/1")
        self.assertEqual(res_m1.status_code, 200)
        self.assertEqual(res_m1.json()["version_number"], 1)

        # 4. GET /api/v1/analyses/{aid}/reports
        res_r = self.client.get(f"/api/v1/analyses/{aid}/reports")
        self.assertEqual(res_r.status_code, 200)
        reports_data = res_r.json()
        self.assertEqual(len(reports_data), 2)

        # 5. GET /api/v1/analyses/{aid}/reports/{report_artifact_id}?download=true
        rep1_id = reports_data[0]["report_artifact_id"]
        res_dl = self.client.get(f"/api/v1/analyses/{aid}/reports/{rep1_id}?download=true")
        self.assertEqual(res_dl.status_code, 200)
        self.assertEqual(res_dl.headers.get("content-type"), "application/pdf")
        self.assertTrue(res_dl.content.startswith(b"%PDF-1.4"))

    # 30. Full workflow: analysis -> v1 -> report v1 -> v2 -> report v2 -> v3
    def test_30_full_workflow_version_progression(self):
        aid = "analysis_full_030"
        pcap_bytes = b"full workflow pcap"
        dto = _build_test_analysis_dto(aid)

        CustodyService.get_or_create_record(aid, "full.pcap", pcap_bytes)
        CustodyService.record_analysis_start(aid)
        CustodyService.record_analysis_completion(aid, dto)

        # Check v1
        v1 = ForensicRepository.get_manifest_version(aid, 1, db_path=self.db_path)
        self.assertEqual(v1["version_number"], 1)
        self.assertEqual(v1["manifest_type"], "ANALYSIS_FINALIZATION_MANIFEST")

        # Report 1
        pdf1 = b"%PDF-1.4 report v1"
        CustodyService.record_report_generation(aid, pdf1)

        v2 = ForensicRepository.get_manifest_version(aid, 2, db_path=self.db_path)
        self.assertEqual(v2["version_number"], 2)
        self.assertEqual(v2["previous_manifest_sha256"], v1["manifest_sha256"])

        # Report 2 (Regeneration)
        pdf2 = b"%PDF-1.4 report v2 regenerated with changes"
        CustodyService.record_report_generation(aid, pdf2)

        v3 = ForensicRepository.get_manifest_version(aid, 3, db_path=self.db_path)
        self.assertEqual(v3["version_number"], 3)
        self.assertEqual(v3["previous_manifest_sha256"], v2["manifest_sha256"])

        # Complete chain verification
        chain_res = ForensicRepository.verify_manifest_chain(aid, db_path=self.db_path)
        self.assertEqual(chain_res["overall_status"], "VERIFIED")
        self.assertEqual(chain_res["versions_count"], 3)


if __name__ == "__main__":
    unittest.main()

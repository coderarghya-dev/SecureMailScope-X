"""
SecureMailScope X - Notarization Provider Abstraction & Local Proof Test Suite (Phase 15)
Deterministic tests for local notarization proof creation, provider abstraction,
manifest linkage, hash chaining, tamper detection, actor attribution, and zero-side-effect verification.
"""

import os
import sys
import tempfile
import unittest
import base64
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from unittest.mock import patch

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.db.database import init_db, get_db_connection, set_custom_db_path
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
)
from app.db.repository import (
    ForensicRepository,
    canonical_json_bytes,
    canonical_json_str,
    compute_sha256,
    ImmutableRecordError,
    IntegrityVerificationError,
)
from app.services.custody_service import CustodyService, GENESIS_PREV_HASH
from app.services.signature_service import SignatureService
from app.services.notarization_service import (
    NotarizationService,
    LocalOnlyNotarizationProvider,
    ExternalNotarizationProvider,
    NotarizationPrerequisiteError,
    ProviderUnavailableError,
    UnsupportedProviderError,
    build_local_proof_payload,
    NOTARIZATION_MODE_LOCAL_ONLY,
    NOTARIZATION_MODE_EXTERNAL_PROVIDER,
    STATUS_LOCAL_PROOF_CREATED,
    VERIFY_STATUS_VERIFIED_LOCAL_PROOF,
    VERIFY_STATUS_INTEGRITY_FAILED,
    VERIFY_STATUS_SIGNATURE_INVALID,
    VERIFY_STATUS_REPORT_INTEGRITY_FAILED,
    VERIFY_STATUS_MANIFEST_INTEGRITY_FAILED,
    VERIFY_STATUS_INCOMPLETE,
    VERIFY_STATUS_UNSUPPORTED_PROVIDER,
)
from app.api.v1.endpoints.analyze import router
from fastapi.testclient import TestClient
from fastapi import FastAPI


class TestNotarization(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary test directory and SQLite database
        self.test_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.test_dir.name, "test_securemailscope.db")
        set_custom_db_path(self.db_path)
        init_db(self.db_path)

        # Clear in-memory service records
        CustodyService._records.clear()

        # Clean environment variables
        self.orig_signing_key_pem = os.environ.get("SMS_SIGNING_PRIVATE_KEY_PEM")
        self.orig_notz_provider = os.environ.get("SMS_NOTARIZATION_PROVIDER")
        self.orig_notz_url = os.environ.get("SMS_NOTARIZATION_API_URL")
        self.orig_notz_key = os.environ.get("SMS_NOTARIZATION_API_KEY")

        if "SMS_NOTARIZATION_PROVIDER" in os.environ:
            del os.environ["SMS_NOTARIZATION_PROVIDER"]
        if "SMS_NOTARIZATION_API_URL" in os.environ:
            del os.environ["SMS_NOTARIZATION_API_URL"]
        if "SMS_NOTARIZATION_API_KEY" in os.environ:
            del os.environ["SMS_NOTARIZATION_API_KEY"]

        # Generate test signing key
        self.ed25519_key = ed25519.Ed25519PrivateKey.generate()
        self.ed25519_pem = self.ed25519_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")
        os.environ["SMS_SIGNING_PRIVATE_KEY_PEM"] = self.ed25519_pem

        # Setup FastAPI TestClient
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        self.client = TestClient(app)

    def tearDown(self):
        CustodyService._records.clear()
        set_custom_db_path(None)

        if self.orig_signing_key_pem is not None:
            os.environ["SMS_SIGNING_PRIVATE_KEY_PEM"] = self.orig_signing_key_pem
        elif "SMS_SIGNING_PRIVATE_KEY_PEM" in os.environ:
            del os.environ["SMS_SIGNING_PRIVATE_KEY_PEM"]

        if self.orig_notz_provider is not None:
            os.environ["SMS_NOTARIZATION_PROVIDER"] = self.orig_notz_provider
        elif "SMS_NOTARIZATION_PROVIDER" in os.environ:
            del os.environ["SMS_NOTARIZATION_PROVIDER"]

        if self.orig_notz_url is not None:
            os.environ["SMS_NOTARIZATION_API_URL"] = self.orig_notz_url
        elif "SMS_NOTARIZATION_API_URL" in os.environ:
            del os.environ["SMS_NOTARIZATION_API_URL"]

        if self.orig_notz_key is not None:
            os.environ["SMS_NOTARIZATION_API_KEY"] = self.orig_notz_key
        elif "SMS_NOTARIZATION_API_KEY" in os.environ:
            del os.environ["SMS_NOTARIZATION_API_KEY"]

        self.test_dir.cleanup()

    def _create_sample_signed_report(
        self,
        analysis_id: str = "analysis_notz_test_01",
        actor: Optional[ActorContext] = None
    ) -> Dict[str, Any]:
        """Helper to create analysis, manifest v1, report artifact v1 -> manifest v2, and signature -> manifest v3."""
        raw_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32
        act = actor or ActorContext.local_declared("analyst_test_01", "Forensic Specialist Alice")

        # 1. Ingest custody record
        rec = CustodyService.get_or_create_record(
            analysis_id=analysis_id,
            filename="smtp_capture.pcap",
            content_bytes=raw_pcap,
            actor=act,
        )

        # 2. Persist analysis
        finding = SecurityFindingDTO(
            id="FINDING-TLS-1",
            title="Plaintext Fallback Risk",
            severity="HIGH",
            category="AUTHENTICATION",
            description="STARTTLS not enforced on port 25.",
            evidence_frames=[1, 2],
            recommendation="Require TLS 1.3.",
        )
        session = SessionDetailDTO(
            session_id="stream_0_192.168.1.10_587",
            stream_index=0,
            protocol="SMTP",
            security_mode="STARTTLS",
            client="192.168.1.10:50000",
            server="192.168.1.1:587",
            duration_seconds=1.5,
            packets_count=10,
            starttls=STARTTLSStateDTO(advertised=True, requested=True, accepted=True, upgrade_successful=True),
            tls=TLSHandshakeDTO(
                negotiated_version="TLS 1.3",
                tls_version="TLS 1.3",
                cipher_name="TLS_AES_256_GCM_SHA384",
                pfs_status="FORWARD_SECRECY_ACTIVE",
                certificate_visibility="PRESENT",
            ),
            capture_health=CaptureHealthDTO(
                score=100,
                grade="A",
                syn_observed=True,
                fin_rst_observed=True,
                total_packets=10,
                retransmissions_count=0,
                retransmission_rate=0.0,
                deduction_reasons=[],
            ),
            evidence_confidence=EvidenceConfidenceDTO(
                score=100,
                level="HIGH",
                handshake_observable=True,
                version_verifiable=True,
                cipher_identifiable=True,
                key_exchange_observable=True,
            ),
            security_assessment=SecurityAssessmentDTO(
                grade="A",
                grade_rationale="Nominal",
                post_quantum_ready=False,
                post_quantum_summary="Classic crypto",
                findings_summary=FindingsSummaryDTO(high=1),
                findings=[finding],
            ),
        )
        detail = AnalysisDetailResponse(
            analysis_id=analysis_id,
            file_name="smtp_capture.pcap",
            file_size_bytes=len(raw_pcap),
            analysis_time_utc="2026-09-25T12:00:00Z",
            tshark_version="TShark 4.6.0",
            total_packets_extracted=10,
            raw_capture_packets_total=10,
            email_sessions_found=1,
            sessions=[session],
            multi_session_summary=None,
            correlated_incidents=[],
            unhandled_transports=[],
            dns_enrichment=None,
        )
        ForensicRepository.save_analysis(detail, actor=act, db_path=self.db_path)

        # 3. Seal Manifest Version 1 (ANALYSIS_FINALIZATION_MANIFEST)
        CustodyService.record_analysis_completion(analysis_id, detail, actor=act)

        # 4. Generate Report Artifact v1 -> Manifest Version 2 (REPORT_LINKAGE_MANIFEST)
        fake_pdf_bytes = b"%PDF-1.4 forensic report test artifact content"
        CustodyService.record_report_generation(analysis_id, fake_pdf_bytes, actor=act)
        reports = ForensicRepository.get_report_artifacts(analysis_id, db_path=self.db_path)
        report_art = reports[0]

        # 5. Sign Report Artifact v1 -> Manifest Version 3 (SIGNATURE_LINKAGE_MANIFEST)
        sig_rec = SignatureService.sign_report_artifact(
            analysis_id=analysis_id,
            report_artifact_id=report_art["report_artifact_id"],
            actor=act,
            db_path=self.db_path,
        )

        return {
            "analysis_id": analysis_id,
            "report_artifact": report_art,
            "signature": sig_rec,
            "actor": act,
        }

    # -----------------------------------------------------------------------
    # Core Tests
    # -----------------------------------------------------------------------
    def test_01_local_only_proof_creation(self):
        """1. LOCAL_ONLY proof can be created from valid signed report."""
        setup = self._create_sample_signed_report("test_analysis_01")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
            signature_id=setup["signature"]["signature_id"],
            mode=NOTARIZATION_MODE_LOCAL_ONLY,
            actor=setup["actor"],
        )

        self.assertEqual(proof["notarization_mode"], "LOCAL_ONLY")
        self.assertEqual(proof["status"], "LOCAL_PROOF_CREATED")
        self.assertIsNotNone(proof["local_proof_sha256"])
        self.assertEqual(len(proof["local_proof_sha256"]), 64)
        self.assertIsNone(proof["provider_name"])
        self.assertIsNone(proof["provider_reference"])
        self.assertIsNone(proof["provider_proof_json"])
        self.assertIsNone(proof["confirmed_at"])

    def test_02_local_only_makes_zero_outbound_network_calls(self):
        """2. LOCAL_ONLY proof makes zero outbound network calls."""
        setup = self._create_sample_signed_report("test_analysis_02")

        with patch("socket.socket") as mock_socket, \
             patch("urllib.request.urlopen") as mock_urlopen:
            proof = NotarizationService.create_notarization_proof(
                analysis_id=setup["analysis_id"],
                report_artifact_id=setup["report_artifact"]["report_artifact_id"],
                signature_id=setup["signature"]["signature_id"],
                mode=NOTARIZATION_MODE_LOCAL_ONLY,
            )
            mock_socket.assert_not_called()
            mock_urlopen.assert_not_called()
            self.assertEqual(proof["status"], "LOCAL_PROOF_CREATED")

    def test_03_local_proof_sha256_deterministic(self):
        """3. local_proof_sha256 is deterministic for identical payloads."""
        payload1 = build_local_proof_payload(
            analysis_id="analysis_123",
            report_artifact_id="rep_123",
            report_artifact_sha256="aaa" * 21 + "a",
            signature_id="sig_123",
            signature_algorithm="ED25519",
            signature_value_sha256="bbb" * 21 + "b",
            public_key_fingerprint_sha256="ccc" * 21 + "c",
            manifest_version_id="cmv_123",
            manifest_sha256="ddd" * 21 + "d",
        )
        payload2 = build_local_proof_payload(
            analysis_id="analysis_123",
            report_artifact_id="rep_123",
            report_artifact_sha256="aaa" * 21 + "a",
            signature_id="sig_123",
            signature_algorithm="ED25519",
            signature_value_sha256="bbb" * 21 + "b",
            public_key_fingerprint_sha256="ccc" * 21 + "c",
            manifest_version_id="cmv_123",
            manifest_sha256="ddd" * 21 + "d",
        )
        hash1 = compute_sha256(canonical_json_bytes(payload1))
        hash2 = compute_sha256(canonical_json_bytes(payload2))
        self.assertEqual(hash1, hash2)

    def test_04_local_proof_verifies_successfully(self):
        """4. Local proof verifies successfully with VERIFIED_LOCAL_PROOF status."""
        setup = self._create_sample_signed_report("test_analysis_04")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
            signature_id=setup["signature"]["signature_id"],
        )

        res = NotarizationService.verify_notarization(proof["notarization_id"])
        self.assertEqual(res["verification_status"], VERIFY_STATUS_VERIFIED_LOCAL_PROOF)
        self.assertEqual(res["notarization_mode"], "LOCAL_ONLY")
        self.assertEqual(res["local_proof_sha256"], proof["local_proof_sha256"])

    def test_05_tampered_report_fails_verification(self):
        """5. Tampered report bytes causes REPORT_INTEGRITY_FAILED."""
        setup = self._create_sample_signed_report("test_analysis_05")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        # Tamper report raw bytes in database
        conn = get_db_connection(self.db_path)
        conn.execute(
            "UPDATE report_artifacts SET raw_bytes = ? WHERE report_artifact_id = ?",
            (b"%PDF-1.4 TAMPERED BYTES", setup["report_artifact"]["report_artifact_id"])
        )
        conn.commit()
        conn.close()

        res = NotarizationService.verify_notarization(proof["notarization_id"])
        self.assertEqual(res["verification_status"], VERIFY_STATUS_REPORT_INTEGRITY_FAILED)
        self.assertIn("tampered", res["details"])

    def test_06_tampered_signature_fails_verification(self):
        """6. Tampered signature bytes causes SIGNATURE_INVALID."""
        setup = self._create_sample_signed_report("test_analysis_06")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        # Tamper digital signature value in database
        tampered_sig_b64 = base64.b64encode(b"TAMPERED_SIGNATURE_BYTES" * 3).decode("ascii")
        conn = get_db_connection(self.db_path)
        conn.execute(
            "UPDATE digital_signatures SET signature_value = ? WHERE signature_id = ?",
            (tampered_sig_b64, setup["signature"]["signature_id"])
        )
        conn.commit()
        conn.close()

        res = NotarizationService.verify_notarization(proof["notarization_id"])
        self.assertEqual(res["verification_status"], VERIFY_STATUS_SIGNATURE_INVALID)

    def test_07_tampered_manifest_fails_verification(self):
        """7. Tampered manifest payload causes MANIFEST_INTEGRITY_FAILED."""
        setup = self._create_sample_signed_report("test_analysis_07")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        # Tamper source manifest json in database
        conn = get_db_connection(self.db_path)
        conn.execute(
            "UPDATE custody_manifest_versions SET manifest_json = ? WHERE manifest_version_id = ?",
            ('{"analysis_id":"tampered"}', proof["manifest_version_id"])
        )
        conn.commit()
        conn.close()

        res = NotarizationService.verify_notarization(proof["notarization_id"])
        self.assertEqual(res["verification_status"], VERIFY_STATUS_MANIFEST_INTEGRITY_FAILED)

    def test_08_tampered_local_proof_sha256_fails_verification(self):
        """8. Tampered local_proof_sha256 in DB causes INTEGRITY_FAILED."""
        setup = self._create_sample_signed_report("test_analysis_08")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        # Tamper local_proof_sha256 in DB
        tampered_hash = "e" * 64
        conn = get_db_connection(self.db_path)
        conn.execute(
            "UPDATE notarization_records SET local_proof_sha256 = ? WHERE notarization_id = ?",
            (tampered_hash, proof["notarization_id"])
        )
        conn.commit()
        conn.close()

        res = NotarizationService.verify_notarization(proof["notarization_id"])
        self.assertEqual(res["verification_status"], VERIFY_STATUS_INTEGRITY_FAILED)
        self.assertIn("mismatch", res["details"])

    def test_09_wrong_lineage_rejected(self):
        """9. Wrong report/signature lineage is rejected."""
        setup1 = self._create_sample_signed_report("test_analysis_09a")
        setup2 = self._create_sample_signed_report("test_analysis_09b")

        # Try to notarize setup1 report using setup2 signature
        with self.assertRaises(NotarizationPrerequisiteError):
            NotarizationService.create_notarization_proof(
                analysis_id=setup1["analysis_id"],
                report_artifact_id=setup1["report_artifact"]["report_artifact_id"],
                signature_id=setup2["signature"]["signature_id"],
            )

    def test_10_unsigned_report_cannot_be_notarized(self):
        """10. Unsigned report cannot be notarized."""
        raw_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32
        analysis_id = "test_analysis_10_unsigned"
        CustodyService.get_or_create_record(analysis_id, "smtp.pcap", raw_pcap)

        detail = AnalysisDetailResponse(
            analysis_id=analysis_id,
            file_name="smtp.pcap",
            file_size_bytes=len(raw_pcap),
            analysis_time_utc="2026-09-25T12:00:00Z",
            tshark_version="TShark 4.6.0",
            total_packets_extracted=1,
            email_sessions_found=0,
            sessions=[],
        )
        ForensicRepository.save_analysis(detail, db_path=self.db_path)
        CustodyService.record_analysis_completion(analysis_id, detail)
        CustodyService.record_report_generation(analysis_id, b"%PDF-1.4 test")
        reports = ForensicRepository.get_report_artifacts(analysis_id, db_path=self.db_path)
        report_art = reports[0]

        with self.assertRaises(NotarizationPrerequisiteError) as ctx:
            NotarizationService.create_notarization_proof(
                analysis_id=analysis_id,
                report_artifact_id=report_art["report_artifact_id"],
                db_path=self.db_path,
            )
        self.assertIn("unsigned", str(ctx.exception).lower())

    def test_11_external_provider_mode_unconfigured_fails_explicitly(self):
        """11. External provider mode without configuration raises ProviderUnavailableError."""
        setup = self._create_sample_signed_report("test_analysis_11")

        with self.assertRaises(ProviderUnavailableError):
            NotarizationService.create_notarization_proof(
                analysis_id=setup["analysis_id"],
                report_artifact_id=setup["report_artifact"]["report_artifact_id"],
                mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
            )

    def test_12_no_fake_transaction_hash_generated(self):
        """12. No fake transaction hash or reference generated in LOCAL_ONLY mode."""
        setup = self._create_sample_signed_report("test_analysis_12")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
            mode=NOTARIZATION_MODE_LOCAL_ONLY,
        )
        self.assertIsNone(proof.get("provider_reference"))
        self.assertIsNone(proof.get("tx_reference"))

    def test_13_no_fake_explorer_url_generated(self):
        """13. No fake explorer URL generated anywhere in record or manifest."""
        setup = self._create_sample_signed_report("test_analysis_13")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )
        rec_json = json.dumps(proof)
        self.assertNotIn("etherscan", rec_json.lower())
        self.assertNotIn("blockchain.com", rec_json.lower())
        self.assertNotIn("explorer", rec_json.lower())

    def test_14_no_api_key_stored_in_db(self):
        """14. No API keys or tokens are stored in SQLite database."""
        setup = self._create_sample_signed_report("test_analysis_14")
        NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(notarization_records);")
        col_names = [r["name"].lower() for r in cursor.fetchall()]
        conn.close()

        for forbidden in ["api_key", "secret", "private_key", "token", "password"]:
            self.assertNotIn(forbidden, col_names)

    def test_15_notarization_creates_append_only_record(self):
        """15. Notarization persists a complete new append-only row in notarization_records."""
        setup = self._create_sample_signed_report("test_analysis_15")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notarization_records WHERE notarization_id = ?", (proof["notarization_id"],))
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["notarization_id"], proof["notarization_id"])
        self.assertEqual(row["status"], "LOCAL_PROOF_CREATED")
        self.assertEqual(row["local_proof_sha256"], proof["local_proof_sha256"])

    def test_16_notarization_creates_notarization_linkage_manifest(self):
        """16. Notarization creates and seals a new NOTARIZATION_LINKAGE_MANIFEST version."""
        setup = self._create_sample_signed_report("test_analysis_16")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        latest_m = ForensicRepository.get_latest_manifest_version(setup["analysis_id"])
        self.assertEqual(latest_m["version_number"], 4)  # v1=final, v2=report, v3=sig, v4=notz
        self.assertEqual(latest_m["manifest_type"], "NOTARIZATION_LINKAGE_MANIFEST")
        self.assertTrue(latest_m["sealed"])

        m_dict = latest_m["manifest_dict"]
        self.assertEqual(len(m_dict["linked_notarizations"]), 1)
        self.assertEqual(m_dict["linked_notarizations"][0]["notarization_id"], proof["notarization_id"])
        self.assertEqual(m_dict["linked_notarizations"][0]["local_proof_sha256"], proof["local_proof_sha256"])

    def test_17_previous_manifest_versions_remain_unchanged(self):
        """17. Manifest versions v1, v2, v3 remain byte-for-byte unchanged after notarization."""
        setup = self._create_sample_signed_report("test_analysis_17")
        v1_before = ForensicRepository.get_manifest_version(setup["analysis_id"], "1")
        v2_before = ForensicRepository.get_manifest_version(setup["analysis_id"], "2")
        v3_before = ForensicRepository.get_manifest_version(setup["analysis_id"], "3")

        NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        v1_after = ForensicRepository.get_manifest_version(setup["analysis_id"], "1")
        v2_after = ForensicRepository.get_manifest_version(setup["analysis_id"], "2")
        v3_after = ForensicRepository.get_manifest_version(setup["analysis_id"], "3")

        self.assertEqual(v1_before["manifest_json"], v1_after["manifest_json"])
        self.assertEqual(v1_before["manifest_sha256"], v1_after["manifest_sha256"])
        self.assertEqual(v2_before["manifest_json"], v2_after["manifest_json"])
        self.assertEqual(v2_before["manifest_sha256"], v2_after["manifest_sha256"])
        self.assertEqual(v3_before["manifest_json"], v3_after["manifest_json"])
        self.assertEqual(v3_before["manifest_sha256"], v3_after["manifest_sha256"])

    def test_18_re_notarization_creates_new_record_not_overwrite(self):
        """18. Re-notarizing creates a second distinct notarization record and manifest version 5."""
        setup = self._create_sample_signed_report("test_analysis_18")
        proof1 = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )
        proof2 = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        self.assertNotEqual(proof1["notarization_id"], proof2["notarization_id"])

        notzs = ForensicRepository.get_analysis_notarizations(setup["analysis_id"])
        self.assertEqual(len(notzs), 2)

        latest_m = ForensicRepository.get_latest_manifest_version(setup["analysis_id"])
        self.assertEqual(latest_m["version_number"], 5)
        self.assertEqual(len(latest_m["manifest_dict"]["linked_notarizations"]), 2)

    def test_19_actor_attribution_frozen(self):
        """19. Actor attribution metadata is frozen at proof creation time."""
        actor = ActorContext.local_declared("analyst_bob_01", "Forensic Specialist Bob")
        setup = self._create_sample_signed_report("test_analysis_19", actor=actor)

        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
            actor=actor,
        )

        self.assertEqual(proof["created_by_actor_id"], "analyst_bob_01")
        self.assertEqual(proof["created_by_actor_display_name"], "Forensic Specialist Bob")
        self.assertEqual(proof["actor_identity_source"], "LOCAL_DECLARED")
        self.assertEqual(proof["actor_attribution_status"], "ATTRIBUTED")

    def test_20_analyst_profile_update_does_not_alter_historical_notarization(self):
        """20. Updating analyst profile in registry never alters frozen notarization actor fields."""
        actor = ActorContext.local_declared("analyst_carol_01", "Carol Original")
        ForensicRepository.register_analyst("analyst_carol_01", "Carol Original")
        setup = self._create_sample_signed_report("test_analysis_20", actor=actor)

        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
            actor=actor,
        )

        # Update analyst profile in registry
        ForensicRepository.update_analyst_profile("analyst_carol_01", "Carol Senior Lead")

        # Reload notarization record
        rec = ForensicRepository.get_notarization_record(proof["notarization_id"])
        self.assertEqual(rec["created_by_actor_display_name"], "Carol Original")

    def test_21_read_only_verification_has_zero_side_effects(self):
        """21. NotarizationService.verify_notarization causes zero writes, mutations, or new rows."""
        setup = self._create_sample_signed_report("test_analysis_21")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        conn = get_db_connection(self.db_path)
        tables = ["analyses", "sessions", "findings", "custody_records", "custody_events",
                  "custody_manifest_versions", "report_artifacts", "digital_signatures", "notarization_records"]
        counts_before = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
        conn.close()

        # Perform 5 read-only verifications
        for _ in range(5):
            res = NotarizationService.verify_notarization(proof["notarization_id"])
            self.assertEqual(res["verification_status"], VERIFY_STATUS_VERIFIED_LOCAL_PROOF)

        conn = get_db_connection(self.db_path)
        counts_after = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
        conn.close()

        self.assertEqual(counts_before, counts_after)

    def test_22_atomic_transaction_rollback_on_failure(self):
        """22. Injected transaction failure rolls back both notarization record and manifest version."""
        setup = self._create_sample_signed_report("test_analysis_22")
        latest_m = ForensicRepository.get_latest_manifest_version(setup["analysis_id"])

        notz_dict = {
            "notarization_id": "notz_rollback_test",
            "analysis_id": "test_analysis_22",
            "report_artifact_id": setup["report_artifact"]["report_artifact_id"],
            "signature_id": setup["signature"]["signature_id"],
            "manifest_version_id": latest_m["manifest_version_id"],
            "notarization_mode": "LOCAL_ONLY",
            "local_proof_sha256": "1" * 64,
            "created_at": "2026-09-25T12:00:00Z",
            "status": "LOCAL_PROOF_CREATED",
        }
        manifest_v4 = {
            "manifest_version_id": "cmv_rollback_v4",
            "analysis_id": "test_analysis_22",
            "version_number": 4,
            "manifest_type": "NOTARIZATION_LINKAGE_MANIFEST",
            "previous_manifest_sha256": latest_m["manifest_sha256"],
            "manifest_json": '{"test":"rollback"}',
            "manifest_sha256": "2" * 64,
            "created_at": "2026-09-25T12:00:00Z",
        }

        with self.assertRaises(RuntimeError):
            ForensicRepository.save_notarization_and_manifest_version(
                notarization_record=notz_dict,
                manifest_version=manifest_v4,
                inject_failure_after_notarization=True
            )

        # Verify nothing was committed
        self.assertIsNone(ForensicRepository.get_notarization_record("notz_rollback_test"))
        self.assertIsNone(ForensicRepository.get_manifest_version("test_analysis_22", "4"))

    def test_23_verify_nonexistent_notarization_returns_incomplete(self):
        """23. Verifying non-existent notarization ID returns INCOMPLETE status."""
        res = NotarizationService.verify_notarization("notz_nonexistent_999")
        self.assertEqual(res["verification_status"], VERIFY_STATUS_INCOMPLETE)
        self.assertIn("not found", res["details"])

    def test_24_rest_api_notarize_endpoint(self):
        """24. POST /api/v1/analyses/{analysis_id}/reports/{report_artifact_id}/notarize endpoint works."""
        setup = self._create_sample_signed_report("test_analysis_24")
        resp = self.client.post(
            f"/api/v1/analyses/{setup['analysis_id']}/reports/{setup['report_artifact']['report_artifact_id']}/notarize",
            json={"mode": "LOCAL_ONLY"},
            headers={"X-Analyst-ID": "analyst_api", "X-Analyst-Name": "API Analyst"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["notarization_mode"], "LOCAL_ONLY")
        self.assertEqual(data["status"], "LOCAL_PROOF_CREATED")
        self.assertEqual(data["created_by_actor_id"], "analyst_api")

    def test_25_rest_api_list_notarizations(self):
        """25. GET /api/v1/analyses/{analysis_id}/notarizations lists records."""
        setup = self._create_sample_signed_report("test_analysis_25")
        NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        resp = self.client.get(f"/api/v1/analyses/{setup['analysis_id']}/notarizations")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_notarizations"], 1)
        self.assertEqual(data["notarizations"][0]["analysis_id"], setup["analysis_id"])

    def test_26_rest_api_verify_endpoint(self):
        """26. GET /api/v1/notarizations/{notarization_id}/verify endpoint performs verification."""
        setup = self._create_sample_signed_report("test_analysis_26")
        proof = NotarizationService.create_notarization_proof(
            analysis_id=setup["analysis_id"],
            report_artifact_id=setup["report_artifact"]["report_artifact_id"],
        )

        resp = self.client.get(f"/api/v1/notarizations/{proof['notarization_id']}/verify")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verification_status"], VERIFY_STATUS_VERIFIED_LOCAL_PROOF)
        self.assertEqual(data["local_proof_sha256"], proof["local_proof_sha256"])


if __name__ == "__main__":
    unittest.main()

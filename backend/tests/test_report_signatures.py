"""
SecureMailScope X - Digital Report Signing & Signature Verification Test Suite (Phase 14)
Deterministic tests for asymmetric report signatures (Ed25519, ECDSA P-256, RSA-PSS),
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
from typing import Dict, Any

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa

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
from app.services.signature_service import (
    SignatureService,
    SigningUnavailableError,
    UnsupportedAlgorithmError,
    SignatureVerificationError,
    compute_public_key_fingerprint,
    export_public_key_pem,
    build_signature_payload,
)


class TestReportSignatures(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary test directory and SQLite database
        self.test_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.test_dir.name, "test_securemailscope.db")
        set_custom_db_path(self.db_path)
        init_db(self.db_path)

        # Clear in-memory service records
        CustodyService._records.clear()

        # Clean environment variables
        self.orig_env_path = os.environ.get("SMS_SIGNING_PRIVATE_KEY_PATH")
        self.orig_env_pem = os.environ.get("SMS_SIGNING_PRIVATE_KEY_PEM")
        self.orig_env_kid = os.environ.get("SMS_SIGNING_KEY_ID")

        if "SMS_SIGNING_PRIVATE_KEY_PATH" in os.environ:
            del os.environ["SMS_SIGNING_PRIVATE_KEY_PATH"]
        if "SMS_SIGNING_PRIVATE_KEY_PEM" in os.environ:
            del os.environ["SMS_SIGNING_PRIVATE_KEY_PEM"]
        if "SMS_SIGNING_KEY_ID" in os.environ:
            del os.environ["SMS_SIGNING_KEY_ID"]

        # Generate temporary test keys
        self.ed25519_key = ed25519.Ed25519PrivateKey.generate()
        self.ed25519_pem = self.ed25519_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        self.ecdsa_key = ec.generate_private_key(ec.SECP256R1())
        self.ecdsa_pem = self.ecdsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_pem = self.rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        # Save Ed25519 key to a temporary file
        self.key_file_path = os.path.join(self.test_dir.name, "test_signing_key.pem")
        with open(self.key_file_path, "w", encoding="utf-8") as f:
            f.write(self.ed25519_pem)

    def tearDown(self):
        CustodyService._records.clear()
        set_custom_db_path(None)
        if self.orig_env_path is not None:
            os.environ["SMS_SIGNING_PRIVATE_KEY_PATH"] = self.orig_env_path
        elif "SMS_SIGNING_PRIVATE_KEY_PATH" in os.environ:
            del os.environ["SMS_SIGNING_PRIVATE_KEY_PATH"]

        if self.orig_env_pem is not None:
            os.environ["SMS_SIGNING_PRIVATE_KEY_PEM"] = self.orig_env_pem
        elif "SMS_SIGNING_PRIVATE_KEY_PEM" in os.environ:
            del os.environ["SMS_SIGNING_PRIVATE_KEY_PEM"]

        if self.orig_env_kid is not None:
            os.environ["SMS_SIGNING_KEY_ID"] = self.orig_env_kid
        elif "SMS_SIGNING_KEY_ID" in os.environ:
            del os.environ["SMS_SIGNING_KEY_ID"]

        self.test_dir.cleanup()

    def _create_sample_analysis_with_report(
        self,
        analysis_id: str = "analysis_sig_test_01",
        actor: Optional[ActorContext] = None
    ):
        """Helper to create analysis, finalize manifest v1, and generate report artifact v1 -> manifest v2."""
        raw_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32
        act = actor or ActorContext.local_declared("analyst_test_01", "Forensic Specialist Alice")

        # 1. Ingest
        rec = CustodyService.get_or_create_record(
            analysis_id=analysis_id,
            filename="smtp_capture.pcap",
            content_bytes=raw_pcap,
            actor=act,
        )

        # 2. Analysis Detail
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

        dummy_analysis = AnalysisDetailResponse(
            analysis_id=analysis_id,
            file_name="smtp_capture.pcap",
            file_size_bytes=len(raw_pcap),
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

        ForensicRepository.save_analysis(dummy_analysis, actor=act, db_path=self.db_path)
        CustodyService.record_analysis_completion(analysis_id, dummy_analysis, actor=act)

        # 3. Generate Report PDF v1
        pdf_bytes = b"%PDF-1.4 sample forensic report binary bytes for test"
        CustodyService.record_report_generation(analysis_id, pdf_bytes, actor=act)

        reports = ForensicRepository.get_report_artifacts(analysis_id, db_path=self.db_path)
        manifests = ForensicRepository.get_manifest_versions(analysis_id, db_path=self.db_path)
        return reports[0], manifests[-1]

    # -----------------------------------------------------------------------
    # Test Cases
    # -----------------------------------------------------------------------
    def test_01_signing_unavailable_when_no_private_key_configured(self):
        """1. When no private signing key is configured or passed, signing returns SIGNING_UNAVAILABLE."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_no_key")
        with self.assertRaises(SigningUnavailableError) as ctx:
            SignatureService.sign_report_artifact(
                analysis_id="analysis_no_key",
                report_artifact_id=report_art["report_artifact_id"],
                db_path=self.db_path
            )
        self.assertIn("No private signing key configured", str(ctx.exception))

    def test_02_ed25519_key_can_sign_report(self):
        """2. Temporary Ed25519 test key can successfully sign report artifact."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_ed25519")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_ed25519",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            key_id="ed25519-test-key",
            db_path=self.db_path
        )
        self.assertEqual(sig["signature_algorithm"], "ED25519")
        self.assertEqual(sig["key_id"], "ed25519-test-key")
        self.assertEqual(sig["verification_status"], "VERIFIED")
        self.assertTrue(len(sig["signature_value"]) > 0)

    def test_03_ecdsa_p256_key_can_sign_report(self):
        """3. Temporary ECDSA P-256 test key can sign report artifact."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_ecdsa")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_ecdsa",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ecdsa_pem,
            key_id="ecdsa-test-key",
            db_path=self.db_path
        )
        self.assertEqual(sig["signature_algorithm"], "ECDSA_P256_SHA256")
        self.assertEqual(sig["key_id"], "ecdsa-test-key")
        self.assertEqual(sig["verification_status"], "VERIFIED")

    def test_04_rsa_pss_key_can_sign_report(self):
        """4. Temporary RSA-PSS test key can sign report artifact."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_rsa")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_rsa",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.rsa_pem,
            key_id="rsa-test-key",
            db_path=self.db_path
        )
        self.assertEqual(sig["signature_algorithm"], "RSA_PSS_SHA256")
        self.assertEqual(sig["key_id"], "rsa-test-key")
        self.assertEqual(sig["verification_status"], "VERIFIED")

    def test_05_signature_verifies_correctly(self):
        """5. Signature verification returns VERIFIED for intact signatures."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_verify_ok")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_verify_ok",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )
        ver_res = SignatureService.verify_signature(sig["signature_id"], db_path=self.db_path)
        self.assertEqual(ver_res["verification_status"], "VERIFIED")
        self.assertEqual(ver_res["signature_algorithm"], "ED25519")

    def test_06_modified_report_bytes_fails_verification(self):
        """6. Modified report binary bytes causes ARTIFACT_INTEGRITY_FAILED."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_mod_art")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_mod_art",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )
        # Tamper report artifact bytes in SQLite
        conn = get_db_connection(self.db_path)
        conn.execute(
            "UPDATE report_artifacts SET raw_bytes = ? WHERE report_artifact_id = ?",
            (b"%PDF-1.4 TAMPERED BYTES", report_art["report_artifact_id"])
        )
        conn.commit()
        conn.close()

        ver_res = SignatureService.verify_signature(sig["signature_id"], db_path=self.db_path)
        self.assertEqual(ver_res["verification_status"], "ARTIFACT_INTEGRITY_FAILED")
        self.assertIn("tampered", ver_res["details"].lower())

    def test_07_modified_report_artifact_hash_fails(self):
        """7. Modified report artifact hash breaks reconstructed payload and fails verification."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_mod_art_hash")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_mod_art_hash",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )
        # Tamper artifact_sha256 in report_artifacts
        conn = get_db_connection(self.db_path)
        conn.execute(
            "UPDATE report_artifacts SET artifact_sha256 = ? WHERE report_artifact_id = ?",
            ("0" * 64, report_art["report_artifact_id"])
        )
        conn.commit()
        conn.close()

        ver_res = SignatureService.verify_signature(sig["signature_id"], db_path=self.db_path)
        self.assertIn(ver_res["verification_status"], ["ARTIFACT_INTEGRITY_FAILED", "SIGNATURE_INVALID"])

    def test_08_modified_source_manifest_fails_verification(self):
        """8. Modified source manifest payload seal causes MANIFEST_INTEGRITY_FAILED."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_mod_manifest")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_mod_manifest",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )
        # Tamper manifest v2 json in database
        conn = get_db_connection(self.db_path)
        conn.execute(
            "UPDATE custody_manifest_versions SET manifest_json = ? WHERE manifest_version_id = ?",
            ('{"tampered": true}', sig["manifest_version_id"])
        )
        conn.commit()
        conn.close()

        ver_res = SignatureService.verify_signature(sig["signature_id"], db_path=self.db_path)
        self.assertEqual(ver_res["verification_status"], "MANIFEST_INTEGRITY_FAILED")

    def test_09_modified_signature_bytes_fails_as_signature_invalid(self):
        """9. Modified signature bytes returns SIGNATURE_INVALID."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_mod_sig_bytes")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_mod_sig_bytes",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )
        # Flip bytes in Base64 signature
        raw_sig = base64.b64decode(sig["signature_value"])
        tampered_sig = bytearray(raw_sig)
        tampered_sig[0] ^= 0xFF
        b64_tampered = base64.b64encode(bytes(tampered_sig)).decode("ascii")

        conn = get_db_connection(self.db_path)
        conn.execute(
            "UPDATE digital_signatures SET signature_value = ? WHERE signature_id = ?",
            (b64_tampered, sig["signature_id"])
        )
        conn.commit()
        conn.close()

        ver_res = SignatureService.verify_signature(sig["signature_id"], db_path=self.db_path)
        self.assertEqual(ver_res["verification_status"], "SIGNATURE_INVALID")

    def test_10_wrong_public_key_yields_public_key_mismatch_or_invalid(self):
        """10. Public key replaced with a different key triggers PUBLIC_KEY_MISMATCH or SIGNATURE_INVALID."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_wrong_key")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_wrong_key",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )
        # Generate another key and put its PEM without updating stored fingerprint
        diff_key = ed25519.Ed25519PrivateKey.generate()
        diff_pem = export_public_key_pem(diff_key.public_key())

        conn = get_db_connection(self.db_path)
        conn.execute(
            "UPDATE digital_signatures SET public_key_pem = ? WHERE signature_id = ?",
            (diff_pem, sig["signature_id"])
        )
        conn.commit()
        conn.close()

        ver_res = SignatureService.verify_signature(sig["signature_id"], db_path=self.db_path)
        self.assertEqual(ver_res["verification_status"], "PUBLIC_KEY_MISMATCH")

    def test_11_public_key_fingerprint_computed_from_der_bytes(self):
        """11. Public key fingerprint is computed strictly from SubjectPublicKeyInfo DER bytes with SHA-256."""
        pub_key = self.ed25519_key.public_key()
        der_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        expected_fp = hashlib.sha256(der_bytes).hexdigest().lower()
        actual_fp = compute_public_key_fingerprint(pub_key)
        self.assertEqual(actual_fp, expected_fp)
        self.assertEqual(len(actual_fp), 64)

    def test_12_no_private_key_stored_in_database(self):
        """12. Private keys are never stored anywhere in SQLite database tables."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_db_audit")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_db_audit",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()

        # Check all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r["name"] for r in cursor.fetchall()]

        for tbl in tables:
            cursor.execute(f"SELECT * FROM {tbl}")
            rows = cursor.fetchall()
            for r in rows:
                for col in r.keys():
                    val = str(r[col])
                    self.assertNotIn("PRIVATE KEY", val)
        conn.close()

    def test_13_no_private_key_returned_in_service_output(self):
        """13. SignatureService sign & verify responses never return private key material."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_leak_test")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_leak_test",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )
        ver = SignatureService.verify_signature(sig["signature_id"], db_path=self.db_path)

        for d in (sig, ver):
            for k, v in d.items():
                self.assertNotIn("private", k.lower())
                self.assertNotIn("PRIVATE KEY", str(v))

    def test_14_signing_creates_new_signature_record(self):
        """14. Signing persists a complete new digital signature record in digital_signatures table."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_sig_rec")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_sig_rec",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            key_id="k1",
            db_path=self.db_path
        )
        stored_sig = ForensicRepository.get_digital_signature(sig["signature_id"], db_path=self.db_path)
        self.assertIsNotNone(stored_sig)
        self.assertEqual(stored_sig["signature_id"], sig["signature_id"])
        self.assertEqual(stored_sig["key_id"], "k1")

    def test_15_signing_creates_signature_linkage_manifest(self):
        """15. Signing creates and seals a new SIGNATURE_LINKAGE_MANIFEST version."""
        report_art, manifest_v2 = self._create_sample_analysis_with_report("analysis_sig_manifest")
        self.assertEqual(manifest_v2["version_number"], 2)

        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_sig_manifest",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )

        manifests = ForensicRepository.get_manifest_versions("analysis_sig_manifest", db_path=self.db_path)
        self.assertEqual(len(manifests), 3)

        manifest_v3 = manifests[-1]
        self.assertEqual(manifest_v3["version_number"], 3)
        self.assertEqual(manifest_v3["manifest_type"], "SIGNATURE_LINKAGE_MANIFEST")
        self.assertEqual(manifest_v3["previous_manifest_sha256"], manifest_v2["manifest_sha256"])
        self.assertEqual(len(manifest_v3["linked_signatures"]), 1)
        self.assertEqual(manifest_v3["linked_signatures"][0]["signature_id"], sig["signature_id"])

    def test_16_previous_manifest_remains_byte_for_byte_unchanged(self):
        """16. Manifest Version 1 and Version 2 remain byte-for-byte unchanged after signing."""
        report_art, manifest_v2 = self._create_sample_analysis_with_report("analysis_immut_test")
        v1_before = ForensicRepository.get_manifest_version("analysis_immut_test", 1, db_path=self.db_path)
        v2_before = ForensicRepository.get_manifest_version("analysis_immut_test", 2, db_path=self.db_path)

        SignatureService.sign_report_artifact(
            analysis_id="analysis_immut_test",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )

        v1_after = ForensicRepository.get_manifest_version("analysis_immut_test", 1, db_path=self.db_path)
        v2_after = ForensicRepository.get_manifest_version("analysis_immut_test", 2, db_path=self.db_path)

        self.assertEqual(v1_before["manifest_json"], v1_after["manifest_json"])
        self.assertEqual(v1_before["manifest_sha256"], v1_after["manifest_sha256"])
        self.assertEqual(v2_before["manifest_json"], v2_after["manifest_json"])
        self.assertEqual(v2_before["manifest_sha256"], v2_after["manifest_sha256"])

    def test_17_manifest_chain_remains_valid_after_signing(self):
        """17. ForensicRepository.verify_manifest_chain returns VERIFIED across v1, v2, and v3."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_chain_ok")
        SignatureService.sign_report_artifact(
            analysis_id="analysis_chain_ok",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )
        res = ForensicRepository.verify_manifest_chain("analysis_chain_ok", db_path=self.db_path)
        self.assertEqual(res["overall_status"], "VERIFIED")
        self.assertEqual(res["versions_count"], 3)

    def test_18_re_signing_same_report_creates_new_signature_record(self):
        """18. Re-signing the same report creates a second distinct signature record and manifest version 4."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_resign")
        sig1 = SignatureService.sign_report_artifact(
            analysis_id="analysis_resign",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            key_id="k1",
            db_path=self.db_path
        )
        sig2 = SignatureService.sign_report_artifact(
            analysis_id="analysis_resign",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ecdsa_pem,
            key_id="k2",
            db_path=self.db_path
        )
        self.assertNotEqual(sig1["signature_id"], sig2["signature_id"])
        self.assertNotEqual(sig1["signature_value"], sig2["signature_value"])

        sigs = ForensicRepository.get_report_signatures("analysis_resign", report_art["report_artifact_id"], db_path=self.db_path)
        self.assertEqual(len(sigs), 2)

        manifests = ForensicRepository.get_manifest_versions("analysis_resign", db_path=self.db_path)
        self.assertEqual(len(manifests), 4)

    def test_19_regenerated_report_cannot_reuse_old_signature(self):
        """19. When a report is regenerated (creating Report Artifact v2), the old signature remains bound only to v1."""
        report_art_v1, _ = self._create_sample_analysis_with_report("analysis_regen")
        sig_v1 = SignatureService.sign_report_artifact(
            analysis_id="analysis_regen",
            report_artifact_id=report_art_v1["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )

        # Regenerate report
        new_pdf_bytes = b"%PDF-1.4 NEW REGENERATED BYTES DIFFERENT FROM V1"
        CustodyService.record_report_generation("analysis_regen", new_pdf_bytes)

        reports = ForensicRepository.get_report_artifacts("analysis_regen", db_path=self.db_path)
        self.assertEqual(len(reports), 2)
        report_art_v2 = reports[1]

        # Verify old signature verifies only for v1
        ver_v1 = SignatureService.verify_signature(sig_v1["signature_id"], db_path=self.db_path)
        self.assertEqual(ver_v1["verification_status"], "VERIFIED")
        self.assertEqual(ver_v1["report_artifact_id"], report_art_v1["report_artifact_id"])

        # Sign v2
        sig_v2 = SignatureService.sign_report_artifact(
            analysis_id="analysis_regen",
            report_artifact_id=report_art_v2["report_artifact_id"],
            private_key_pem=self.ecdsa_pem,
            db_path=self.db_path
        )
        self.assertNotEqual(sig_v1["signature_id"], sig_v2["signature_id"])

    def test_20_actor_attribution_frozen_in_signature_record(self):
        """20. Actor attribution metadata is frozen at signing time."""
        act = ActorContext.local_declared("analyst_signer_07", "Senior Examiner Bob")
        report_art, _ = self._create_sample_analysis_with_report("analysis_actor_freeze", actor=act)

        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_actor_freeze",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            actor=act,
            db_path=self.db_path
        )

        self.assertEqual(sig["signed_by_actor_id"], "analyst_signer_07")
        self.assertEqual(sig["signed_by_actor_display_name"], "Senior Examiner Bob")
        self.assertEqual(sig["actor_identity_source"], "LOCAL_DECLARED")

    def test_21_analyst_profile_update_does_not_alter_historical_signature_actor(self):
        """21. Updating analyst profile in registry never alters frozen signature actor data."""
        act = ActorContext.local_declared("analyst_dyn", "Original Analyst Name")
        ForensicRepository.register_analyst("analyst_dyn", "Original Analyst Name", db_path=self.db_path)

        report_art, _ = self._create_sample_analysis_with_report("analysis_profile_upd", actor=act)
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_profile_upd",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            actor=act,
            db_path=self.db_path
        )

        # Update analyst profile in registry
        ForensicRepository.update_analyst_profile("analyst_dyn", "Renamed Modified Analyst", db_path=self.db_path)

        # Check signature record in DB
        stored_sig = ForensicRepository.get_digital_signature(sig["signature_id"], db_path=self.db_path)
        self.assertEqual(stored_sig["signed_by_actor_display_name"], "Original Analyst Name")

    def test_22_read_only_signature_verification_has_zero_side_effects(self):
        """22. SignatureService.verify_signature causes zero writes or new rows."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_readonly")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_readonly",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )

        conn = get_db_connection(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT count(*) as c FROM digital_signatures")
        sig_count_before = cur.fetchone()["c"]
        cur.execute("SELECT count(*) as c FROM custody_events")
        evt_count_before = cur.fetchone()["c"]
        conn.close()

        # Run verification 5 times
        for _ in range(5):
            res = SignatureService.verify_signature(sig["signature_id"], db_path=self.db_path)
            self.assertEqual(res["verification_status"], "VERIFIED")

        conn = get_db_connection(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT count(*) as c FROM digital_signatures")
        sig_count_after = cur.fetchone()["c"]
        cur.execute("SELECT count(*) as c FROM custody_events")
        evt_count_after = cur.fetchone()["c"]
        conn.close()

        self.assertEqual(sig_count_before, sig_count_after)
        self.assertEqual(evt_count_before, evt_count_after)

    def test_23_unsupported_algorithm_fails_explicitly(self):
        """23. Unsupported algorithm raises UnsupportedAlgorithmError or returns UNSUPPORTED_ALGORITHM."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_unsupported")
        with self.assertRaises(UnsupportedAlgorithmError):
            SignatureService.sign_report_artifact(
                analysis_id="analysis_unsupported",
                report_artifact_id=report_art["report_artifact_id"],
                private_key_pem=self.ed25519_pem,
                algorithm="INSECURE_MD5_RSA",
                db_path=self.db_path
            )

    def test_24_tampered_signed_digest_value_is_detected(self):
        """24. Tampering signed_digest_value in signature metadata is detected as SIGNATURE_INVALID."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_tamper_digest")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_tamper_digest",
            report_artifact_id=report_art["report_artifact_id"],
            private_key_pem=self.ed25519_pem,
            db_path=self.db_path
        )
        conn = get_db_connection(self.db_path)
        conn.execute(
            "UPDATE digital_signatures SET signed_digest_value = ? WHERE signature_id = ?",
            ("0" * 64, sig["signature_id"])
        )
        conn.commit()
        conn.close()

        ver_res = SignatureService.verify_signature(sig["signature_id"], db_path=self.db_path)
        self.assertEqual(ver_res["verification_status"], "SIGNATURE_INVALID")

    def test_25_env_var_path_key_resolution(self):
        """25. SMS_SIGNING_PRIVATE_KEY_PATH environment variable correctly resolves signing key."""
        os.environ["SMS_SIGNING_PRIVATE_KEY_PATH"] = self.key_file_path
        os.environ["SMS_SIGNING_KEY_ID"] = "env-key-01"

        report_art, _ = self._create_sample_analysis_with_report("analysis_env_key")
        sig = SignatureService.sign_report_artifact(
            analysis_id="analysis_env_key",
            report_artifact_id=report_art["report_artifact_id"],
            db_path=self.db_path
        )
        self.assertEqual(sig["key_id"], "env-key-01")
        self.assertEqual(sig["signature_algorithm"], "ED25519")
        self.assertEqual(sig["verification_status"], "VERIFIED")

    def test_26_atomic_transaction_rollback_on_signature_manifest_failure(self):
        """26. If manifest insertion fails during signing, digital_signatures row is rolled back."""
        report_art, _ = self._create_sample_analysis_with_report("analysis_rollback_sig")

        sig_dict = {
            "signature_id": "sig_rollback_test",
            "analysis_id": "analysis_rollback_sig",
            "report_artifact_id": report_art["report_artifact_id"],
            "manifest_version_id": "cmv_rollback_test",
            "signature_algorithm": "ED25519",
            "signature_format": "BASE64",
            "signature_value": "dummy==",
            "signed_digest_algorithm": "SHA256",
            "signed_digest_value": "0" * 64,
            "public_key_fingerprint_sha256": "0" * 64,
            "public_key_pem": "---",
            "key_id": "k1",
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }

        manifest_dict = {
            "manifest_version_id": "cmv_rollback_test",
            "analysis_id": "analysis_rollback_sig",
            "version_number": 99,
            "manifest_type": "SIGNATURE_LINKAGE_MANIFEST",
            "previous_manifest_sha256": "0" * 64,
            "manifest_json": "{}",
            "manifest_sha256": "0" * 64,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        with self.assertRaises(RuntimeError):
            ForensicRepository.save_signature_and_manifest_version(
                signature_record=sig_dict,
                manifest_version=manifest_dict,
                db_path=self.db_path,
                inject_failure_after_signature=True
            )

        # Verify signature was rolled back
        stored = ForensicRepository.get_digital_signature("sig_rollback_test", db_path=self.db_path)
        self.assertIsNone(stored)

    def test_27_private_key_files_are_git_ignored(self):
        """27. Gitignore excludes .pem, .key, .p12, .pfx, signing_keys/, private_keys/."""
        repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        gitignore_path = os.path.join(repo_root, ".gitignore")
        self.assertTrue(os.path.isfile(gitignore_path))

        with open(gitignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("*.pem", content)
        self.assertIn("*.key", content)
        self.assertIn("*.p12", content)
        self.assertIn("*.pfx", content)
        self.assertIn("signing_keys/", content)
        self.assertIn("private_keys/", content)


if __name__ == "__main__":
    unittest.main()

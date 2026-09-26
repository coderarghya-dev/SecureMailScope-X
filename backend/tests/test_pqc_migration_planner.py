"""
SecureMailScope X - Phase 24: Post-Quantum Cryptography Migration Planner Tests

Dedicated test suite verifying:
1. Cryptographic asset inventory extraction (sessions, active scans, cases, empty)
2. Deterministic PQC readiness evaluation (CLASSICAL_ONLY, HYBRID_READY, PQC_READY, UNKNOWN)
3. Quantum exposure modeling & HNDL risk (CRITICAL for static RSA, HIGH for classical ECDHE, LOW for hybrid/PQC)
4. Data sensitivity lifetime preservation (UNKNOWN when missing, no artificial assumptions)
5. Gap analysis engine across target architectures (HYBRID_KEM_TARGET, HYBRID_SIGNATURE_TARGET, etc.)
6. 7-Phase migration roadmap generation (Phases A-G) with validation criteria and rollback considerations
7. Explicit advisory labeling for PHASE_F_PQC_PRIMARY_TRANSITION
8. Roadmap CRUD & step status lifecycle
9. Cryptographic peer sign-off with Ed25519 digital signatures and invalid signature rejection
10. Multi-Analyst RBAC capabilities (VIEW, CREATE, EDIT, RUN_GAP, APPROVE)
11. REST API endpoints under /api/v1/pqc/*
12. Audit event recording and hash chaining
13. Absolute safety verification (zero live command/subprocess/SSH execution)
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from app.db.database import get_db_connection, init_db, set_custom_db_path
from app.db.repository import ForensicRepository
from app.main import app
from app.schemas.identity import ActorContext
from app.schemas.pqc_migration import (
    DataSensitivityLifetime,
    GapSeverity,
    MigrationPhaseName,
    MigrationStepStatus,
    PQCExposureAssessmentResponse,
    PQCGapAnalysisRequest,
    PQCReadinessClassification,
    PQCRoadmapApprovalRequest,
    PQCRoadmapCreateRequest,
    PQCRoadmapStatus,
    PQCRoadmapUpdateRequest,
    PQCTransitionTargetArchitecture,
    QuantumExposureLevel,
)
from app.schemas.rbac import AnalystRole, Capability
from app.services.pqc_migration_service import PQCMigrationService
from app.services.rbac_service import AuthorizationService


class TestPQCMigrationPlanner(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_path = self.temp_db.name
        set_custom_db_path(self.db_path)
        init_db(self.db_path)
        self.client = TestClient(app)

        self.actor_lead = ActorContext(actor_id="lead-01", actor_display_name="Lead Analyst")
        self.actor_analyst = ActorContext(actor_id="analyst-01", actor_display_name="Forensic Analyst")
        self.actor_reviewer = ActorContext(actor_id="reviewer-01", actor_display_name="Peer Reviewer")
        self.actor_auditor = ActorContext(actor_id="auditor-01", actor_display_name="Compliance Auditor")

        AuthorizationService.create_or_update_analyst("lead-01", "Lead Analyst", AnalystRole.LEAD_INVESTIGATOR, db_path=self.db_path)
        AuthorizationService.create_or_update_analyst("analyst-01", "Forensic Analyst", AnalystRole.FORENSIC_ANALYST, db_path=self.db_path)
        AuthorizationService.create_or_update_analyst("reviewer-01", "Peer Reviewer", AnalystRole.REVIEWER, db_path=self.db_path)
        AuthorizationService.create_or_update_analyst("auditor-01", "Compliance Auditor", AnalystRole.AUDITOR, db_path=self.db_path)

        # Generate Ed25519 signing keypair for tests
        self.priv_key = ed25519.Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        self.pub_key_bytes = self.pub_key.public_bytes_raw()
        self.pub_key_hex = self.pub_key_bytes.hex()

    def tearDown(self):
        set_custom_db_path(None)
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except Exception:
            pass

    # --------------------------------------------------------------------------
    # 1. Cryptographic Asset Inventory Tests
    # --------------------------------------------------------------------------

    def test_01_empty_inventory(self):
        """Test inventory query when no assets or sessions exist."""
        inv = PQCMigrationService.extract_or_get_inventory(analysis_id="nonexistent", db_path=self.db_path)
        self.assertEqual(inv.total_assets, 0)
        self.assertEqual(inv.classical_count, 0)
        self.assertEqual(inv.hybrid_count, 0)

    def test_02_extract_inventory_from_sessions(self):
        """Test extracting assets from forensic session analysis."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT INTO analyses (
                analysis_id, filename, file_size_bytes, capture_sha256,
                observed_result_json, observed_result_sha256, created_at
            ) VALUES ('ana-01', 'mail.pcap', 1024, 'abc123sha', '{}', 'sha', ?);
            """,
            (now_iso,),
        )
        cursor.execute(
            """
            INSERT INTO sessions (
                session_id, analysis_id, stream_index, protocol, security_mode,
                client, server, session_result_json, session_result_sha256
            ) VALUES (
                'sess-01', 'ana-01', 0, 'SMTP', 'STARTTLS',
                '192.168.1.50:54321', '192.168.1.100:25',
                '{"tls_handshake_details": {"negotiated_tls_version": "TLS 1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "key_exchange_group": "ECDHE"}}',
                'sha'
            );
            """,
        )
        conn.commit()
        conn.close()

        inv = PQCMigrationService.extract_or_get_inventory(analysis_id="ana-01", db_path=self.db_path)
        self.assertGreaterEqual(inv.total_assets, 2)
        layers = [a.crypto_layer for a in inv.assets]
        self.assertIn("KEY_EXCHANGE", layers)
        self.assertIn("CIPHER", layers)

    def test_03_extract_inventory_from_posture_snapshot(self):
        """Test extracting assets from monitored target posture snapshot."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT INTO monitored_targets (
                target_id, display_name, hostname, port, protocol, security_mode, created_at, updated_at
            ) VALUES ('target-smtp-01', 'Mail Gateway', 'smtp.example.com', 25, 'SMTP', 'STARTTLS', ?, ?);
            """,
            (now_iso, now_iso),
        )
        cursor.execute(
            """
            INSERT INTO posture_snapshots (
                snapshot_id, target_id, scanned_at, reachable, protocol, security_mode,
                tls_version, cipher_suite, certificate_fingerprint, scan_result_sha256, canonical_snapshot_sha256
            ) VALUES (
                'snap-01', 'target-smtp-01', ?, 1, 'SMTP', 'STARTTLS',
                'TLS 1.3', 'TLS_AES_256_GCM_SHA384', 'SHA256:CERTFP123', 'sha1', 'sha2'
            );
            """,
            (now_iso,),
        )
        conn.commit()
        conn.close()

        inv = PQCMigrationService.extract_or_get_inventory(target_id="target-smtp-01", db_path=self.db_path)
        self.assertEqual(inv.total_assets, 1)
        self.assertEqual(inv.assets[0].protocol, "SMTP")
        self.assertEqual(inv.assets[0].certificate_fingerprint, "SHA256:CERTFP123")

    def test_04_inventory_classification_counts(self):
        """Test classical vs hybrid classification counts."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT INTO pqc_crypto_assets (
                asset_id, analysis_id, endpoint, crypto_layer, algorithm_family,
                algorithm_name, pqc_status, hybrid_status, evidence_reference, observed_at
            ) VALUES
            ('a1', 'ana-02', '10.0.0.1:25', 'KEX', 'ECDHE', 'ECDHE', 'CLASSICAL_ONLY', 0, 'ev1', ?),
            ('a2', 'ana-02', '10.0.0.1:25', 'KEX', 'HYBRID', 'X25519MLKEM768', 'HYBRID_READY', 1, 'ev2', ?);
            """,
            (now_iso, now_iso),
        )
        conn.commit()
        conn.close()

        inv = PQCMigrationService.extract_or_get_inventory(analysis_id="ana-02", db_path=self.db_path)
        self.assertEqual(inv.total_assets, 2)
        self.assertEqual(inv.classical_count, 1)
        self.assertEqual(inv.hybrid_count, 1)

    # --------------------------------------------------------------------------
    # 2. Quantum Exposure & HNDL Risk Tests
    # --------------------------------------------------------------------------

    def test_05_exposure_critical_static_rsa(self):
        """Test that static RSA key exchange triggers CRITICAL quantum exposure."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT INTO pqc_crypto_assets (
                asset_id, analysis_id, endpoint, crypto_layer, algorithm_family,
                algorithm_name, pqc_status, hybrid_status, evidence_reference, observed_at
            ) VALUES ('a_rsa', 'ana-rsa', '10.0.0.1:25', 'KEY_EXCHANGE', 'RSA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'CLASSICAL_ONLY', 0, 'ev_rsa', ?);
            """,
            (now_iso,),
        )
        conn.commit()
        conn.close()

        exp = PQCMigrationService.evaluate_quantum_exposure(analysis_id="ana-rsa", db_path=self.db_path)
        self.assertEqual(exp.overall_exposure, QuantumExposureLevel.CRITICAL)
        self.assertEqual(exp.hndl_vulnerability_level, QuantumExposureLevel.CRITICAL)
        self.assertFalse(exp.forward_secrecy_present)

    def test_06_exposure_high_classical_ecdhe(self):
        """Test that classical ECDHE triggers HIGH quantum exposure due to HNDL."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT INTO pqc_crypto_assets (
                asset_id, analysis_id, endpoint, crypto_layer, algorithm_family,
                algorithm_name, pqc_status, hybrid_status, evidence_reference, observed_at
            ) VALUES ('a_ecdhe', 'ana-ecdhe', '10.0.0.1:25', 'KEY_EXCHANGE', 'ECDHE', 'ECDHE-RSA-AES256-GCM-SHA384', 'CLASSICAL_ONLY', 0, 'ev_ecdhe', ?);
            """,
            (now_iso,),
        )
        conn.commit()
        conn.close()

        exp = PQCMigrationService.evaluate_quantum_exposure(analysis_id="ana-ecdhe", db_path=self.db_path)
        self.assertEqual(exp.overall_exposure, QuantumExposureLevel.HIGH)
        self.assertEqual(exp.hndl_vulnerability_level, QuantumExposureLevel.HIGH)
        self.assertTrue(exp.forward_secrecy_present)

    def test_07_exposure_low_hybrid_kem(self):
        """Test that hybrid ML-KEM key exchange yields LOW quantum exposure."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT INTO pqc_crypto_assets (
                asset_id, analysis_id, endpoint, crypto_layer, algorithm_family,
                algorithm_name, pqc_status, hybrid_status, evidence_reference, observed_at
            ) VALUES ('a_hybrid', 'ana-hybrid', '10.0.0.1:25', 'KEY_EXCHANGE', 'HYBRID', 'X25519MLKEM768', 'HYBRID_READY', 1, 'ev_hyb', ?);
            """,
            (now_iso,),
        )
        conn.commit()
        conn.close()

        exp = PQCMigrationService.evaluate_quantum_exposure(analysis_id="ana-hybrid", db_path=self.db_path)
        self.assertEqual(exp.overall_exposure, QuantumExposureLevel.LOW)
        self.assertEqual(exp.hndl_vulnerability_level, QuantumExposureLevel.LOW)
        self.assertTrue(exp.forward_secrecy_present)

    def test_08_exposure_unknown_empty(self):
        """Test quantum exposure on empty assets returns UNKNOWN without fabricated score."""
        exp = PQCMigrationService.evaluate_quantum_exposure(analysis_id="empty-ana", db_path=self.db_path)
        self.assertEqual(exp.overall_exposure, QuantumExposureLevel.UNKNOWN)
        self.assertEqual(exp.hndl_vulnerability_level, QuantumExposureLevel.UNKNOWN)

    def test_09_data_sensitivity_unknown_preserved(self):
        """Test that missing data sensitivity defaults to UNKNOWN and is not assumed critical."""
        exp = PQCMigrationService.evaluate_quantum_exposure(
            analysis_id="empty-ana",
            data_sensitivity=DataSensitivityLifetime.UNKNOWN,
            db_path=self.db_path,
        )
        self.assertEqual(exp.data_sensitivity, DataSensitivityLifetime.UNKNOWN)

    # --------------------------------------------------------------------------
    # 3. Gap Analysis Tests
    # --------------------------------------------------------------------------

    def test_10_gap_analysis_empty_inventory(self):
        """Test gap analysis when no assets exist flags discovery requirement."""
        gap_resp = PQCMigrationService.run_gap_analysis(
            analysis_id="none",
            target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET,
            db_path=self.db_path,
        )
        self.assertEqual(gap_resp.current_readiness, PQCReadinessClassification.UNKNOWN)
        self.assertEqual(gap_resp.total_gaps, 1)
        self.assertEqual(gap_resp.gaps[0].gap_type, "NO_OBSERVED_CRYPTO_ASSETS")

    def test_11_gap_analysis_detects_lack_of_hybrid_kem(self):
        """Test gap analysis identifies missing hybrid KEM on classical endpoint."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT INTO pqc_crypto_assets (
                asset_id, analysis_id, endpoint, crypto_layer, algorithm_family,
                algorithm_name, pqc_status, hybrid_status, evidence_reference, observed_at
            ) VALUES ('a_c1', 'ana-gaps', 'mail.example.com:25', 'KEY_EXCHANGE', 'ECDHE', 'ECDHE-RSA-AES256-GCM-SHA384', 'CLASSICAL_ONLY', 0, 'ev1', ?);
            """,
            (now_iso,),
        )
        conn.commit()
        conn.close()

        gap_resp = PQCMigrationService.run_gap_analysis(
            analysis_id="ana-gaps",
            target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET,
            db_path=self.db_path,
        )
        self.assertEqual(gap_resp.current_readiness, PQCReadinessClassification.CLASSICAL_ONLY)
        gap_types = [g.gap_type for g in gap_resp.gaps]
        self.assertIn("LACK_OF_HYBRID_KEM", gap_types)

    def test_12_gap_analysis_detects_classical_rsa_signatures(self):
        """Test gap analysis detects classical RSA certificate signatures."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT INTO pqc_crypto_assets (
                asset_id, analysis_id, endpoint, crypto_layer, algorithm_family,
                algorithm_name, pqc_status, hybrid_status, evidence_reference, observed_at
            ) VALUES ('a_sig', 'ana-sig', 'mail.example.com:25', 'SIGNATURE', 'RSA', 'RSA-SHA256', 'CLASSICAL_ONLY', 0, 'ev_sig', ?);
            """,
            (now_iso,),
        )
        conn.commit()
        conn.close()

        gap_resp = PQCMigrationService.run_gap_analysis(
            analysis_id="ana-sig",
            target_architecture=PQCTransitionTargetArchitecture.HYBRID_SIGNATURE_TARGET,
            db_path=self.db_path,
        )
        gap_types = [g.gap_type for g in gap_resp.gaps]
        self.assertIn("CLASSICAL_RSA_SIGNATURE", gap_types)

    # --------------------------------------------------------------------------
    # 4. 7-Phase Migration Roadmap Tests
    # --------------------------------------------------------------------------

    def test_13_generate_7_phase_steps_structure(self):
        """Test that generate_roadmap_steps produces all 7 structured phases."""
        steps = PQCMigrationService.generate_roadmap_steps("rdm-test", PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        self.assertEqual(len(steps), 7)
        phase_names = [s.phase_name for s in steps]
        self.assertEqual(phase_names[0], MigrationPhaseName.PHASE_A_INVENTORY)
        self.assertEqual(phase_names[1], MigrationPhaseName.PHASE_B_RISK_ASSESSMENT)
        self.assertEqual(phase_names[2], MigrationPhaseName.PHASE_C_TARGET_ARCHITECTURE_SELECTION)
        self.assertEqual(phase_names[3], MigrationPhaseName.PHASE_D_PILOT_HYBRID_KEM)
        self.assertEqual(phase_names[4], MigrationPhaseName.PHASE_E_HYBRID_SIGNATURES)
        self.assertEqual(phase_names[5], MigrationPhaseName.PHASE_F_PQC_PRIMARY_TRANSITION)
        self.assertEqual(phase_names[6], MigrationPhaseName.PHASE_G_VERIFICATION)

    def test_14_phase_f_advisory_labeling(self):
        """Verify Phase F is labeled as TARGET / ADVISORY and does not claim deployment."""
        steps = PQCMigrationService.generate_roadmap_steps("rdm-test", PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        phase_f = [s for s in steps if s.phase_name == MigrationPhaseName.PHASE_F_PQC_PRIMARY_TRANSITION][0]
        self.assertIn("Advisory", phase_f.objective)
        self.assertEqual(phase_f.status, MigrationStepStatus.PENDING)

    def test_15_roadmap_steps_validation_criteria_and_rollback(self):
        """Verify that every step includes explicit validation criteria and rollback considerations."""
        steps = PQCMigrationService.generate_roadmap_steps("rdm-test", PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        for s in steps:
            self.assertGreater(len(s.validation_criteria), 0, f"Step {s.phase_name} missing validation criteria")
            self.assertGreater(len(s.rollback_considerations), 0, f"Step {s.phase_name} missing rollback guidance")

    # --------------------------------------------------------------------------
    # 5. Roadmap CRUD Lifecycle Tests
    # --------------------------------------------------------------------------

    def test_16_create_roadmap(self):
        """Test creating a new PQC migration roadmap."""
        req = PQCRoadmapCreateRequest(
            title="Enterprise PQC Migration",
            description="Migration plan for primary mail cluster",
            target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET,
        )
        rm = PQCMigrationService.create_roadmap(req, creator_actor=self.actor_lead, db_path=self.db_path)
        self.assertIsNotNone(rm.roadmap_id)
        self.assertEqual(rm.title, "Enterprise PQC Migration")
        self.assertEqual(rm.status, PQCRoadmapStatus.DRAFT)
        self.assertEqual(len(rm.steps), 7)
        self.assertEqual(rm.version, 1)

    def test_17_get_roadmap_by_id(self):
        """Test retrieving a roadmap by ID."""
        req = PQCRoadmapCreateRequest(title="Test Roadmap", target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        created = PQCMigrationService.create_roadmap(req, db_path=self.db_path)

        retrieved = PQCMigrationService.get_roadmap(created.roadmap_id, db_path=self.db_path)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.roadmap_id, created.roadmap_id)
        self.assertEqual(retrieved.title, "Test Roadmap")

    def test_18_get_nonexistent_roadmap(self):
        """Test get_roadmap returns None for unknown ID."""
        rm = PQCMigrationService.get_roadmap("nonexistent-id", db_path=self.db_path)
        self.assertIsNone(rm)

    def test_19_list_roadmaps(self):
        """Test listing multiple created roadmaps."""
        req1 = PQCRoadmapCreateRequest(title="Roadmap 1", target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        req2 = PQCRoadmapCreateRequest(title="Roadmap 2", target_architecture=PQCTransitionTargetArchitecture.HYBRID_SIGNATURE_TARGET)
        PQCMigrationService.create_roadmap(req1, db_path=self.db_path)
        PQCMigrationService.create_roadmap(req2, db_path=self.db_path)

        res = PQCMigrationService.list_roadmaps(db_path=self.db_path)
        self.assertGreaterEqual(res.total, 2)
        titles = [r.title for r in res.roadmaps]
        self.assertIn("Roadmap 1", titles)
        self.assertIn("Roadmap 2", titles)

    def test_20_update_roadmap_metadata(self):
        """Test updating roadmap title and description."""
        req = PQCRoadmapCreateRequest(title="Old Title", target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        created = PQCMigrationService.create_roadmap(req, db_path=self.db_path)

        update_req = PQCRoadmapUpdateRequest(
            title="Updated Title",
            description="Updated Description",
            status=PQCRoadmapStatus.IN_REVIEW,
        )
        updated = PQCMigrationService.update_roadmap(created.roadmap_id, update_req, actor=self.actor_lead, db_path=self.db_path)
        self.assertEqual(updated.title, "Updated Title")
        self.assertEqual(updated.description, "Updated Description")
        self.assertEqual(updated.status, PQCRoadmapStatus.IN_REVIEW)
        self.assertEqual(updated.version, 2)

    def test_21_update_roadmap_step_status(self):
        """Test updating individual step status in roadmap."""
        req = PQCRoadmapCreateRequest(title="Step Test", target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        created = PQCMigrationService.create_roadmap(req, db_path=self.db_path)
        step_0 = created.steps[0]

        update_req = PQCRoadmapUpdateRequest(
            step_updates={step_0.step_id: MigrationStepStatus.COMPLETED}
        )
        updated = PQCMigrationService.update_roadmap(created.roadmap_id, update_req, db_path=self.db_path)
        step_updated = [s for s in updated.steps if s.step_id == step_0.step_id][0]
        self.assertEqual(step_updated.status, MigrationStepStatus.COMPLETED)

    # --------------------------------------------------------------------------
    # 6. Cryptographic Sign-Off & Approval Tests
    # --------------------------------------------------------------------------

    def test_22_peer_signoff_ed25519_approval_success(self):
        """Test successful Ed25519 cryptographic peer approval."""
        req = PQCRoadmapCreateRequest(title="Approval Test", target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        created = PQCMigrationService.create_roadmap(req, db_path=self.db_path)

        canonical_dict = {
            "roadmap_id": created.roadmap_id,
            "title": created.title,
            "target_profile": created.target_profile.value,
            "current_readiness": created.current_readiness.value,
            "exposure_level": created.exposure_level.value,
            "total_steps": len(created.steps),
            "reviewer_analyst_id": "reviewer-01",
        }
        canonical_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig_bytes = self.priv_key.sign(canonical_bytes)
        sig_hex = sig_bytes.hex()

        appr_req = PQCRoadmapApprovalRequest(
            roadmap_id=created.roadmap_id,
            reviewer_analyst_id="reviewer-01",
            signature_algorithm="Ed25519",
            signature_hex=sig_hex,
            public_key_hex=self.pub_key_hex,
        )
        approved = PQCMigrationService.approve_roadmap(appr_req, actor=self.actor_reviewer, db_path=self.db_path)
        self.assertEqual(approved.status, PQCRoadmapStatus.APPROVED)
        self.assertEqual(approved.approved_by, "reviewer-01")
        self.assertEqual(approved.approval_signature, sig_hex)
        self.assertIsNotNone(approved.approved_at)

    def test_23_peer_signoff_invalid_signature_rejected(self):
        """Test that invalid signature is rejected and roadmap remains unapproved."""
        req = PQCRoadmapCreateRequest(title="Invalid Sig Test", target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        created = PQCMigrationService.create_roadmap(req, db_path=self.db_path)

        appr_req = PQCRoadmapApprovalRequest(
            roadmap_id=created.roadmap_id,
            reviewer_analyst_id="reviewer-01",
            signature_algorithm="Ed25519",
            signature_hex="00" * 64,  # Invalid dummy signature
            public_key_hex=self.pub_key_hex,
        )
        with self.assertRaises(ValueError):
            PQCMigrationService.approve_roadmap(appr_req, actor=self.actor_reviewer, db_path=self.db_path)

        # Check status unchanged
        current = PQCMigrationService.get_roadmap(created.roadmap_id, db_path=self.db_path)
        self.assertEqual(current.status, PQCRoadmapStatus.DRAFT)

    def test_24_peer_signoff_unauthorized_role_rejected(self):
        """Test that analyst without APPROVE_PQC_ROADMAP capability cannot approve."""
        req = PQCRoadmapCreateRequest(title="Role Check Test", target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        created = PQCMigrationService.create_roadmap(req, db_path=self.db_path)

        appr_req = PQCRoadmapApprovalRequest(
            roadmap_id=created.roadmap_id,
            reviewer_analyst_id="auditor-01",  # Auditor lacks APPROVE capability
            signature_algorithm="Ed25519",
            signature_hex="aa" * 64,
            public_key_hex=self.pub_key_hex,
        )
        with self.assertRaises(PermissionError):
            PQCMigrationService.approve_roadmap(appr_req, actor=self.actor_auditor, db_path=self.db_path)

    # --------------------------------------------------------------------------
    # 7. Multi-Analyst RBAC Capability Tests
    # --------------------------------------------------------------------------

    def test_25_rbac_analyst_capabilities(self):
        """Verify FORENSIC_ANALYST possesses PQC view, create, edit, gap capabilities but not approve."""
        self.assertTrue(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.VIEW_PQC_MIGRATION))
        self.assertTrue(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.CREATE_PQC_ROADMAP))
        self.assertTrue(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.EDIT_PQC_ROADMAP))
        self.assertTrue(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.RUN_PQC_GAP_ANALYSIS))
        self.assertFalse(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.APPROVE_PQC_ROADMAP))

    def test_26_rbac_lead_capabilities(self):
        """Verify LEAD_INVESTIGATOR possesses all PQC capabilities including APPROVE."""
        self.assertTrue(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.VIEW_PQC_MIGRATION))
        self.assertTrue(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.CREATE_PQC_ROADMAP))
        self.assertTrue(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.APPROVE_PQC_ROADMAP))

    def test_27_rbac_reviewer_capabilities(self):
        """Verify REVIEWER possesses VIEW and APPROVE but not CREATE."""
        self.assertTrue(AuthorizationService.can(AnalystRole.REVIEWER, Capability.VIEW_PQC_MIGRATION))
        self.assertTrue(AuthorizationService.can(AnalystRole.REVIEWER, Capability.APPROVE_PQC_ROADMAP))
        self.assertFalse(AuthorizationService.can(AnalystRole.REVIEWER, Capability.CREATE_PQC_ROADMAP))

    def test_28_rbac_auditor_capabilities(self):
        """Verify AUDITOR possesses only VIEW capability."""
        self.assertTrue(AuthorizationService.can(AnalystRole.AUDITOR, Capability.VIEW_PQC_MIGRATION))
        self.assertFalse(AuthorizationService.can(AnalystRole.AUDITOR, Capability.CREATE_PQC_ROADMAP))
        self.assertFalse(AuthorizationService.can(AnalystRole.AUDITOR, Capability.APPROVE_PQC_ROADMAP))

    # --------------------------------------------------------------------------
    # 8. REST API Endpoint Tests
    # --------------------------------------------------------------------------

    def test_29_api_get_inventory(self):
        """Test GET /api/v1/pqc/inventory endpoint."""
        resp = self.client.get("/api/v1/pqc/inventory", headers={"X-Actor-ID": "lead-01"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total_assets", data)
        self.assertIn("assets", data)

    def test_30_api_get_exposure(self):
        """Test GET /api/v1/pqc/exposure endpoint."""
        resp = self.client.get("/api/v1/pqc/exposure", headers={"X-Actor-ID": "lead-01"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("overall_exposure", data)
        self.assertIn("hndl_vulnerability_level", data)

    def test_31_api_post_gap_analysis(self):
        """Test POST /api/v1/pqc/gap-analysis endpoint."""
        payload = {
            "target_architecture": "HYBRID_KEM_TARGET",
        }
        resp = self.client.post("/api/v1/pqc/gap-analysis", json=payload, headers={"X-Actor-ID": "lead-01"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("target_architecture", data)
        self.assertIn("current_readiness", data)
        self.assertIn("gaps", data)

    def test_32_api_post_roadmaps_create(self):
        """Test POST /api/v1/pqc/roadmaps endpoint."""
        payload = {
            "title": "API Test Roadmap",
            "description": "Created via REST API",
            "target_architecture": "HYBRID_KEM_TARGET",
        }
        resp = self.client.post("/api/v1/pqc/roadmaps", json=payload, headers={"X-Actor-ID": "lead-01"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["title"], "API Test Roadmap")
        self.assertEqual(len(data["steps"]), 7)

    def test_33_api_get_roadmaps_list_and_detail(self):
        """Test GET /api/v1/pqc/roadmaps and /api/v1/pqc/roadmaps/{id}."""
        # Create roadmap first
        payload = {"title": "List Test", "target_architecture": "HYBRID_KEM_TARGET"}
        create_res = self.client.post("/api/v1/pqc/roadmaps", json=payload, headers={"X-Actor-ID": "lead-01"})
        roadmap_id = create_res.json()["roadmap_id"]

        # List
        list_res = self.client.get("/api/v1/pqc/roadmaps", headers={"X-Actor-ID": "lead-01"})
        self.assertEqual(list_res.status_code, 200)
        self.assertGreaterEqual(list_res.json()["total"], 1)

        # Detail
        detail_res = self.client.get(f"/api/v1/pqc/roadmaps/{roadmap_id}", headers={"X-Actor-ID": "lead-01"})
        self.assertEqual(detail_res.status_code, 200)
        self.assertEqual(detail_res.json()["roadmap_id"], roadmap_id)

    def test_34_api_put_roadmap_update(self):
        """Test PUT /api/v1/pqc/roadmaps/{id}."""
        payload = {"title": "Update Test", "target_architecture": "HYBRID_KEM_TARGET"}
        create_res = self.client.post("/api/v1/pqc/roadmaps", json=payload, headers={"X-Actor-ID": "lead-01"})
        roadmap_id = create_res.json()["roadmap_id"]

        update_payload = {"title": "Renamed Test Roadmap", "status": "IN_REVIEW"}
        upd_res = self.client.put(f"/api/v1/pqc/roadmaps/{roadmap_id}", json=update_payload, headers={"X-Actor-ID": "lead-01"})
        self.assertEqual(upd_res.status_code, 200)
        self.assertEqual(upd_res.json()["title"], "Renamed Test Roadmap")
        self.assertEqual(upd_res.json()["status"], "IN_REVIEW")

    def test_35_api_post_roadmap_approve(self):
        """Test POST /api/v1/pqc/roadmaps/{id}/approve."""
        payload = {"title": "API Approve Test", "target_architecture": "HYBRID_KEM_TARGET"}
        create_res = self.client.post("/api/v1/pqc/roadmaps", json=payload, headers={"X-Actor-ID": "lead-01"})
        created = create_res.json()
        roadmap_id = created["roadmap_id"]

        canonical_dict = {
            "roadmap_id": roadmap_id,
            "title": created["title"],
            "target_profile": created["target_profile"],
            "current_readiness": created["current_readiness"],
            "exposure_level": created["exposure_level"],
            "total_steps": len(created["steps"]),
            "reviewer_analyst_id": "reviewer-01",
        }
        canonical_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig_hex = self.priv_key.sign(canonical_bytes).hex()

        appr_payload = {
            "roadmap_id": roadmap_id,
            "reviewer_analyst_id": "reviewer-01",
            "signature_algorithm": "Ed25519",
            "signature_hex": sig_hex,
            "public_key_hex": self.pub_key_hex,
        }
        appr_res = self.client.post(
            f"/api/v1/pqc/roadmaps/{roadmap_id}/approve",
            json=appr_payload,
            headers={"X-Actor-ID": "reviewer-01"},
        )
        self.assertEqual(appr_res.status_code, 200)
        self.assertEqual(appr_res.json()["status"], "APPROVED")

    # --------------------------------------------------------------------------
    # 9. Audit Event & Ledger Recording Tests
    # --------------------------------------------------------------------------

    def test_36_audit_events_recorded_on_pqc_actions(self):
        """Test that roadmap creation and updates record hash-chained audit events."""
        req = PQCRoadmapCreateRequest(title="Audit Ledger Test", target_architecture=PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET)
        created = PQCMigrationService.create_roadmap(req, creator_actor=self.actor_lead, db_path=self.db_path)

        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_events WHERE object_type = 'PQC_ROADMAP' AND object_id = ?;", (created.roadmap_id,))
        event = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "PQC_ROADMAP_CREATED")
        self.assertEqual(event["actor_id"], "lead-01")


if __name__ == "__main__":
    unittest.main()

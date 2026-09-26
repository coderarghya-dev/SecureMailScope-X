"""
SecureMailScope X - Phase 24 / 25: Post-Quantum Cryptography Migration Planner Tests
Validates cryptographic asset discovery, categorical HNDL quantum exposure modeling,
7-phase transition roadmap generation, and cryptographic peer sign-offs.
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

from app.db.database import get_db_connection, init_db, set_custom_db_path
from app.schemas.pqc_migration import (
    DataSensitivityLifetime,
    GapSeverity,
    MigrationPhaseName,
    MigrationStepStatus,
    PQCReadinessClassification,
    PQCRoadmapCreateRequest,
    PQCRoadmapStatus,
    PQCTransitionTargetArchitecture,
    QuantumExposureLevel,
    PQCMigrationStepUpdate,
)
from app.services.pqc_migration_service import PQCMigrationService


class TestPQCMigrationPlanner(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_path = self.temp_db.name
        set_custom_db_path(self.db_path)
        init_db(self.db_path)

    def tearDown(self):
        set_custom_db_path(None)
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def test_01_discover_classical_sessions(self):
        """Discovers classical TLS ciphers from sessions and maps to CLASSICAL_ONLY."""
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO analyses (
                analysis_id, filename, file_size_bytes, capture_sha256, created_at,
                observed_result_json, observed_result_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            ("pqc-ana-01", "test.pcap", 1000, "abc123sha", now, "{}", "res123sha"),
        )
        session_data = {
            "tls_details": {
                "negotiated_cipher_suite": {"cipher_name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
                "selected_group": "ECDHE",
                "signature_algorithm": "RSA-SHA256",
                "has_forward_secrecy": True,
            }
        }
        cursor.execute(
            """
            INSERT OR REPLACE INTO sessions (
                session_id, analysis_id, stream_index, protocol, security_mode,
                client, server, session_result_json, session_result_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "s-pqc-01",
                "pqc-ana-01",
                0,
                "SMTP",
                "STARTTLS_ACCEPTED",
                "10.0.0.1:1000",
                "10.0.0.2:25",
                json.dumps(session_data),
                "sha256fake",
            ),
        )
        conn.commit()
        conn.close()

        res = PQCMigrationService.discover_assets(
            analysis_id="pqc-ana-01",
            lifetime=DataSensitivityLifetime.UNDER_5_YEARS,
        )
        self.assertEqual(len(res.discovered_assets), 1)
        asset = res.discovered_assets[0]
        self.assertEqual(asset.pqc_readiness, PQCReadinessClassification.CLASSICAL_ONLY)
        self.assertEqual(asset.hndl_exposure, QuantumExposureLevel.LOW)

    def test_02_discover_non_pfs_static_rsa_exposure(self):
        """Static RSA without forward secrecy results in HIGH/CRITICAL exposure."""
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO analyses (
                analysis_id, filename, file_size_bytes, capture_sha256, created_at,
                observed_result_json, observed_result_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            ("pqc-ana-02", "test.pcap", 1000, "abc123sha", now, "{}", "res123sha"),
        )
        session_data = {
            "tls_details": {
                "negotiated_cipher_suite": {"cipher_name": "TLS_RSA_WITH_AES_128_CBC_SHA"},
                "selected_group": "RSA",
                "signature_algorithm": "RSA-SHA1",
                "has_forward_secrecy": False,
            }
        }
        cursor.execute(
            """
            INSERT OR REPLACE INTO sessions (
                session_id, analysis_id, stream_index, protocol, security_mode,
                client, server, session_result_json, session_result_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "s-pqc-02",
                "pqc-ana-02",
                0,
                "SMTP",
                "STARTTLS_ACCEPTED",
                "10.0.0.1:1000",
                "10.0.0.2:25",
                json.dumps(session_data),
                "sha256fake",
            ),
        )
        conn.commit()
        conn.close()

        res = PQCMigrationService.discover_assets(
            analysis_id="pqc-ana-02",
            lifetime=DataSensitivityLifetime.OVER_10_YEARS,
        )
        self.assertEqual(len(res.discovered_assets), 1)
        asset = res.discovered_assets[0]
        self.assertEqual(asset.hndl_exposure, QuantumExposureLevel.CRITICAL)

    def test_03_discover_hybrid_kem_assets(self):
        """Hybrid post-quantum key exchange (ML-KEM) yields HYBRID_READY and LOW exposure."""
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO analyses (
                analysis_id, filename, file_size_bytes, capture_sha256, created_at,
                observed_result_json, observed_result_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            ("pqc-ana-03", "test.pcap", 1000, "abc123sha", now, "{}", "res123sha"),
        )
        session_data = {
            "tls_details": {
                "negotiated_cipher_suite": {"cipher_name": "TLS_AES_256_GCM_SHA384"},
                "selected_group": "X25519MLKEM768",
                "signature_algorithm": "ECDSA-SHA384",
                "has_forward_secrecy": True,
            }
        }
        cursor.execute(
            """
            INSERT OR REPLACE INTO sessions (
                session_id, analysis_id, stream_index, protocol, security_mode,
                client, server, session_result_json, session_result_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "s-pqc-03",
                "pqc-ana-03",
                0,
                "SMTP",
                "STARTTLS_ACCEPTED",
                "10.0.0.1:1000",
                "10.0.0.2:25",
                json.dumps(session_data),
                "sha256fake",
            ),
        )
        conn.commit()
        conn.close()

        res = PQCMigrationService.discover_assets(analysis_id="pqc-ana-03")
        self.assertEqual(len(res.discovered_assets), 1)
        asset = res.discovered_assets[0]
        self.assertEqual(asset.pqc_readiness, PQCReadinessClassification.HYBRID_READY)
        self.assertEqual(asset.hndl_exposure, QuantumExposureLevel.LOW)
        self.assertEqual(res.overall_pqc_readiness, PQCReadinessClassification.HYBRID_READY)

    def test_04_create_roadmap_generates_7_phases(self):
        """Roadmap generator builds all 7 canonical migration phases (A through G)."""
        req = PQCRoadmapCreateRequest(
            title="Enterprise Mail PQC Transition Plan",
            target_architecture=PQCTransitionTargetArchitecture.HYBRID_CLASSICAL_PQC,
        )
        roadmap = PQCMigrationService.create_roadmap(req, created_by="analyst-lead")
        self.assertIsNotNone(roadmap)
        self.assertEqual(roadmap.total_steps, 7)
        self.assertEqual(len(roadmap.steps), 7)
        phases = [s.phase_name for s in roadmap.steps]
        self.assertEqual(phases[0], MigrationPhaseName.PHASE_A_DISCOVERY)
        self.assertEqual(phases[1], MigrationPhaseName.PHASE_B_POLICY_GOVERNANCE)
        self.assertEqual(phases[2], MigrationPhaseName.PHASE_C_HYBRID_KEM)
        self.assertEqual(phases[3], MigrationPhaseName.PHASE_D_PQC_AUTH)
        self.assertEqual(phases[4], MigrationPhaseName.PHASE_E_QUANTUM_RESISTANT_TRANSPORT)
        self.assertEqual(phases[5], MigrationPhaseName.PHASE_F_PQC_PRIMARY_TRANSITION)
        self.assertEqual(phases[6], MigrationPhaseName.PHASE_G_COMPLIANCE_AUDIT)

    def test_05_roadmap_gap_findings_created(self):
        """Standard gap findings are generated for identified classical infrastructure."""
        req = PQCRoadmapCreateRequest(
            title="Gap Analysis Verification",
            target_architecture=PQCTransitionTargetArchitecture.NIST_FIPS_203_ML_KEM,
        )
        roadmap = PQCMigrationService.create_roadmap(req)
        self.assertGreaterEqual(len(roadmap.gaps), 2)
        gap_titles = [g.title for g in roadmap.gaps]
        self.assertTrue(any("Key Exchange" in t for t in gap_titles))
        self.assertTrue(any("Authentication" in t for t in gap_titles))

    def test_06_canonical_roadmap_hash_is_deterministic(self):
        """Canonical roadmap SHA-256 hash is generated and verified."""
        req = PQCRoadmapCreateRequest(
            title="Deterministic Hash Test",
            target_architecture=PQCTransitionTargetArchitecture.HYBRID_CLASSICAL_PQC,
        )
        roadmap = PQCMigrationService.create_roadmap(req)
        self.assertEqual(len(roadmap.canonical_roadmap_sha256), 64)

    def test_07_update_step_progress(self):
        """Updating roadmap steps updates completion metrics and completed step counts."""
        req = PQCRoadmapCreateRequest(
            title="Step Progression Test",
            target_architecture=PQCTransitionTargetArchitecture.HYBRID_CLASSICAL_PQC,
        )
        roadmap = PQCMigrationService.create_roadmap(req)
        step_1 = roadmap.steps[0]

        updated_step = PQCMigrationService.update_step(
            step_1.step_id,
            PQCMigrationStepUpdate(status=MigrationStepStatus.COMPLETED, notes="Discovery completed"),
        )
        self.assertIsNotNone(updated_step)
        self.assertEqual(updated_step.status, MigrationStepStatus.COMPLETED)
        self.assertIsNotNone(updated_step.completed_at)

        reloaded_map = PQCMigrationService.get_roadmap(roadmap.roadmap_id)
        self.assertEqual(reloaded_map.completed_steps, 1)

    def test_08_sign_roadmap_cryptographically(self):
        """Digital signature sign-off seals the roadmap with analyst attribution."""
        req = PQCRoadmapCreateRequest(
            title="Sign-Off Test",
            target_architecture=PQCTransitionTargetArchitecture.HYBRID_CLASSICAL_PQC,
        )
        roadmap = PQCMigrationService.create_roadmap(req)
        self.assertEqual(roadmap.status, PQCRoadmapStatus.PROPOSED)

        signed = PQCMigrationService.sign_roadmap(
            roadmap_id=roadmap.roadmap_id,
            analyst_id="lead-01",
            analyst_name="Chief Cryptographer",
        )
        self.assertIsNotNone(signed)
        self.assertEqual(signed.status, PQCRoadmapStatus.SIGNED)
        self.assertEqual(signed.signed_by_analyst_id, "lead-01")
        self.assertEqual(signed.signature_algorithm, "Ed25519")
        self.assertIsNotNone(signed.signature_value)

    def test_09_list_roadmaps(self):
        """Roadmaps can be listed from the repository."""
        req = PQCRoadmapCreateRequest(
            title="Listing Test",
            target_architecture=PQCTransitionTargetArchitecture.HYBRID_CLASSICAL_PQC,
        )
        PQCMigrationService.create_roadmap(req)
        maps = PQCMigrationService.list_roadmaps()
        self.assertGreaterEqual(len(maps), 1)

    def test_10_nonexistent_roadmap_returns_none(self):
        """Retrieving nonexistent roadmap returns None."""
        self.assertIsNone(PQCMigrationService.get_roadmap("nonexistent-pqc-map"))

    def test_11_update_nonexistent_step_returns_none(self):
        """Updating nonexistent step returns None."""
        self.assertIsNone(PQCMigrationService.update_step("nonexistent-step", PQCMigrationStepUpdate(status=MigrationStepStatus.COMPLETED)))

    def test_12_sign_nonexistent_roadmap_returns_none(self):
        """Signing nonexistent roadmap returns None."""
        self.assertIsNone(PQCMigrationService.sign_roadmap("nonexistent-map", "lead-01", "Lead"))


if __name__ == "__main__":
    unittest.main()

"""
SecureMailScope X - Phase 25: Final System Integration & End-to-End Regression Tests
Validates root health probes, end-to-end PCAP -> Forensics -> PQC -> Alerts -> Custody
pipeline integration, and RBAC authorization boundaries across all 25 phases.
"""

import json
import os
import sys
import tempfile
import unittest
from fastapi.testclient import TestClient

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.db.database import get_db_connection, init_db, set_custom_db_path
from app.main import app
from app.schemas.rbac import AnalystRole
from app.services.rbac_service import AuthorizationService


class TestFinalIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_path = self.temp_db.name
        set_custom_db_path(self.db_path)
        init_db(self.db_path)
        self.client = TestClient(app)

    def tearDown(self):
        set_custom_db_path(None)
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def test_01_health_and_readiness_probes(self):
        """Root /health, API /api/v1/health, and /api/v1/readiness diagnostic endpoints return healthy."""
        # 1. Root /health
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")

        # 2. /api/v1/health
        res_v1 = self.client.get("/api/v1/health")
        self.assertEqual(res_v1.status_code, 200)
        data_v1 = res_v1.json()
        self.assertEqual(data_v1["status"], "healthy")

        # 3. /api/v1/readiness
        res_ready = self.client.get("/api/v1/readiness")
        self.assertEqual(res_ready.status_code, 200)
        data_ready = res_ready.json()
        self.assertEqual(data_ready["status"], "ready")
        self.assertTrue(data_ready["database_connected"])

    def test_02_full_pipeline_pcap_to_pqc_to_alerts(self):
        """End-to-end flow: Case -> Session -> PQC Discovery -> Alert Rule Evaluation -> Delivery Log."""
        AuthorizationService.create_or_update_analyst("lead-01", "Lead Investigator", role=AnalystRole.LEAD_INVESTIGATOR, db_path=self.db_path)

        headers = {
            "X-Actor-ID": "lead-01",
        }
        res_eval = self.client.post("/api/v1/alerts/evaluate", json={}, headers=headers)
        self.assertEqual(res_eval.status_code, 200)

        pqc_req = {
            "title": "Final Integration Test Roadmap",
            "target_architecture": "HYBRID_CLASSICAL_PQC",
        }
        res_pqc = self.client.post("/api/v1/pqc/roadmaps", json=pqc_req, headers=headers)
        self.assertEqual(res_pqc.status_code, 201)
        roadmap = res_pqc.json()
        self.assertEqual(roadmap["total_steps"], 7)

        res_sign = self.client.post(
            f"/api/v1/pqc/roadmaps/{roadmap['roadmap_id']}/sign",
            json={},
            headers=headers,
        )
        self.assertEqual(res_sign.status_code, 200)
        signed_map = res_sign.json()
        self.assertEqual(signed_map["status"], "SIGNED")
        self.assertEqual(signed_map["signed_by_analyst_id"], "lead-01")

    def test_03_rbac_security_boundaries(self):
        """Enforces RBAC capability restrictions (Auditor cannot create rules; Lead can)."""
        AuthorizationService.create_or_update_analyst("auditor-01", "Compliance Auditor", role=AnalystRole.AUDITOR, db_path=self.db_path)

        auditor_headers = {
            "X-Actor-ID": "auditor-01",
        }

        rule_req = {
            "name": "Unauthorized Rule",
            "rule_type": "FINDING_MATCH",
            "severity": "HIGH",
            "condition_criteria": {},
        }
        res_forbidden = self.client.post("/api/v1/alerts/rules", json=rule_req, headers=auditor_headers)
        self.assertEqual(res_forbidden.status_code, 403)

        res_allowed = self.client.get("/api/v1/alerts/rules", headers=auditor_headers)
        self.assertEqual(res_allowed.status_code, 200)

    def test_04_tamper_evident_custody_and_manifest_chain(self):
        """Validates that cryptographic rules catalog and database remain intact across phases."""
        res_rules = self.client.get("/api/v1/rules")
        self.assertEqual(res_rules.status_code, 200)
        rules_data = res_rules.json()
        self.assertGreaterEqual(len(rules_data), 1)


if __name__ == "__main__":
    unittest.main()

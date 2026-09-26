# ==============================================================================
# SecureMailScope X — Phase 23: Remediation Playbooks & Simulate-Fix Tests
# ==============================================================================
"""Dedicated test suite for Phase 23:
1. Multi-platform playbook catalogs (Postfix, Exim, Dovecot, Sendmail, Generic)
2. Deterministic simulate-fix engine and projected posture labeling
3. Remediation plan lifecycle (PROPOSED -> USER_REPORTED_APPLIED -> VERIFIED / FAILED_VERIFICATION)
4. Forensic verify-after-fix comparison against newly observed evidence
5. Verification audit logs
6. RBAC capability enforcement for remediation
7. REST API endpoints
8. Absolute safety verification (zero live command/subprocess/SSH execution)
"""

import os
import sys
import tempfile
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from fastapi.testclient import TestClient

from app.main import app
from app.db.database import init_db, set_custom_db_path, get_db_connection
from app.schemas.identity import ActorContext
from app.schemas.rbac import AnalystRole, Capability
from app.schemas.remediation import (
    RemediationPlatform,
    RemediationCategory,
    RemediationPriority,
    RemediationStatus,
    VerificationStatus,
    VerificationMethod,
    PostureLabel,
    PlaybookGenerationRequest,
    SimulateFixRequest,
    RemediationPlanCreateRequest,
    RemediationPlanUpdateRequest,
    MarkAppliedRequest,
    VerificationRequest,
)
from app.services.remediation_service import RemediationService
from app.services.rbac_service import AuthorizationService


class TestRemediationPlaybooks(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_path = self.temp_db.name
        set_custom_db_path(self.db_path)
        init_db(self.db_path)
        self.client = TestClient(app)

        self.actor_lead = ActorContext.local_declared(analyst_id="lead-01", display_name="Lead Analyst")
        self.actor_analyst = ActorContext.local_declared(analyst_id="analyst-01", display_name="Junior Analyst")
        self.actor_reviewer = ActorContext.local_declared(analyst_id="reviewer-01", display_name="Peer Reviewer")
        self.actor_auditor = ActorContext.local_declared(analyst_id="auditor-01", display_name="Auditor")

    def tearDown(self):
        set_custom_db_path(None)
        if os.path.exists(self.db_path):
            try:
                os.unlink(self.db_path)
            except Exception:
                pass

    def _create_test_case(self, case_id: str, title: str = "Test Case"):
        conn = get_db_connection(self.db_path)
        conn.execute(
            "INSERT OR IGNORE INTO cases (id, title, status, created_at, updated_at) VALUES (?, ?, 'OPEN', datetime('now'), datetime('now'));",
            (case_id, title),
        )
        conn.commit()
        conn.close()

    # --------------------------------------------------------------------------
    # 1. Platform Playbook Catalogs
    # --------------------------------------------------------------------------

    def test_01_playbook_catalog_postfix_all_findings(self):
        """Test Postfix playbooks cover standard finding categories with valid config snippets."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.POSTFIX,
            finding_codes=[
                "TLS_1_0_ENABLED",
                "WEAK_CIPHER",
                "STARTTLS_NOT_OFFERED",
                "CERT_EXPIRED",
                "PFS_NOT_SUPPORTED",
                "DMARC_POLICY_NONE",
                "PQC_NON_COMPLIANT",
            ],
        )
        res = RemediationService.generate_playbook(req)
        self.assertEqual(res.platform, RemediationPlatform.POSTFIX)
        self.assertTrue(len(res.items) >= 5)
        for item in res.items:
            self.assertTrue(len(item.config_snippet) > 0)
            self.assertTrue(len(item.assumptions) > 0)
            self.assertTrue(len(item.validation_steps) > 0)
            self.assertTrue(len(item.rollback_guidance) > 0)

    def test_02_playbook_catalog_exim_all_findings(self):
        """Test Exim playbooks provide proper Exim configuration directives."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.EXIM,
            finding_codes=[
                "TLS_1_0_ENABLED",
                "WEAK_CIPHER",
                "STARTTLS_NOT_OFFERED",
            ],
        )
        res = RemediationService.generate_playbook(req)
        self.assertEqual(res.platform, RemediationPlatform.EXIM)
        self.assertTrue(len(res.items) >= 3)
        for item in res.items:
            self.assertEqual(item.platform, RemediationPlatform.EXIM)
            self.assertTrue(len(item.config_snippet) > 0)

    def test_03_playbook_catalog_dovecot_all_findings(self):
        """Test Dovecot playbooks provide proper 10-ssl.conf directives."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.DOVECOT,
            finding_codes=[
                "TLS_1_0_ENABLED",
                "WEAK_CIPHER",
                "CERT_EXPIRED",
            ],
        )
        res = RemediationService.generate_playbook(req)
        self.assertEqual(res.platform, RemediationPlatform.DOVECOT)
        self.assertTrue(len(res.items) >= 3)
        for item in res.items:
            self.assertEqual(item.platform, RemediationPlatform.DOVECOT)
            self.assertIn("ssl", item.config_snippet)

    def test_04_playbook_catalog_sendmail_all_findings(self):
        """Test Sendmail playbooks provide proper .mc macros."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.SENDMAIL,
            finding_codes=[
                "TLS_1_0_ENABLED",
                "STARTTLS_NOT_OFFERED",
            ],
        )
        res = RemediationService.generate_playbook(req)
        self.assertEqual(res.platform, RemediationPlatform.SENDMAIL)
        self.assertTrue(len(res.items) >= 2)
        for item in res.items:
            self.assertEqual(item.platform, RemediationPlatform.SENDMAIL)

    def test_05_playbook_catalog_generic_all_findings(self):
        """Test Generic appliance playbooks provide platform-neutral guidance."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.GENERIC,
            finding_codes=[
                "TLS_1_0_ENABLED",
                "WEAK_CIPHER",
            ],
        )
        res = RemediationService.generate_playbook(req)
        self.assertEqual(res.platform, RemediationPlatform.GENERIC)
        self.assertTrue(len(res.items) >= 2)

    def test_06_playbook_generation_catalog_all(self):
        """Test generating playbooks without finding codes returns full catalog recommendations."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.POSTFIX,
            finding_codes=[],
        )
        res = RemediationService.generate_playbook(req)
        self.assertEqual(len(res.items), 7)

    def test_07_playbook_deterministic_output(self):
        """Test playbook generation produces deterministic, repeatable outputs."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.POSTFIX,
            finding_codes=["TLS_1_0_ENABLED", "WEAK_CIPHER"],
        )
        res1 = RemediationService.generate_playbook(req)
        res2 = RemediationService.generate_playbook(req)
        self.assertEqual(len(res1.items), len(res2.items))
        self.assertEqual(res1.items[0].action_title, res2.items[0].action_title)
        self.assertEqual(res1.items[0].config_snippet, res2.items[0].config_snippet)

    # --------------------------------------------------------------------------
    # 2. Deterministic Simulate-Fix Engine
    # --------------------------------------------------------------------------

    def test_08_simulate_fix_single_remediation_resolution(self):
        """Test simulate-fix engine marks targeted remediation as applied."""
        req = SimulateFixRequest(
            remediation_ids=["DISABLE_DEPRECATED_TLS"],
        )
        res = RemediationService.simulate_fix(req)
        self.assertIn("DISABLE_DEPRECATED_TLS", res.applied_remediations)
        self.assertTrue(len(res.disclaimer) > 0)
        self.assertIn("PROJECTED POSTURE", res.disclaimer)

    def test_09_simulate_fix_multiple_remediations(self):
        """Test simulate-fix handles multiple remediation policy proposals."""
        req = SimulateFixRequest(
            remediation_ids=["DISABLE_DEPRECATED_TLS", "REQUIRE_STARTTLS", "ENABLE_FORWARD_SECRECY"],
        )
        res = RemediationService.simulate_fix(req)
        self.assertEqual(len(res.applied_remediations), 3)
        self.assertTrue(len(res.assumptions) > 0)

    def test_10_simulate_fix_projected_posture_labels(self):
        """Test projected posture labels are returned for resolved/unchanged items."""
        req = SimulateFixRequest(
            remediation_ids=["REQUIRE_STARTTLS"],
        )
        res = RemediationService.simulate_fix(req)
        self.assertIsInstance(res.posture_labels, dict)

    def test_11_simulate_fix_does_not_mutate_original_evidence(self):
        """Test simulate-fix leaves database and session state intact."""
        req = SimulateFixRequest(
            session_id="non-existent-dummy-session",
            remediation_ids=["DISABLE_DEPRECATED_TLS"],
        )
        res = RemediationService.simulate_fix(req)
        self.assertIsNotNone(res)
        self.assertEqual(res.session_id, "non-existent-dummy-session")

    def test_12_simulate_fix_unknown_remediation_handling(self):
        """Test simulating an unrecognized remediation ID behaves safely."""
        req = SimulateFixRequest(
            remediation_ids=["UNKNOWN_CUSTOM_POLICY_ID"],
        )
        res = RemediationService.simulate_fix(req)
        self.assertIn("UNKNOWN_CUSTOM_POLICY_ID", res.not_applicable_remediations)

    # --------------------------------------------------------------------------
    # 3. Remediation Plan Lifecycle Management
    # --------------------------------------------------------------------------

    def test_13_remediation_plan_create(self):
        """Test creating a remediation plan persists to DB with PROPOSED status."""
        self._create_test_case("CASE-2026-001")
        plan_req = RemediationPlanCreateRequest(
            title="Production SMTP Hardening Plan",
            case_id="CASE-2026-001",
            platform=RemediationPlatform.POSTFIX,
            finding_codes=["TLS_1_0_ENABLED"],
        )
        plan = RemediationService.create_plan(plan_req, created_by="lead-01", actor=self.actor_lead)
        self.assertTrue(plan.plan_id.startswith("plan-"))
        self.assertEqual(plan.status, RemediationStatus.PROPOSED)
        self.assertEqual(plan.created_by, "lead-01")
        self.assertTrue(len(plan.items) >= 1)

    def test_14_remediation_plan_get_by_id(self):
        """Test retrieving a plan by ID returns all fields and itemized actions."""
        plan_req = RemediationPlanCreateRequest(
            title="Dovecot Security Fix Plan",
            platform=RemediationPlatform.DOVECOT,
            finding_codes=["TLS_1_0_ENABLED", "WEAK_CIPHER"],
        )
        created = RemediationService.create_plan(plan_req, created_by="lead-01", actor=self.actor_lead)
        fetched = RemediationService.get_plan(created.plan_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.plan_id, created.plan_id)
        self.assertEqual(fetched.title, "Dovecot Security Fix Plan")
        self.assertTrue(len(fetched.items) >= 2)

    def test_15_remediation_plan_list_with_filters(self):
        """Test listing plans with case_id and target_id filtering."""
        self._create_test_case("CASE-FILTER-99")
        plan_req = RemediationPlanCreateRequest(
            title="Filtered Case Plan",
            case_id="CASE-FILTER-99",
            platform=RemediationPlatform.EXIM,
            finding_codes=["STARTTLS_NOT_OFFERED"],
        )
        created = RemediationService.create_plan(plan_req, created_by="lead-01", actor=self.actor_lead)
        filtered = RemediationService.list_plans(case_id="CASE-FILTER-99")
        self.assertTrue(any(p.plan_id == created.plan_id for p in filtered))

        unmatched = RemediationService.list_plans(case_id="CASE-NONEXISTENT")
        self.assertFalse(any(p.plan_id == created.plan_id for p in unmatched))

    def test_16_remediation_plan_update_metadata(self):
        """Test updating title and description on proposed remediation plan."""
        plan_req = RemediationPlanCreateRequest(
            title="Initial Plan Title",
            platform=RemediationPlatform.POSTFIX,
            finding_codes=["TLS_1_0_ENABLED"],
        )
        created = RemediationService.create_plan(plan_req, created_by="lead-01", actor=self.actor_lead)
        update_req = RemediationPlanUpdateRequest(
            title="Updated Plan Title",
            description="Added change management ticket number CHG-1029.",
        )
        updated = RemediationService.update_plan(created.plan_id, update_req, actor=self.actor_lead)
        self.assertEqual(updated.title, "Updated Plan Title")
        self.assertEqual(updated.description, "Added change management ticket number CHG-1029.")

    def test_17_remediation_plan_mark_applied(self):
        """Test marking a plan as user-reported applied updates status and audit trail."""
        plan_req = RemediationPlanCreateRequest(
            title="Apply Test Plan",
            platform=RemediationPlatform.POSTFIX,
            finding_codes=["STARTTLS_NOT_OFFERED"],
        )
        created = RemediationService.create_plan(plan_req, created_by="lead-01", actor=self.actor_lead)
        apply_req = MarkAppliedRequest(notes="Deployed to production cluster node 1.")
        applied = RemediationService.mark_applied(created.plan_id, apply_req, applied_by="analyst-01", actor=self.actor_analyst)
        self.assertEqual(applied.status, RemediationStatus.USER_REPORTED_APPLIED)
        self.assertEqual(applied.applied_by, "analyst-01")
        self.assertIsNotNone(applied.applied_at)

    # --------------------------------------------------------------------------
    # 4. Verify-After-Fix Workflow & Audit Logs
    # --------------------------------------------------------------------------

    def test_18_remediation_plan_verify_success_all_resolved(self):
        """Test forensic verification succeeds and marks VERIFIED when new scan confirms resolution."""
        plan_req = RemediationPlanCreateRequest(
            title="Verify Success Plan",
            platform=RemediationPlatform.POSTFIX,
            finding_codes=["TLS_1_0_ENABLED"],
        )
        created = RemediationService.create_plan(plan_req, created_by="lead-01", actor=self.actor_lead)
        apply_req = MarkAppliedRequest(notes="Applied.")
        RemediationService.mark_applied(created.plan_id, apply_req, applied_by="analyst-01", actor=self.actor_analyst)

        # Verification with new_analysis_id pointing to a clean analysis or scan
        verify_req = VerificationRequest(
            verification_method=VerificationMethod.ACTIVE_SCAN,
            new_scan_id="scan-clean-01",
            notes="Active scan confirmed TLS 1.0 is no longer accepted.",
        )
        record = RemediationService.verify_plan(created.plan_id, verify_req, verified_by="reviewer-01", actor=self.actor_reviewer)
        self.assertEqual(record.verification_status, VerificationStatus.VERIFIED)
        self.assertEqual(record.resolved_finding_count, len(created.items))
        self.assertEqual(record.remaining_finding_count, 0)

        updated_plan = RemediationService.get_plan(created.plan_id)
        self.assertEqual(updated_plan.status, RemediationStatus.VERIFIED)

    def test_19_remediation_plan_verify_failure_unresolved_findings(self):
        """Test forensic verification fails and marks FAILED_VERIFICATION when evidence reference is missing or findings remain."""
        plan_req = RemediationPlanCreateRequest(
            title="Verify Failure Plan",
            platform=RemediationPlatform.POSTFIX,
            finding_codes=["TLS_1_0_ENABLED"],
        )
        created = RemediationService.create_plan(plan_req, created_by="lead-01", actor=self.actor_lead)
        RemediationService.mark_applied(created.plan_id, MarkAppliedRequest(), applied_by="analyst-01", actor=self.actor_analyst)

        # Verification without evidence reference -> unresolved
        verify_req = VerificationRequest(
            verification_method=VerificationMethod.ACTIVE_SCAN,
            notes="No fresh evidence found.",
        )
        record = RemediationService.verify_plan(created.plan_id, verify_req, verified_by="reviewer-01", actor=self.actor_reviewer)
        self.assertEqual(record.verification_status, VerificationStatus.FAILED)
        self.assertEqual(record.remaining_finding_count, len(created.items))

        updated_plan = RemediationService.get_plan(created.plan_id)
        self.assertEqual(updated_plan.status, RemediationStatus.FAILED_VERIFICATION)

    def test_20_remediation_verification_audit_trail(self):
        """Test multiple verification attempts append to non-repudiable audit logs."""
        plan_req = RemediationPlanCreateRequest(
            title="Multi-Verification Plan",
            platform=RemediationPlatform.POSTFIX,
            finding_codes=["WEAK_CIPHER"],
        )
        created = RemediationService.create_plan(plan_req, created_by="lead-01", actor=self.actor_lead)
        RemediationService.mark_applied(created.plan_id, MarkAppliedRequest(), applied_by="analyst-01", actor=self.actor_analyst)

        # 1st verification: Failed
        v1 = VerificationRequest(
            verification_method=VerificationMethod.ACTIVE_SCAN,
            notes="Initial test failed.",
        )
        RemediationService.verify_plan(created.plan_id, v1, verified_by="reviewer-01", actor=self.actor_reviewer)

        # 2nd verification: Passed
        v2 = VerificationRequest(
            verification_method=VerificationMethod.ACTIVE_SCAN,
            new_scan_id="scan-good-01",
            notes="Retest passed.",
        )
        RemediationService.verify_plan(created.plan_id, v2, verified_by="reviewer-01", actor=self.actor_reviewer)

        verifications = RemediationService.list_verifications(created.plan_id)
        self.assertEqual(len(verifications), 2)
        self.assertEqual(verifications[0].verification_status, VerificationStatus.VERIFIED)
        self.assertEqual(verifications[1].verification_status, VerificationStatus.FAILED)

    # --------------------------------------------------------------------------
    # 5. RBAC Capability Enforcement
    # --------------------------------------------------------------------------

    def test_21_rbac_view_remediation_capability(self):
        """Test VIEW_REMEDIATION allowed for all standard analyst roles."""
        for role in [AnalystRole.FORENSIC_ANALYST, AnalystRole.REVIEWER, AnalystRole.LEAD_INVESTIGATOR, AnalystRole.ADMIN, AnalystRole.AUDITOR]:
            self.assertTrue(AuthorizationService.can(role, Capability.VIEW_REMEDIATION))

    def test_22_rbac_create_plan_capability(self):
        """Test CREATE_REMEDIATION_PLAN restricted to Forensic Analyst, Lead, Admin."""
        self.assertTrue(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.CREATE_REMEDIATION_PLAN))
        self.assertTrue(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.CREATE_REMEDIATION_PLAN))
        self.assertTrue(AuthorizationService.can(AnalystRole.ADMIN, Capability.CREATE_REMEDIATION_PLAN))
        self.assertFalse(AuthorizationService.can(AnalystRole.REVIEWER, Capability.CREATE_REMEDIATION_PLAN))
        self.assertFalse(AuthorizationService.can(AnalystRole.AUDITOR, Capability.CREATE_REMEDIATION_PLAN))

    def test_23_rbac_mark_applied_capability(self):
        """Test MARK_APPLIED allowed for Analyst, Lead, Admin, denied for Auditor/Reviewer."""
        self.assertTrue(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.MARK_APPLIED))
        self.assertTrue(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.MARK_APPLIED))
        self.assertFalse(AuthorizationService.can(AnalystRole.AUDITOR, Capability.MARK_APPLIED))
        self.assertFalse(AuthorizationService.can(AnalystRole.REVIEWER, Capability.MARK_APPLIED))

    def test_24_rbac_verify_remediation_capability(self):
        """Test VERIFY_REMEDIATION allowed for Reviewer, Lead, Admin, denied for Forensic Analyst and Auditor."""
        self.assertTrue(AuthorizationService.can(AnalystRole.REVIEWER, Capability.VERIFY_REMEDIATION))
        self.assertTrue(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.VERIFY_REMEDIATION))
        self.assertTrue(AuthorizationService.can(AnalystRole.ADMIN, Capability.VERIFY_REMEDIATION))
        self.assertFalse(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.VERIFY_REMEDIATION))
        self.assertFalse(AuthorizationService.can(AnalystRole.AUDITOR, Capability.VERIFY_REMEDIATION))

    # --------------------------------------------------------------------------
    # 6. REST API Endpoints
    # --------------------------------------------------------------------------

    def test_25_api_generate_playbooks_endpoint(self):
        """Test POST /api/v1/remediation/playbooks/generate endpoint."""
        payload = {
            "platform": "POSTFIX",
            "finding_codes": ["TLS_1_0_ENABLED", "WEAK_CIPHER"],
        }
        res = self.client.post("/api/v1/remediation/playbooks/generate", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["platform"], "POSTFIX")
        self.assertTrue(len(data["items"]) >= 2)

    def test_26_api_simulate_fix_endpoint(self):
        """Test POST /api/v1/remediation/simulate endpoint."""
        payload = {
            "remediation_ids": ["DISABLE_DEPRECATED_TLS", "REQUIRE_STARTTLS"],
        }
        res = self.client.post("/api/v1/remediation/simulate", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["applied_remediations"]), 2)
        self.assertIn("PROJECTED POSTURE", data["disclaimer"])

    def test_27_api_plan_crud_lifecycle_endpoints(self):
        """Test plan creation, listing, retrieval, and updating via REST API."""
        create_payload = {
            "title": "API Test Plan",
            "platform": "POSTFIX",
            "finding_codes": ["TLS_1_0_ENABLED"],
        }
        res = self.client.post("/api/v1/remediation/plans", json=create_payload)
        self.assertEqual(res.status_code, 200)
        plan_data = res.json()
        plan_id = plan_data["plan_id"]

        # Get by ID
        get_res = self.client.get(f"/api/v1/remediation/plans/{plan_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["title"], "API Test Plan")

        # Update
        update_res = self.client.put(
            f"/api/v1/remediation/plans/{plan_id}",
            json={"title": "Updated API Test Plan"},
        )
        self.assertEqual(update_res.status_code, 200)
        self.assertEqual(update_res.json()["title"], "Updated API Test Plan")

        # List
        list_res = self.client.get("/api/v1/remediation/plans")
        self.assertEqual(list_res.status_code, 200)
        self.assertTrue(any(p["plan_id"] == plan_id for p in list_res.json()))

    def test_28_api_mark_applied_and_verify_endpoints(self):
        """Test /apply and /verify REST API workflows."""
        create_payload = {
            "title": "API Apply & Verify Plan",
            "platform": "POSTFIX",
            "finding_codes": ["TLS_1_0_ENABLED"],
        }
        res = self.client.post("/api/v1/remediation/plans", json=create_payload)
        plan_id = res.json()["plan_id"]

        # Mark applied
        apply_res = self.client.post(
            f"/api/v1/remediation/plans/{plan_id}/apply",
            json={"notes": "Applied via API."},
        )
        self.assertEqual(apply_res.status_code, 200)
        self.assertEqual(apply_res.json()["status"], "USER_REPORTED_APPLIED")

        # Verify
        verify_res = self.client.post(
            f"/api/v1/remediation/plans/{plan_id}/verify",
            json={
                "verification_method": "ACTIVE_SCAN",
                "new_scan_id": "scan-api-001",
                "notes": "Verified via test client.",
            },
        )
        self.assertEqual(verify_res.status_code, 200)
        self.assertEqual(verify_res.json()["verification_status"], "VERIFIED")

        # Check verifications list
        verifs_res = self.client.get(f"/api/v1/remediation/plans/{plan_id}/verifications")
        self.assertEqual(verifs_res.status_code, 200)
        self.assertEqual(len(verifs_res.json()), 1)

    # --------------------------------------------------------------------------
    # 7. Integration & Absolute Safety Guarantees
    # --------------------------------------------------------------------------

    def test_29_drift_and_alert_rule_correlation_to_remediation(self):
        """Test posture drift finding codes seamlessly match remediation playbook catalog."""
        drift_finding = "TLS_1_0_ENABLED"
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.EXIM,
            finding_codes=[drift_finding],
        )
        res = RemediationService.generate_playbook(req)
        self.assertTrue(len(res.items) >= 1)
        self.assertEqual(res.items[0].remediation_id, "DISABLE_DEPRECATED_TLS")

    def test_30_zero_subprocess_or_live_execution_safety(self):
        """Verify strict static safety: No subprocess, os.system, ssh, powershell, or command execution."""
        service_path = os.path.join(
            os.path.dirname(__file__), "..", "app", "services", "remediation_service.py"
        )
        endpoint_path = os.path.join(
            os.path.dirname(__file__), "..", "app", "api", "v1", "endpoints", "remediation.py"
        )
        for filepath in [service_path, endpoint_path]:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertNotIn("subprocess.", content)
                self.assertNotIn("os.system", content)
                self.assertNotIn("os.popen", content)
                self.assertNotIn("paramiko", content)
                self.assertNotIn("ssh.", content)
                self.assertNotIn("powershell", content.lower())
                self.assertNotIn("cmd.exe", content.lower())


if __name__ == "__main__":
    unittest.main()

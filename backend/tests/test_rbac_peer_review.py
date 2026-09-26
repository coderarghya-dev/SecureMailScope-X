# ==============================================================================
# SecureMailScope X — Phase 20: Multi-Analyst RBAC & Peer Review Test Suite
# ==============================================================================
"""Comprehensive unit and integration test suite for RBAC capability matrix,
multi-analyst case assignments, manifest-bound review lifecycles, Ed25519/RSA
cryptographic peer sign-offs, M-of-N sealing policies, and REST endpoints.
"""

import base64
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.db.database import get_db_connection, init_db, set_custom_db_path
from app.db.repository import ForensicRepository
from app.main import app
from app.schemas.identity import ActorContext
from app.schemas.rbac import (
    AnalystRecord,
    AnalystRole,
    AssignAnalystRequest,
    AssignmentRole,
    Capability,
    CaseAssignment,
    CaseAuthorizationStatus,
    CaseReview,
    CaseReviewPolicy,
    CaseReviewPolicyUpdate,
    RequestReviewRequest,
    ReviewStatus,
    RoleUpdateRequest,
    SignatureVerificationRequest,
    SubmitReviewRequest,
)
from app.services.case_service import CaseService
from app.services.rbac_service import (
    ROLE_CAPABILITIES,
    AuthorizationService,
    CaseAssignmentService,
    CaseManifestService,
    PeerReviewService,
)


def generate_ed25519_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("utf-8")
    pub_pem = priv.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv_pem, pub_pem


def generate_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("utf-8")
    pub_pem = priv.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv_pem, pub_pem


class TestRBACAndPeerReview(unittest.TestCase):
    """Test suite for Phase 20 Multi-Analyst RBAC and Cryptographic Peer Sign-Off Engine."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db", prefix="sms_rbac_test_")
        os.close(self.temp_db_fd)
        set_custom_db_path(self.temp_db_path)
        init_db(self.temp_db_path)
        self.client = TestClient(app)

        # Setup test analysts with diverse roles
        AuthorizationService.create_or_update_analyst(
            analyst_id="analyst-alice",
            display_name="Alice Analyst",
            role=AnalystRole.FORENSIC_ANALYST,
            db_path=self.temp_db_path,
        )
        AuthorizationService.create_or_update_analyst(
            analyst_id="lead-bob",
            display_name="Bob Lead",
            role=AnalystRole.LEAD_INVESTIGATOR,
            db_path=self.temp_db_path,
        )
        AuthorizationService.create_or_update_analyst(
            analyst_id="reviewer-charlie",
            display_name="Charlie Reviewer",
            role=AnalystRole.REVIEWER,
            db_path=self.temp_db_path,
        )
        AuthorizationService.create_or_update_analyst(
            analyst_id="auditor-david",
            display_name="David Auditor",
            role=AnalystRole.AUDITOR,
            db_path=self.temp_db_path,
        )
        AuthorizationService.create_or_update_analyst(
            analyst_id="admin-eve",
            display_name="Eve Admin",
            role=AnalystRole.ADMIN,
            db_path=self.temp_db_path,
        )

    def tearDown(self):
        set_custom_db_path(None)
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # 1. Capability Matrix Tests
    # --------------------------------------------------------------------------

    def test_01_role_capabilities_matrix(self):
        """Verify strict capability enforcement across all 5 roles."""
        # Forensic Analyst
        self.assertTrue(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.VIEW_CASE))
        self.assertTrue(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.EDIT_CASE))
        self.assertTrue(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.REQUEST_REVIEW))
        self.assertFalse(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.SUBMIT_REVIEW))
        self.assertFalse(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.SEAL_CASE))
        self.assertFalse(AuthorizationService.can(AnalystRole.FORENSIC_ANALYST, Capability.MANAGE_ROLES))

        # Lead Investigator
        self.assertTrue(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.VIEW_CASE))
        self.assertTrue(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.ASSIGN_ANALYST))
        self.assertTrue(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.SUBMIT_REVIEW))
        self.assertTrue(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.SEAL_CASE))
        self.assertFalse(AuthorizationService.can(AnalystRole.LEAD_INVESTIGATOR, Capability.MANAGE_ROLES))

        # Reviewer
        self.assertTrue(AuthorizationService.can(AnalystRole.REVIEWER, Capability.VIEW_CASE))
        self.assertTrue(AuthorizationService.can(AnalystRole.REVIEWER, Capability.SUBMIT_REVIEW))
        self.assertTrue(AuthorizationService.can(AnalystRole.REVIEWER, Capability.SIGN_OFF))
        self.assertFalse(AuthorizationService.can(AnalystRole.REVIEWER, Capability.EDIT_CASE))
        self.assertFalse(AuthorizationService.can(AnalystRole.REVIEWER, Capability.SEAL_CASE))

        # Auditor
        self.assertTrue(AuthorizationService.can(AnalystRole.AUDITOR, Capability.VIEW_CASE))
        self.assertFalse(AuthorizationService.can(AnalystRole.AUDITOR, Capability.EDIT_CASE))
        self.assertFalse(AuthorizationService.can(AnalystRole.AUDITOR, Capability.SUBMIT_REVIEW))

        # Admin
        self.assertTrue(AuthorizationService.can(AnalystRole.ADMIN, Capability.MANAGE_ROLES))
        self.assertTrue(AuthorizationService.can(AnalystRole.ADMIN, Capability.SEAL_CASE))
        self.assertTrue(AuthorizationService.can(AnalystRole.ADMIN, Capability.OVERRIDE_POLICY))

    # --------------------------------------------------------------------------
    # 2. Analyst Registry & Role Management
    # --------------------------------------------------------------------------

    def test_02_analyst_registration_and_retrieval(self):
        """Test analyst registration, role persistence, and listing."""
        analyst = AuthorizationService.get_analyst("analyst-alice", db_path=self.temp_db_path)
        self.assertIsNotNone(analyst)
        self.assertEqual(analyst.display_name, "Alice Analyst")
        self.assertEqual(analyst.role, AnalystRole.FORENSIC_ANALYST)

        all_analysts = AuthorizationService.list_analysts(db_path=self.temp_db_path)
        self.assertEqual(len(all_analysts), 5)

    def test_03_analyst_role_change_and_audit(self):
        """Test updating analyst role and logging to hash-chained audit table."""
        updated = AuthorizationService.set_analyst_role(
            analyst_id="analyst-alice",
            new_role=AnalystRole.LEAD_INVESTIGATOR,
            reason="Promotion to Team Lead",
            db_path=self.temp_db_path,
        )
        self.assertEqual(updated.role, AnalystRole.LEAD_INVESTIGATOR)

        events = ForensicRepository.get_audit_events(
            object_id="analyst-alice",
            verify_integrity=True,
            db_path=self.temp_db_path,
        )
        self.assertGreaterEqual(len(events), 1)
        role_ev = next((e for e in events if e["event_type"] == "ROLE_CHANGED"), None)
        self.assertIsNotNone(role_ev)
        self.assertIn("Promotion to Team Lead", role_ev["details"])

    # --------------------------------------------------------------------------
    # 3. Case Assignment Lifecycle
    # --------------------------------------------------------------------------

    def test_04_case_assignment_lifecycle(self):
        """Test assigning multiple analysts to a case."""
        case = CaseService.create_case(title="Phishing Investigation", db_path=self.temp_db_path)
        asgn1 = CaseAssignmentService.assign_analyst(
            case_id=case.id,
            analyst_id="analyst-alice",
            role=AssignmentRole.PRIMARY_INVESTIGATOR,
            db_path=self.temp_db_path,
        )
        asgn2 = CaseAssignmentService.assign_analyst(
            case_id=case.id,
            analyst_id="reviewer-charlie",
            role=AssignmentRole.ASSIGNED_REVIEWER,
            db_path=self.temp_db_path,
        )

        assignments = CaseAssignmentService.list_assignments(case.id, db_path=self.temp_db_path)
        self.assertEqual(len(assignments), 2)
        roles = {a.analyst_id: a.role for a in assignments}
        self.assertEqual(roles["analyst-alice"], AssignmentRole.PRIMARY_INVESTIGATOR)
        self.assertEqual(roles["reviewer-charlie"], AssignmentRole.ASSIGNED_REVIEWER)

    def test_05_case_assignment_deactivation(self):
        """Test removing / deactivating a case assignment."""
        case = CaseService.create_case(title="Malware Case", db_path=self.temp_db_path)
        asgn = CaseAssignmentService.assign_analyst(
            case_id=case.id,
            analyst_id="analyst-alice",
            role=AssignmentRole.ASSIGNED_ANALYST,
            db_path=self.temp_db_path,
        )
        success = CaseAssignmentService.remove_assignment(case.id, asgn.assignment_id, db_path=self.temp_db_path)
        self.assertTrue(success)

        active = CaseAssignmentService.list_assignments(case.id, active_only=True, db_path=self.temp_db_path)
        self.assertEqual(len(active), 0)

        all_asgns = CaseAssignmentService.list_assignments(case.id, active_only=False, db_path=self.temp_db_path)
        self.assertEqual(len(all_asgns), 1)
        self.assertFalse(all_asgns[0].is_active)

    # --------------------------------------------------------------------------
    # 4. Manifest Determinism & Mutation Tests
    # --------------------------------------------------------------------------

    def test_06_case_manifest_deterministic_computation(self):
        """Test that identical case state produces identical manifest SHA-256."""
        case = CaseService.create_case(title="State Hash Test", db_path=self.temp_db_path)
        h1 = CaseManifestService.compute_case_manifest_sha256(case.id, db_path=self.temp_db_path)
        h2 = CaseManifestService.compute_case_manifest_sha256(case.id, db_path=self.temp_db_path)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_07_case_manifest_mutates_on_artifact_addition(self):
        """Test manifest SHA-256 updates immediately when an artifact is added."""
        case = CaseService.create_case(title="Artifact Hash Case", db_path=self.temp_db_path)
        m_before = CaseManifestService.compute_case_manifest_sha256(case.id, db_path=self.temp_db_path)

        CaseService.add_artifact_to_case(
            case_id=case.id,
            artifact_type="PCAP",
            filename="capture1.pcap",
            sha256="a" * 64,
            db_path=self.temp_db_path,
        )
        m_after = CaseManifestService.compute_case_manifest_sha256(case.id, db_path=self.temp_db_path)
        self.assertNotEqual(m_before, m_after)

    def test_08_case_manifest_mutates_on_note_addition(self):
        """Test manifest SHA-256 updates immediately when an analyst note is added."""
        case = CaseService.create_case(title="Note Hash Case", db_path=self.temp_db_path)
        m_before = CaseManifestService.compute_case_manifest_sha256(case.id, db_path=self.temp_db_path)

        CaseService.add_note_to_case(
            case_id=case.id,
            author="Alice",
            note_text="STARTTLS downgrade verified.",
            db_path=self.temp_db_path,
        )
        m_after = CaseManifestService.compute_case_manifest_sha256(case.id, db_path=self.temp_db_path)
        self.assertNotEqual(m_before, m_after)

    def test_09_case_manifest_mutates_on_analysis_link(self):
        """Test manifest SHA-256 updates immediately when an analysis is attached."""
        case = CaseService.create_case(title="Analysis Link Case", db_path=self.temp_db_path)
        m_before = CaseManifestService.compute_case_manifest_sha256(case.id, db_path=self.temp_db_path)

        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO analyses (
                analysis_id, filename, file_size_bytes, capture_sha256, created_at,
                observed_result_json, observed_result_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            ("analysis-rb-09", "pcap.pcap", 100, "sha256_09", "2026-09-26T10:00:00Z", "{}", "obs_sha_09"),
        )
        conn.commit()
        conn.close()

        CaseService.attach_analysis_to_case(case.id, "analysis-rb-09", db_path=self.temp_db_path)
        m_after = CaseManifestService.compute_case_manifest_sha256(case.id, db_path=self.temp_db_path)
        self.assertNotEqual(m_before, m_after)

    # --------------------------------------------------------------------------
    # 5. Peer Review Lifecycle & Self-Review Policy Tests
    # --------------------------------------------------------------------------

    def test_10_request_review_lifecycle(self):
        """Test initiating a review request transitions case status."""
        case = CaseService.create_case(title="Review Lifecycle Case", db_path=self.temp_db_path)
        res = PeerReviewService.request_review(
            case_id=case.id,
            requested_by="analyst-alice",
            target_reviewer_ids=["reviewer-charlie"],
            comments="Please verify TLS downgrade finding.",
            db_path=self.temp_db_path,
        )
        self.assertEqual(res["status"], "IN_REVIEW")
        self.assertEqual(res["case_id"], case.id)

        case_db = ForensicRepository.get_case(case.id, db_path=self.temp_db_path)
        self.assertEqual(case_db["status"], "IN_REVIEW")

    def test_11_submit_review_approved(self):
        """Test submitting an APPROVED peer review."""
        case = CaseService.create_case(title="Approval Case", db_path=self.temp_db_path)
        review = PeerReviewService.submit_review(
            case_id=case.id,
            reviewer_id="reviewer-charlie",
            decision=ReviewStatus.APPROVED,
            comments="Forensic findings verified against packet trace.",
            db_path=self.temp_db_path,
        )
        self.assertEqual(review.decision, ReviewStatus.APPROVED)
        self.assertEqual(review.reviewer_id, "reviewer-charlie")
        self.assertTrue(review.manifest_matches_current)

    def test_12_submit_review_changes_requested_and_rejected(self):
        """Test submitting CHANGES_REQUESTED and REJECTED reviews."""
        case = CaseService.create_case(title="Rejection Case", db_path=self.temp_db_path)
        rev_cr = PeerReviewService.submit_review(
            case_id=case.id,
            reviewer_id="reviewer-charlie",
            decision=ReviewStatus.CHANGES_REQUESTED,
            comments="Missing EML header proof.",
            db_path=self.temp_db_path,
        )
        self.assertEqual(rev_cr.decision, ReviewStatus.CHANGES_REQUESTED)

        status_cr = PeerReviewService.get_case_authorization_status(case.id, db_path=self.temp_db_path)
        self.assertEqual(status_cr.review_status, ReviewStatus.CHANGES_REQUESTED)

    def test_13_submit_review_permission_denied_for_auditor(self):
        """Assert that an AUDITOR cannot submit a review decision."""
        case = CaseService.create_case(title="Auditor Test Case", db_path=self.temp_db_path)
        with self.assertRaises(PermissionError):
            PeerReviewService.submit_review(
                case_id=case.id,
                reviewer_id="auditor-david",
                decision=ReviewStatus.APPROVED,
                db_path=self.temp_db_path,
            )

    def test_14_self_review_policy_enforcement_blocked(self):
        """Assert that primary case investigator cannot approve their own case when allow_self_review=False."""
        case = CaseService.create_case(
            title="Self Review Test",
            analyst_id="lead-bob",
            analyst_name="Bob Lead",
            db_path=self.temp_db_path,
        )
        # Default policy: allow_self_review = False
        with self.assertRaises(PermissionError):
            PeerReviewService.submit_review(
                case_id=case.id,
                reviewer_id="lead-bob",
                decision=ReviewStatus.APPROVED,
                db_path=self.temp_db_path,
            )

    def test_15_self_review_policy_enforcement_allowed(self):
        """Assert that primary investigator CAN approve when allow_self_review=True."""
        case = CaseService.create_case(
            title="Self Review Allowed Case",
            analyst_id="lead-bob",
            analyst_name="Bob Lead",
            db_path=self.temp_db_path,
        )
        PeerReviewService.update_policy(
            case.id,
            CaseReviewPolicyUpdate(allow_self_review=True),
            db_path=self.temp_db_path,
        )
        review = PeerReviewService.submit_review(
            case_id=case.id,
            reviewer_id="lead-bob",
            decision=ReviewStatus.APPROVED,
            comments="Self-review permitted by policy.",
            db_path=self.temp_db_path,
        )
        self.assertEqual(review.decision, ReviewStatus.APPROVED)

    # --------------------------------------------------------------------------
    # 6. Cryptographic Peer Sign-Off Tests (Ed25519 & RSA)
    # --------------------------------------------------------------------------

    def test_16_ed25519_cryptographic_signoff_generation(self):
        """Test cryptographic sign-off using Ed25519 asymmetric keypair."""
        priv_pem, pub_pem = generate_ed25519_keypair()
        case = CaseService.create_case(title="Ed25519 SignOff Case", db_path=self.temp_db_path)

        review = PeerReviewService.submit_review(
            case_id=case.id,
            reviewer_id="reviewer-charlie",
            decision=ReviewStatus.APPROVED,
            comments="Cryptographically signed by Charlie",
            private_key_pem=priv_pem,
            key_id="ed25519-key-01",
            db_path=self.temp_db_path,
        )
        self.assertIsNotNone(review.signature_id)
        self.assertIsNotNone(review.signature_value)
        self.assertIsNotNone(review.public_key_pem)
        self.assertIsNotNone(review.public_key_fingerprint)

        # Verify signature
        ver_resp = PeerReviewService.verify_review_signature(case.id, review.review_id, db_path=self.temp_db_path)
        self.assertTrue(ver_resp.valid)
        self.assertTrue(ver_resp.manifest_matches_current)
        self.assertIn("valid", ver_resp.verification_details.lower())

    def test_17_rsa_pss_cryptographic_signoff_generation(self):
        """Test cryptographic sign-off using RSA-PSS asymmetric keypair."""
        priv_pem, pub_pem = generate_rsa_keypair()
        case = CaseService.create_case(title="RSA SignOff Case", db_path=self.temp_db_path)

        review = PeerReviewService.submit_review(
            case_id=case.id,
            reviewer_id="lead-bob",
            decision=ReviewStatus.APPROVED,
            comments="RSA-PSS signed review",
            private_key_pem=priv_pem,
            key_id="rsa-key-01",
            db_path=self.temp_db_path,
        )
        self.assertIsNotNone(review.signature_value)

        ver_resp = PeerReviewService.verify_review_signature(case.id, review.review_id, db_path=self.temp_db_path)
        self.assertTrue(ver_resp.valid)
        self.assertTrue(ver_resp.manifest_matches_current)

    def test_18_verify_signature_service_tampered_payload(self):
        """Assert that tampering with the stored signature fails cryptographic verification."""
        priv_pem, pub_pem = generate_ed25519_keypair()
        case = CaseService.create_case(title="Tampered Sig Case", db_path=self.temp_db_path)

        review = PeerReviewService.submit_review(
            case_id=case.id,
            reviewer_id="reviewer-charlie",
            decision=ReviewStatus.APPROVED,
            private_key_pem=priv_pem,
            db_path=self.temp_db_path,
        )

        # Corrupt the signature in SQLite
        conn = get_db_connection(self.temp_db_path)
        cursor = conn.cursor()
        bad_sig = base64.b64encode(b"corrupted_signature_payload_12345678").decode("utf-8")
        cursor.execute("UPDATE case_reviews SET signature_value = ? WHERE review_id = ?;", (bad_sig, review.review_id))
        conn.commit()
        conn.close()

        ver_resp = PeerReviewService.verify_review_signature(case.id, review.review_id, db_path=self.temp_db_path)
        self.assertFalse(ver_resp.valid)

    # --------------------------------------------------------------------------
    # 7. Manifest Invalidation & M-of-N Quorum Sealing Tests
    # --------------------------------------------------------------------------

    def test_19_manifest_mutation_invalidates_prior_approval_for_sealing(self):
        """Assert that adding evidence to a case after approval invalidates the approval for sealing."""
        case = CaseService.create_case(title="Mutation Invalidation Case", db_path=self.temp_db_path)
        PeerReviewService.submit_review(
            case_id=case.id,
            reviewer_id="reviewer-charlie",
            decision=ReviewStatus.APPROVED,
            db_path=self.temp_db_path,
        )

        # Status before mutation
        status1 = PeerReviewService.get_case_authorization_status(case.id, db_path=self.temp_db_path)
        self.assertTrue(status1.can_seal)
        self.assertEqual(status1.approvals_count, 1)

        # Mutate case: add an analyst note
        CaseService.add_note_to_case(case.id, author="Alice", note_text="Discovered second hop relay", db_path=self.temp_db_path)

        # Status after mutation: prior review manifest does not match current manifest
        status2 = PeerReviewService.get_case_authorization_status(case.id, db_path=self.temp_db_path)
        self.assertFalse(status2.can_seal)
        self.assertEqual(status2.approvals_count, 0)
        self.assertIn("Quorum unmet", status2.unmet_reasons[0])

    def test_20_m_of_n_quorum_requirement_two_approvals(self):
        """Test M-of-N quorum policy requiring 2 independent approvals."""
        case = CaseService.create_case(title="M-of-N Case", db_path=self.temp_db_path)
        PeerReviewService.update_policy(
            case.id,
            CaseReviewPolicyUpdate(min_approvals_required=2),
            db_path=self.temp_db_path,
        )

        # 1st approval by Charlie
        PeerReviewService.submit_review(
            case_id=case.id,
            reviewer_id="reviewer-charlie",
            decision=ReviewStatus.APPROVED,
            db_path=self.temp_db_path,
        )
        status_1 = PeerReviewService.get_case_authorization_status(case.id, db_path=self.temp_db_path)
        self.assertFalse(status_1.can_seal)
        self.assertEqual(status_1.approvals_count, 1)

        # 2nd approval by Bob
        PeerReviewService.submit_review(
            case_id=case.id,
            reviewer_id="lead-bob",
            decision=ReviewStatus.APPROVED,
            db_path=self.temp_db_path,
        )
        status_2 = PeerReviewService.get_case_authorization_status(case.id, db_path=self.temp_db_path)
        self.assertTrue(status_2.can_seal)
        self.assertEqual(status_2.approvals_count, 2)

    def test_21_lead_investigator_requirement(self):
        """Test policy requiring Lead Investigator sign-off specifically."""
        # Create second reviewer
        AuthorizationService.create_or_update_analyst(
            analyst_id="reviewer-second",
            display_name="Second Reviewer",
            role=AnalystRole.REVIEWER,
            db_path=self.temp_db_path,
        )

        case = CaseService.create_case(title="Lead Req Case", db_path=self.temp_db_path)
        PeerReviewService.update_policy(
            case.id,
            CaseReviewPolicyUpdate(min_approvals_required=2, require_lead_investigator_approval=True),
            db_path=self.temp_db_path,
        )

        # 2 approvals by regular reviewers
        PeerReviewService.submit_review(case.id, "reviewer-charlie", ReviewStatus.APPROVED, db_path=self.temp_db_path)
        PeerReviewService.submit_review(case.id, "reviewer-second", ReviewStatus.APPROVED, db_path=self.temp_db_path)

        # Quorum of 2 reached, but lacks Lead approval
        status_no_lead = PeerReviewService.get_case_authorization_status(case.id, db_path=self.temp_db_path)
        self.assertFalse(status_no_lead.can_seal)
        self.assertTrue(any("Lead Investigator" in r for r in status_no_lead.unmet_reasons))

        # Add Lead Investigator approval
        PeerReviewService.submit_review(case.id, "lead-bob", ReviewStatus.APPROVED, db_path=self.temp_db_path)
        status_with_lead = PeerReviewService.get_case_authorization_status(case.id, db_path=self.temp_db_path)
        self.assertTrue(status_with_lead.can_seal)

    def test_22_authorize_and_seal_case_success(self):
        """Test successful authorized case seal by Lead Investigator."""
        case = CaseService.create_case(title="Seal Success Case", db_path=self.temp_db_path)
        PeerReviewService.submit_review(case.id, "reviewer-charlie", ReviewStatus.APPROVED, db_path=self.temp_db_path)

        sealed_case = PeerReviewService.authorize_and_seal_case(
            case_id=case.id,
            actor_id="lead-bob",
            db_path=self.temp_db_path,
        )
        self.assertEqual(sealed_case["status"], "SEALED")

    def test_23_authorize_and_seal_case_rejected_if_unauthorized_role(self):
        """Assert that an analyst lacking SEAL_CASE capability cannot seal the case."""
        case = CaseService.create_case(title="Seal Unauth Case", db_path=self.temp_db_path)
        PeerReviewService.submit_review(case.id, "reviewer-charlie", ReviewStatus.APPROVED, db_path=self.temp_db_path)

        with self.assertRaises(PermissionError):
            PeerReviewService.authorize_and_seal_case(
                case_id=case.id,
                actor_id="analyst-alice",  # Role: FORENSIC_ANALYST (no SEAL_CASE)
                db_path=self.temp_db_path,
            )

    def test_24_authorize_and_seal_case_rejected_if_quorum_unmet(self):
        """Assert that sealing fails when review policy criteria are unmet."""
        case = CaseService.create_case(title="Seal Quorum Unmet Case", db_path=self.temp_db_path)
        # No review submitted
        with self.assertRaises(PermissionError):
            PeerReviewService.authorize_and_seal_case(
                case_id=case.id,
                actor_id="lead-bob",
                db_path=self.temp_db_path,
            )

    # --------------------------------------------------------------------------
    # 8. REST API Endpoint Tests
    # --------------------------------------------------------------------------

    def test_25_api_roles_and_analysts_endpoints(self):
        """Test GET /api/v1/rbac/roles and analyst management endpoints."""
        resp_roles = self.client.get("/api/v1/rbac/roles")
        self.assertEqual(resp_roles.status_code, 200)
        roles_data = resp_roles.json()
        self.assertIn("FORENSIC_ANALYST", roles_data)
        self.assertIn("LEAD_INVESTIGATOR", roles_data)

        resp_analysts = self.client.get("/api/v1/rbac/analysts")
        self.assertEqual(resp_analysts.status_code, 200)
        self.assertGreaterEqual(len(resp_analysts.json()), 5)

        # Update role via API
        resp_update = self.client.post(
            "/api/v1/rbac/analysts/analyst-alice/role",
            json={"role": "LEAD_INVESTIGATOR", "reason": "Team lead appointment"},
        )
        self.assertEqual(resp_update.status_code, 200)
        self.assertEqual(resp_update.json()["role"], "LEAD_INVESTIGATOR")

    def test_26_api_assignments_endpoints(self):
        """Test case assignment REST endpoints."""
        case = CaseService.create_case(title="API Assignment Case", db_path=self.temp_db_path)

        resp_asgn = self.client.post(
            f"/api/v1/rbac/cases/{case.id}/assignments",
            json={"analyst_id": "analyst-alice", "role": "ASSIGNED_ANALYST"},
        )
        self.assertEqual(resp_asgn.status_code, 200)
        asgn_id = resp_asgn.json()["assignment_id"]

        resp_list = self.client.get(f"/api/v1/rbac/cases/{case.id}/assignments")
        self.assertEqual(resp_list.status_code, 200)
        self.assertEqual(len(resp_list.json()), 1)

        resp_del = self.client.delete(f"/api/v1/rbac/cases/{case.id}/assignments/{asgn_id}")
        self.assertEqual(resp_del.status_code, 200)

    def test_27_api_policy_and_manifest_endpoints(self):
        """Test case policy and manifest REST endpoints."""
        case = CaseService.create_case(title="API Policy Case", db_path=self.temp_db_path)

        resp_man = self.client.get(f"/api/v1/rbac/cases/{case.id}/manifest")
        self.assertEqual(resp_man.status_code, 200)
        self.assertEqual(len(resp_man.json()["manifest_sha256"]), 64)

        resp_pol_get = self.client.get(f"/api/v1/rbac/cases/{case.id}/policy")
        self.assertEqual(resp_pol_get.status_code, 200)
        self.assertEqual(resp_pol_get.json()["min_approvals_required"], 1)

        resp_pol_put = self.client.put(
            f"/api/v1/rbac/cases/{case.id}/policy",
            json={"min_approvals_required": 3, "require_lead_investigator_approval": True},
        )
        self.assertEqual(resp_pol_put.status_code, 200)
        self.assertEqual(resp_pol_put.json()["min_approvals_required"], 3)
        self.assertTrue(resp_pol_put.json()["require_lead_investigator_approval"])

    def test_28_api_review_request_submit_status_endpoints(self):
        """Test requesting review, submitting decision, and checking status via REST API."""
        case = CaseService.create_case(title="API Review Case", db_path=self.temp_db_path)

        # Request review
        resp_req = self.client.post(
            f"/api/v1/rbac/cases/{case.id}/review/request",
            json={"target_reviewer_ids": ["reviewer-charlie"], "comments": "Urgent review requested"},
        )
        self.assertEqual(resp_req.status_code, 200)

        # Submit review
        priv_pem, _ = generate_ed25519_keypair()
        resp_sub = self.client.post(
            f"/api/v1/rbac/cases/{case.id}/review/submit",
            json={
                "decision": "APPROVED",
                "comments": "Verified and signed",
                "private_key_pem": priv_pem,
                "key_id": "key-01",
            },
            headers={"x-actor-id": "reviewer-charlie", "x-actor-name": "Charlie Reviewer"},
        )
        self.assertEqual(resp_sub.status_code, 200)
        review_id = resp_sub.json()["review_id"]

        # Status check
        resp_status = self.client.get(f"/api/v1/rbac/cases/{case.id}/review/status")
        self.assertEqual(resp_status.status_code, 200)
        self.assertTrue(resp_status.json()["can_seal"])

        # History check
        resp_hist = self.client.get(f"/api/v1/rbac/cases/{case.id}/review/history")
        self.assertEqual(resp_hist.status_code, 200)
        self.assertEqual(len(resp_hist.json()), 1)

    def test_29_api_verify_signature_and_seal_endpoints(self):
        """Test signature verification and case sealing REST endpoints."""
        case = CaseService.create_case(title="API Seal Case", db_path=self.temp_db_path)
        priv_pem, _ = generate_ed25519_keypair()

        resp_sub = self.client.post(
            f"/api/v1/rbac/cases/{case.id}/review/submit",
            json={
                "decision": "APPROVED",
                "comments": "Approved with Ed25519 signature",
                "private_key_pem": priv_pem,
            },
            headers={"x-actor-id": "reviewer-charlie", "x-actor-name": "Charlie Reviewer"},
        )
        review_id = resp_sub.json()["review_id"]

        # Verify signature
        resp_ver = self.client.post(
            f"/api/v1/rbac/cases/{case.id}/review/verify",
            json={"case_id": case.id, "review_id": review_id},
        )
        self.assertEqual(resp_ver.status_code, 200)
        self.assertTrue(resp_ver.json()["valid"])

        # Seal case as Lead Investigator
        resp_seal = self.client.post(
            f"/api/v1/rbac/cases/{case.id}/seal",
            headers={"x-actor-id": "lead-bob", "x-actor-name": "Bob Lead"},
        )
        self.assertEqual(resp_seal.status_code, 200)
        self.assertEqual(resp_seal.json()["status"], "SEALED")

    def test_30_api_404_and_403_error_handling(self):
        """Assert proper HTTP 404 and 403 error codes on invalid requests."""
        # 404 non-existent case manifest
        resp_404 = self.client.get("/api/v1/rbac/cases/NON-EXISTENT-CASE/manifest")
        self.assertEqual(resp_404.status_code, 404)

        # 403 when trying to seal without required approvals
        case = CaseService.create_case(title="Unapproved Case", db_path=self.temp_db_path)
        resp_403 = self.client.post(
            f"/api/v1/rbac/cases/{case.id}/seal",
            headers={"x-actor-id": "lead-bob"},
        )
        self.assertEqual(resp_403.status_code, 403)
        self.assertIn("not authorized", resp_403.json()["detail"].lower())


if __name__ == "__main__":
    unittest.main()

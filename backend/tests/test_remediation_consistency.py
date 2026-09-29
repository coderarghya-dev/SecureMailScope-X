# ==============================================================================
# SecureMailScope X — Remediation Playbook Findings Consistency & Isolation Tests
# ==============================================================================
"""Regression test suite for Remediation Playbook consistency:
1. Active analysis findings appear dynamically in remediation playbook generation.
2. Unrelated hardcoded findings (Cleartext Auth, TLS 1.0) do NOT appear when not present in active case.
3. Zero-findings analysis returns empty playbook recommendations.
4. User A cannot access or generate playbooks from User B's analysis (Workspace Isolation).
5. Generated playbooks reference only selected real finding IDs.
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
from app.core.auth import UserRepository, hash_password, create_access_token
from app.schemas.remediation import (
    RemediationPlatform,
    PlaybookGenerationRequest,
)
from app.services.remediation_service import RemediationService


class TestRemediationConsistency(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_path = self.temp_db.name
        set_custom_db_path(self.db_path)
        init_db(self.db_path)
        self.client = TestClient(app)

        # Create two isolated users
        self.user_a = UserRepository.create_user(
            name="Analyst A",
            email="user_a@example.com",
            password_hash=hash_password("Password123!"),
            db_path=self.db_path,
        )
        self.user_b = UserRepository.create_user(
            name="Analyst B",
            email="user_b@example.com",
            password_hash=hash_password("Password123!"),
            db_path=self.db_path,
        )

        # Setup an analysis for User A (e.g. smtp-starttls-test.pcapng)
        self.analysis_id_user_a = "analysis-user-a-smtp-tls13"
        self._seed_analysis(
            analysis_id=self.analysis_id_user_a,
            user_id=self.user_a["id"],
            filename="smtp-starttls-test.pcapng",
            findings=[
                {
                    "finding_id": "FINDING-TLS-1.3-NEGOTIATED",
                    "rule_id": "RULE-TLS-1.3-NEGOTIATED",
                    "title": "State-of-the-Art TLS 1.3 Negotiated",
                    "severity": "INFO",
                    "category": "TLS_CONFIGURATION",
                },
                {
                    "finding_id": "FINDING-PQC-CLASSICAL-KEX-EXPOSURE",
                    "rule_id": "RULE-PQC-CLASSICAL-KEX-EXPOSURE",
                    "title": "Vulnerable to Harvest Now, Decrypt Later (HNDL)",
                    "severity": "MEDIUM",
                    "category": "PQC_MIGRATION",
                },
            ],
        )

        # Setup an empty findings analysis for User A
        self.analysis_id_zero_findings = "analysis-user-a-zero-findings"
        self._seed_analysis(
            analysis_id=self.analysis_id_zero_findings,
            user_id=self.user_a["id"],
            filename="clean-case.pcapng",
            findings=[],
        )

    def tearDown(self):
        set_custom_db_path(None)
        if os.path.exists(self.db_path):
            try:
                os.unlink(self.db_path)
            except Exception:
                pass

    def _seed_analysis(self, analysis_id: str, user_id: str, filename: str, findings: list):
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO analyses (analysis_id, filename, file_size_bytes, capture_sha256, observed_result_json, observed_result_sha256, security_grade, created_at)
               VALUES (?, ?, 1024, ?, '{}', 'sha256_mock', 'A', datetime('now'));""",
            (analysis_id, filename, f"hash_{analysis_id}"),
        )
        # Associate with user
        cursor.execute(
            """INSERT INTO user_analyses (user_id, analysis_id, created_at)
               VALUES (?, ?, datetime('now'));""",
            (user_id, analysis_id),
        )
        # Seed findings
        for idx, f in enumerate(findings):
            fid = f"find_{analysis_id}_{idx}"
            cursor.execute(
                """INSERT INTO findings (id, finding_id, analysis_id, session_id, severity, category, rule_id, title, description, finding_json, finding_sha256)
                   VALUES (?, ?, ?, 'sess_1', ?, ?, ?, ?, 'Test finding description', '{}', 'hash_mock');""",
                (fid, f["finding_id"], analysis_id, f["severity"], f["category"], f["rule_id"], f["title"]),
            )
        conn.commit()
        conn.close()

    def test_01_active_analysis_findings_appear_in_remediation(self):
        """Active analysis findings (TLS 1.3, HNDL) appear dynamically in generated playbook."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.POSTFIX,
            analysis_id=self.analysis_id_user_a,
        )
        res = RemediationService.generate_playbook(req, user_id=self.user_a["id"], db_path=self.db_path)

        self.assertGreaterEqual(res.total_recommendations, 1)
        # Check that matched playbooks correspond to the actual findings
        remediation_ids = [item.remediation_id for item in res.items]
        self.assertTrue("MAINTAIN_MODERN_TLS" in remediation_ids or "ENABLE_HYBRID_PQC" in remediation_ids)

    def test_02_unrelated_hardcoded_findings_do_not_appear(self):
        """Unrelated findings like Cleartext Auth or Obsolete TLS 1.0 do not appear when not in analysis."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.POSTFIX,
            analysis_id=self.analysis_id_user_a,
        )
        res = RemediationService.generate_playbook(req, user_id=self.user_a["id"], db_path=self.db_path)

        remediation_ids = [item.remediation_id for item in res.items]
        # Should NOT contain DISABLE_DEPRECATED_TLS or REQUIRE_STARTTLS since case is healthy TLS 1.3
        self.assertNotIn("DISABLE_DEPRECATED_TLS", remediation_ids)
        self.assertNotIn("REQUIRE_STARTTLS", remediation_ids)

    def test_03_zero_findings_analysis_returns_empty_playbook(self):
        """Analysis with zero findings returns 0 recommendations."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.POSTFIX,
            analysis_id=self.analysis_id_zero_findings,
        )
        res = RemediationService.generate_playbook(req, user_id=self.user_a["id"], db_path=self.db_path)
        self.assertEqual(res.total_recommendations, 0)
        self.assertEqual(len(res.items), 0)

    def test_04_user_isolation_user_b_cannot_access_user_a_findings(self):
        """User B cannot generate playbooks using User A's analysis_id (User isolation)."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.POSTFIX,
            analysis_id=self.analysis_id_user_a,
        )
        # Service level check
        with self.assertRaises(ValueError) as ctx:
            RemediationService.generate_playbook(req, user_id=self.user_b["id"], db_path=self.db_path)
        self.assertIn("not found in user workspace", str(ctx.exception))

        # API level check with User B token
        token_b = create_access_token({"sub": self.user_b["id"], "email": self.user_b["email"]})
        response = self.client.post(
            "/api/v1/remediation/playbooks/generate",
            json={"platform": "POSTFIX", "analysis_id": self.analysis_id_user_a},
            headers={"Authorization": f"Bearer {token_b}"},
        )
        self.assertEqual(response.status_code, 404)

    def test_05_generated_playbook_references_only_selected_real_finding_ids(self):
        """When specific finding codes are provided, only matching playbooks are generated."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.POSTFIX,
            analysis_id=self.analysis_id_user_a,
            finding_codes=["FINDING-PQC-CLASSICAL-KEX-EXPOSURE"],
        )
        res = RemediationService.generate_playbook(req, user_id=self.user_a["id"], db_path=self.db_path)
        self.assertEqual(res.total_recommendations, 1)
        self.assertEqual(res.items[0].remediation_id, "ENABLE_HYBRID_PQC")
        self.assertEqual(res.items[0].finding_code, "FINDING-PQC-CLASSICAL-KEX-EXPOSURE")

    def test_06_no_unsupported_forward_secrecy_claims(self):
        """Playbook must not claim verified PFS when passive evidence is unknown/unverified."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.POSTFIX,
            finding_codes=["FINDING-TLS-1.3-NEGOTIATED"],
        )
        res = RemediationService.generate_playbook(req, db_path=self.db_path)
        self.assertEqual(res.total_recommendations, 1)
        item = res.items[0]
        # Must contain bounded wording about PFS
        self.assertIn("Forward secrecy cannot be verified from the available passive evidence", item.expected_security_effect)
        # Must not make unconditional verified PFS claims for TLS 1.3 alone
        self.assertNotIn("forward secrecy is preserved", item.expected_security_effect.lower())

    def test_07_tls_recommendation_matches_protocol_floor(self):
        """Playbook recommendation text and title must match configured protocol floor (>=TLSv1.2)."""
        req = PlaybookGenerationRequest(
            platform=RemediationPlatform.POSTFIX,
            finding_codes=["FINDING-TLS-1.3-NEGOTIATED"],
        )
        res = RemediationService.generate_playbook(req, db_path=self.db_path)
        item = res.items[0]
        self.assertIn("TLS 1.2", item.action_title)
        self.assertIn("TLS 1.3 Preferred", item.action_title)
        self.assertIn("smtpd_tls_mandatory_protocols = >=TLSv1.2", item.config_snippet)

    def test_08_generated_commands_explicitly_marked_advisory_manual(self):
        """All configuration snippets must mark commands as manual advisory actions (NOT executed)."""
        platforms = [
            RemediationPlatform.POSTFIX,
            RemediationPlatform.EXIM,
            RemediationPlatform.DOVECOT,
            RemediationPlatform.SENDMAIL,
        ]
        for plat in platforms:
            req = PlaybookGenerationRequest(platform=plat, finding_codes=[])
            res = RemediationService.generate_playbook(req, db_path=self.db_path)
            for item in res.items:
                # Must NOT contain unqualified active '# Execute:'
                self.assertNotIn("# Execute:", item.config_snippet)
                # If command instructions exist, they must be marked manual and not executed
                if "reload" in item.config_snippet or "restart" in item.config_snippet or "make" in item.config_snippet:
                    self.assertIn("Manual action after human review (NOT executed by SecureMailScope X)", item.config_snippet)


if __name__ == "__main__":
    unittest.main()

"""
SecureMailScope X - Authentication Test Suite (Phase 29)
Validates User Registration, Duplicate Prevention, Secure Password Hashing, Login, JWT Token Issuance, and Protected Profile Access.
"""

import os
import sys
import tempfile
import unittest
from fastapi.testclient import TestClient

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.main import app
from app.db.database import set_custom_db_path, init_db
from app.core.auth import hash_password, verify_password, create_access_token, decode_access_token, UserRepository


class TestAuthService(unittest.TestCase):
    """Test suite for authentication engine and endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = os.path.join(cls.temp_dir.name, "test_auth.db")
        set_custom_db_path(cls.test_db_path)
        init_db(cls.test_db_path)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        import gc
        set_custom_db_path(None)
        gc.collect()
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass

    def test_01_password_hashing_and_verification(self):
        """Verify password is securely hashed and verified with constant-time check."""
        password = "ForensicSuperSecret#2026"
        hashed = hash_password(password)

        self.assertNotEqual(password, hashed)
        self.assertTrue(hashed.startswith(("$2b$", "$2a$", "$2y$")))
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password("WrongPassword123", hashed))
        self.assertFalse(verify_password("", hashed))

    def test_02_jwt_creation_and_decoding(self):
        """Verify JWT token encoding, claims, and decoding."""
        payload = {"sub": "user_test_01", "email": "analyst@securemailscope.io", "name": "Agent Smith"}
        token = create_access_token(payload)

        self.assertIsInstance(token, str)
        decoded = decode_access_token(token)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["sub"], "user_test_01")
        self.assertEqual(decoded["email"], "analyst@securemailscope.io")
        self.assertEqual(decoded["name"], "Agent Smith")
        self.assertEqual(decoded["iss"], "SecureMailScope-X")

        # Tampered token check
        tampered_token = token[:-5] + "XXXXX"
        self.assertIsNone(decode_access_token(tampered_token))

    def test_03_register_user_success(self):
        """Verify POST /api/v1/auth/register creates user and returns JWT token."""
        res = self.client.post(
            "/api/v1/auth/register",
            json={
                "name": "Forensic Lead",
                "email": "lead.analyst@soc.gov",
                "password": "SecurePassword#999"
            }
        )
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["user"]["name"], "Forensic Lead")
        self.assertEqual(data["user"]["email"], "lead.analyst@soc.gov")
        self.assertTrue(data["user"]["id"].startswith("user_"))

        # Verify password in DB is hashed, not plaintext
        user_in_db = UserRepository.get_user_by_email("lead.analyst@soc.gov", self.test_db_path)
        self.assertIsNotNone(user_in_db)
        self.assertNotEqual(user_in_db["password_hash"], "SecurePassword#999")
        self.assertTrue(verify_password("SecurePassword#999", user_in_db["password_hash"]))

    def test_04_register_duplicate_email_rejected(self):
        """Verify duplicate email registration returns 400 Bad Request."""
        res = self.client.post(
            "/api/v1/auth/register",
            json={
                "name": "Duplicate User",
                "email": "lead.analyst@soc.gov",
                "password": "AnotherPassword#123"
            }
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("already exists", res.json()["detail"].lower())

    def test_05_login_success(self):
        """Verify POST /api/v1/auth/login authenticates valid user."""
        res = self.client.post(
            "/api/v1/auth/login",
            json={
                "email": "lead.analyst@soc.gov",
                "password": "SecurePassword#999"
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["email"], "lead.analyst@soc.gov")

    def test_06_login_invalid_password_rejected(self):
        """Verify invalid password returns 401 Unauthorized."""
        res = self.client.post(
            "/api/v1/auth/login",
            json={
                "email": "lead.analyst@soc.gov",
                "password": "WrongPasswordIncorrect"
            }
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("invalid email or password", res.json()["detail"].lower())

    def test_07_login_nonexistent_email_rejected(self):
        """Verify unknown email returns 401 Unauthorized."""
        res = self.client.post(
            "/api/v1/auth/login",
            json={
                "email": "unknown.user@doesnotexist.com",
                "password": "AnyPassword"
            }
        )
        self.assertEqual(res.status_code, 401)

    def test_08_auth_me_with_valid_token(self):
        """Verify GET /api/v1/auth/me returns user profile with valid Bearer token."""
        # Login first to get token
        login_res = self.client.post(
            "/api/v1/auth/login",
            json={
                "email": "lead.analyst@soc.gov",
                "password": "SecurePassword#999"
            }
        )
        token = login_res.json()["access_token"]

        res = self.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(res.status_code, 200)
        user_data = res.json()
        self.assertEqual(user_data["email"], "lead.analyst@soc.gov")
        self.assertEqual(user_data["name"], "Forensic Lead")

    def test_09_auth_me_without_token_rejected(self):
        """Verify GET /api/v1/auth/me returns 401 when Authorization header is absent."""
        res = self.client.get("/api/v1/auth/me")
        self.assertEqual(res.status_code, 401)
        self.assertIn("missing", res.json()["detail"].lower())

    def test_10_datetime_created_at_compatibility(self):
        """Verify UserRepository and UserResponse handle datetime objects from PostgreSQL driver gracefully."""
        from datetime import datetime, timezone
        from app.api.v1.endpoints.auth import UserResponse

        dt_now = datetime.now(timezone.utc)
        user_resp = UserResponse(
            id="user_test_dt",
            name="DateTime Analyst",
            email="dt@securemailscope.io",
            created_at=dt_now
        )
        self.assertIsInstance(user_resp.created_at, str)
        self.assertEqual(user_resp.created_at, dt_now.isoformat())

    def test_11_user_workspace_isolation_and_ownership(self):
        """Verify User A analysis is isolated and inaccessible to User B."""
        # 1. Register User A & User B
        res_a = self.client.post(
            "/api/v1/auth/register",
            json={"name": "Alice Analyst", "email": "alice@cyber.gov", "password": "AliceSecretPassword123"}
        )
        self.assertEqual(res_a.status_code, 201)
        token_a = res_a.json()["access_token"]
        user_a_id = res_a.json()["user"]["id"]

        res_b = self.client.post(
            "/api/v1/auth/register",
            json={"name": "Bob Analyst", "email": "bob@cyber.gov", "password": "BobSecretPassword123"}
        )
        self.assertEqual(res_b.status_code, 201)
        token_b = res_b.json()["access_token"]
        user_b_id = res_b.json()["user"]["id"]

        # 2. User B has empty analysis list initially
        b_list = self.client.get("/api/v1/analyses", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(b_list.status_code, 200)
        self.assertEqual(b_list.json(), [])

        # 3. User A uploads/analyzes a synthetic PCAP
        dummy_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32
        res_upload = self.client.post(
            "/api/v1/analyze",
            files={"file": ("alice_evidence.pcap", dummy_pcap, "application/octet-stream")},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        self.assertEqual(res_upload.status_code, 200)
        analysis_id = res_upload.json()["analysis_id"]

        # 4. User A sees analysis in their list and can retrieve it
        a_list = self.client.get("/api/v1/analyses", headers={"Authorization": f"Bearer {token_a}"})
        self.assertEqual(a_list.status_code, 200)
        self.assertEqual(len(a_list.json()), 1)
        self.assertEqual(a_list.json()[0]["analysis_id"], analysis_id)

        a_detail = self.client.get(f"/api/v1/analyze/{analysis_id}", headers={"Authorization": f"Bearer {token_a}"})
        self.assertEqual(a_detail.status_code, 200)
        self.assertEqual(a_detail.json()["analysis_id"], analysis_id)

        # 5. User B still has empty analysis list
        b_list2 = self.client.get("/api/v1/analyses", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(b_list2.status_code, 200)
        self.assertEqual(b_list2.json(), [])

        # 6. User B cannot retrieve User A's analysis (clean 404)
        b_detail = self.client.get(f"/api/v1/analyze/{analysis_id}", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(b_detail.status_code, 404)

        # 7. User B cannot access PDF, JSON, HTML exports of User A's analysis (404)
        b_pdf = self.client.get(f"/api/v1/analyze/{analysis_id}/pdf", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(b_pdf.status_code, 404)

        b_json = self.client.get(f"/api/v1/analyze/{analysis_id}/export/json", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(b_json.status_code, 404)

        b_html = self.client.get(f"/api/v1/analyze/{analysis_id}/export/html", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(b_html.status_code, 404)

        # 8. User B cannot access sessions, custody, or reports of User A's analysis (404)
        b_sessions = self.client.get(f"/api/v1/analyses/{analysis_id}/sessions", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(b_sessions.status_code, 404)

        b_custody = self.client.get(f"/api/v1/analyses/{analysis_id}/custody", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(b_custody.status_code, 404)

        b_report = self.client.get(f"/api/v1/analyses/{analysis_id}/report", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(b_report.status_code, 404)

    def test_12_same_analysis_mapping_does_not_duplicate_evidence_and_preserves_custody(self):
        """Verify uploading the same capture by User B maps ownership without mutating evidence or custody hashes."""
        # Login User A and User B
        res_a = self.client.post("/api/v1/auth/login", json={"email": "alice@cyber.gov", "password": "AliceSecretPassword123"})
        token_a = res_a.json()["access_token"]
        res_b = self.client.post("/api/v1/auth/login", json={"email": "bob@cyber.gov", "password": "BobSecretPassword123"})
        token_b = res_b.json()["access_token"]

        dummy_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32

        # User A custody record
        a_list = self.client.get("/api/v1/analyses", headers={"Authorization": f"Bearer {token_a}"})
        analysis_id = a_list.json()[0]["analysis_id"]

        custody_before = self.client.get(f"/api/v1/analyses/{analysis_id}/custody", headers={"Authorization": f"Bearer {token_a}"}).json()
        seal_before = custody_before["capture_integrity"]["sha256"]
        manifest_hash_before = custody_before["manifest_integrity"]["manifest_hash"]

        # User B uploads identical PCAP
        res_upload_b = self.client.post(
            "/api/v1/analyze",
            files={"file": ("bob_copy.pcap", dummy_pcap, "application/octet-stream")},
            headers={"Authorization": f"Bearer {token_b}"}
        )
        self.assertEqual(res_upload_b.status_code, 200)
        self.assertEqual(res_upload_b.json()["analysis_id"], analysis_id)

        # User B now has the analysis mapped in their workspace
        b_list = self.client.get("/api/v1/analyses", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(len(b_list.json()), 1)
        self.assertEqual(b_list.json()[0]["analysis_id"], analysis_id)

        # Custody seal and manifest hash remain EXACTLY the same
        custody_after = self.client.get(f"/api/v1/analyses/{analysis_id}/custody", headers={"Authorization": f"Bearer {token_b}"}).json()
        self.assertEqual(custody_after["capture_integrity"]["sha256"], seal_before)
        self.assertEqual(custody_after["manifest_integrity"]["manifest_hash"], manifest_hash_before)
        self.assertEqual(custody_after["overall_status"], "VERIFIED")



    def test_13_repository_ownership_methods_direct(self):
        """Directly verify repository ownership helper functions."""
        from app.db.repository import ForensicRepository

        # Create user in database
        u = UserRepository.create_user(name="Direct User", email="direct@soc.gov", password_hash="hash123", db_path=self.test_db_path)
        user_id = u["id"]

        # Get existing analysis id from earlier test
        all_analyses = ForensicRepository.list_analyses(db_path=self.test_db_path)
        self.assertTrue(len(all_analyses) > 0)
        analysis_id = all_analyses[0]["analysis_id"]

        # Initially not owned by new user
        self.assertFalse(ForensicRepository.is_analysis_owned_by_user(user_id, analysis_id, self.test_db_path))
        self.assertNotIn(analysis_id, ForensicRepository.get_user_analysis_ids(user_id, self.test_db_path))

        # Associate
        ok = ForensicRepository.associate_user_analysis(user_id, analysis_id, self.test_db_path)
        self.assertTrue(ok)

        # Now owned
        self.assertTrue(ForensicRepository.is_analysis_owned_by_user(user_id, analysis_id, self.test_db_path))
        self.assertIn(analysis_id, ForensicRepository.get_user_analysis_ids(user_id, self.test_db_path))

        # Idempotent re-association
        ok2 = ForensicRepository.associate_user_analysis(user_id, analysis_id, self.test_db_path)
        self.assertTrue(ok2)
        self.assertTrue(ForensicRepository.is_analysis_owned_by_user(user_id, analysis_id, self.test_db_path))



if __name__ == "__main__":
    unittest.main(verbosity=2)


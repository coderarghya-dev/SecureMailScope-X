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


if __name__ == "__main__":
    unittest.main(verbosity=2)

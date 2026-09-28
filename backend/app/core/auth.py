"""
SecureMailScope X - Authentication & Security Module (Phase 29)
Provides secure password hashing (bcrypt / PBKDF2), JWT issuance, and user repository operations.
"""

import os
import uuid
import hmac
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

import jwt
import bcrypt

from app.db.database import get_db_connection

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "securemailscope-x-sih26159-default-jwt-secret-key-for-dev")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", str(60 * 24)))  # 24 Hours Default


def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using bcrypt with standard salt generation.
    Returns standard bcrypt hash string ($2b$...).
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Securely verifies plaintext password against stored hash.
    Supports bcrypt ($2a$, $2b$, $2y$) and PBKDF2-HMAC-SHA256 ($pbkdf2$).
    """
    if not plain_password or not hashed_password:
        return False

    try:
        if hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        elif hashed_password.startswith("$pbkdf2$"):
            parts = hashed_password.split("$")
            if len(parts) == 5:
                iterations = int(parts[2])
                salt = base64.b64decode(parts[3])
                expected_hash = base64.b64decode(parts[4])
                computed = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
                return hmac.compare_digest(computed, expected_hash)
        return False
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Encodes and signs a JSON Web Token (JWT) with standard expiration and claims.
    """
    to_encode = data.copy()
    now_utc = datetime.now(timezone.utc)
    if expires_delta:
        expire = now_utc + expires_delta
    else:
        expire = now_utc + timedelta(minutes=JWT_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": now_utc,
        "nbf": now_utc,
        "iss": "SecureMailScope-X"
    })

    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and verifies a JWT token. Returns payload dict or None if invalid/expired.
    """
    if not token:
        return None
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer="SecureMailScope-X"
        )
        return payload
    except (jwt.PyJWTError, Exception):
        return None


# =====================================================================
# User Repository Operations
# =====================================================================

class UserRepository:
    """Provides thread-safe, engine-agnostic User CRUD queries."""

    @staticmethod
    def create_user(name: str, email: str, password_hash: str, db_path: Optional[str] = None) -> Dict[str, Any]:
        """Creates a new user record in the database."""
        clean_email = email.strip().lower()
        clean_name = name.strip()
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users (id, name, email, password_hash, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, clean_name, clean_email, password_hash, now_iso)
        )
        conn.commit()

        return {
            "id": user_id,
            "name": clean_name,
            "email": clean_email,
            "created_at": now_iso
        }

    @staticmethod
    def get_user_by_email(email: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Finds user by email address."""
        if not email:
            return None
        clean_email = email.strip().lower()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, name, email, password_hash, created_at FROM users WHERE email = ? LIMIT 1",
            (clean_email,)
        )
        row = cursor.fetchone()
        if not row:
            return None

        return {
            "id": row["id"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[0],
            "name": row["name"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[1],
            "email": row["email"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[2],
            "password_hash": row["password_hash"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[3],
            "created_at": row["created_at"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[4],
        }

    @staticmethod
    def get_user_by_id(user_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Finds user by unique user_id."""
        if not user_id:
            return None

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, name, email, password_hash, created_at FROM users WHERE id = ? LIMIT 1",
            (user_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None

        return {
            "id": row["id"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[0],
            "name": row["name"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[1],
            "email": row["email"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[2],
            "password_hash": row["password_hash"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[3],
            "created_at": row["created_at"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[4],
        }

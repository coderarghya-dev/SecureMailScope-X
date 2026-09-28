"""
test_database_adapter.py - Unit tests for Database Adapter and Dual Mode Engine.
Phase 28: PostgreSQL / Supabase Migration + Deployment Readiness.
"""

import os
import unittest
from unittest.mock import patch, MagicMock

from app.db.database import (
    get_database_engine_type,
    sanitize_db_url_for_logs,
    translate_query_for_postgres,
    PostgresRowWrapper,
    PostgresCursorWrapper,
    get_db_connection,
    set_custom_db_path,
    get_db_path,
    DB_ENGINE_SQLITE,
    DB_ENGINE_POSTGRES,
)


class TestDatabaseAdapter(unittest.TestCase):
    """Test suite for dual database adapter, parameter translation, and URL sanitization."""

    def test_get_database_engine_type_sqlite(self):
        """Verify default and file paths return SQLITE engine."""
        self.assertEqual(get_database_engine_type(None), DB_ENGINE_SQLITE)
        self.assertEqual(get_database_engine_type(""), DB_ENGINE_SQLITE)
        self.assertEqual(get_database_engine_type("backend/data/securemailscope.db"), DB_ENGINE_SQLITE)
        self.assertEqual(get_database_engine_type(":memory:"), DB_ENGINE_SQLITE)

    def test_get_database_engine_type_postgres(self):
        """Verify PostgreSQL connection strings return POSTGRESQL engine."""
        self.assertEqual(
            get_database_engine_type("postgresql://user:pass@localhost:5432/db"),
            DB_ENGINE_POSTGRES
        )
        self.assertEqual(
            get_database_engine_type("postgresql+psycopg://user:pass@host:5432/db?sslmode=require"),
            DB_ENGINE_POSTGRES
        )
        self.assertEqual(
            get_database_engine_type("postgres://user:pass@host:5432/db"),
            DB_ENGINE_POSTGRES
        )

    def test_sanitize_db_url_for_logs(self):
        """Verify secrets are masked in database URLs."""
        # Unmasked SQLite paths are unchanged
        self.assertEqual(
            sanitize_db_url_for_logs("backend/data/securemailscope.db"),
            "backend/data/securemailscope.db"
        )
        # Passwords masked in PostgreSQL URLs
        url = "postgresql+psycopg://postgres:SuperSecret123@db.supabase.co:5432/postgres?sslmode=require"
        sanitized = sanitize_db_url_for_logs(url)
        self.assertNotIn("SuperSecret123", sanitized)
        self.assertIn("postgres:***@db.supabase.co:5432", sanitized)

    def test_translate_query_for_postgres(self):
        """Verify SQL parameter translation from ? to %s and syntax adaptations."""
        # Standard placeholder replacement
        q1 = "SELECT * FROM analyses WHERE analysis_id = ? AND status = ?"
        t1 = translate_query_for_postgres(q1)
        self.assertEqual(t1, "SELECT * FROM analyses WHERE analysis_id = %s AND status = %s")

        # Quoted strings containing question marks should not be modified
        q2 = "SELECT * FROM findings WHERE description = 'Is this ok?' AND id = ?"
        t2 = translate_query_for_postgres(q2)
        self.assertEqual(t2, "SELECT * FROM findings WHERE description = 'Is this ok?' AND id = %s")

        # INSERT OR IGNORE translation
        q3 = "INSERT OR IGNORE INTO findings (id, title) VALUES (?, ?)"
        t3 = translate_query_for_postgres(q3)
        self.assertIn("INSERT INTO findings", t3)
        self.assertIn("ON CONFLICT DO NOTHING", t3)
        self.assertNotIn("OR IGNORE", t3)

    def test_postgres_row_wrapper(self):
        """Verify PostgresRowWrapper mimics sqlite3.Row dict, key, index, and slice access."""
        data = {
            "analysis_id": "ana-12345",
            "filename": "test.pcap",
            "file_size": 1024,
            "risk_score": 85.5
        }
        row = PostgresRowWrapper(data)

        # Dict / key access
        self.assertEqual(row["analysis_id"], "ana-12345")
        self.assertEqual(row["filename"], "test.pcap")
        self.assertEqual(row["file_size"], 1024)
        self.assertEqual(row["risk_score"], 85.5)

        # Index access
        self.assertEqual(row[0], "ana-12345")
        self.assertEqual(row[1], "test.pcap")
        self.assertEqual(row[2], 1024)
        self.assertEqual(row[3], 85.5)

        # KeyError on missing column
        with self.assertRaises(KeyError):
            _ = row["non_existent_column"]

        # Membership check
        self.assertIn("analysis_id", row)
        self.assertNotIn("unknown_field", row)

        # .get() behavior
        self.assertEqual(row.get("filename"), "test.pcap")
        self.assertEqual(row.get("unknown", "default_val"), "default_val")

        # .keys() and .values()
        self.assertEqual(list(row.keys()), list(data.keys()))
        self.assertEqual(list(row.values()), list(data.values()))

        # Iteration
        self.assertEqual(list(row), list(data.values()))
        self.assertEqual(len(row), 4)

    def test_sqlite_fallback_and_custom_db_path(self):
        """Verify that when DATABASE_URL is not set, SQLite remains the operational backend."""
        # Unset DATABASE_URL if present
        with patch.dict(os.environ, {}, clear=True):
            engine = get_database_engine_type(get_db_path())
            self.assertEqual(engine, DB_ENGINE_SQLITE)

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1 AS num")
            row = cursor.fetchone()
            self.assertEqual(row[0], 1)
            self.assertEqual(row["num"], 1)
            conn.close()


if __name__ == "__main__":
    unittest.main()

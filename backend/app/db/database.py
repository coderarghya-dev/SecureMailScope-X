"""
SecureMailScope X - Persistent SQLite Database Engine
Provides durable local persistence for analyses, cases, custody records, signatures, and notarizations.
"""

import os
import sqlite3
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "securemailscope.db")


def get_db_connection() -> sqlite3.Connection:
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Analyses table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id TEXT PRIMARY KEY,
            filename TEXT,
            file_sha256 TEXT,
            status TEXT,
            total_packets INTEGER,
            total_sessions INTEGER,
            created_at TEXT,
            payload_json TEXT
        )
    """)

    # 2. Cases table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            status TEXT,
            analyst_id TEXT,
            analyst_name TEXT,
            tags_json TEXT,
            created_at TEXT,
            updated_at TEXT,
            payload_json TEXT
        )
    """)

    # 3. Custody records table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS custody_records (
            analysis_id TEXT PRIMARY KEY,
            capture_sha256 TEXT,
            manifest_v1_hash TEXT,
            manifest_v2_hash TEXT,
            is_sealed INTEGER,
            events_json TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    """)

    # 4. Digital signatures table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS digital_signatures (
            id TEXT PRIMARY KEY,
            target_type TEXT,
            target_id TEXT,
            content_sha256 TEXT,
            signature_hex TEXT,
            public_key_pem TEXT,
            signed_at TEXT,
            analyst_name TEXT
        )
    """)

    # 5. Notarization records table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notarization_records (
            id TEXT PRIMARY KEY,
            analysis_id TEXT,
            manifest_hash TEXT,
            provider TEXT,
            status TEXT,
            tx_reference TEXT,
            notarized_at TEXT,
            payload_json TEXT
        )
    """)

    conn.commit()
    conn.close()


# Initialize database schemas on module import
init_db()

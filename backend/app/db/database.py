"""
SecureMailScope X - Dual-Mode Persistent Database Engine (SQLite & PostgreSQL / Supabase)
Provides durable local persistence (SQLite) and cloud-ready deployment (PostgreSQL / Supabase)
for analyses, cases, custody records, signatures, posture snapshots, PQC roadmaps, and audit trails.
"""

import os
import re
import sqlite3
import threading
import logging
from typing import Optional, Any, Dict, List, Tuple, Union

logger = logging.getLogger("securemailscope.db")

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
DEFAULT_DB_PATH = os.path.join(DB_DIR, "securemailscope.db")

# Global custom DB path for test isolation
_custom_db_path: Optional[str] = None


def set_custom_db_path(path: Optional[str]):
    """Set custom DB path for test isolation (forces SQLite mode)."""
    global _custom_db_path
    _custom_db_path = path


def get_db_path() -> str:
    """Retrieve active DB path (custom override or default)."""
    global _custom_db_path
    return _custom_db_path or os.environ.get("SMS_DB_PATH", DEFAULT_DB_PATH)


DB_ENGINE_SQLITE = "SQLITE"
DB_ENGINE_POSTGRES = "POSTGRESQL"


def sanitize_db_url_for_logs(url: Optional[str]) -> str:
    """Mask credentials in database URL to prevent secret leakage in logs."""
    if not url:
        return "sqlite://local"
    # Mask password in URL: postgresql://user:password@host:port/dbname
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", url)


def get_database_engine_type(db_path: Optional[str] = None) -> str:
    """
    Determines active database engine: 'SQLITE' or 'POSTGRESQL'.
    If db_path starts with postgresql/postgres scheme -> 'POSTGRESQL'.
    If db_path or custom test path is provided -> 'SQLITE'.
    Otherwise inspects DATABASE_URL environment variable.
    """
    global _custom_db_path
    if db_path:
        db_path_str = str(db_path).strip()
        if db_path_str.startswith(("postgresql://", "postgres://", "postgresql+psycopg://")):
            return DB_ENGINE_POSTGRES
        return DB_ENGINE_SQLITE

    if _custom_db_path is not None:
        return DB_ENGINE_SQLITE

    db_url = os.environ.get("DATABASE_URL", "").strip()
    if db_url.startswith(("postgresql://", "postgres://", "postgresql+psycopg://")):
        return DB_ENGINE_POSTGRES

    return DB_ENGINE_SQLITE


# ---------------------------------------------------------------------------
# PostgreSQL Query & Connection Adapters
# ---------------------------------------------------------------------------

def translate_query_for_postgres(sql: str) -> str:
    """
    Translates SQLite-compatible query placeholders '?' to psycopg '%s' format,
    while avoiding quotes or comments.
    Also translates SQLite INSERT OR IGNORE / INSERT OR REPLACE to PostgreSQL ON CONFLICT.
    """
    # Replace non-quoted '?' with '%s'
    # Simple, reliable tokenizer for SQL strings
    out = []
    in_single = False
    in_double = False
    i = 0
    n = len(sql)
    while i < n:
        c = sql[i]
        if c == "'" and not in_double:
            in_single = not in_single
            out.append(c)
        elif c == '"' and not in_single:
            in_double = not in_double
            out.append(c)
        elif c == '?' and not in_single and not in_double:
            out.append('%s')
        else:
            out.append(c)
        i += 1

    translated = "".join(out)

    # Convert SQLite specific "INSERT OR IGNORE INTO table" -> "INSERT INTO table ... ON CONFLICT DO NOTHING"
    if re.search(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", translated, re.IGNORECASE):
        translated = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", translated, flags=re.IGNORECASE)
        if "ON CONFLICT" not in translated.upper():
            translated = translated.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

    return translated


class PostgresRowWrapper:
    """
    Dict-like wrapper for PostgreSQL rows returned by psycopg dict_row,
    providing full compatibility with sqlite3.Row access patterns:
    row["col"], row[0], row.keys(), dict(row), and row.get("col").
    """
    def __init__(self, data: Dict[str, Any]):
        self._data = data
        self._keys = list(data.keys())
        self._values = list(data.values())

    def __getitem__(self, key: Union[str, int]) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def keys(self) -> List[str]:
        return self._keys

    def values(self) -> List[Any]:
        return self._values

    def items(self):
        return self._data.items()

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"<Row {self._data}>"


class PostgresCursorWrapper:
    """Transparent cursor wrapper translating parameters and wrapping returned rows."""
    def __init__(self, cursor: Any):
        self._cursor = cursor

    def execute(self, query: str, params: Optional[Union[tuple, list, dict]] = None):
        translated_sql = translate_query_for_postgres(query)
        if params is not None:
            # If params is a single element passed as tuple or list
            if isinstance(params, (tuple, list)):
                self._cursor.execute(translated_sql, tuple(params))
            elif isinstance(params, dict):
                self._cursor.execute(translated_sql, params)
            else:
                self._cursor.execute(translated_sql, (params,))
        else:
            self._cursor.execute(translated_sql)
        return self

    def executemany(self, query: str, seq_of_params: Any):
        translated_sql = translate_query_for_postgres(query)
        self._cursor.executemany(translated_sql, seq_of_params)
        return self

    def fetchone(self) -> Optional[PostgresRowWrapper]:
        row = self._cursor.fetchone()
        if row is None:
            return None
        return PostgresRowWrapper(row)

    def fetchall(self) -> List[PostgresRowWrapper]:
        rows = self._cursor.fetchall()
        return [PostgresRowWrapper(r) for r in rows]

    def fetchmany(self, size: int = 1) -> List[PostgresRowWrapper]:
        rows = self._cursor.fetchmany(size)
        return [PostgresRowWrapper(r) for r in rows]

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    @property
    def description(self) -> Any:
        return self._cursor.description

    @property
    def lastrowid(self) -> Any:
        return getattr(self._cursor, "lastrowid", None)

    def close(self):
        self._cursor.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class PostgresConnectionWrapper:
    """Transparent connection wrapper for PostgreSQL ensuring sqlite3-like API."""
    def __init__(self, raw_conn: Any):
        self._conn = raw_conn

    def cursor(self) -> PostgresCursorWrapper:
        from psycopg.rows import dict_row
        raw_cur = self._conn.cursor(row_factory=dict_row)
        return PostgresCursorWrapper(raw_cur)

    def execute(self, query: str, params: Optional[Union[tuple, list, dict]] = None) -> PostgresCursorWrapper:
        cur = self.cursor()
        cur.execute(query, params)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


def _get_postgres_dsn() -> str:
    """Retrieves and normalizes DATABASE_URL for psycopg connection with SSL support."""
    db_url = os.environ.get("DATABASE_URL", "").strip()
    if db_url.startswith("postgresql+psycopg://"):
        db_url = db_url.replace("postgresql+psycopg://", "postgresql://", 1)
    
    # Ensure sslmode=require if connected to remote Supabase / Render database and not already set
    if "sslmode=" not in db_url and not any(h in db_url for h in ["localhost", "127.0.0.1", "::1"]):
        separator = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{separator}sslmode=require"
    
    return db_url


def get_db_connection(db_path: Optional[str] = None):
    """
    Creates a configured database connection.
    - If in SQLite mode: returns configured SQLite connection with WAL mode, foreign keys, and busy timeout.
    - If in PostgreSQL mode: returns configured PostgreSQL connection wrapper (psycopg).
    """
    engine_type = get_database_engine_type(db_path)

    if engine_type == "POSTGRESQL":
        try:
            import psycopg
            dsn = _get_postgres_dsn()
            raw_conn = psycopg.connect(dsn, autocommit=False)
            return PostgresConnectionWrapper(raw_conn)
        except Exception as e:
            logger.error("Failed to connect to PostgreSQL database (%s): %s", sanitize_db_url_for_logs(os.environ.get("DATABASE_URL")), e)
            raise

    # Default: Local SQLite Engine
    target_path = db_path or get_db_path()
    db_directory = os.path.dirname(os.path.abspath(target_path))
    if db_directory:
        os.makedirs(db_directory, exist_ok=True)

    conn = sqlite3.connect(target_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn


# ---------------------------------------------------------------------------
# Schema Initialization (Deterministic for both SQLite & PostgreSQL)
# ---------------------------------------------------------------------------

def _init_sqlite_schema(conn: sqlite3.Connection):
    """Initializes SQLite tables and incremental column migrations."""
    cursor = conn.cursor()

    # Incremental non-destructive migration checks
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analyses';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(analyses);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "is_archived" not in existing_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN is_archived INTEGER NOT NULL DEFAULT 0;")
        if "analyzer_version" not in existing_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN analyzer_version TEXT NOT NULL DEFAULT 'SecureMailScope X 1.0.0';")
        if "schema_version" not in existing_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN schema_version TEXT NOT NULL DEFAULT '1.0';")
        if "custody_link_hash" not in existing_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN custody_link_hash TEXT;")
        if "report_link_hash" not in existing_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN report_link_hash TEXT;")
        if "created_by_actor_id" not in existing_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED';")
        if "finalized_by_actor_id" not in existing_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN finalized_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED';")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cases';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(cases);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "is_archived" not in existing_cols:
            cursor.execute("ALTER TABLE cases ADD COLUMN is_archived INTEGER NOT NULL DEFAULT 0;")
        if "created_by_actor_id" not in existing_cols:
            cursor.execute("ALTER TABLE cases ADD COLUMN created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED';")
        if "created_by_display_name" not in existing_cols:
            cursor.execute("ALTER TABLE cases ADD COLUMN created_by_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst';")
        if "archived_by_actor_id" not in existing_cols:
            cursor.execute("ALTER TABLE cases ADD COLUMN archived_by_actor_id TEXT;")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(audit_events);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "actor_id" not in existing_cols:
            cursor.execute("ALTER TABLE audit_events ADD COLUMN actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED';")
        if "actor_display_name" not in existing_cols:
            cursor.execute("ALTER TABLE audit_events ADD COLUMN actor_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst';")
        if "actor_identity_source" not in existing_cols:
            cursor.execute("ALTER TABLE audit_events ADD COLUMN actor_identity_source TEXT NOT NULL DEFAULT 'UNKNOWN';")
        if "actor_attribution_status" not in existing_cols:
            cursor.execute("ALTER TABLE audit_events ADD COLUMN actor_attribution_status TEXT NOT NULL DEFAULT 'UNATTRIBUTED';")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='custody_events';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(custody_events);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "actor_id" not in existing_cols:
            cursor.execute("ALTER TABLE custody_events ADD COLUMN actor_id TEXT NOT NULL DEFAULT 'SYSTEM';")
        if "actor_display_name" not in existing_cols:
            cursor.execute("ALTER TABLE custody_events ADD COLUMN actor_display_name TEXT NOT NULL DEFAULT 'SecureMailScope X';")
        if "actor_identity_source" not in existing_cols:
            cursor.execute("ALTER TABLE custody_events ADD COLUMN actor_identity_source TEXT NOT NULL DEFAULT 'SYSTEM';")
        if "actor_attribution_status" not in existing_cols:
            cursor.execute("ALTER TABLE custody_events ADD COLUMN actor_attribution_status TEXT NOT NULL DEFAULT 'SYSTEM_GENERATED';")
        if "hash_format_version" not in existing_cols:
            cursor.execute("ALTER TABLE custody_events ADD COLUMN hash_format_version TEXT NOT NULL DEFAULT 'LEGACY_PIPE_V1';")

    # Table definitions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_analyses (
            user_id TEXT NOT NULL,
            analysis_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (user_id, analysis_id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysts (
            analyst_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            email_or_label TEXT,
            role TEXT NOT NULL DEFAULT 'FORENSIC_ANALYST',
            identity_source TEXT NOT NULL DEFAULT 'LOCAL_DECLARED',
            attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id TEXT PRIMARY KEY,
            revision INTEGER NOT NULL DEFAULT 1,
            filename TEXT NOT NULL,
            file_size_bytes INTEGER NOT NULL,
            capture_sha256 TEXT NOT NULL,
            analyzer_version TEXT NOT NULL DEFAULT 'SecureMailScope X 1.0.0',
            schema_version TEXT NOT NULL DEFAULT '1.0',
            analysis_status TEXT NOT NULL DEFAULT 'FINALIZED',
            created_at TEXT NOT NULL,
            finalized_at TEXT,
            is_finalized INTEGER NOT NULL DEFAULT 1,
            is_archived INTEGER NOT NULL DEFAULT 0,
            created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            finalized_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            observed_result_json TEXT NOT NULL,
            observed_result_sha256 TEXT NOT NULL,
            custody_link_hash TEXT,
            report_link_hash TEXT,
            total_packets INTEGER NOT NULL DEFAULT 0,
            raw_total_frames INTEGER NOT NULL DEFAULT 0,
            email_sessions_found INTEGER NOT NULL DEFAULT 0,
            evidence_confidence_score INTEGER,
            evidence_confidence_level TEXT,
            security_grade TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL,
            stream_index INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            security_mode TEXT NOT NULL,
            client TEXT NOT NULL,
            server TEXT NOT NULL,
            server_hostname TEXT,
            start_time_iso TEXT,
            duration_seconds REAL NOT NULL DEFAULT 0.0,
            packets_count INTEGER NOT NULL DEFAULT 0,
            security_grade TEXT,
            health_score INTEGER,
            confidence_score INTEGER,
            pqc_ready INTEGER NOT NULL DEFAULT 0,
            session_result_json TEXT NOT NULL,
            session_result_sha256 TEXT NOT NULL,
            evidence_packets_json TEXT,
            FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE RESTRICT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            analysis_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            rule_id TEXT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT,
            evidence_frames_json TEXT,
            finding_json TEXT NOT NULL,
            finding_sha256 TEXT NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE RESTRICT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            analysis_id TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            correlation_method TEXT NOT NULL DEFAULT 'DETERMINISTIC_RULE_CORRELATION',
            evidence_backed INTEGER NOT NULL DEFAULT 1,
            correlation_result_json TEXT NOT NULL,
            incident_sha256 TEXT NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE RESTRICT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS custody_records (
            analysis_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            capture_sha256 TEXT NOT NULL,
            raw_bytes BLOB,
            ingestion_timestamp TEXT NOT NULL,
            start_timestamp TEXT,
            completion_timestamp TEXT,
            manifest_dict_json TEXT,
            manifest_hash TEXT,
            report_pdf_bytes BLOB,
            report_pdf_hash TEXT,
            is_sealed INTEGER NOT NULL DEFAULT 0,
            overall_status TEXT NOT NULL DEFAULT 'VERIFIED',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS custody_events (
            event_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            artifact_hash TEXT NOT NULL,
            previous_event_hash TEXT NOT NULL,
            current_event_hash TEXT NOT NULL,
            details TEXT,
            sequence_order INTEGER NOT NULL,
            actor_id TEXT NOT NULL DEFAULT 'SYSTEM',
            actor_display_name TEXT NOT NULL DEFAULT 'SecureMailScope X',
            actor_identity_source TEXT NOT NULL DEFAULT 'SYSTEM',
            actor_attribution_status TEXT NOT NULL DEFAULT 'SYSTEM_GENERATED',
            hash_format_version TEXT NOT NULL DEFAULT 'CUSTODY_EVENT_HASH_V2',
            FOREIGN KEY (analysis_id) REFERENCES custody_records (analysis_id) ON DELETE RESTRICT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'OPEN',
            analyst_id TEXT NOT NULL DEFAULT 'analyst-01',
            analyst_name TEXT NOT NULL DEFAULT 'Default Local Analyst',
            tags_json TEXT DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_archived INTEGER NOT NULL DEFAULT 0,
            created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            created_by_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst',
            archived_by_actor_id TEXT,
            payload_json TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_analyses (
            case_id TEXT NOT NULL,
            analysis_id TEXT NOT NULL,
            attached_at TEXT NOT NULL,
            attached_by TEXT DEFAULT 'analyst',
            PRIMARY KEY (case_id, analysis_id),
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_artifacts (
            artifact_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            analysis_id TEXT,
            added_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyst_notes (
            note_id TEXT PRIMARY KEY,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            analyst_id TEXT NOT NULL DEFAULT 'analyst-01',
            analyst_name TEXT NOT NULL DEFAULT 'Local Forensic Analyst',
            note_text TEXT NOT NULL,
            note_sha256 TEXT NOT NULL,
            identity_source TEXT NOT NULL DEFAULT 'LOCAL_DECLARED',
            attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED',
            created_at TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS simulations (
            simulation_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            requested_actions_json TEXT NOT NULL,
            parameters_json TEXT,
            projection_json TEXT NOT NULL,
            projection_sha256 TEXT NOT NULL,
            authoritative INTEGER NOT NULL DEFAULT 0,
            historical_applicability TEXT NOT NULL DEFAULT 'HYPOTHETICAL',
            created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED',
            created_at TEXT NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE RESTRICT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS active_scans (
            scan_id TEXT PRIMARY KEY,
            target_host TEXT NOT NULL,
            connected_ip TEXT,
            ports_scanned_json TEXT NOT NULL,
            provenance TEXT NOT NULL DEFAULT 'ACTIVE_NETWORK_PROBE',
            historical_applicability TEXT NOT NULL DEFAULT 'CURRENT_STATE_ONLY',
            result_json TEXT NOT NULL,
            result_sha256 TEXT NOT NULL,
            initiated_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED',
            created_at TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_enrichments (
            enrichment_id TEXT PRIMARY KEY,
            target_domain TEXT NOT NULL,
            resolver_provider TEXT,
            provenance TEXT NOT NULL DEFAULT 'ACTIVE_DNS_ENRICHMENT',
            historical_applicability TEXT NOT NULL DEFAULT 'CURRENT_STATE_ONLY',
            result_json TEXT NOT NULL,
            result_sha256 TEXT NOT NULL,
            queried_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED',
            queried_at_utc TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            actor_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst',
            actor_identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            actor_attribution_status TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            details TEXT,
            previous_event_hash TEXT NOT NULL,
            current_event_hash TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS custody_manifest_versions (
            manifest_version_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL,
            version_number INTEGER NOT NULL,
            manifest_type TEXT NOT NULL,
            parent_manifest_version_id TEXT,
            previous_manifest_sha256 TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            canonicalization_version TEXT NOT NULL DEFAULT 'SECUREMAILSCOPE_CANONICAL_JSON_V1',
            created_at TEXT NOT NULL,
            created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            created_by_actor_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst',
            actor_identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            actor_attribution_status TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            sealed INTEGER NOT NULL DEFAULT 1,
            supersedes_version_id TEXT,
            purpose TEXT,
            schema_version TEXT NOT NULL DEFAULT '1.0',
            FOREIGN KEY (analysis_id) REFERENCES custody_records (analysis_id) ON DELETE RESTRICT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS report_artifacts (
            report_artifact_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL,
            report_type TEXT NOT NULL DEFAULT 'PDF',
            report_version INTEGER NOT NULL DEFAULT 1,
            filename TEXT NOT NULL,
            media_type TEXT NOT NULL DEFAULT 'application/pdf',
            artifact_sha256 TEXT NOT NULL,
            artifact_size_bytes INTEGER NOT NULL,
            file_path TEXT,
            raw_bytes BLOB,
            generated_at TEXT NOT NULL,
            generated_by_actor_id TEXT NOT NULL DEFAULT 'SYSTEM',
            generated_by_actor_display_name TEXT NOT NULL DEFAULT 'SecureMailScope X',
            actor_identity_source TEXT NOT NULL DEFAULT 'SYSTEM',
            actor_attribution_status TEXT NOT NULL DEFAULT 'SYSTEM_GENERATED',
            generator_version TEXT NOT NULL DEFAULT 'SecureMailScope X 1.0.0',
            source_manifest_version_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'GENERATED',
            FOREIGN KEY (analysis_id) REFERENCES custody_records (analysis_id) ON DELETE RESTRICT,
            FOREIGN KEY (source_manifest_version_id) REFERENCES custody_manifest_versions (manifest_version_id) ON DELETE RESTRICT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS digital_signatures (
            signature_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL,
            report_artifact_id TEXT NOT NULL,
            manifest_version_id TEXT NOT NULL,
            signature_algorithm TEXT NOT NULL,
            signature_format TEXT NOT NULL DEFAULT 'BASE64',
            signature_value TEXT NOT NULL,
            signed_digest_algorithm TEXT NOT NULL DEFAULT 'SHA256',
            signed_digest_value TEXT NOT NULL,
            public_key_fingerprint_sha256 TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            key_id TEXT NOT NULL,
            signed_at TEXT NOT NULL,
            signed_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            signed_by_actor_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst',
            actor_identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            actor_attribution_status TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            verification_status TEXT NOT NULL DEFAULT 'VERIFIED',
            schema_version TEXT NOT NULL DEFAULT '1.0',
            FOREIGN KEY (analysis_id) REFERENCES custody_records (analysis_id) ON DELETE RESTRICT,
            FOREIGN KEY (report_artifact_id) REFERENCES report_artifacts (report_artifact_id) ON DELETE RESTRICT,
            FOREIGN KEY (manifest_version_id) REFERENCES custody_manifest_versions (manifest_version_id) ON DELETE RESTRICT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notarization_records (
            notarization_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL,
            report_artifact_id TEXT NOT NULL,
            signature_id TEXT NOT NULL,
            manifest_version_id TEXT NOT NULL,
            notarization_mode TEXT NOT NULL DEFAULT 'LOCAL_ONLY',
            provider_name TEXT,
            provider_reference TEXT,
            submitted_payload_sha256 TEXT,
            local_proof_sha256 TEXT NOT NULL,
            provider_proof_json TEXT,
            provider_proof_sha256 TEXT,
            status TEXT NOT NULL DEFAULT 'LOCAL_PROOF_CREATED',
            chain_id INTEGER,
            transaction_hash TEXT,
            block_number INTEGER,
            receipt_status INTEGER,
            anchored_value TEXT,
            submitted_at TEXT,
            confirmed_at TEXT,
            external_verification_timestamp TEXT,
            created_at TEXT NOT NULL,
            created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            created_by_actor_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst',
            actor_identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            actor_attribution_status TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            schema_version TEXT NOT NULL DEFAULT '1.0',
            FOREIGN KEY (analysis_id) REFERENCES custody_records (analysis_id) ON DELETE RESTRICT,
            FOREIGN KEY (report_artifact_id) REFERENCES report_artifacts (report_artifact_id) ON DELETE RESTRICT,
            FOREIGN KEY (signature_id) REFERENCES digital_signatures (signature_id) ON DELETE RESTRICT,
            FOREIGN KEY (manifest_version_id) REFERENCES custody_manifest_versions (manifest_version_id) ON DELETE RESTRICT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS siem_deliveries (
            delivery_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            format TEXT NOT NULL,
            transport TEXT NOT NULL,
            destination_label TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            status TEXT NOT NULL,
            error_message TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_assignments (
            assignment_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            analyst_id TEXT NOT NULL,
            analyst_name TEXT NOT NULL,
            role TEXT NOT NULL,
            assigned_by TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_review_policies (
            policy_id TEXT PRIMARY KEY,
            case_id TEXT UNIQUE NOT NULL,
            min_approvals_required INTEGER NOT NULL DEFAULT 1,
            require_lead_investigator_approval INTEGER NOT NULL DEFAULT 0,
            allow_self_review INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_reviews (
            review_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            manifest_sha256_at_review TEXT NOT NULL,
            reviewer_id TEXT NOT NULL,
            reviewer_name TEXT NOT NULL,
            reviewer_role TEXT NOT NULL,
            decision TEXT NOT NULL,
            comments TEXT,
            signature_id TEXT,
            signature_value TEXT,
            signed_payload_sha256 TEXT,
            public_key_pem TEXT,
            public_key_fingerprint TEXT,
            reviewed_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitored_targets (
            target_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            hostname TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            security_mode TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            schedule_type TEXT NOT NULL DEFAULT 'MANUAL',
            schedule_value TEXT,
            baseline_snapshot_id TEXT,
            baseline_pinned_by TEXT,
            baseline_pinned_at TEXT,
            last_scanned_at TEXT,
            next_scan_due_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT 'analyst-01'
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posture_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            reachable INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            security_mode TEXT NOT NULL,
            starttls_supported INTEGER,
            starttls_accepted INTEGER,
            tls_version TEXT,
            cipher_suite TEXT,
            certificate_fingerprint TEXT,
            certificate_subject TEXT,
            certificate_issuer TEXT,
            certificate_not_before TEXT,
            certificate_not_after TEXT,
            certificate_valid INTEGER,
            pfs_status TEXT,
            pqc_status TEXT,
            auth_posture TEXT,
            raw_evidence_reference TEXT,
            scan_result_sha256 TEXT NOT NULL,
            canonical_snapshot_sha256 TEXT NOT NULL,
            FOREIGN KEY (target_id) REFERENCES monitored_targets (target_id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posture_drift_events (
            event_id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL,
            prior_snapshot_id TEXT,
            current_snapshot_id TEXT NOT NULL,
            drift_type TEXT NOT NULL,
            classification TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            details TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            compared_against_baseline INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (target_id) REFERENCES monitored_targets (target_id) ON DELETE CASCADE,
            FOREIGN KEY (current_snapshot_id) REFERENCES posture_snapshots (snapshot_id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediation_plans (
            plan_id TEXT PRIMARY KEY,
            case_id TEXT,
            analysis_id TEXT,
            target_id TEXT,
            title TEXT NOT NULL,
            description TEXT,
            platform TEXT NOT NULL DEFAULT 'GENERIC',
            status TEXT NOT NULL DEFAULT 'PROPOSED',
            version INTEGER NOT NULL DEFAULT 1,
            supersedes_plan_id TEXT,
            assumptions_json TEXT,
            limitations_json TEXT,
            created_by TEXT NOT NULL DEFAULT 'analyst-01',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            applied_by TEXT,
            applied_at TEXT,
            verified_by TEXT,
            verified_at TEXT,
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE SET NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE SET NULL,
            FOREIGN KEY (target_id) REFERENCES monitored_targets (target_id) ON DELETE SET NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediation_plan_items (
            item_id TEXT PRIMARY KEY,
            plan_id TEXT NOT NULL,
            finding_id TEXT,
            finding_code TEXT NOT NULL,
            remediation_id TEXT NOT NULL,
            action_title TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            guidance_text TEXT NOT NULL,
            config_snippet TEXT,
            expected_security_effect TEXT,
            validation_steps_json TEXT,
            rollback_guidance TEXT,
            status TEXT NOT NULL DEFAULT 'PROPOSED',
            evidence_reference TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (plan_id) REFERENCES remediation_plans (plan_id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediation_verifications (
            verification_id TEXT PRIMARY KEY,
            plan_id TEXT NOT NULL,
            verified_by TEXT NOT NULL,
            verified_at TEXT NOT NULL,
            verification_status TEXT NOT NULL,
            verification_method TEXT NOT NULL,
            verification_evidence_reference TEXT,
            prior_finding_count INTEGER NOT NULL DEFAULT 0,
            resolved_finding_count INTEGER NOT NULL DEFAULT 0,
            remaining_finding_count INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            details_json TEXT,
            FOREIGN KEY (plan_id) REFERENCES remediation_plans (plan_id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_rules (
            rule_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            rule_type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'MEDIUM',
            enabled INTEGER NOT NULL DEFAULT 1,
            condition_criteria_json TEXT NOT NULL,
            cooldown_seconds INTEGER NOT NULL DEFAULT 300,
            channels_json TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT 'analyst-01',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW',
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_id TEXT,
            evidence_reference TEXT,
            fingerprint TEXT NOT NULL,
            details_json TEXT,
            triggered_at TEXT NOT NULL,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            resolved_by TEXT,
            resolved_at TEXT,
            resolution_notes TEXT,
            FOREIGN KEY (rule_id) REFERENCES alert_rules (rule_id) ON DELETE RESTRICT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_deliveries (
            delivery_id TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            status TEXT NOT NULL,
            destination TEXT NOT NULL,
            payload_json TEXT,
            error_message TEXT,
            delivered_at TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts (alert_id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pqc_crypto_assets (
            asset_id TEXT PRIMARY KEY,
            analysis_id TEXT,
            target_id TEXT,
            asset_type TEXT NOT NULL,
            identifier TEXT NOT NULL,
            key_exchange_algorithm TEXT,
            cipher_algorithm TEXT,
            signature_algorithm TEXT,
            key_length_bits INTEGER,
            has_forward_secrecy INTEGER NOT NULL DEFAULT 0,
            pqc_readiness TEXT NOT NULL DEFAULT 'CLASSICAL_ONLY',
            hndl_exposure TEXT NOT NULL DEFAULT 'UNKNOWN',
            data_sensitivity_lifetime TEXT NOT NULL DEFAULT 'UNKNOWN',
            first_observed_at TEXT NOT NULL,
            last_observed_at TEXT NOT NULL,
            evidence_reference TEXT,
            FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE,
            FOREIGN KEY (target_id) REFERENCES monitored_targets (target_id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pqc_migration_roadmaps (
            roadmap_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            target_architecture TEXT NOT NULL,
            current_readiness TEXT NOT NULL,
            highest_exposure TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'DRAFT',
            total_steps INTEGER NOT NULL DEFAULT 7,
            completed_steps INTEGER NOT NULL DEFAULT 0,
            canonical_roadmap_sha256 TEXT NOT NULL,
            signed_by_analyst_id TEXT,
            signed_by_analyst_name TEXT,
            signature_algorithm TEXT,
            signature_value TEXT,
            created_by TEXT NOT NULL DEFAULT 'analyst-01',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pqc_migration_steps (
            step_id TEXT PRIMARY KEY,
            roadmap_id TEXT NOT NULL,
            phase_number INTEGER NOT NULL,
            phase_name TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            target_standards_json TEXT NOT NULL,
            deliverables_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NOT_STARTED',
            order_index INTEGER NOT NULL,
            notes TEXT,
            completed_at TEXT,
            FOREIGN KEY (roadmap_id) REFERENCES pqc_migration_roadmaps (roadmap_id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pqc_gap_findings (
            gap_id TEXT PRIMARY KEY,
            roadmap_id TEXT NOT NULL,
            asset_id TEXT,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            affected_component TEXT NOT NULL,
            recommended_pqc_replacement TEXT NOT NULL,
            nist_standard_ref TEXT NOT NULL,
            FOREIGN KEY (roadmap_id) REFERENCES pqc_migration_roadmaps (roadmap_id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES pqc_crypto_assets (asset_id) ON DELETE SET NULL
        );
    """)

    # Performance Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_analysis_id ON sessions(analysis_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_analysis_id ON findings(analysis_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_analysis_id ON incidents(analysis_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_custody_events_analysis ON custody_events(analysis_id, sequence_order);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyst_notes_target ON analyst_notes(target_type, target_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_analyses_case ON case_analyses(case_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_analyses_analysis ON case_analyses(analysis_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysts_active ON analysts(is_active);")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_manifest_version_unique ON custody_manifest_versions(analysis_id, version_number);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_manifest_sha ON custody_manifest_versions(manifest_sha256);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_report_artifacts_analysis ON report_artifacts(analysis_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_report_artifacts_sha ON report_artifacts(artifact_sha256);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_digital_signatures_analysis ON digital_signatures(analysis_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_digital_signatures_report ON digital_signatures(report_artifact_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_digital_signatures_key_id ON digital_signatures(key_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notarization_records_analysis ON notarization_records(analysis_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notarization_records_report ON notarization_records(report_artifact_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notarization_records_sig ON notarization_records(signature_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notarization_records_proof_sha ON notarization_records(local_proof_sha256);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notarization_records_tx_hash ON notarization_records(transaction_hash);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_assignments_case ON case_assignments(case_id, is_active);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_assignments_analyst ON case_assignments(analyst_id, is_active);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_reviews_case ON case_reviews(case_id, is_active);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_reviews_manifest ON case_reviews(case_id, manifest_sha256_at_review);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_monitored_targets_enabled ON monitored_targets(enabled);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_monitored_targets_hostname ON monitored_targets(hostname);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_posture_snapshots_target ON posture_snapshots(target_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_posture_snapshots_scanned_at ON posture_snapshots(scanned_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_posture_snapshots_canonical_sha ON posture_snapshots(canonical_snapshot_sha256);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_posture_drift_events_target ON posture_drift_events(target_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_posture_drift_events_detected_at ON posture_drift_events(detected_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_posture_drift_events_classification ON posture_drift_events(classification);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_plans_case ON remediation_plans(case_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_plans_target ON remediation_plans(target_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_plans_status ON remediation_plans(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_plan_items_plan ON remediation_plan_items(plan_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_plan_items_code ON remediation_plan_items(finding_code);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_verifications_plan ON remediation_verifications(plan_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_verifications_status ON remediation_verifications(verification_status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts(triggered_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_deliveries_alert_id ON alert_deliveries(alert_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pqc_crypto_assets_analysis ON pqc_crypto_assets(analysis_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pqc_crypto_assets_target ON pqc_crypto_assets(target_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pqc_crypto_assets_exposure ON pqc_crypto_assets(hndl_exposure);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pqc_roadmaps_status ON pqc_migration_roadmaps(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pqc_steps_roadmap ON pqc_migration_steps(roadmap_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pqc_gap_findings_roadmap ON pqc_gap_findings(roadmap_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_analyses_user_id ON user_analyses(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_analyses_analysis_id ON user_analyses(analysis_id);")

    conn.commit()


def _init_postgres_schema(conn: PostgresConnectionWrapper):
    """Initializes PostgreSQL tables, foreign keys, and indexes."""
    cursor = conn.cursor()

    pg_tables = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(128) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS user_analyses (
            user_id VARCHAR(128) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
            analysis_id TEXT NOT NULL REFERENCES analyses (analysis_id) ON DELETE CASCADE,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (user_id, analysis_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS analysts (
            analyst_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            email_or_label TEXT,
            role TEXT NOT NULL DEFAULT 'FORENSIC_ANALYST',
            identity_source TEXT NOT NULL DEFAULT 'LOCAL_DECLARED',
            attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id TEXT PRIMARY KEY,
            revision INTEGER NOT NULL DEFAULT 1,
            filename TEXT NOT NULL,
            file_size_bytes BIGINT NOT NULL,
            capture_sha256 TEXT NOT NULL,
            analyzer_version TEXT NOT NULL DEFAULT 'SecureMailScope X 1.0.0',
            schema_version TEXT NOT NULL DEFAULT '1.0',
            analysis_status TEXT NOT NULL DEFAULT 'FINALIZED',
            created_at TEXT NOT NULL,
            finalized_at TEXT,
            is_finalized INTEGER NOT NULL DEFAULT 1,
            is_archived INTEGER NOT NULL DEFAULT 0,
            created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            finalized_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            observed_result_json TEXT NOT NULL,
            observed_result_sha256 TEXT NOT NULL,
            custody_link_hash TEXT,
            report_link_hash TEXT,
            total_packets INTEGER NOT NULL DEFAULT 0,
            raw_total_frames INTEGER NOT NULL DEFAULT 0,
            email_sessions_found INTEGER NOT NULL DEFAULT 0,
            evidence_confidence_score INTEGER,
            evidence_confidence_level TEXT,
            security_grade TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL REFERENCES analyses (analysis_id) ON DELETE RESTRICT,
            stream_index INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            security_mode TEXT NOT NULL,
            client TEXT NOT NULL,
            server TEXT NOT NULL,
            server_hostname TEXT,
            start_time_iso TEXT,
            duration_seconds DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            packets_count INTEGER NOT NULL DEFAULT 0,
            security_grade TEXT,
            health_score INTEGER,
            confidence_score INTEGER,
            pqc_ready INTEGER NOT NULL DEFAULT 0,
            session_result_json TEXT NOT NULL,
            session_result_sha256 TEXT NOT NULL,
            evidence_packets_json TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            analysis_id TEXT NOT NULL REFERENCES analyses (analysis_id) ON DELETE RESTRICT,
            session_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            rule_id TEXT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT,
            evidence_frames_json TEXT,
            finding_json TEXT NOT NULL,
            finding_sha256 TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            analysis_id TEXT NOT NULL REFERENCES analyses (analysis_id) ON DELETE RESTRICT,
            incident_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            correlation_method TEXT NOT NULL DEFAULT 'DETERMINISTIC_RULE_CORRELATION',
            evidence_backed INTEGER NOT NULL DEFAULT 1,
            correlation_result_json TEXT NOT NULL,
            incident_sha256 TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS custody_records (
            analysis_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_size BIGINT NOT NULL,
            capture_sha256 TEXT NOT NULL,
            raw_bytes BYTEA,
            ingestion_timestamp TEXT NOT NULL,
            start_timestamp TEXT,
            completion_timestamp TEXT,
            manifest_dict_json TEXT,
            manifest_hash TEXT,
            report_pdf_bytes BYTEA,
            report_pdf_hash TEXT,
            is_sealed INTEGER NOT NULL DEFAULT 0,
            overall_status TEXT NOT NULL DEFAULT 'VERIFIED',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS custody_events (
            event_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL REFERENCES custody_records (analysis_id) ON DELETE RESTRICT,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            artifact_hash TEXT NOT NULL,
            previous_event_hash TEXT NOT NULL,
            current_event_hash TEXT NOT NULL,
            details TEXT,
            sequence_order INTEGER NOT NULL,
            actor_id TEXT NOT NULL DEFAULT 'SYSTEM',
            actor_display_name TEXT NOT NULL DEFAULT 'SecureMailScope X',
            actor_identity_source TEXT NOT NULL DEFAULT 'SYSTEM',
            actor_attribution_status TEXT NOT NULL DEFAULT 'SYSTEM_GENERATED',
            hash_format_version TEXT NOT NULL DEFAULT 'CUSTODY_EVENT_HASH_V2'
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'OPEN',
            analyst_id TEXT NOT NULL DEFAULT 'analyst-01',
            analyst_name TEXT NOT NULL DEFAULT 'Default Local Analyst',
            tags_json TEXT DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_archived INTEGER NOT NULL DEFAULT 0,
            created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            created_by_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst',
            archived_by_actor_id TEXT,
            payload_json TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS case_analyses (
            case_id TEXT NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
            analysis_id TEXT NOT NULL,
            attached_at TEXT NOT NULL,
            attached_by TEXT DEFAULT 'analyst',
            PRIMARY KEY (case_id, analysis_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS case_artifacts (
            artifact_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
            artifact_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            analysis_id TEXT,
            added_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS analyst_notes (
            note_id TEXT PRIMARY KEY,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            analyst_id TEXT NOT NULL DEFAULT 'analyst-01',
            analyst_name TEXT NOT NULL DEFAULT 'Local Forensic Analyst',
            note_text TEXT NOT NULL,
            note_sha256 TEXT NOT NULL,
            identity_source TEXT NOT NULL DEFAULT 'LOCAL_DECLARED',
            attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED',
            created_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS simulations (
            simulation_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL REFERENCES analyses (analysis_id) ON DELETE RESTRICT,
            session_id TEXT NOT NULL,
            requested_actions_json TEXT NOT NULL,
            parameters_json TEXT,
            projection_json TEXT NOT NULL,
            projection_sha256 TEXT NOT NULL,
            authoritative INTEGER NOT NULL DEFAULT 0,
            historical_applicability TEXT NOT NULL DEFAULT 'HYPOTHETICAL',
            created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED',
            created_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS active_scans (
            scan_id TEXT PRIMARY KEY,
            target_host TEXT NOT NULL,
            connected_ip TEXT,
            ports_scanned_json TEXT NOT NULL,
            provenance TEXT NOT NULL DEFAULT 'ACTIVE_NETWORK_PROBE',
            historical_applicability TEXT NOT NULL DEFAULT 'CURRENT_STATE_ONLY',
            result_json TEXT NOT NULL,
            result_sha256 TEXT NOT NULL,
            initiated_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED',
            created_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS dns_enrichments (
            enrichment_id TEXT PRIMARY KEY,
            target_domain TEXT NOT NULL,
            resolver_provider TEXT,
            provenance TEXT NOT NULL DEFAULT 'ACTIVE_DNS_ENRICHMENT',
            historical_applicability TEXT NOT NULL DEFAULT 'CURRENT_STATE_ONLY',
            result_json TEXT NOT NULL,
            result_sha256 TEXT NOT NULL,
            queried_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED',
            queried_at_utc TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            actor_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst',
            actor_identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            actor_attribution_status TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            details TEXT,
            previous_event_hash TEXT NOT NULL,
            current_event_hash TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS custody_manifest_versions (
            manifest_version_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL REFERENCES custody_records (analysis_id) ON DELETE RESTRICT,
            version_number INTEGER NOT NULL,
            manifest_type TEXT NOT NULL,
            parent_manifest_version_id TEXT,
            previous_manifest_sha256 TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            canonicalization_version TEXT NOT NULL DEFAULT 'SECUREMAILSCOPE_CANONICAL_JSON_V1',
            created_at TEXT NOT NULL,
            created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            created_by_actor_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst',
            actor_identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            actor_attribution_status TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            sealed INTEGER NOT NULL DEFAULT 1,
            supersedes_version_id TEXT,
            purpose TEXT,
            schema_version TEXT NOT NULL DEFAULT '1.0'
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS report_artifacts (
            report_artifact_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL REFERENCES custody_records (analysis_id) ON DELETE RESTRICT,
            report_type TEXT NOT NULL DEFAULT 'PDF',
            report_version INTEGER NOT NULL DEFAULT 1,
            filename TEXT NOT NULL,
            media_type TEXT NOT NULL DEFAULT 'application/pdf',
            artifact_sha256 TEXT NOT NULL,
            artifact_size_bytes BIGINT NOT NULL,
            file_path TEXT,
            raw_bytes BYTEA,
            generated_at TEXT NOT NULL,
            generated_by_actor_id TEXT NOT NULL DEFAULT 'SYSTEM',
            generated_by_actor_display_name TEXT NOT NULL DEFAULT 'SecureMailScope X',
            actor_identity_source TEXT NOT NULL DEFAULT 'SYSTEM',
            actor_attribution_status TEXT NOT NULL DEFAULT 'SYSTEM_GENERATED',
            generator_version TEXT NOT NULL DEFAULT 'SecureMailScope X 1.0.0',
            source_manifest_version_id TEXT NOT NULL REFERENCES custody_manifest_versions (manifest_version_id) ON DELETE RESTRICT,
            status TEXT NOT NULL DEFAULT 'GENERATED'
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS digital_signatures (
            signature_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL REFERENCES custody_records (analysis_id) ON DELETE RESTRICT,
            report_artifact_id TEXT NOT NULL REFERENCES report_artifacts (report_artifact_id) ON DELETE RESTRICT,
            manifest_version_id TEXT NOT NULL REFERENCES custody_manifest_versions (manifest_version_id) ON DELETE RESTRICT,
            signature_algorithm TEXT NOT NULL,
            signature_format TEXT NOT NULL DEFAULT 'BASE64',
            signature_value TEXT NOT NULL,
            signed_digest_algorithm TEXT NOT NULL DEFAULT 'SHA256',
            signed_digest_value TEXT NOT NULL,
            public_key_fingerprint_sha256 TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            key_id TEXT NOT NULL,
            signed_at TEXT NOT NULL,
            signed_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            signed_by_actor_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst',
            actor_identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            actor_attribution_status TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            verification_status TEXT NOT NULL DEFAULT 'VERIFIED',
            schema_version TEXT NOT NULL DEFAULT '1.0'
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS notarization_records (
            notarization_id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL REFERENCES custody_records (analysis_id) ON DELETE RESTRICT,
            report_artifact_id TEXT NOT NULL REFERENCES report_artifacts (report_artifact_id) ON DELETE RESTRICT,
            signature_id TEXT NOT NULL REFERENCES digital_signatures (signature_id) ON DELETE RESTRICT,
            manifest_version_id TEXT NOT NULL REFERENCES custody_manifest_versions (manifest_version_id) ON DELETE RESTRICT,
            notarization_mode TEXT NOT NULL DEFAULT 'LOCAL_ONLY',
            provider_name TEXT,
            provider_reference TEXT,
            submitted_payload_sha256 TEXT,
            local_proof_sha256 TEXT NOT NULL,
            provider_proof_json TEXT,
            provider_proof_sha256 TEXT,
            status TEXT NOT NULL DEFAULT 'LOCAL_PROOF_CREATED',
            chain_id BIGINT,
            transaction_hash TEXT,
            block_number BIGINT,
            receipt_status INTEGER,
            anchored_value TEXT,
            submitted_at TEXT,
            confirmed_at TEXT,
            external_verification_timestamp TEXT,
            created_at TEXT NOT NULL,
            created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            created_by_actor_display_name TEXT NOT NULL DEFAULT 'Unattributed Analyst',
            actor_identity_source TEXT NOT NULL DEFAULT 'UNKNOWN',
            actor_attribution_status TEXT NOT NULL DEFAULT 'UNATTRIBUTED',
            schema_version TEXT NOT NULL DEFAULT '1.0'
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS siem_deliveries (
            delivery_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            format TEXT NOT NULL,
            transport TEXT NOT NULL,
            destination_label TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            status TEXT NOT NULL,
            error_message TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS case_assignments (
            assignment_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
            analyst_id TEXT NOT NULL,
            analyst_name TEXT NOT NULL,
            role TEXT NOT NULL,
            assigned_by TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS case_review_policies (
            policy_id TEXT PRIMARY KEY,
            case_id TEXT UNIQUE NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
            min_approvals_required INTEGER NOT NULL DEFAULT 1,
            require_lead_investigator_approval INTEGER NOT NULL DEFAULT 0,
            allow_self_review INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS case_reviews (
            review_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
            manifest_sha256_at_review TEXT NOT NULL,
            reviewer_id TEXT NOT NULL,
            reviewer_name TEXT NOT NULL,
            reviewer_role TEXT NOT NULL,
            decision TEXT NOT NULL,
            comments TEXT,
            signature_id TEXT,
            signature_value TEXT,
            signed_payload_sha256 TEXT,
            public_key_pem TEXT,
            public_key_fingerprint TEXT,
            reviewed_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS monitored_targets (
            target_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            hostname TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            security_mode TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            schedule_type TEXT NOT NULL DEFAULT 'MANUAL',
            schedule_value TEXT,
            baseline_snapshot_id TEXT,
            baseline_pinned_by TEXT,
            baseline_pinned_at TEXT,
            last_scanned_at TEXT,
            next_scan_due_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT 'analyst-01'
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS posture_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL REFERENCES monitored_targets (target_id) ON DELETE CASCADE,
            scanned_at TEXT NOT NULL,
            reachable INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            security_mode TEXT NOT NULL,
            starttls_supported INTEGER,
            starttls_accepted INTEGER,
            tls_version TEXT,
            cipher_suite TEXT,
            certificate_fingerprint TEXT,
            certificate_subject TEXT,
            certificate_issuer TEXT,
            certificate_not_before TEXT,
            certificate_not_after TEXT,
            certificate_valid INTEGER,
            pfs_status TEXT,
            pqc_status TEXT,
            auth_posture TEXT,
            raw_evidence_reference TEXT,
            scan_result_sha256 TEXT NOT NULL,
            canonical_snapshot_sha256 TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS posture_drift_events (
            event_id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL REFERENCES monitored_targets (target_id) ON DELETE CASCADE,
            prior_snapshot_id TEXT,
            current_snapshot_id TEXT NOT NULL REFERENCES posture_snapshots (snapshot_id) ON DELETE CASCADE,
            drift_type TEXT NOT NULL,
            classification TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            details TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            compared_against_baseline INTEGER NOT NULL DEFAULT 0
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS remediation_plans (
            plan_id TEXT PRIMARY KEY,
            case_id TEXT REFERENCES cases (id) ON DELETE SET NULL,
            analysis_id TEXT REFERENCES analyses (analysis_id) ON DELETE SET NULL,
            target_id TEXT REFERENCES monitored_targets (target_id) ON DELETE SET NULL,
            title TEXT NOT NULL,
            description TEXT,
            platform TEXT NOT NULL DEFAULT 'GENERIC',
            status TEXT NOT NULL DEFAULT 'PROPOSED',
            version INTEGER NOT NULL DEFAULT 1,
            supersedes_plan_id TEXT,
            assumptions_json TEXT,
            limitations_json TEXT,
            created_by TEXT NOT NULL DEFAULT 'analyst-01',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            applied_by TEXT,
            applied_at TEXT,
            verified_by TEXT,
            verified_at TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS remediation_plan_items (
            item_id TEXT PRIMARY KEY,
            plan_id TEXT NOT NULL REFERENCES remediation_plans (plan_id) ON DELETE CASCADE,
            finding_id TEXT,
            finding_code TEXT NOT NULL,
            remediation_id TEXT NOT NULL,
            action_title TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            guidance_text TEXT NOT NULL,
            config_snippet TEXT,
            expected_security_effect TEXT,
            validation_steps_json TEXT,
            rollback_guidance TEXT,
            status TEXT NOT NULL DEFAULT 'PROPOSED',
            evidence_reference TEXT,
            created_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS remediation_verifications (
            verification_id TEXT PRIMARY KEY,
            plan_id TEXT NOT NULL REFERENCES remediation_plans (plan_id) ON DELETE CASCADE,
            verified_by TEXT NOT NULL,
            verified_at TEXT NOT NULL,
            verification_status TEXT NOT NULL,
            verification_method TEXT NOT NULL,
            verification_evidence_reference TEXT,
            prior_finding_count INTEGER NOT NULL DEFAULT 0,
            resolved_finding_count INTEGER NOT NULL DEFAULT 0,
            remaining_finding_count INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            details_json TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS alert_rules (
            rule_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            rule_type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'MEDIUM',
            enabled INTEGER NOT NULL DEFAULT 1,
            condition_criteria_json TEXT NOT NULL,
            cooldown_seconds INTEGER NOT NULL DEFAULT 300,
            channels_json TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT 'analyst-01',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL REFERENCES alert_rules (rule_id) ON DELETE RESTRICT,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW',
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_id TEXT,
            evidence_reference TEXT,
            fingerprint TEXT NOT NULL,
            details_json TEXT,
            triggered_at TEXT NOT NULL,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            resolved_by TEXT,
            resolved_at TEXT,
            resolution_notes TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS alert_deliveries (
            delivery_id TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL REFERENCES alerts (alert_id) ON DELETE CASCADE,
            channel TEXT NOT NULL,
            status TEXT NOT NULL,
            destination TEXT NOT NULL,
            payload_json TEXT,
            error_message TEXT,
            delivered_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS pqc_crypto_assets (
            asset_id TEXT PRIMARY KEY,
            analysis_id TEXT REFERENCES analyses (analysis_id) ON DELETE CASCADE,
            target_id TEXT REFERENCES monitored_targets (target_id) ON DELETE CASCADE,
            asset_type TEXT NOT NULL,
            identifier TEXT NOT NULL,
            key_exchange_algorithm TEXT,
            cipher_algorithm TEXT,
            signature_algorithm TEXT,
            key_length_bits INTEGER,
            has_forward_secrecy INTEGER NOT NULL DEFAULT 0,
            pqc_readiness TEXT NOT NULL DEFAULT 'CLASSICAL_ONLY',
            hndl_exposure TEXT NOT NULL DEFAULT 'UNKNOWN',
            data_sensitivity_lifetime TEXT NOT NULL DEFAULT 'UNKNOWN',
            first_observed_at TEXT NOT NULL,
            last_observed_at TEXT NOT NULL,
            evidence_reference TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS pqc_migration_roadmaps (
            roadmap_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            target_architecture TEXT NOT NULL,
            current_readiness TEXT NOT NULL,
            highest_exposure TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'DRAFT',
            total_steps INTEGER NOT NULL DEFAULT 7,
            completed_steps INTEGER NOT NULL DEFAULT 0,
            canonical_roadmap_sha256 TEXT NOT NULL,
            signed_by_analyst_id TEXT,
            signed_by_analyst_name TEXT,
            signature_algorithm TEXT,
            signature_value TEXT,
            created_by TEXT NOT NULL DEFAULT 'analyst-01',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS pqc_migration_steps (
            step_id TEXT PRIMARY KEY,
            roadmap_id TEXT NOT NULL REFERENCES pqc_migration_roadmaps (roadmap_id) ON DELETE CASCADE,
            phase_number INTEGER NOT NULL,
            phase_name TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            target_standards_json TEXT NOT NULL,
            deliverables_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NOT_STARTED',
            order_index INTEGER NOT NULL,
            notes TEXT,
            completed_at TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS pqc_gap_findings (
            gap_id TEXT PRIMARY KEY,
            roadmap_id TEXT NOT NULL REFERENCES pqc_migration_roadmaps (roadmap_id) ON DELETE CASCADE,
            asset_id TEXT REFERENCES pqc_crypto_assets (asset_id) ON DELETE SET NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            affected_component TEXT NOT NULL,
            recommended_pqc_replacement TEXT NOT NULL,
            nist_standard_ref TEXT NOT NULL
        );
        """
    ]

    for ddl in pg_tables:
        cursor.execute(ddl)

    pg_indexes = [
        "CREATE INDEX IF NOT EXISTS idx_sessions_analysis_id ON sessions(analysis_id);",
        "CREATE INDEX IF NOT EXISTS idx_findings_analysis_id ON findings(analysis_id);",
        "CREATE INDEX IF NOT EXISTS idx_incidents_analysis_id ON incidents(analysis_id);",
        "CREATE INDEX IF NOT EXISTS idx_custody_events_analysis ON custody_events(analysis_id, sequence_order);",
        "CREATE INDEX IF NOT EXISTS idx_analyst_notes_target ON analyst_notes(target_type, target_id);",
        "CREATE INDEX IF NOT EXISTS idx_case_analyses_case ON case_analyses(case_id);",
        "CREATE INDEX IF NOT EXISTS idx_case_analyses_analysis ON case_analyses(analysis_id);",
        "CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id);",
        "CREATE INDEX IF NOT EXISTS idx_analysts_active ON analysts(is_active);",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_manifest_version_unique ON custody_manifest_versions(analysis_id, version_number);",
        "CREATE INDEX IF NOT EXISTS idx_manifest_sha ON custody_manifest_versions(manifest_sha256);",
        "CREATE INDEX IF NOT EXISTS idx_report_artifacts_analysis ON report_artifacts(analysis_id);",
        "CREATE INDEX IF NOT EXISTS idx_report_artifacts_sha ON report_artifacts(artifact_sha256);",
        "CREATE INDEX IF NOT EXISTS idx_digital_signatures_analysis ON digital_signatures(analysis_id);",
        "CREATE INDEX IF NOT EXISTS idx_digital_signatures_report ON digital_signatures(report_artifact_id);",
        "CREATE INDEX IF NOT EXISTS idx_digital_signatures_key_id ON digital_signatures(key_id);",
        "CREATE INDEX IF NOT EXISTS idx_notarization_records_analysis ON notarization_records(analysis_id);",
        "CREATE INDEX IF NOT EXISTS idx_notarization_records_report ON notarization_records(report_artifact_id);",
        "CREATE INDEX IF NOT EXISTS idx_notarization_records_sig ON notarization_records(signature_id);",
        "CREATE INDEX IF NOT EXISTS idx_notarization_records_proof_sha ON notarization_records(local_proof_sha256);",
        "CREATE INDEX IF NOT EXISTS idx_notarization_records_tx_hash ON notarization_records(transaction_hash);",
        "CREATE INDEX IF NOT EXISTS idx_case_assignments_case ON case_assignments(case_id, is_active);",
        "CREATE INDEX IF NOT EXISTS idx_case_assignments_analyst ON case_assignments(analyst_id, is_active);",
        "CREATE INDEX IF NOT EXISTS idx_case_reviews_case ON case_reviews(case_id, is_active);",
        "CREATE INDEX IF NOT EXISTS idx_case_reviews_manifest ON case_reviews(case_id, manifest_sha256_at_review);",
        "CREATE INDEX IF NOT EXISTS idx_monitored_targets_enabled ON monitored_targets(enabled);",
        "CREATE INDEX IF NOT EXISTS idx_monitored_targets_hostname ON monitored_targets(hostname);",
        "CREATE INDEX IF NOT EXISTS idx_posture_snapshots_target ON posture_snapshots(target_id);",
        "CREATE INDEX IF NOT EXISTS idx_posture_snapshots_scanned_at ON posture_snapshots(scanned_at);",
        "CREATE INDEX IF NOT EXISTS idx_posture_snapshots_canonical_sha ON posture_snapshots(canonical_snapshot_sha256);",
        "CREATE INDEX IF NOT EXISTS idx_posture_drift_events_target ON posture_drift_events(target_id);",
        "CREATE INDEX IF NOT EXISTS idx_posture_drift_events_detected_at ON posture_drift_events(detected_at);",
        "CREATE INDEX IF NOT EXISTS idx_posture_drift_events_classification ON posture_drift_events(classification);",
        "CREATE INDEX IF NOT EXISTS idx_remediation_plans_case ON remediation_plans(case_id);",
        "CREATE INDEX IF NOT EXISTS idx_remediation_plans_target ON remediation_plans(target_id);",
        "CREATE INDEX IF NOT EXISTS idx_remediation_plans_status ON remediation_plans(status);",
        "CREATE INDEX IF NOT EXISTS idx_remediation_plan_items_plan ON remediation_plan_items(plan_id);",
        "CREATE INDEX IF NOT EXISTS idx_remediation_plan_items_code ON remediation_plan_items(finding_code);",
        "CREATE INDEX IF NOT EXISTS idx_remediation_verifications_plan ON remediation_verifications(plan_id);",
        "CREATE INDEX IF NOT EXISTS idx_remediation_verifications_status ON remediation_verifications(verification_status);",
        "CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts(triggered_at);",
        "CREATE INDEX IF NOT EXISTS idx_alert_deliveries_alert_id ON alert_deliveries(alert_id);",
        "CREATE INDEX IF NOT EXISTS idx_pqc_crypto_assets_analysis ON pqc_crypto_assets(analysis_id);",
        "CREATE INDEX IF NOT EXISTS idx_pqc_crypto_assets_target ON pqc_crypto_assets(target_id);",
        "CREATE INDEX IF NOT EXISTS idx_pqc_crypto_assets_exposure ON pqc_crypto_assets(hndl_exposure);",
        "CREATE INDEX IF NOT EXISTS idx_pqc_roadmaps_status ON pqc_migration_roadmaps(status);",
        "CREATE INDEX IF NOT EXISTS idx_pqc_steps_roadmap ON pqc_migration_steps(roadmap_id);",
        "CREATE INDEX IF NOT EXISTS idx_pqc_gap_findings_roadmap ON pqc_gap_findings(roadmap_id);",
        "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
        "CREATE INDEX IF NOT EXISTS idx_user_analyses_user_id ON user_analyses(user_id);",
        "CREATE INDEX IF NOT EXISTS idx_user_analyses_analysis_id ON user_analyses(analysis_id);"
    ]

    for idx_sql in pg_indexes:
        cursor.execute(idx_sql)

    conn.commit()


def init_db(db_path: Optional[str] = None):
    """Initializes all required database schemas deterministically for active engine (SQLite or PostgreSQL)."""
    conn = get_db_connection(db_path)
    engine_type = get_database_engine_type(db_path)

    if engine_type == "POSTGRESQL":
        _init_postgres_schema(conn)
    else:
        _init_sqlite_schema(conn)

    conn.close()


# Initialize database schemas on module import
init_db()

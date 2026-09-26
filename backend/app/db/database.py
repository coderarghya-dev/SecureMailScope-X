"""
SecureMailScope X - Persistent SQLite Database Engine
Provides durable local persistence for analyses, cases, custody records, signatures, and audit trails.
"""

import os
import sqlite3
import threading
from typing import Optional

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
DEFAULT_DB_PATH = os.path.join(DB_DIR, "securemailscope.db")

# Global custom DB path for test isolation
_custom_db_path: Optional[str] = None


def set_custom_db_path(path: Optional[str]):
    """Set custom DB path for test isolation."""
    global _custom_db_path
    _custom_db_path = path


def get_db_path() -> str:
    """Retrieve active DB path (custom override or default)."""
    global _custom_db_path
    return _custom_db_path or os.environ.get("SMS_DB_PATH", DEFAULT_DB_PATH)


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a configured SQLite connection with WAL mode, foreign keys, and busy timeout."""
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


def init_db(db_path: Optional[str] = None):
    """Initializes all required database schemas deterministically."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Non-destructive schema migration checks
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

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='simulations';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(simulations);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "created_by_actor_id" not in existing_cols:
            cursor.execute("ALTER TABLE simulations ADD COLUMN created_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED';")
        if "identity_source" not in existing_cols:
            cursor.execute("ALTER TABLE simulations ADD COLUMN identity_source TEXT NOT NULL DEFAULT 'UNKNOWN';")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='active_scans';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(active_scans);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "initiated_by_actor_id" not in existing_cols:
            cursor.execute("ALTER TABLE active_scans ADD COLUMN initiated_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED';")
        if "identity_source" not in existing_cols:
            cursor.execute("ALTER TABLE active_scans ADD COLUMN identity_source TEXT NOT NULL DEFAULT 'UNKNOWN';")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='dns_enrichments';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(dns_enrichments);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "queried_by_actor_id" not in existing_cols:
            cursor.execute("ALTER TABLE dns_enrichments ADD COLUMN queried_by_actor_id TEXT NOT NULL DEFAULT 'UNATTRIBUTED';")
        if "identity_source" not in existing_cols:
            cursor.execute("ALTER TABLE dns_enrichments ADD COLUMN identity_source TEXT NOT NULL DEFAULT 'UNKNOWN';")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analyst_notes';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(analyst_notes);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "identity_source" not in existing_cols:
            cursor.execute("ALTER TABLE analyst_notes ADD COLUMN identity_source TEXT NOT NULL DEFAULT 'LOCAL_DECLARED';")
        if "attribution_status" not in existing_cols:
            cursor.execute("ALTER TABLE analyst_notes ADD COLUMN attribution_status TEXT NOT NULL DEFAULT 'ATTRIBUTED';")

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

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='report_artifacts';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(report_artifacts);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "generated_by_actor_display_name" not in existing_cols:
            cursor.execute("ALTER TABLE report_artifacts ADD COLUMN generated_by_actor_display_name TEXT NOT NULL DEFAULT 'SecureMailScope X';")
        if "actor_identity_source" not in existing_cols:
            cursor.execute("ALTER TABLE report_artifacts ADD COLUMN actor_identity_source TEXT NOT NULL DEFAULT 'SYSTEM';")
        if "actor_attribution_status" not in existing_cols:
            cursor.execute("ALTER TABLE report_artifacts ADD COLUMN actor_attribution_status TEXT NOT NULL DEFAULT 'SYSTEM_GENERATED';")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='digital_signatures';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(digital_signatures);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "signature_id" not in existing_cols:
            cursor.execute("ALTER TABLE digital_signatures RENAME TO legacy_digital_signatures_old;")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notarization_records';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(notarization_records);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "notarization_id" not in existing_cols:
            cursor.execute("ALTER TABLE notarization_records RENAME TO legacy_notarization_records_old;")
        else:
            if "chain_id" not in existing_cols:
                cursor.execute("ALTER TABLE notarization_records ADD COLUMN chain_id INTEGER;")
            if "transaction_hash" not in existing_cols:
                cursor.execute("ALTER TABLE notarization_records ADD COLUMN transaction_hash TEXT;")
            if "block_number" not in existing_cols:
                cursor.execute("ALTER TABLE notarization_records ADD COLUMN block_number INTEGER;")
            if "receipt_status" not in existing_cols:
                cursor.execute("ALTER TABLE notarization_records ADD COLUMN receipt_status INTEGER;")
            if "anchored_value" not in existing_cols:
                cursor.execute("ALTER TABLE notarization_records ADD COLUMN anchored_value TEXT;")
            if "submitted_at" not in existing_cols:
                cursor.execute("ALTER TABLE notarization_records ADD COLUMN submitted_at TEXT;")
            if "external_verification_timestamp" not in existing_cols:
                cursor.execute("ALTER TABLE notarization_records ADD COLUMN external_verification_timestamp TEXT;")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analysts';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(analysts);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "role" not in existing_cols:
            cursor.execute("ALTER TABLE analysts ADD COLUMN role TEXT NOT NULL DEFAULT 'FORENSIC_ANALYST';")

    # 0. Analysts table (Attribution Registry - No credentials or secrets)
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
        )
    """)

    # 1. Analyses table (Authoritative Observed Analyses)
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
        )
    """)

    # 2. Sessions table
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
        )
    """)

    # 3. Findings table
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
        )
    """)

    # 4. Incidents table
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
        )
    """)

    # 5. Custody records table
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
        )
    """)

    # 6. Custody events table (Append-only chained audit log)
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
        )
    """)

    # 7. Cases table
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
        )
    """)

    # 8. Case-Analyses link table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_analyses (
            case_id TEXT NOT NULL,
            analysis_id TEXT NOT NULL,
            attached_at TEXT NOT NULL,
            attached_by TEXT DEFAULT 'analyst',
            PRIMARY KEY (case_id, analysis_id),
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
    """)

    # 9. Case Artifacts table
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
        )
    """)

    # 10. Analyst notes table (Additive annotation log)
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
        )
    """)

    # 11. Simulations table (Hypothetical what-if models)
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
        )
    """)

    # 12. Active Scans table (Current state probes)
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
        )
    """)

    # 13. DNS Enrichments table (Live DNS state)
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
        )
    """)

    # 14. Audit Events table (System-wide hash-chained audit log with actor attribution)
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
        )
    """)

    # 15. Digital signatures table (Phase 14 Asymmetric Report Signatures)
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
        )
    """)

    # 16. Notarization records table (Phase 15 & 16 Notarization & External Anchoring)
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
        )
    """)

    # 17. Custody Manifest Versions table (Phase 13 Immutable Versioning)
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
        )
    """)

    # 18. Report Artifacts table (Phase 13 Separate Report Storage & Linkage)
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
        )
    """)

    # 19. SIEM Deliveries table (Phase 19 SIEM Delivery Audit Log)
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
        )
    """)

    # 20. Case Assignments table (Phase 20 Multi-Analyst RBAC)
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
        )
    """)

    # 21. Case Review Policies table (Phase 20 M-of-N Approval Policy)
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
        )
    """)

    # 22. Case Reviews & Cryptographic Sign-Offs (Phase 20 Peer Review)
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
        )
    """)

    # 23. Monitored Targets table (Phase 21 Continuous Mail Security Posture Monitoring)
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
        )
    """)

    # 24. Posture Snapshots table (Phase 21 Deterministic Snapshots & Hash Binding)
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
        )
    """)

    # 25. Posture Drift Events table (Phase 21 Drift Ledger)
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
        )
    """)

    # Create Performance Indexes
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

    conn.commit()
    conn.close()


# Initialize database schemas on module import
init_db()


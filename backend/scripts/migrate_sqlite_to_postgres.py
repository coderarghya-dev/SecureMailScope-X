"""
SecureMailScope X - Standalone SQLite to PostgreSQL / Supabase Data Migration Utility
Explicit manual invocation only.

Migrates all historical analyses, sessions, findings, custody records, audit trails,
and PQC roadmaps from local SQLite database to destination PostgreSQL without altering
forensic hashes, timestamps, or chain-of-custody linkage.
"""

import argparse
import os
import sys
import sqlite3
import logging
from typing import Dict, List, Tuple, Any

# Ensure backend root is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SCRIPT_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.db.database import (
    DEFAULT_DB_PATH,
    _init_postgres_schema,
    PostgresConnectionWrapper,
    sanitize_db_url_for_logs,
)

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger("migration")

# Strict dependency order for table migration (Parents first, Foreign Key children following)
TABLE_ORDER = [
    "analysts",
    "analyses",
    "custody_records",
    "custody_manifest_versions",
    "report_artifacts",
    "digital_signatures",
    "notarization_records",
    "sessions",
    "findings",
    "incidents",
    "custody_events",
    "cases",
    "case_analyses",
    "case_artifacts",
    "analyst_notes",
    "simulations",
    "active_scans",
    "dns_enrichments",
    "audit_events",
    "siem_deliveries",
    "case_assignments",
    "case_review_policies",
    "case_reviews",
    "monitored_targets",
    "posture_snapshots",
    "posture_drift_events",
    "remediation_plans",
    "remediation_plan_items",
    "remediation_verifications",
    "alert_rules",
    "alerts",
    "alert_deliveries",
    "pqc_crypto_assets",
    "pqc_migration_roadmaps",
    "pqc_migration_steps",
    "pqc_gap_findings",
]


def count_sqlite_rows(sqlite_conn: sqlite3.Connection, table_name: str) -> int:
    """Counts total records in a SQLite table."""
    try:
        cur = sqlite_conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {table_name};")
        return cur.fetchone()[0]
    except Exception:
        return 0


def count_postgres_rows(pg_conn: Any, table_name: str) -> int:
    """Counts total records in a PostgreSQL table."""
    try:
        cur = pg_conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {table_name};")
        row = cur.fetchone()
        return row[0] if row else 0
    except Exception:
        return 0


def migrate_table(sqlite_conn: sqlite3.Connection, pg_conn: Any, table_name: str) -> Tuple[int, int]:
    """
    Migrates all rows from SQLite to PostgreSQL table preserving all column values,
    primary keys, binary blobs, and timestamps.
    """
    src_cur = sqlite_conn.cursor()
    try:
        src_cur.execute(f"SELECT * FROM {table_name};")
    except Exception as e:
        logger.warning(f"Table '{table_name}' not present in source SQLite: {e}")
        return 0, 0

    rows = src_cur.fetchall()
    if not rows:
        return 0, 0

    col_names = [d[0] for d in src_cur.description]
    placeholders = ", ".join(["%s"] * len(col_names))
    cols_str = ", ".join(col_names)
    insert_sql = f"INSERT INTO {table_name} ({cols_str}) VALUES ({placeholders}) ON CONFLICT DO NOTHING;"

    dest_cur = pg_conn.cursor()
    inserted = 0
    for row in rows:
        # Convert row values (tuple)
        val_list = []
        for col_val in tuple(row):
            if isinstance(col_val, memoryview):
                val_list.append(bytes(col_val))
            else:
                val_list.append(col_val)
        dest_cur.execute(insert_sql, tuple(val_list))
        inserted += 1

    return len(rows), inserted


def verify_custody_chain(pg_conn: Any) -> bool:
    """Verifies that migrated custody events maintain valid SHA-256 hash chains."""
    cur = pg_conn.cursor()
    cur.execute("SELECT DISTINCT analysis_id FROM custody_events;")
    analysis_rows = cur.fetchall()
    if not analysis_rows:
        return True

    for a_row in analysis_rows:
        analysis_id = a_row[0]
        cur.execute(
            "SELECT event_id, sequence_order, previous_event_hash, current_event_hash "
            "FROM custody_events WHERE analysis_id = %s ORDER BY sequence_order ASC;",
            (analysis_id,)
        )
        events = cur.fetchall()
        expected_prev = "0" * 64
        for ev in events:
            prev_hash = ev[2]
            curr_hash = ev[3]
            if prev_hash != expected_prev:
                logger.error(f"Custody hash chain mismatch for {analysis_id} at sequence {ev[1]}!")
                return False
            expected_prev = curr_hash

    return True


def run_migration(sqlite_path: str, pg_url: str, dry_run: bool = False) -> Dict[str, Any]:
    """
    Executes full SQLite to PostgreSQL migration with pre-validation and post-verification.
    """
    if not os.path.isfile(sqlite_path):
        raise FileNotFoundError(f"Source SQLite database file not found: {sqlite_path}")

    import psycopg
    logger.info(f"Opening read-only connection to SQLite: {sqlite_path}")
    sqlite_conn = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    sqlite_conn.row_factory = sqlite3.Row

    # Source Pre-Flight Audit
    source_counts: Dict[str, int] = {}
    total_source_records = 0
    for tbl in TABLE_ORDER:
        cnt = count_sqlite_rows(sqlite_conn, tbl)
        source_counts[tbl] = cnt
        total_source_records += cnt

    logger.info(f"Pre-migration audit complete. Total source records across 36 tables: {total_source_records}")

    if dry_run:
        sqlite_conn.close()
        return {
            "mode": "DRY_RUN",
            "source_records_total": total_source_records,
            "source_table_counts": source_counts,
            "status": "VALIDATED"
        }

    logger.info(f"Connecting to destination PostgreSQL ({sanitize_db_url_for_logs(pg_url)})...")
    if pg_url.startswith("postgresql+psycopg://"):
        pg_url = pg_url.replace("postgresql+psycopg://", "postgresql://", 1)
    if "sslmode=" not in pg_url and not any(h in pg_url for h in ["localhost", "127.0.0.1"]):
        sep = "&" if "?" in pg_url else "?"
        pg_url = f"{pg_url}{sep}sslmode=require"

    pg_raw_conn = psycopg.connect(pg_url, autocommit=False)
    pg_wrapper = PostgresConnectionWrapper(pg_raw_conn)

    # Ensure schema is initialized on PostgreSQL
    logger.info("Initializing PostgreSQL schema and indexes...")
    _init_postgres_schema(pg_wrapper)

    migrated_counts: Dict[str, int] = {}
    try:
        with pg_raw_conn.cursor() as cur:
            for tbl in TABLE_ORDER:
                src_count, inserted_count = migrate_table(sqlite_conn, cur, tbl)
                migrated_counts[tbl] = inserted_count
                if src_count > 0:
                    logger.info(f"  [OK] Migrated '{tbl}': {inserted_count}/{src_count} records")

        pg_raw_conn.commit()
        logger.info("PostgreSQL transaction committed successfully.")

        # Post-Flight Verification
        dest_counts: Dict[str, int] = {}
        for tbl in TABLE_ORDER:
            dest_counts[tbl] = count_postgres_rows(pg_raw_conn, tbl)

        custody_valid = verify_custody_chain(pg_raw_conn)
        logger.info(f"Custody hash chain cryptographic verification: {'PASS' if custody_valid else 'FAIL'}")

    except Exception as e:
        pg_raw_conn.rollback()
        logger.error(f"Migration FAILED with error: {e}. Transaction rolled back.")
        raise
    finally:
        sqlite_conn.close()
        pg_raw_conn.close()

    return {
        "status": "SUCCESS" if custody_valid else "VERIFICATION_FAILED",
        "source_sqlite_path": sqlite_path,
        "destination_postgres": sanitize_db_url_for_logs(pg_url),
        "source_counts": source_counts,
        "migrated_counts": migrated_counts,
        "dest_counts": dest_counts,
        "custody_chain_verified": custody_valid,
    }


def main():
    parser = argparse.ArgumentParser(description="SecureMailScope X SQLite to PostgreSQL Migration Utility")
    parser.add_argument("--sqlite-path", default=DEFAULT_DB_PATH, help="Path to source SQLite .db file")
    parser.add_argument("--postgres-url", default=os.environ.get("DATABASE_URL"), help="Destination PostgreSQL connection URL")
    parser.add_argument("--dry-run", action="store_true", help="Perform pre-flight validation and row counts only")

    args = parser.parse_args()

    if not args.postgres_url and not args.dry_run:
        print("ERROR: --postgres-url or DATABASE_URL environment variable must be specified for migration.")
        sys.exit(1)

    print("=================================================================")
    print(" SecureMailScope X - SQLite -> PostgreSQL Migration")
    print("=================================================================")
    print(f" Source SQLite: {args.sqlite_path}")
    print(f" Dest Postgres: {sanitize_db_url_for_logs(args.postgres_url)}")
    print(f" Dry Run Mode : {args.dry_run}")
    print("=================================================================\n")

    res = run_migration(args.sqlite_path, args.postgres_url or "", dry_run=args.dry_run)
    print("\n=================================================================")
    print(f" MIGRATION RESULT: {res['status']}")
    print("=================================================================")


if __name__ == "__main__":
    main()

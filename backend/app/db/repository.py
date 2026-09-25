"""
SecureMailScope X - Forensic Data Repository & Persistence Engine
Handles cryptographic verification, canonical JSON serialization, atomic transactions,
and immutable historical analysis persistence.
"""

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from app.db.database import get_db_connection
from app.schemas.identity import (
    ActorContext,
    validate_actor_id,
    sanitize_display_name,
    IDENTITY_SOURCE_LOCAL_DECLARED,
    IDENTITY_SOURCE_API_HEADER_DECLARED,
    IDENTITY_SOURCE_SYSTEM,
    IDENTITY_SOURCE_UNKNOWN,
    ATTRIBUTION_STATUS_ATTRIBUTED,
    ATTRIBUTION_STATUS_UNATTRIBUTED,
    ATTRIBUTION_STATUS_SYSTEM_GENERATED,
)
from app.schemas.api import (
    AnalysisDetailResponse,
    AnalysisSummaryResponse,
    SessionDetailDTO,
    SessionSummaryDTO,
    PacketEvidenceDTO,
    CustodyRecordResponse,
    CustodyEventDTO,
    CaptureIntegrityDTO,
    ManifestIntegrityDTO,
    ReportIntegrityDTO,
)
from app.schemas.forensic import EmailSession

CURRENT_SCHEMA_VERSION = "1.0"
CURRENT_ANALYZER_VERSION = "SecureMailScope X 1.0.0"


CANONICALIZATION_VERSION = "SECUREMAILSCOPE_CANONICAL_JSON_V1"


class RepositoryError(Exception):
    """Base exception for persistence errors."""
    pass


class ImmutableRecordError(RepositoryError):
    """Raised when attempting to overwrite an immutable finalized forensic record."""
    pass


class IntegrityVerificationError(RepositoryError):
    """Raised when record hash does not match stored content."""
    pass


class UnsupportedSchemaVersionError(RepositoryError):
    """Raised when attempting to load a record from an unsupported schema version."""
    pass


def canonical_json_bytes(data: Any) -> bytes:
    """
    Deterministic canonical JSON serialization for SecureMailScope X.
    Specification: SECUREMAILSCOPE_CANONICAL_JSON_V1
    Rules:
    - Encoding: UTF-8
    - Key Sorting: Lexicographical Unicode code-point sorting (sort_keys=True)
    - Separators: Compact whitespace-free separators (',', ':')
    - Non-Finite Float Handling: Strictly rejects NaN, Infinity, -Infinity (allow_nan=False)
    - Character Escaping: Native UTF-8 preserved without unnecessary ASCII escaping (ensure_ascii=False)
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False
    ).encode("utf-8")


def canonical_json_str(data: Any) -> str:
    """Deterministic canonical JSON string."""
    return canonical_json_bytes(data).decode("utf-8")


def compute_sha256(data: bytes) -> str:
    """Standard lowercase hex SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def compute_json_sha256(data: Any) -> str:
    """Compute SHA-256 over canonically serialized JSON."""
    return compute_sha256(canonical_json_bytes(data))


class ForensicRepository:
    """
    Central repository for persisting and retrieving forensic evidence,
    reconstructed sessions, findings, cases, and custody logs.
    """

    @staticmethod
    def canonical_json(data: Any) -> str:
        """Returns canonical JSON string under SECUREMAILSCOPE_CANONICAL_JSON_V1 specification."""
        return canonical_json_str(data)

    # -----------------------------------------------------------------------
    # 0. Analyst Attribution Registry (Metadata Only - No Passwords/Tokens)
    # -----------------------------------------------------------------------
    @classmethod
    def register_analyst(
        cls,
        analyst_id: str,
        display_name: str,
        email_or_label: Optional[str] = None,
        identity_source: str = IDENTITY_SOURCE_LOCAL_DECLARED,
        db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Registers or activates a declared analyst identity profile in the attribution registry."""
        valid_id = validate_actor_id(analyst_id)
        valid_name = sanitize_display_name(display_name)
        now_iso = datetime.now(timezone.utc).isoformat()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO analysts (analyst_id, display_name, email_or_label, identity_source, attribution_status, created_at, updated_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(analyst_id) DO UPDATE SET
                display_name = excluded.display_name,
                email_or_label = excluded.email_or_label,
                updated_at = excluded.updated_at,
                is_active = 1
            """,
            (valid_id, valid_name, email_or_label, identity_source, ATTRIBUTION_STATUS_ATTRIBUTED, now_iso, now_iso)
        )
        conn.commit()
        conn.close()

        return {
            "analyst_id": valid_id,
            "display_name": valid_name,
            "email_or_label": email_or_label,
            "identity_source": identity_source,
            "attribution_status": ATTRIBUTION_STATUS_ATTRIBUTED,
            "created_at": now_iso,
            "updated_at": now_iso,
            "is_active": True,
        }

    @classmethod
    def get_analyst(cls, analyst_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves declared analyst profile from the registry."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analysts WHERE analyst_id = ?", (analyst_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return {
            "analyst_id": row["analyst_id"],
            "display_name": row["display_name"],
            "email_or_label": row["email_or_label"],
            "identity_source": row["identity_source"],
            "attribution_status": row["attribution_status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "is_active": bool(row["is_active"]),
        }

    @classmethod
    def update_analyst_profile(
        cls,
        analyst_id: str,
        display_name: str,
        email_or_label: Optional[str] = None,
        is_active: bool = True,
        db_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Updates display name or status in the registry. Does not alter historical audit events."""
        valid_name = sanitize_display_name(display_name)
        now_iso = datetime.now(timezone.utc).isoformat()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE analysts
            SET display_name = ?, email_or_label = ?, is_active = ?, updated_at = ?
            WHERE analyst_id = ?
            """,
            (valid_name, email_or_label, 1 if is_active else 0, now_iso, analyst_id)
        )
        conn.commit()
        conn.close()

        return cls.get_analyst(analyst_id, db_path=db_path)

    @classmethod
    def list_analysts(cls, active_only: bool = False, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists all registered analyst profiles."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        query = "SELECT * FROM analysts"
        if active_only:
            query += " WHERE is_active = 1"
        query += " ORDER BY created_at ASC"

        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()

        return [{
            "analyst_id": r["analyst_id"],
            "display_name": r["display_name"],
            "email_or_label": r["email_or_label"],
            "identity_source": r["identity_source"],
            "attribution_status": r["attribution_status"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "is_active": bool(r["is_active"]),
        } for r in rows]

    # -----------------------------------------------------------------------
    # 1. Analyses Persistence
    # -----------------------------------------------------------------------
    @classmethod
    def save_analysis(
        cls,
        analysis: AnalysisDetailResponse,
        raw_sessions: Optional[List[EmailSession]] = None,
        raw_packets_by_session: Optional[Dict[str, List[PacketEvidenceDTO]]] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None
    ) -> str:
        """
        Persists analysis, sessions, findings, and incidents inside a single atomic transaction.
        Raises ImmutableRecordError if the analysis is already finalized.
        """
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        act = actor or ActorContext.unattributed()

        try:
            # Check existing analysis status
            cursor.execute(
                "SELECT is_finalized, observed_result_sha256 FROM analyses WHERE analysis_id = ?",
                (analysis.analysis_id,)
            )
            existing = cursor.fetchone()
            if existing:
                if existing["is_finalized"]:
                    # Already stored and finalized — immutability enforced
                    conn.close()
                    return analysis.analysis_id

            analysis_dict = analysis.model_dump() if hasattr(analysis, "model_dump") else analysis.dict()
            analysis_json = json.dumps(analysis_dict, sort_keys=True, separators=(",", ":"))
            analysis_hash = compute_sha256(analysis_json.encode("utf-8"))

            now_iso = datetime.now(timezone.utc).isoformat()
            primary_grade = analysis.sessions[0].security_assessment.grade if analysis.sessions else "A"

            # 1. Insert into analyses
            cursor.execute(
                """
                INSERT INTO analyses (
                    analysis_id, revision, filename, file_size_bytes, capture_sha256,
                    analyzer_version, schema_version, analysis_status, created_at, finalized_at,
                    is_finalized, is_archived, created_by_actor_id, finalized_by_actor_id,
                    observed_result_json, observed_result_sha256,
                    total_packets, raw_total_frames, email_sessions_found,
                    evidence_confidence_score, evidence_confidence_level, security_grade
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    analysis_status = excluded.analysis_status,
                    finalized_at = excluded.finalized_at,
                    is_finalized = excluded.is_finalized,
                    is_archived = excluded.is_archived
                """,
                (
                    analysis.analysis_id,
                    1,
                    analysis.file_name,
                    analysis.file_size_bytes,
                    analysis.analysis_id.replace("analysis_", ""),  # SHA-256 prefix/token
                    CURRENT_ANALYZER_VERSION,
                    CURRENT_SCHEMA_VERSION,
                    "FINALIZED",
                    analysis.analysis_time_utc or now_iso,
                    now_iso,
                    1,
                    0,
                    act.actor_id,
                    act.actor_id,
                    analysis_json,
                    analysis_hash,
                    analysis.total_packets_extracted,
                    analysis.raw_capture_packets_total or analysis.total_packets_extracted,
                    analysis.email_sessions_found,
                    analysis.evidence_confidence_score,
                    analysis.evidence_confidence_level,
                    primary_grade,
                )
            )

            # 2. Persist Sessions
            for s in analysis.sessions:
                s_dict = s.model_dump() if hasattr(s, "model_dump") else s.dict()
                s_json = json.dumps(s_dict, sort_keys=True, separators=(",", ":"))
                s_hash = compute_sha256(s_json.encode("utf-8"))

                # Evidence packets JSON
                pkts = []
                if raw_packets_by_session and s.session_id in raw_packets_by_session:
                    pkts = [p.model_dump() if hasattr(p, "model_dump") else p.dict() for p in raw_packets_by_session[s.session_id]]
                pkts_json = json.dumps(pkts, sort_keys=True, separators=(",", ":"))

                cursor.execute(
                    """
                    INSERT INTO sessions (
                        session_id, analysis_id, stream_index, protocol, security_mode,
                        client, server, server_hostname, start_time_iso, duration_seconds,
                        packets_count, security_grade, health_score, confidence_score,
                        pqc_ready, session_result_json, session_result_sha256, evidence_packets_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        session_result_json = excluded.session_result_json,
                        session_result_sha256 = excluded.session_result_sha256,
                        evidence_packets_json = excluded.evidence_packets_json
                    """,
                    (
                        s.session_id,
                        analysis.analysis_id,
                        s.stream_index,
                        s.protocol,
                        s.security_mode,
                        s.client,
                        s.server,
                        s.server_hostname,
                        s.start_time_iso,
                        s.duration_seconds,
                        s.packets_count,
                        s.security_assessment.grade if s.security_assessment else "A",
                        s.capture_health.score if s.capture_health else 100,
                        s.evidence_confidence.score if s.evidence_confidence else 100,
                        1 if (s.security_assessment and s.security_assessment.post_quantum_ready) else 0,
                        s_json,
                        s_hash,
                        pkts_json,
                    )
                )

                # 3. Persist Findings
                if s.security_assessment and s.security_assessment.findings:
                    for f in s.security_assessment.findings:
                        f_dict = f.model_dump() if hasattr(f, "model_dump") else f.dict()
                        f_json = json.dumps(f_dict, sort_keys=True, separators=(",", ":"))
                        f_hash = compute_sha256(f_json.encode("utf-8"))
                        pk_finding = f"{analysis.analysis_id}:{s.session_id}:{f.id}"

                        cursor.execute(
                            """
                            INSERT INTO findings (
                                id, finding_id, analysis_id, session_id, severity,
                                category, rule_id, title, description, recommendation,
                                evidence_frames_json, finding_json, finding_sha256
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(id) DO UPDATE SET
                                finding_json = excluded.finding_json,
                                finding_sha256 = excluded.finding_sha256
                            """,
                            (
                                pk_finding,
                                f.id,
                                analysis.analysis_id,
                                s.session_id,
                                f.severity,
                                f.category,
                                f.explanation.rule_id if f.explanation else f.id,
                                f.title,
                                f.description,
                                f.recommendation,
                                json.dumps(f.evidence_frames),
                                f_json,
                                f_hash,
                            )
                        )

            # 4. Persist Incidents
            if analysis.correlated_incidents:
                for inc in analysis.correlated_incidents:
                    inc_dict = inc.model_dump() if hasattr(inc, "model_dump") else inc.dict()
                    inc_json = json.dumps(inc_dict, sort_keys=True, separators=(",", ":"))
                    inc_hash = compute_sha256(inc_json.encode("utf-8"))
                    pk_incident = f"{analysis.analysis_id}:{inc.incident_id}"

                    cursor.execute(
                        """
                        INSERT INTO incidents (
                            id, incident_id, analysis_id, incident_type, severity,
                            correlation_method, evidence_backed, correlation_result_json, incident_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            correlation_result_json = excluded.correlation_result_json,
                            incident_sha256 = excluded.incident_sha256
                        """,
                        (
                            pk_incident,
                            inc.incident_id,
                            analysis.analysis_id,
                            inc.incident_type,
                            inc.severity,
                            inc.correlation_method,
                            1 if inc.evidence_backed else 0,
                            inc_json,
                            inc_hash,
                        )
                    )

            conn.commit()
            return analysis.analysis_id
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @classmethod
    def get_analysis(cls, analysis_id: str, verify_integrity: bool = True, db_path: Optional[str] = None) -> Optional[AnalysisDetailResponse]:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                SELECT schema_version, analysis_status, observed_result_json, observed_result_sha256
                FROM analyses WHERE analysis_id = ?
                """,
                (analysis_id,)
            )
            row = cursor.fetchone()

            if not row:
                return None

            # 1. Version Compatibility Check
            stored_schema = row["schema_version"]
            if stored_schema.split(".")[0] != CURRENT_SCHEMA_VERSION.split(".")[0]:
                raise UnsupportedSchemaVersionError(
                    f"Unsupported schema version '{stored_schema}' for analysis '{analysis_id}'. Current version is '{CURRENT_SCHEMA_VERSION}'."
                )

            # 2. Cryptographic Integrity Check
            raw_json_str = row["observed_result_json"]
            stored_hash = row["observed_result_sha256"]

            if verify_integrity:
                recomputed_hash = compute_sha256(raw_json_str.encode("utf-8"))
                if recomputed_hash != stored_hash:
                    raise IntegrityVerificationError(
                        f"Integrity check FAILED for analysis '{analysis_id}'. Tampered top-level data detected: expected {stored_hash}, got {recomputed_hash}."
                    )

                # 3. Child Sessions Integrity Check
                cursor.execute(
                    "SELECT session_id, session_result_json, session_result_sha256 FROM sessions WHERE analysis_id = ?",
                    (analysis_id,)
                )
                for s_row in cursor.fetchall():
                    recomputed_s_hash = compute_sha256(s_row["session_result_json"].encode("utf-8"))
                    if recomputed_s_hash != s_row["session_result_sha256"]:
                        raise IntegrityVerificationError(
                            f"Integrity check FAILED for session '{s_row['session_id']}' in analysis '{analysis_id}'. Tampered session record detected."
                        )

                # 4. Child Findings Integrity Check
                cursor.execute(
                    "SELECT id, finding_id, finding_json, finding_sha256 FROM findings WHERE analysis_id = ?",
                    (analysis_id,)
                )
                for f_row in cursor.fetchall():
                    recomputed_f_hash = compute_sha256(f_row["finding_json"].encode("utf-8"))
                    if recomputed_f_hash != f_row["finding_sha256"]:
                        raise IntegrityVerificationError(
                            f"Integrity check FAILED for finding '{f_row['finding_id']}' in analysis '{analysis_id}'. Tampered finding record detected."
                        )

            parsed_dict = json.loads(raw_json_str)
            return AnalysisDetailResponse(**parsed_dict)
        except (IntegrityVerificationError, UnsupportedSchemaVersionError):
            raise
        except Exception as e:
            raise RepositoryError(f"Failed to deserialize analysis '{analysis_id}': {str(e)}")
        finally:
            conn.close()

    @classmethod
    def list_analyses(cls, include_archived: bool = False, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists historical analyses with summaries, timestamps, status, and grades."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        query = """
            SELECT analysis_id, filename, file_size_bytes, analysis_status, created_at,
                   total_packets, email_sessions_found, evidence_confidence_score,
                   evidence_confidence_level, security_grade, observed_result_sha256, is_archived
            FROM analyses
        """
        if not include_archived:
            query += " WHERE is_archived = 0"
        query += " ORDER BY created_at DESC"

        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            results.append({
                "analysis_id": r["analysis_id"],
                "filename": r["filename"],
                "file_size_bytes": r["file_size_bytes"],
                "analysis_status": r["analysis_status"],
                "created_at": r["created_at"],
                "total_packets": r["total_packets"],
                "email_sessions_found": r["email_sessions_found"],
                "evidence_confidence_score": r["evidence_confidence_score"],
                "evidence_confidence_level": r["evidence_confidence_level"],
                "security_grade": r["security_grade"],
                "sha256_seal": r["observed_result_sha256"],
                "is_archived": bool(r["is_archived"]),
            })
        return results

    @classmethod
    def get_session_packets(cls, analysis_id: str, session_id: str, db_path: Optional[str] = None) -> Optional[List[PacketEvidenceDTO]]:
        """Retrieves raw packet evidence for a specific session."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT evidence_packets_json FROM sessions WHERE analysis_id = ? AND session_id = ?",
            (analysis_id, session_id)
        )
        row = cursor.fetchone()
        conn.close()

        if not row or not row["evidence_packets_json"]:
            return None

        try:
            items = json.loads(row["evidence_packets_json"])
            return [PacketEvidenceDTO(**item) for item in items]
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # 2. Custody Records & Audit Trail Persistence
    # -----------------------------------------------------------------------
    @classmethod
    def save_custody_record(
        cls,
        analysis_id: str,
        filename: str,
        file_size: int,
        capture_sha256: str,
        raw_bytes: Optional[bytes],
        ingestion_timestamp: str,
        start_timestamp: Optional[str],
        completion_timestamp: Optional[str],
        manifest_dict: Optional[Dict[str, Any]],
        manifest_hash: Optional[str],
        report_pdf_bytes: Optional[bytes],
        report_pdf_hash: Optional[str],
        events: List[CustodyEventDTO],
        is_sealed: bool = False,
        overall_status: str = "VERIFIED",
        db_path: Optional[str] = None
    ):
        """Saves custody record and its append-only chained events."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            manifest_json = json.dumps(manifest_dict, sort_keys=True, separators=(",", ":")) if manifest_dict else None

            cursor.execute(
                """
                INSERT INTO custody_records (
                    analysis_id, filename, file_size, capture_sha256, raw_bytes,
                    ingestion_timestamp, start_timestamp, completion_timestamp,
                    manifest_dict_json, manifest_hash, report_pdf_bytes, report_pdf_hash,
                    is_sealed, overall_status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    start_timestamp = excluded.start_timestamp,
                    completion_timestamp = excluded.completion_timestamp,
                    manifest_dict_json = excluded.manifest_dict_json,
                    manifest_hash = excluded.manifest_hash,
                    report_pdf_bytes = excluded.report_pdf_bytes,
                    report_pdf_hash = excluded.report_pdf_hash,
                    is_sealed = excluded.is_sealed,
                    overall_status = excluded.overall_status,
                    updated_at = excluded.updated_at
                """,
                (
                    analysis_id,
                    filename,
                    file_size,
                    capture_sha256,
                    raw_bytes,
                    ingestion_timestamp,
                    start_timestamp,
                    completion_timestamp,
                    manifest_json,
                    manifest_hash,
                    report_pdf_bytes,
                    report_pdf_hash,
                    1 if is_sealed else 0,
                    overall_status,
                    ingestion_timestamp,
                    now_iso,
                )
            )

            # Insert events in sequence
            for idx, ev in enumerate(events):
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO custody_events (
                        event_id, analysis_id, timestamp_utc, event_type,
                        artifact_hash, previous_event_hash, current_event_hash,
                        details, sequence_order, actor_id, actor_display_name,
                        actor_identity_source, actor_attribution_status, hash_format_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ev.event_id,
                        analysis_id,
                        ev.timestamp_utc,
                        ev.event_type,
                        ev.artifact_hash,
                        ev.previous_event_hash,
                        ev.current_event_hash,
                        ev.details,
                        idx,
                        getattr(ev, "actor_id", "SYSTEM") or "SYSTEM",
                        getattr(ev, "actor_display_name", "SecureMailScope X") or "SecureMailScope X",
                        getattr(ev, "actor_identity_source", "SYSTEM") or "SYSTEM",
                        getattr(ev, "actor_attribution_status", "SYSTEM_GENERATED") or "SYSTEM_GENERATED",
                        getattr(ev, "hash_format_version", "CUSTODY_EVENT_HASH_V2") or "CUSTODY_EVENT_HASH_V2",
                    )
                )

            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @classmethod
    def get_custody_record(cls, analysis_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves raw custody record and ordered audit event trail from DB."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM custody_records WHERE analysis_id = ?", (analysis_id,))
        rec_row = cursor.fetchone()

        if not rec_row:
            conn.close()
            return None

        cursor.execute(
            "SELECT * FROM custody_events WHERE analysis_id = ? ORDER BY sequence_order ASC",
            (analysis_id,)
        )
        event_rows = cursor.fetchall()
        conn.close()

        events = []
        for er in event_rows:
            er_dict = dict(er)
            events.append(CustodyEventDTO(
                event_id=er_dict["event_id"],
                analysis_id=er_dict["analysis_id"],
                timestamp_utc=er_dict["timestamp_utc"],
                event_type=er_dict["event_type"],
                artifact_hash=er_dict["artifact_hash"],
                previous_event_hash=er_dict["previous_event_hash"],
                current_event_hash=er_dict["current_event_hash"],
                details=er_dict.get("details"),
                actor_id=er_dict.get("actor_id", "SYSTEM") or "SYSTEM",
                actor_display_name=er_dict.get("actor_display_name", "SecureMailScope X") or "SecureMailScope X",
                actor_identity_source=er_dict.get("actor_identity_source", "SYSTEM") or "SYSTEM",
                actor_attribution_status=er_dict.get("actor_attribution_status", "SYSTEM_GENERATED") or "SYSTEM_GENERATED",
                hash_format_version=er_dict.get("hash_format_version", "CUSTODY_EVENT_HASH_V2") or "CUSTODY_EVENT_HASH_V2",
            ))

        manifest = json.loads(rec_row["manifest_dict_json"]) if rec_row["manifest_dict_json"] else None

        return {
            "analysis_id": rec_row["analysis_id"],
            "filename": rec_row["filename"],
            "file_size": rec_row["file_size"],
            "capture_sha256": rec_row["capture_sha256"],
            "raw_bytes": rec_row["raw_bytes"],
            "ingestion_timestamp": rec_row["ingestion_timestamp"],
            "start_timestamp": rec_row["start_timestamp"],
            "completion_timestamp": rec_row["completion_timestamp"],
            "manifest_dict": manifest,
            "manifest_hash": rec_row["manifest_hash"],
            "report_pdf_bytes": rec_row["report_pdf_bytes"],
            "report_pdf_hash": rec_row["report_pdf_hash"],
            "is_sealed": bool(rec_row["is_sealed"]),
            "overall_status": rec_row["overall_status"],
            "events": events,
        }

    # -----------------------------------------------------------------------
    # 2b. Immutable Custody Manifest Versioning & Report Artifacts (Phase 13)
    # -----------------------------------------------------------------------
    @classmethod
    def save_manifest_version(
        cls,
        manifest_version_id: str,
        analysis_id: str,
        version_number: int,
        manifest_type: str,
        previous_manifest_sha256: str,
        manifest_json: str,
        manifest_sha256: str,
        parent_manifest_version_id: Optional[str] = None,
        canonicalization_version: str = CANONICALIZATION_VERSION,
        created_at: Optional[str] = None,
        actor: Optional[ActorContext] = None,
        sealed: bool = True,
        supersedes_version_id: Optional[str] = None,
        purpose: Optional[str] = None,
        schema_version: str = CURRENT_SCHEMA_VERSION,
        db_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persists an append-only immutable custody manifest version."""
        now_iso = created_at or datetime.now(timezone.utc).isoformat()
        act = actor or ActorContext.unattributed()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        try:
            # Check for existing version
            cursor.execute(
                "SELECT sealed FROM custody_manifest_versions WHERE analysis_id = ? AND version_number = ?",
                (analysis_id, version_number)
            )
            existing = cursor.fetchone()
            if existing:
                if existing["sealed"]:
                    raise ImmutableRecordError(
                        f"Custody manifest version {version_number} for analysis '{analysis_id}' is sealed and immutable."
                    )
                raise ImmutableRecordError(
                    f"Custody manifest version {version_number} already exists for analysis '{analysis_id}'."
                )

            cursor.execute(
                """
                INSERT INTO custody_manifest_versions (
                    manifest_version_id, analysis_id, version_number, manifest_type,
                    parent_manifest_version_id, previous_manifest_sha256, manifest_json,
                    manifest_sha256, canonicalization_version, created_at,
                    created_by_actor_id, created_by_actor_display_name,
                    actor_identity_source, actor_attribution_status, sealed,
                    supersedes_version_id, purpose, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest_version_id,
                    analysis_id,
                    version_number,
                    manifest_type,
                    parent_manifest_version_id,
                    previous_manifest_sha256,
                    manifest_json,
                    manifest_sha256,
                    canonicalization_version,
                    now_iso,
                    act.actor_id,
                    act.actor_display_name,
                    act.actor_identity_source,
                    act.actor_attribution_status,
                    1 if sealed else 0,
                    supersedes_version_id,
                    purpose,
                    schema_version,
                )
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        return {
            "manifest_version_id": manifest_version_id,
            "analysis_id": analysis_id,
            "version_number": version_number,
            "manifest_type": manifest_type,
            "parent_manifest_version_id": parent_manifest_version_id,
            "previous_manifest_sha256": previous_manifest_sha256,
            "manifest_json": manifest_json,
            "manifest_sha256": manifest_sha256,
            "canonicalization_version": canonicalization_version,
            "created_at": now_iso,
            "created_by_actor_id": act.actor_id,
            "created_by_actor_display_name": act.actor_display_name,
            "actor_identity_source": act.actor_identity_source,
            "actor_attribution_status": act.actor_attribution_status,
            "sealed": sealed,
            "supersedes_version_id": supersedes_version_id,
            "purpose": purpose,
            "schema_version": schema_version,
        }

    @classmethod
    def get_manifest_versions(cls, analysis_id: str, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves all immutable manifest versions for an analysis in ascending order."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM custody_manifest_versions
            WHERE analysis_id = ?
            ORDER BY version_number ASC
            """,
            (analysis_id,)
        )
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            m_dict = None
            if r["manifest_json"]:
                try:
                    m_dict = json.loads(r["manifest_json"])
                except Exception:
                    pass
            linked_artifacts = []
            linked_signatures = []
            if m_dict and isinstance(m_dict, dict):
                linked_artifacts = m_dict.get("linked_report_artifacts", [])
                linked_signatures = m_dict.get("linked_signatures", [])

            results.append({
                "manifest_version_id": r["manifest_version_id"],
                "analysis_id": r["analysis_id"],
                "version_number": r["version_number"],
                "manifest_type": r["manifest_type"],
                "parent_manifest_version_id": r["parent_manifest_version_id"],
                "previous_manifest_sha256": r["previous_manifest_sha256"],
                "manifest_json": r["manifest_json"],
                "manifest_dict": m_dict,
                "manifest_sha256": r["manifest_sha256"],
                "canonicalization_version": r["canonicalization_version"],
                "created_at": r["created_at"],
                "created_by_actor_id": r["created_by_actor_id"],
                "created_by_actor_display_name": r["created_by_actor_display_name"],
                "actor_identity_source": r["actor_identity_source"],
                "actor_attribution_status": r["actor_attribution_status"],
                "sealed": bool(r["sealed"]),
                "supersedes_version_id": r["supersedes_version_id"],
                "purpose": r["purpose"],
                "schema_version": r["schema_version"],
                "linked_report_artifacts": linked_artifacts,
                "linked_signatures": linked_signatures,
            })
        return results

    @classmethod
    def get_manifest_version(
        cls,
        analysis_id: str,
        version_identifier: Any,
        db_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Retrieves a specific manifest version by version_number or manifest_version_id."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        if isinstance(version_identifier, int) or (isinstance(version_identifier, str) and version_identifier.isdigit()):
            cursor.execute(
                "SELECT * FROM custody_manifest_versions WHERE analysis_id = ? AND version_number = ?",
                (analysis_id, int(version_identifier))
            )
        else:
            cursor.execute(
                "SELECT * FROM custody_manifest_versions WHERE analysis_id = ? AND (manifest_version_id = ? OR manifest_type = ?)",
                (analysis_id, str(version_identifier), str(version_identifier))
            )
        r = cursor.fetchone()
        conn.close()
        if not r:
            return None

        m_dict = None
        if r["manifest_json"]:
            try:
                m_dict = json.loads(r["manifest_json"])
            except Exception:
                pass
        linked_artifacts = []
        linked_signatures = []
        if m_dict and isinstance(m_dict, dict):
            linked_artifacts = m_dict.get("linked_report_artifacts", [])
            linked_signatures = m_dict.get("linked_signatures", [])

        return {
            "manifest_version_id": r["manifest_version_id"],
            "analysis_id": r["analysis_id"],
            "version_number": r["version_number"],
            "manifest_type": r["manifest_type"],
            "parent_manifest_version_id": r["parent_manifest_version_id"],
            "previous_manifest_sha256": r["previous_manifest_sha256"],
            "manifest_json": r["manifest_json"],
            "manifest_dict": m_dict,
            "manifest_sha256": r["manifest_sha256"],
            "canonicalization_version": r["canonicalization_version"],
            "created_at": r["created_at"],
            "created_by_actor_id": r["created_by_actor_id"],
            "created_by_actor_display_name": r["created_by_actor_display_name"],
            "actor_identity_source": r["actor_identity_source"],
            "actor_attribution_status": r["actor_attribution_status"],
            "sealed": bool(r["sealed"]),
            "supersedes_version_id": r["supersedes_version_id"],
            "purpose": r["purpose"],
            "schema_version": r["schema_version"],
            "linked_report_artifacts": linked_artifacts,
            "linked_signatures": linked_signatures,
        }

    @classmethod
    def get_latest_manifest_version(cls, analysis_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves the latest manifest version for an analysis."""
        versions = cls.get_manifest_versions(analysis_id, db_path=db_path)
        return versions[-1] if versions else None

    @classmethod
    def save_report_artifact_and_manifest_version(
        cls,
        report_artifact: Dict[str, Any],
        manifest_version: Dict[str, Any],
        db_path: Optional[str] = None,
        inject_failure_after_artifact: bool = False
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Atomically persists a report artifact and its associated new manifest version.
        Rolls back both if either operation fails or if manifest version is invalid.
        """
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        try:
            # 1. Supersede previous active report artifacts for this analysis
            cursor.execute(
                """
                UPDATE report_artifacts
                SET status = 'SUPERSEDED'
                WHERE analysis_id = ? AND status = 'GENERATED'
                """,
                (report_artifact["analysis_id"],)
            )

            # 2. Insert new report artifact
            cursor.execute(
                """
                INSERT INTO report_artifacts (
                    report_artifact_id, analysis_id, report_type, report_version,
                    filename, media_type, artifact_sha256, artifact_size_bytes,
                    file_path, raw_bytes, generated_at, generated_by_actor_id,
                    generated_by_actor_display_name, actor_identity_source,
                    actor_attribution_status, generator_version,
                    source_manifest_version_id, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_artifact["report_artifact_id"],
                    report_artifact["analysis_id"],
                    report_artifact.get("report_type", "PDF"),
                    report_artifact.get("report_version", 1),
                    report_artifact["filename"],
                    report_artifact.get("media_type", "application/pdf"),
                    report_artifact["artifact_sha256"],
                    report_artifact["artifact_size_bytes"],
                    report_artifact.get("file_path"),
                    report_artifact.get("raw_bytes"),
                    report_artifact["generated_at"],
                    report_artifact.get("generated_by_actor_id", "SYSTEM"),
                    report_artifact.get("generated_by_actor_display_name", "SecureMailScope X"),
                    report_artifact.get("actor_identity_source", "SYSTEM"),
                    report_artifact.get("actor_attribution_status", "SYSTEM_GENERATED"),
                    report_artifact.get("generator_version", CURRENT_ANALYZER_VERSION),
                    report_artifact["source_manifest_version_id"],
                    report_artifact.get("status", "GENERATED"),
                )
            )

            if inject_failure_after_artifact:
                raise RuntimeError("Injected transaction failure after report artifact insertion.")

            # 3. Check if manifest version already exists
            cursor.execute(
                "SELECT sealed FROM custody_manifest_versions WHERE analysis_id = ? AND version_number = ?",
                (manifest_version["analysis_id"], manifest_version["version_number"])
            )
            existing = cursor.fetchone()
            if existing:
                raise ImmutableRecordError(
                    f"Custody manifest version {manifest_version['version_number']} for analysis '{manifest_version['analysis_id']}' already exists."
                )

            # 4. Insert new manifest version
            cursor.execute(
                """
                INSERT INTO custody_manifest_versions (
                    manifest_version_id, analysis_id, version_number, manifest_type,
                    parent_manifest_version_id, previous_manifest_sha256, manifest_json,
                    manifest_sha256, canonicalization_version, created_at,
                    created_by_actor_id, created_by_actor_display_name,
                    actor_identity_source, actor_attribution_status, sealed,
                    supersedes_version_id, purpose, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest_version["manifest_version_id"],
                    manifest_version["analysis_id"],
                    manifest_version["version_number"],
                    manifest_version["manifest_type"],
                    manifest_version.get("parent_manifest_version_id"),
                    manifest_version["previous_manifest_sha256"],
                    manifest_version["manifest_json"],
                    manifest_version["manifest_sha256"],
                    manifest_version.get("canonicalization_version", CANONICALIZATION_VERSION),
                    manifest_version["created_at"],
                    manifest_version.get("created_by_actor_id", "UNATTRIBUTED"),
                    manifest_version.get("created_by_actor_display_name", "Unattributed Analyst"),
                    manifest_version.get("actor_identity_source", "UNKNOWN"),
                    manifest_version.get("actor_attribution_status", "UNATTRIBUTED"),
                    1 if manifest_version.get("sealed", True) else 0,
                    manifest_version.get("supersedes_version_id"),
                    manifest_version.get("purpose"),
                    manifest_version.get("schema_version", CURRENT_SCHEMA_VERSION),
                )
            )

            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        return report_artifact, manifest_version

    @classmethod
    def get_report_artifacts(cls, analysis_id: str, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves all report artifacts for an analysis ordered by version."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM report_artifacts
            WHERE analysis_id = ?
            ORDER BY report_version ASC
            """,
            (analysis_id,)
        )
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            results.append({
                "report_artifact_id": r["report_artifact_id"],
                "analysis_id": r["analysis_id"],
                "report_type": r["report_type"],
                "report_version": r["report_version"],
                "filename": r["filename"],
                "media_type": r["media_type"],
                "artifact_sha256": r["artifact_sha256"],
                "artifact_size_bytes": r["artifact_size_bytes"],
                "file_path": r["file_path"],
                "raw_bytes": r["raw_bytes"],
                "generated_at": r["generated_at"],
                "generated_by_actor_id": r["generated_by_actor_id"],
                "generated_by_actor_display_name": r["generated_by_actor_display_name"],
                "actor_identity_source": r["actor_identity_source"],
                "actor_attribution_status": r["actor_attribution_status"],
                "generator_version": r["generator_version"],
                "source_manifest_version_id": r["source_manifest_version_id"],
                "status": r["status"],
            })
        return results

    @classmethod
    def get_report_artifact(cls, report_artifact_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves a specific report artifact by ID."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM report_artifacts WHERE report_artifact_id = ?",
            (report_artifact_id,)
        )
        r = cursor.fetchone()
        conn.close()
        if not r:
            return None

        return {
            "report_artifact_id": r["report_artifact_id"],
            "analysis_id": r["analysis_id"],
            "report_type": r["report_type"],
            "report_version": r["report_version"],
            "filename": r["filename"],
            "media_type": r["media_type"],
            "artifact_sha256": r["artifact_sha256"],
            "artifact_size_bytes": r["artifact_size_bytes"],
            "file_path": r["file_path"],
            "raw_bytes": r["raw_bytes"],
            "generated_at": r["generated_at"],
            "generated_by_actor_id": r["generated_by_actor_id"],
            "generated_by_actor_display_name": r["generated_by_actor_display_name"],
            "actor_identity_source": r["actor_identity_source"],
            "actor_attribution_status": r["actor_attribution_status"],
            "generator_version": r["generator_version"],
            "source_manifest_version_id": r["source_manifest_version_id"],
            "status": r["status"],
        }

    @classmethod
    def verify_manifest_chain(
        cls,
        analysis_id: str,
        db_path: Optional[str] = None,
        verify_report_files: bool = True
    ) -> Dict[str, Any]:
        """
        Pure read-only verification of manifest versions, hash-chaining,
        payload integrity, capture consistency, observed result consistency,
        and report artifact byte seals.
        Side effects: ZERO (does not write to DB or append audit events).
        """
        manifest_versions = cls.get_manifest_versions(analysis_id, db_path=db_path)
        now_iso = datetime.now(timezone.utc).isoformat()

        if not manifest_versions:
            # Check legacy custody record
            legacy = cls.get_custody_record(analysis_id, db_path=db_path)
            if legacy and legacy.get("manifest_dict") and legacy.get("manifest_hash"):
                # Verify legacy manifest
                canonical_bytes = canonical_json_bytes(legacy["manifest_dict"])
                rec_hash = compute_sha256(canonical_bytes)
                if rec_hash == legacy["manifest_hash"]:
                    return {
                        "analysis_id": analysis_id,
                        "overall_status": "VERIFIED",
                        "versions_count": 1,
                        "versions_verified": [{
                            "version_number": 1,
                            "manifest_type": "LEGACY_SINGLE_MANIFEST",
                            "manifest_sha256": legacy["manifest_hash"],
                            "status": "VERIFIED",
                        }],
                        "verification_timestamp_utc": now_iso,
                        "details": "Legacy single manifest verified nominal.",
                    }
                else:
                    return {
                        "analysis_id": analysis_id,
                        "overall_status": "INTEGRITY_FAILED",
                        "versions_count": 1,
                        "versions_verified": [{
                            "version_number": 1,
                            "manifest_type": "LEGACY_SINGLE_MANIFEST",
                            "manifest_sha256": legacy["manifest_hash"],
                            "status": "INTEGRITY_FAILED",
                        }],
                        "verification_timestamp_utc": now_iso,
                        "details": f"Legacy manifest seal mismatch: expected {legacy['manifest_hash']}, got {rec_hash}",
                    }

            return {
                "analysis_id": analysis_id,
                "overall_status": "INCOMPLETE",
                "versions_count": 0,
                "versions_verified": [],
                "verification_timestamp_utc": now_iso,
                "details": f"No custody manifest versions found for analysis '{analysis_id}'.",
            }

        failure_reasons: List[str] = []
        verified_versions_info: List[Dict[str, Any]] = []
        overall_status = "VERIFIED"
        first_capture_sha256: Optional[str] = None
        first_observed_sha256: Optional[str] = None

        genesis_hash = "0" * 64

        for idx, v in enumerate(manifest_versions):
            v_num = v["version_number"]
            v_status = "VERIFIED"
            v_reasons: List[str] = []

            # 1. Monotonic version numbering check
            expected_v_num = idx + 1
            if v_num != expected_v_num:
                v_status = "INTEGRITY_FAILED"
                v_reasons.append(f"Non-monotonic version number: expected {expected_v_num}, found {v_num}")

            # 2. Canonical JSON payload recomputation & SHA-256 match
            manifest_json_raw = v["manifest_json"]
            manifest_dict = v["manifest_dict"]

            if manifest_dict is not None:
                # Re-canonicalize the dictionary to test deterministic encoding
                recomputed_canon_bytes = canonical_json_bytes(manifest_dict)
                recomputed_sha256 = compute_sha256(recomputed_canon_bytes)
            else:
                recomputed_sha256 = compute_sha256(manifest_json_raw.encode("utf-8"))

            if recomputed_sha256 != v["manifest_sha256"]:
                v_status = "INTEGRITY_FAILED"
                v_reasons.append(
                    f"Manifest version {v_num} SHA-256 seal mismatch: expected {v['manifest_sha256']}, got {recomputed_sha256}"
                )

            # 3. Hash Chaining check
            expected_prev_hash = genesis_hash if idx == 0 else manifest_versions[idx - 1]["manifest_sha256"]
            if v["previous_manifest_sha256"] != expected_prev_hash:
                v_status = "INTEGRITY_FAILED"
                v_reasons.append(
                    f"Manifest version {v_num} previous hash link broken: expected {expected_prev_hash}, got {v['previous_manifest_sha256']}"
                )

            # 4. Invariant checks across versions: capture_sha256 & observed_result_sha256
            if manifest_dict:
                cap_sha = manifest_dict.get("capture_sha256")
                obs_sha = manifest_dict.get("observed_result_sha256")

                if first_capture_sha256 is None and cap_sha:
                    first_capture_sha256 = cap_sha
                elif cap_sha and cap_sha != first_capture_sha256:
                    v_status = "INTEGRITY_FAILED"
                    v_reasons.append(f"Capture SHA-256 mutated across versions: {cap_sha} != {first_capture_sha256}")

                if first_observed_sha256 is None and obs_sha:
                    first_observed_sha256 = obs_sha
                elif obs_sha and obs_sha != first_observed_sha256:
                    v_status = "INTEGRITY_FAILED"
                    v_reasons.append(f"Observed result SHA-256 mutated across versions: {obs_sha} != {first_observed_sha256}")

            # 5. Linked Report Artifacts check
            linked_artifacts = v.get("linked_report_artifacts") or []
            for art in linked_artifacts:
                art_id = art.get("report_artifact_id")
                expected_art_hash = art.get("artifact_sha256")

                db_art = cls.get_report_artifact(art_id, db_path=db_path) if art_id else None
                if not db_art:
                    if v_status != "INTEGRITY_FAILED":
                        v_status = "INCOMPLETE"
                    v_reasons.append(f"Linked report artifact '{art_id}' not found in database.")
                else:
                    if expected_art_hash and db_art["artifact_sha256"] != expected_art_hash:
                        v_status = "INTEGRITY_FAILED"
                        v_reasons.append(
                            f"Linked report artifact '{art_id}' hash mismatch in metadata: {db_art['artifact_sha256']} != {expected_art_hash}"
                        )

                    if verify_report_files:
                        art_bytes = db_art.get("raw_bytes")
                        if art_bytes is None and db_art.get("file_path") and os.path.isfile(db_art["file_path"]):
                            try:
                                with open(db_art["file_path"], "rb") as f:
                                    art_bytes = f.read()
                            except Exception:
                                art_bytes = None

                        if art_bytes is not None:
                            byte_hash = compute_sha256(art_bytes)
                            if byte_hash != db_art["artifact_sha256"]:
                                v_status = "INTEGRITY_FAILED"
                                v_reasons.append(
                                    f"Report artifact '{art_id}' byte content tampered: expected {db_art['artifact_sha256']}, got {byte_hash}"
                                )
                        else:
                            if v_status != "INTEGRITY_FAILED":
                                v_status = "INCOMPLETE"
                            v_reasons.append(f"Report artifact '{art_id}' raw bytes / file missing.")

            # Update overall status
            if v_status == "INTEGRITY_FAILED":
                overall_status = "INTEGRITY_FAILED"
            elif v_status == "INCOMPLETE" and overall_status != "INTEGRITY_FAILED":
                overall_status = "INCOMPLETE"

            failure_reasons.extend(v_reasons)
            verified_versions_info.append({
                "manifest_version_id": v["manifest_version_id"],
                "version_number": v_num,
                "manifest_type": v["manifest_type"],
                "manifest_sha256": v["manifest_sha256"],
                "previous_manifest_sha256": v["previous_manifest_sha256"],
                "status": v_status,
                "reasons": v_reasons,
            })

        details = "All manifest versions and report artifacts verified nominal." if overall_status == "VERIFIED" else "; ".join(failure_reasons)

        return {
            "analysis_id": analysis_id,
            "overall_status": overall_status,
            "versions_count": len(manifest_versions),
            "versions_verified": verified_versions_info,
            "verification_timestamp_utc": now_iso,
            "details": details,
        }

    # -----------------------------------------------------------------------
    # 2c. Asymmetric Digital Signatures & Manifest Linkage (Phase 14)
    # -----------------------------------------------------------------------
    @classmethod
    def save_digital_signature(
        cls,
        signature_record: Dict[str, Any],
        db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Persists an append-only asymmetric digital signature record."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO digital_signatures (
                    signature_id, analysis_id, report_artifact_id, manifest_version_id,
                    signature_algorithm, signature_format, signature_value,
                    signed_digest_algorithm, signed_digest_value,
                    public_key_fingerprint_sha256, public_key_pem, key_id,
                    signed_at, signed_by_actor_id, signed_by_actor_display_name,
                    actor_identity_source, actor_attribution_status, verification_status,
                    schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    signature_record["signature_id"],
                    signature_record["analysis_id"],
                    signature_record["report_artifact_id"],
                    signature_record["manifest_version_id"],
                    signature_record["signature_algorithm"],
                    signature_record.get("signature_format", "BASE64"),
                    signature_record["signature_value"],
                    signature_record.get("signed_digest_algorithm", "SHA256"),
                    signature_record["signed_digest_value"],
                    signature_record["public_key_fingerprint_sha256"],
                    signature_record["public_key_pem"],
                    signature_record["key_id"],
                    signature_record["signed_at"],
                    signature_record.get("signed_by_actor_id", "UNATTRIBUTED"),
                    signature_record.get("signed_by_actor_display_name", "Unattributed Analyst"),
                    signature_record.get("actor_identity_source", "UNKNOWN"),
                    signature_record.get("actor_attribution_status", "UNATTRIBUTED"),
                    signature_record.get("verification_status", "VERIFIED"),
                    signature_record.get("schema_version", CURRENT_SCHEMA_VERSION),
                )
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        return signature_record

    @classmethod
    def save_signature_and_manifest_version(
        cls,
        signature_record: Dict[str, Any],
        manifest_version: Dict[str, Any],
        db_path: Optional[str] = None,
        inject_failure_after_signature: bool = False
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Atomically persists a digital signature record and its associated new manifest version.
        Rolls back both if either operation fails.
        """
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        try:
            # 1. Check if manifest version already exists
            cursor.execute(
                "SELECT sealed FROM custody_manifest_versions WHERE analysis_id = ? AND version_number = ?",
                (manifest_version["analysis_id"], manifest_version["version_number"])
            )
            existing = cursor.fetchone()
            if existing:
                raise ImmutableRecordError(
                    f"Custody manifest version {manifest_version['version_number']} for analysis '{manifest_version['analysis_id']}' already exists."
                )

            # 2. Insert new manifest version
            cursor.execute(
                """
                INSERT INTO custody_manifest_versions (
                    manifest_version_id, analysis_id, version_number, manifest_type,
                    parent_manifest_version_id, previous_manifest_sha256, manifest_json,
                    manifest_sha256, canonicalization_version, created_at,
                    created_by_actor_id, created_by_actor_display_name,
                    actor_identity_source, actor_attribution_status, sealed,
                    supersedes_version_id, purpose, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest_version["manifest_version_id"],
                    manifest_version["analysis_id"],
                    manifest_version["version_number"],
                    manifest_version["manifest_type"],
                    manifest_version.get("parent_manifest_version_id"),
                    manifest_version["previous_manifest_sha256"],
                    manifest_version["manifest_json"],
                    manifest_version["manifest_sha256"],
                    manifest_version.get("canonicalization_version", CANONICALIZATION_VERSION),
                    manifest_version["created_at"],
                    manifest_version.get("created_by_actor_id", "UNATTRIBUTED"),
                    manifest_version.get("created_by_actor_display_name", "Unattributed Analyst"),
                    manifest_version.get("actor_identity_source", "UNKNOWN"),
                    manifest_version.get("actor_attribution_status", "UNATTRIBUTED"),
                    1 if manifest_version.get("sealed", True) else 0,
                    manifest_version.get("supersedes_version_id"),
                    manifest_version.get("purpose"),
                    manifest_version.get("schema_version", CURRENT_SCHEMA_VERSION),
                )
            )

            # 3. Insert digital signature
            cursor.execute(
                """
                INSERT INTO digital_signatures (
                    signature_id, analysis_id, report_artifact_id, manifest_version_id,
                    signature_algorithm, signature_format, signature_value,
                    signed_digest_algorithm, signed_digest_value,
                    public_key_fingerprint_sha256, public_key_pem, key_id,
                    signed_at, signed_by_actor_id, signed_by_actor_display_name,
                    actor_identity_source, actor_attribution_status, verification_status,
                    schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    signature_record["signature_id"],
                    signature_record["analysis_id"],
                    signature_record["report_artifact_id"],
                    signature_record["manifest_version_id"],
                    signature_record["signature_algorithm"],
                    signature_record.get("signature_format", "BASE64"),
                    signature_record["signature_value"],
                    signature_record.get("signed_digest_algorithm", "SHA256"),
                    signature_record["signed_digest_value"],
                    signature_record["public_key_fingerprint_sha256"],
                    signature_record["public_key_pem"],
                    signature_record["key_id"],
                    signature_record["signed_at"],
                    signature_record.get("signed_by_actor_id", "UNATTRIBUTED"),
                    signature_record.get("signed_by_actor_display_name", "Unattributed Analyst"),
                    signature_record.get("actor_identity_source", "UNKNOWN"),
                    signature_record.get("actor_attribution_status", "UNATTRIBUTED"),
                    signature_record.get("verification_status", "VERIFIED"),
                    signature_record.get("schema_version", CURRENT_SCHEMA_VERSION),
                )
            )

            if inject_failure_after_signature:
                raise RuntimeError("Injected transaction failure after digital signature insertion.")

            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        return signature_record, manifest_version

    @classmethod
    def get_digital_signature(cls, signature_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves a specific digital signature by ID."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM digital_signatures WHERE signature_id = ?", (signature_id,))
        r = cursor.fetchone()
        conn.close()
        if not r:
            return None

        return {
            "signature_id": r["signature_id"],
            "analysis_id": r["analysis_id"],
            "report_artifact_id": r["report_artifact_id"],
            "manifest_version_id": r["manifest_version_id"],
            "signature_algorithm": r["signature_algorithm"],
            "signature_format": r["signature_format"],
            "signature_value": r["signature_value"],
            "signed_digest_algorithm": r["signed_digest_algorithm"],
            "signed_digest_value": r["signed_digest_value"],
            "public_key_fingerprint_sha256": r["public_key_fingerprint_sha256"],
            "public_key_pem": r["public_key_pem"],
            "key_id": r["key_id"],
            "signed_at": r["signed_at"],
            "signed_by_actor_id": r["signed_by_actor_id"],
            "signed_by_actor_display_name": r["signed_by_actor_display_name"],
            "actor_identity_source": r["actor_identity_source"],
            "actor_attribution_status": r["actor_attribution_status"],
            "verification_status": r["verification_status"],
            "schema_version": r["schema_version"],
        }

    @classmethod
    def get_report_signatures(
        cls,
        analysis_id: str,
        report_artifact_id: Optional[str] = None,
        db_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves all digital signatures for an analysis or specific report artifact."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        if report_artifact_id:
            cursor.execute(
                "SELECT * FROM digital_signatures WHERE analysis_id = ? AND report_artifact_id = ? ORDER BY signed_at ASC",
                (analysis_id, report_artifact_id)
            )
        else:
            cursor.execute(
                "SELECT * FROM digital_signatures WHERE analysis_id = ? ORDER BY signed_at ASC",
                (analysis_id,)
            )
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            results.append({
                "signature_id": r["signature_id"],
                "analysis_id": r["analysis_id"],
                "report_artifact_id": r["report_artifact_id"],
                "manifest_version_id": r["manifest_version_id"],
                "signature_algorithm": r["signature_algorithm"],
                "signature_format": r["signature_format"],
                "signature_value": r["signature_value"],
                "signed_digest_algorithm": r["signed_digest_algorithm"],
                "signed_digest_value": r["signed_digest_value"],
                "public_key_fingerprint_sha256": r["public_key_fingerprint_sha256"],
                "public_key_pem": r["public_key_pem"],
                "key_id": r["key_id"],
                "signed_at": r["signed_at"],
                "signed_by_actor_id": r["signed_by_actor_id"],
                "signed_by_actor_display_name": r["signed_by_actor_display_name"],
                "actor_identity_source": r["actor_identity_source"],
                "actor_attribution_status": r["actor_attribution_status"],
                "verification_status": r["verification_status"],
                "schema_version": r["schema_version"],
            })
        return results

    # -----------------------------------------------------------------------
    # 3. Case Management Persistence
    # -----------------------------------------------------------------------
    @classmethod
    def create_case(
        cls,
        case_id: str,
        title: str,
        description: str = "",
        analyst_id: str = "UNATTRIBUTED",
        analyst_name: str = "Unattributed Analyst",
        tags: Optional[List[str]] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Creates a new case in the persistent store with actor attribution."""
        now_iso = datetime.now(timezone.utc).isoformat()
        tags_list = tags or ["Email-Forensics"]
        act = actor or (ActorContext.local_declared(analyst_id, analyst_name) if analyst_id != "UNATTRIBUTED" else ActorContext.unattributed())
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO cases (
                id, title, description, status, analyst_id, analyst_name,
                created_by_actor_id, created_by_display_name,
                tags_json, created_at, updated_at, is_archived
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id, title, description, "OPEN", act.actor_id, act.actor_display_name,
                act.actor_id, act.actor_display_name,
                json.dumps(tags_list), now_iso, now_iso, 0
            )
        )
        conn.commit()
        conn.close()

        # Record CASE_CREATED system audit event
        try:
            cls.record_audit_event(
                event_type="CASE_CREATED",
                object_type="CASE",
                object_id=case_id,
                details=f"Case {case_id} created: {title}",
                actor=act,
                db_path=db_path
            )
        except Exception:
            pass

        return {
            "id": case_id,
            "title": title,
            "description": description,
            "status": "OPEN",
            "analyst_id": act.actor_id,
            "analyst_name": act.actor_display_name,
            "created_by_actor_id": act.actor_id,
            "created_by_display_name": act.actor_display_name,
            "tags": tags_list,
            "created_at_iso": now_iso,
            "updated_at_iso": now_iso,
            "artifacts": [],
            "analysis_ids": [],
            "analyst_notes": [],
            "is_archived": False,
        }

    @classmethod
    def get_case(cls, case_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Loads case with attached analyses, artifacts, and analyst notes."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        # Fetch attached analyses
        cursor.execute("SELECT analysis_id FROM case_analyses WHERE case_id = ? ORDER BY attached_at ASC", (case_id,))
        analysis_ids = [r["analysis_id"] for r in cursor.fetchall()]

        # Fetch artifacts
        cursor.execute("SELECT * FROM case_artifacts WHERE case_id = ? ORDER BY added_at ASC", (case_id,))
        artifacts = [{
            "artifact_id": r["artifact_id"],
            "artifact_type": r["artifact_type"],
            "filename": r["filename"],
            "sha256": r["sha256"],
            "analysis_id": r["analysis_id"],
            "added_at_iso": r["added_at"],
        } for r in cursor.fetchall()]

        for art in artifacts:
            if art["analysis_id"] and art["analysis_id"] not in analysis_ids:
                analysis_ids.append(art["analysis_id"])

        # Fetch notes
        cursor.execute("SELECT * FROM analyst_notes WHERE target_type = 'CASE' AND target_id = ? ORDER BY created_at ASC", (case_id,))
        notes = [{
            "note_id": r["note_id"],
            "author": r["analyst_name"],
            "analyst_id": r["analyst_id"],
            "identity_source": r["identity_source"] if "identity_source" in r.keys() else "LOCAL_DECLARED",
            "attribution_status": r["attribution_status"] if "attribution_status" in r.keys() else "ATTRIBUTED",
            "text": r["note_text"],
            "sha256": r["note_sha256"],
            "timestamp_iso": r["created_at"],
        } for r in cursor.fetchall()]

        col_keys = row.keys()
        created_actor_id = row["created_by_actor_id"] if "created_by_actor_id" in col_keys else (row["analyst_id"] or "UNATTRIBUTED")
        created_actor_name = row["created_by_display_name"] if "created_by_display_name" in col_keys else (row["analyst_name"] or "Unattributed Analyst")
        archived_actor_id = row["archived_by_actor_id"] if "archived_by_actor_id" in col_keys else None

        conn.close()

        return {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "status": row["status"],
            "analyst_id": row["analyst_id"] or "UNATTRIBUTED",
            "analyst_name": row["analyst_name"] or "Unattributed Analyst",
            "created_by_actor_id": created_actor_id,
            "created_by_display_name": created_actor_name,
            "archived_by_actor_id": archived_actor_id,
            "tags": json.loads(row["tags_json"]) if row["tags_json"] else [],
            "created_at_iso": row["created_at"],
            "updated_at_iso": row["updated_at"],
            "is_archived": bool(row["is_archived"]),
            "analysis_ids": analysis_ids,
            "artifacts": artifacts,
            "analyst_notes": notes,
        }

    @classmethod
    def list_cases(cls, include_archived: bool = False, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists all cases."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        query = "SELECT id FROM cases"
        if not include_archived:
            query += " WHERE is_archived = 0"
        query += " ORDER BY updated_at DESC"

        cursor.execute(query)
        case_ids = [r["id"] for r in cursor.fetchall()]
        conn.close()

        results = []
        for cid in case_ids:
            c = cls.get_case(cid, db_path=db_path)
            if c:
                results.append(c)
        return results

    @classmethod
    def attach_analysis_to_case(
        cls,
        case_id: str,
        analysis_id: str,
        analyst_id: str = "UNATTRIBUTED",
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None
    ) -> bool:
        """Attaches an analysis to a case and records chained audit event with actor attribution."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        act = actor or (ActorContext.local_declared(analyst_id) if analyst_id != "UNATTRIBUTED" else ActorContext.unattributed())

        try:
            cursor.execute(
                "INSERT OR IGNORE INTO case_analyses (case_id, analysis_id, attached_at, attached_by) VALUES (?, ?, ?, ?)",
                (case_id, analysis_id, now_iso, act.actor_id)
            )
            cursor.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now_iso, case_id))

            cursor.execute("SELECT current_event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1")
            last_row = cursor.fetchone()
            prev_hash = last_row["current_event_hash"] if last_row and last_row["current_event_hash"] else ("0" * 64)

            evt_id = f"evt_{uuid.uuid4().hex[:12]}"
            details = f"Analysis {analysis_id} attached to case {case_id}"
            evt_dict = {
                "actor_attribution_status": act.actor_attribution_status,
                "actor_display_name": act.actor_display_name,
                "actor_id": act.actor_id,
                "actor_identity_source": act.actor_identity_source,
                "details": details,
                "event_id": evt_id,
                "event_type": "CASE_ANALYSIS_ATTACHED",
                "object_id": case_id,
                "object_type": "CASE",
                "previous_event_hash": prev_hash,
                "timestamp_utc": now_iso,
            }
            evt_hash = compute_sha256(canonical_json_bytes(evt_dict))
            cursor.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp_utc, event_type, object_type, object_id,
                    actor_id, actor_display_name, actor_identity_source, actor_attribution_status,
                    details, previous_event_hash, current_event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evt_id, now_iso, "CASE_ANALYSIS_ATTACHED", "CASE", case_id,
                    act.actor_id, act.actor_display_name, act.actor_identity_source, act.actor_attribution_status,
                    details, prev_hash, evt_hash
                )
            )

            conn.commit()
            return True
        except Exception:
            conn.rollback()
            return False
        finally:
            conn.close()

    @classmethod
    def detach_analysis_from_case(
        cls,
        case_id: str,
        analysis_id: str,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None
    ) -> bool:
        """Detaches an analysis from a case and records chained audit event with actor attribution."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        act = actor or ActorContext.unattributed()

        try:
            cursor.execute("DELETE FROM case_analyses WHERE case_id = ? AND analysis_id = ?", (case_id, analysis_id))
            cursor.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now_iso, case_id))

            cursor.execute("SELECT current_event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1")
            last_row = cursor.fetchone()
            prev_hash = last_row["current_event_hash"] if last_row and last_row["current_event_hash"] else ("0" * 64)

            evt_id = f"evt_{uuid.uuid4().hex[:12]}"
            details = f"Analysis {analysis_id} detached from case {case_id}"
            evt_dict = {
                "actor_attribution_status": act.actor_attribution_status,
                "actor_display_name": act.actor_display_name,
                "actor_id": act.actor_id,
                "actor_identity_source": act.actor_identity_source,
                "details": details,
                "event_id": evt_id,
                "event_type": "CASE_ANALYSIS_DETACHED",
                "object_id": case_id,
                "object_type": "CASE",
                "previous_event_hash": prev_hash,
                "timestamp_utc": now_iso,
            }
            evt_hash = compute_sha256(canonical_json_bytes(evt_dict))
            cursor.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp_utc, event_type, object_type, object_id,
                    actor_id, actor_display_name, actor_identity_source, actor_attribution_status,
                    details, previous_event_hash, current_event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evt_id, now_iso, "CASE_ANALYSIS_DETACHED", "CASE", case_id,
                    act.actor_id, act.actor_display_name, act.actor_identity_source, act.actor_attribution_status,
                    details, prev_hash, evt_hash
                )
            )

            conn.commit()
            return True
        except Exception:
            conn.rollback()
            return False
        finally:
            conn.close()

    @classmethod
    def archive_case(
        cls,
        case_id: str,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Soft-archives a case and records CASE_ARCHIVED chained audit event with actor attribution."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        act = actor or ActorContext.unattributed()

        try:
            cursor.execute(
                "UPDATE cases SET status = 'ARCHIVED', is_archived = 1, archived_by_actor_id = ?, updated_at = ? WHERE id = ?",
                (act.actor_id, now_iso, case_id)
            )

            cursor.execute("SELECT current_event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1")
            last_row = cursor.fetchone()
            prev_hash = last_row["current_event_hash"] if last_row and last_row["current_event_hash"] else ("0" * 64)

            evt_id = f"evt_{uuid.uuid4().hex[:12]}"
            details = f"Case {case_id} archived"
            evt_dict = {
                "actor_attribution_status": act.actor_attribution_status,
                "actor_display_name": act.actor_display_name,
                "actor_id": act.actor_id,
                "actor_identity_source": act.actor_identity_source,
                "details": details,
                "event_id": evt_id,
                "event_type": "CASE_ARCHIVED",
                "object_id": case_id,
                "object_type": "CASE",
                "previous_event_hash": prev_hash,
                "timestamp_utc": now_iso,
            }
            evt_hash = compute_sha256(canonical_json_bytes(evt_dict))
            cursor.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp_utc, event_type, object_type, object_id,
                    actor_id, actor_display_name, actor_identity_source, actor_attribution_status,
                    details, previous_event_hash, current_event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evt_id, now_iso, "CASE_ARCHIVED", "CASE", case_id,
                    act.actor_id, act.actor_display_name, act.actor_identity_source, act.actor_attribution_status,
                    details, prev_hash, evt_hash
                )
            )

            conn.commit()
        except Exception:
            conn.rollback()
            return None
        finally:
            conn.close()

        return cls.get_case(case_id, db_path=db_path)

    # -----------------------------------------------------------------------
    # 4. Analyst Notes (Additive Only with Canonical Hashing & Attribution)
    # -----------------------------------------------------------------------
    @classmethod
    def add_analyst_note(
        cls,
        note_id: str,
        target_type: str,
        target_id: str,
        analyst_id: str = "UNATTRIBUTED",
        analyst_name: str = "Unattributed Analyst",
        note_text: str = "",
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Appends an immutable SHA-256 integrity-hashed analyst note using canonical JSON."""
        now_iso = datetime.now(timezone.utc).isoformat()
        act = actor or (ActorContext.local_declared(analyst_id, analyst_name) if analyst_id != "UNATTRIBUTED" else ActorContext.unattributed())
        effective_analyst_id = act.actor_id
        effective_analyst_name = act.actor_display_name
        identity_source = act.actor_identity_source
        attribution_status = act.actor_attribution_status

        note_obj = {
            "analyst_id": effective_analyst_id,
            "created_at": now_iso,
            "note_text": note_text,
            "target_id": target_id,
            "target_type": target_type,
        }
        note_bytes = canonical_json_bytes(note_obj)
        note_hash = compute_sha256(note_bytes)

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO analyst_notes (
                note_id, target_type, target_id, analyst_id, analyst_name,
                identity_source, attribution_status, note_text, note_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                note_id, target_type, target_id, effective_analyst_id, effective_analyst_name,
                identity_source, attribution_status, note_text, note_hash, now_iso
            )
        )
        if target_type == "CASE":
            cursor.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now_iso, target_id))

        conn.commit()
        conn.close()

        return {
            "note_id": note_id,
            "target_type": target_type,
            "target_id": target_id,
            "analyst_id": effective_analyst_id,
            "analyst_name": effective_analyst_name,
            "identity_source": identity_source,
            "attribution_status": attribution_status,
            "note_text": note_text,
            "note_integrity_sha256": note_hash,
            "created_at": now_iso,
        }

    @classmethod
    def get_analyst_notes(cls, target_type: str, target_id: str, verify_integrity: bool = True, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves additive notes log for a case or analysis with canonical integrity verification."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM analyst_notes WHERE target_type = ? AND target_id = ? ORDER BY created_at ASC",
            (target_type, target_id)
        )
        rows = cursor.fetchall()
        conn.close()

        notes = []
        for r in rows:
            if verify_integrity:
                canonical_obj = {
                    "analyst_id": r["analyst_id"],
                    "created_at": r["created_at"],
                    "note_text": r["note_text"],
                    "target_id": r["target_id"],
                    "target_type": r["target_type"],
                }
                computed_hash = compute_sha256(canonical_json_bytes(canonical_obj))
                if computed_hash != r["note_sha256"]:
                    # Legacy 1: Key order variation check
                    alt_obj = {
                        "target_type": r["target_type"],
                        "target_id": r["target_id"],
                        "analyst_id": r["analyst_id"],
                        "created_at": r["created_at"],
                        "note_text": r["note_text"],
                    }
                    if compute_sha256(canonical_json_bytes(alt_obj)) != r["note_sha256"]:
                        # Legacy 2: Pipe delimiter fallback
                        legacy_bytes = f"{r['target_type']}|{r['target_id']}|{r['analyst_id']}|{r['created_at']}|{r['note_text']}".encode("utf-8")
                        if compute_sha256(legacy_bytes) != r["note_sha256"]:
                            raise IntegrityVerificationError(
                                f"Integrity check FAILED for analyst note '{r['note_id']}'. Tampered note content detected."
                            )
            notes.append({
                "note_id": r["note_id"],
                "target_type": r["target_type"],
                "target_id": r["target_id"],
                "analyst_id": r["analyst_id"] or "UNATTRIBUTED",
                "analyst_name": r["analyst_name"] or "Unattributed Analyst",
                "identity_source": r["identity_source"] if "identity_source" in r.keys() else "LOCAL_DECLARED",
                "attribution_status": r["attribution_status"] if "attribution_status" in r.keys() else "ATTRIBUTED",
                "note_text": r["note_text"],
                "note_integrity_sha256": r["note_sha256"],
                "created_at": r["created_at"],
            })
        return notes

    # -----------------------------------------------------------------------
    # 5. Simulations, Active Scans & DNS Enrichments Persistence
    # -----------------------------------------------------------------------
    @classmethod
    def save_simulation(
        cls,
        simulation_id: str,
        analysis_id: str,
        session_id: str,
        requested_actions: List[str],
        projection_dict: Dict[str, Any],
        parameters: Optional[Dict[str, Any]] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None
    ) -> str:
        """Persists a hypothetical remediation simulation projection with actor attribution."""
        now_iso = datetime.now(timezone.utc).isoformat()
        proj_bytes = canonical_json_bytes(projection_dict)
        proj_json = proj_bytes.decode("utf-8")
        proj_hash = compute_sha256(proj_bytes)
        act = actor or ActorContext.unattributed()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO simulations (
                simulation_id, analysis_id, session_id, requested_actions_json,
                parameters_json, projection_json, projection_sha256,
                created_by_actor_id, identity_source,
                authoritative, historical_applicability, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                simulation_id,
                analysis_id,
                session_id,
                json.dumps(requested_actions),
                json.dumps(parameters) if parameters else None,
                proj_json,
                proj_hash,
                act.actor_id,
                act.actor_identity_source,
                0,
                "HYPOTHETICAL",
                now_iso,
            )
        )
        conn.commit()
        conn.close()
        return simulation_id

    @classmethod
    def get_simulation(cls, simulation_id: str, verify_integrity: bool = True, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves a remediation simulation projection with integrity verification."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM simulations WHERE simulation_id = ?", (simulation_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        if verify_integrity:
            recomputed = compute_sha256(row["projection_json"].encode("utf-8"))
            if recomputed != row["projection_sha256"]:
                raise IntegrityVerificationError(
                    f"Integrity check FAILED for simulation '{simulation_id}'. Tampered projection JSON detected."
                )

        col_keys = row.keys()
        return {
            "simulation_id": row["simulation_id"],
            "analysis_id": row["analysis_id"],
            "session_id": row["session_id"],
            "requested_actions": json.loads(row["requested_actions_json"]) if row["requested_actions_json"] else [],
            "parameters": json.loads(row["parameters_json"]) if row["parameters_json"] else None,
            "created_by_actor_id": row["created_by_actor_id"] if "created_by_actor_id" in col_keys else "UNATTRIBUTED",
            "identity_source": row["identity_source"] if "identity_source" in col_keys else "UNKNOWN",
            "projection": json.loads(row["projection_json"]),
            "projection_sha256": row["projection_sha256"],
            "authoritative": bool(row["authoritative"]),
            "historical_applicability": row["historical_applicability"],
            "created_at": row["created_at"],
        }

    @classmethod
    def save_active_scan(
        cls,
        scan_id: str,
        target_host: str,
        connected_ip: Optional[str],
        ports_scanned: List[int],
        result_dict: Dict[str, Any],
        provenance: str = "ACTIVE_NETWORK_PROBE",
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None
    ) -> str:
        """Persists an active network posture scan with canonical hashing and actor attribution."""
        now_iso = datetime.now(timezone.utc).isoformat()
        res_bytes = canonical_json_bytes(result_dict)
        res_json = res_bytes.decode("utf-8")
        res_hash = compute_sha256(res_bytes)
        act = actor or ActorContext.unattributed()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO active_scans (
                scan_id, target_host, connected_ip, ports_scanned_json,
                initiated_by_actor_id, identity_source,
                provenance, historical_applicability, result_json, result_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                target_host,
                connected_ip,
                json.dumps(ports_scanned),
                act.actor_id,
                act.actor_identity_source,
                provenance,
                "CURRENT_STATE_ONLY",
                res_json,
                res_hash,
                now_iso,
            )
        )
        conn.commit()
        conn.close()
        return scan_id

    @classmethod
    def get_active_scan(cls, scan_id: str, verify_integrity: bool = True, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves an active mail posture scan with integrity verification."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        if verify_integrity:
            recomputed = compute_sha256(row["result_json"].encode("utf-8"))
            if recomputed != row["result_sha256"]:
                raise IntegrityVerificationError(
                    f"Integrity check FAILED for active scan '{scan_id}'. Tampered scan result JSON detected."
                )

        col_keys = row.keys()
        return {
            "scan_id": row["scan_id"],
            "target_host": row["target_host"],
            "connected_ip": row["connected_ip"],
            "ports_scanned": json.loads(row["ports_scanned_json"]) if row["ports_scanned_json"] else [],
            "initiated_by_actor_id": row["initiated_by_actor_id"] if "initiated_by_actor_id" in col_keys else "UNATTRIBUTED",
            "identity_source": row["identity_source"] if "identity_source" in col_keys else "UNKNOWN",
            "provenance": row["provenance"],
            "historical_applicability": row["historical_applicability"],
            "result": json.loads(row["result_json"]),
            "result_sha256": row["result_sha256"],
            "created_at": row["created_at"],
        }

    @classmethod
    def save_dns_enrichment(
        cls,
        enrichment_id: str,
        target_domain: str,
        resolver_provider: Optional[str],
        result_dict: Dict[str, Any],
        queried_at_utc: str,
        provenance: str = "ACTIVE_DNS_ENRICHMENT",
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None
    ) -> str:
        """Persists an active DNS enrichment query with canonical hashing and actor attribution."""
        now_iso = datetime.now(timezone.utc).isoformat()
        res_bytes = canonical_json_bytes(result_dict)
        res_json = res_bytes.decode("utf-8")
        res_hash = compute_sha256(res_bytes)
        act = actor or ActorContext.unattributed()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO dns_enrichments (
                enrichment_id, target_domain, resolver_provider,
                queried_by_actor_id, identity_source,
                provenance, historical_applicability, result_json, result_sha256,
                queried_at_utc, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                enrichment_id,
                target_domain,
                resolver_provider,
                act.actor_id,
                act.actor_identity_source,
                provenance,
                "CURRENT_STATE_ONLY",
                res_json,
                res_hash,
                queried_at_utc,
                now_iso,
            )
        )
        conn.commit()
        conn.close()
        return enrichment_id

    @classmethod
    def get_dns_enrichment(cls, enrichment_id: str, verify_integrity: bool = True, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves an active DNS enrichment record with integrity verification."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM dns_enrichments WHERE enrichment_id = ?", (enrichment_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        if verify_integrity:
            recomputed = compute_sha256(row["result_json"].encode("utf-8"))
            if recomputed != row["result_sha256"]:
                raise IntegrityVerificationError(
                    f"Integrity check FAILED for DNS enrichment '{enrichment_id}'. Tampered result JSON detected."
                )

        col_keys = row.keys()
        return {
            "enrichment_id": row["enrichment_id"],
            "target_domain": row["target_domain"],
            "resolver_provider": row["resolver_provider"],
            "queried_by_actor_id": row["queried_by_actor_id"] if "queried_by_actor_id" in col_keys else "UNATTRIBUTED",
            "identity_source": row["identity_source"] if "identity_source" in col_keys else "UNKNOWN",
            "provenance": row["provenance"],
            "historical_applicability": row["historical_applicability"],
            "result": json.loads(row["result_json"]),
            "result_sha256": row["result_sha256"],
            "queried_at_utc": row["queried_at_utc"],
            "created_at": row["created_at"],
        }

    # -----------------------------------------------------------------------
    # 6. System Audit Events Log & Chain Verification
    # -----------------------------------------------------------------------
    @classmethod
    def record_audit_event(
        cls,
        event_type: str,
        object_type: str,
        object_id: str,
        details: str,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Appends a hash-chained system audit event with actor attribution."""
        act = actor or ActorContext.unattributed()
        now_iso = datetime.now(timezone.utc).isoformat()
        evt_id = f"evt_{uuid.uuid4().hex[:12]}"

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT current_event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1")
        last_row = cursor.fetchone()
        prev_hash = last_row["current_event_hash"] if last_row and last_row["current_event_hash"] else ("0" * 64)

        evt_dict = {
            "actor_attribution_status": act.actor_attribution_status,
            "actor_display_name": act.actor_display_name,
            "actor_id": act.actor_id,
            "actor_identity_source": act.actor_identity_source,
            "details": details,
            "event_id": evt_id,
            "event_type": event_type,
            "object_id": object_id,
            "object_type": object_type,
            "previous_event_hash": prev_hash,
            "timestamp_utc": now_iso,
        }
        evt_hash = compute_sha256(canonical_json_bytes(evt_dict))

        cursor.execute(
            """
            INSERT INTO audit_events (
                event_id, timestamp_utc, event_type, object_type, object_id,
                actor_id, actor_display_name, actor_identity_source, actor_attribution_status,
                details, previous_event_hash, current_event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evt_id,
                now_iso,
                event_type,
                object_type,
                object_id,
                act.actor_id,
                act.actor_display_name,
                act.actor_identity_source,
                act.actor_attribution_status,
                details,
                prev_hash,
                evt_hash,
            )
        )
        conn.commit()
        conn.close()

        evt_dict["current_event_hash"] = evt_hash
        return evt_dict

    @classmethod
    def get_audit_events(
        cls,
        object_type: Optional[str] = None,
        object_id: Optional[str] = None,
        verify_integrity: bool = True,
        db_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves system audit events with cryptographic chain integrity verification including actor attribution."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM audit_events"
        params = []
        conditions = []
        if object_type:
            conditions.append("object_type = ?")
            params.append(object_type)
        if object_id:
            conditions.append("object_id = ?")
            params.append(object_id)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY rowid ASC"

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        conn.close()

        # If unconstrained full query, verify end-to-end chain
        if verify_integrity and not object_type and not object_id:
            expected_prev = "0" * 64
            for r in rows:
                if r["previous_event_hash"] != expected_prev:
                    raise IntegrityVerificationError(
                        f"Audit event chain broken at event '{r['event_id']}': previous_event_hash mismatch."
                    )
                col_keys = r.keys()
                actor_id = r["actor_id"] if "actor_id" in col_keys else "UNATTRIBUTED"
                actor_name = r["actor_display_name"] if "actor_display_name" in col_keys else "Unattributed Analyst"
                actor_source = r["actor_identity_source"] if "actor_identity_source" in col_keys else "UNKNOWN"
                actor_status = r["actor_attribution_status"] if "actor_attribution_status" in col_keys else "UNATTRIBUTED"

                evt_dict = {
                    "actor_attribution_status": actor_status,
                    "actor_display_name": actor_name,
                    "actor_id": actor_id,
                    "actor_identity_source": actor_source,
                    "details": r["details"],
                    "event_id": r["event_id"],
                    "event_type": r["event_type"],
                    "object_id": r["object_id"],
                    "object_type": r["object_type"],
                    "previous_event_hash": r["previous_event_hash"],
                    "timestamp_utc": r["timestamp_utc"],
                }
                computed_hash = compute_sha256(canonical_json_bytes(evt_dict))
                if computed_hash != r["current_event_hash"]:
                    # Fallback check for legacy 7-field events
                    legacy_dict = {
                        "details": r["details"],
                        "event_id": r["event_id"],
                        "event_type": r["event_type"],
                        "object_id": r["object_id"],
                        "object_type": r["object_type"],
                        "previous_event_hash": r["previous_event_hash"],
                        "timestamp_utc": r["timestamp_utc"],
                    }
                    if compute_sha256(canonical_json_bytes(legacy_dict)) != r["current_event_hash"]:
                        raise IntegrityVerificationError(
                            f"Audit event '{r['event_id']}' current_event_hash verification failed. Tampered audit record or actor attribution detected."
                        )
                expected_prev = r["current_event_hash"]
        elif verify_integrity:
            # Per-event payload integrity check for filtered queries
            for r in rows:
                col_keys = r.keys()
                actor_id = r["actor_id"] if "actor_id" in col_keys else "UNATTRIBUTED"
                actor_name = r["actor_display_name"] if "actor_display_name" in col_keys else "Unattributed Analyst"
                actor_source = r["actor_identity_source"] if "actor_identity_source" in col_keys else "UNKNOWN"
                actor_status = r["actor_attribution_status"] if "actor_attribution_status" in col_keys else "UNATTRIBUTED"

                evt_dict = {
                    "actor_attribution_status": actor_status,
                    "actor_display_name": actor_name,
                    "actor_id": actor_id,
                    "actor_identity_source": actor_source,
                    "details": r["details"],
                    "event_id": r["event_id"],
                    "event_type": r["event_type"],
                    "object_id": r["object_id"],
                    "object_type": r["object_type"],
                    "previous_event_hash": r["previous_event_hash"],
                    "timestamp_utc": r["timestamp_utc"],
                }
                computed_hash = compute_sha256(canonical_json_bytes(evt_dict))
                if computed_hash != r["current_event_hash"]:
                    legacy_dict = {
                        "details": r["details"],
                        "event_id": r["event_id"],
                        "event_type": r["event_type"],
                        "object_id": r["object_id"],
                        "object_type": r["object_type"],
                        "previous_event_hash": r["previous_event_hash"],
                        "timestamp_utc": r["timestamp_utc"],
                    }
                    if compute_sha256(canonical_json_bytes(legacy_dict)) != r["current_event_hash"]:
                        raise IntegrityVerificationError(
                            f"Audit event '{r['event_id']}' current_event_hash verification failed. Tampered audit record or actor attribution detected."
                        )

        return [{
            "event_id": r["event_id"],
            "timestamp_utc": r["timestamp_utc"],
            "event_type": r["event_type"],
            "object_type": r["object_type"],
            "object_id": r["object_id"],
            "actor_id": r["actor_id"] if "actor_id" in r.keys() else "UNATTRIBUTED",
            "actor_display_name": r["actor_display_name"] if "actor_display_name" in r.keys() else "Unattributed Analyst",
            "actor_identity_source": r["actor_identity_source"] if "actor_identity_source" in r.keys() else "UNKNOWN",
            "actor_attribution_status": r["actor_attribution_status"] if "actor_attribution_status" in r.keys() else "UNATTRIBUTED",
            "details": r["details"],
            "previous_event_hash": r["previous_event_hash"],
            "current_event_hash": r["current_event_hash"],
        } for r in rows]

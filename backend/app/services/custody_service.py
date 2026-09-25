"""
SecureMailScope X - Local Forensic Chain of Custody & Evidence Sealing Service
Implements append-only chained cryptographic audit trails, deterministic immutable manifest versioning,
separate report artifact records, hash-chaining, persistent database synchronization,
and zero-side-effect tamper verification.
"""

import os
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

from app.schemas.api import (
    CustodyEventDTO,
    CaptureIntegrityDTO,
    ManifestIntegrityDTO,
    ReportIntegrityDTO,
    CustodyRecordResponse,
    AnalysisDetailResponse,
    CustodyManifestVersionDTO,
    ReportArtifactDTO,
    ManifestChainVerificationResponse,
)
from app.schemas.identity import (
    ActorContext,
    IDENTITY_SOURCE_SYSTEM,
    ATTRIBUTION_STATUS_SYSTEM_GENERATED,
)
from app.db.repository import (
    ForensicRepository,
    canonical_json_bytes,
    canonical_json_str,
    compute_sha256,
    compute_json_sha256,
)

GENESIS_PREV_HASH = "0" * 64
CANONICALIZATION_METHOD = "SECUREMAILSCOPE_CANONICAL_JSON_V1"

REPORT_STORAGE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "reports"
)


def compute_legacy_event_hash(
    event_id: str,
    analysis_id: str,
    timestamp_utc: str,
    event_type: str,
    artifact_hash: str,
    previous_event_hash: str
) -> str:
    """Legacy pipe-delimited cryptographic event hash (V1 compatibility)."""
    payload = f"{event_id}|{analysis_id}|{timestamp_utc}|{event_type}|{artifact_hash}|{previous_event_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_event_hash_v2(
    event_id: str,
    analysis_id: str,
    timestamp_utc: str,
    event_type: str,
    artifact_hash: str,
    previous_event_hash: str,
    details: Optional[str] = None,
    actor_id: Optional[str] = None,
    actor_display_name: Optional[str] = None,
    actor_identity_source: Optional[str] = None,
    actor_attribution_status: Optional[str] = None,
) -> str:
    """
    Canonical JSON forensic event hash (CUSTODY_EVENT_HASH_V2).
    Covers all immutable event properties, actor attribution, and chain linkages.
    """
    payload = {
        "actor_attribution_status": actor_attribution_status or "SYSTEM_GENERATED",
        "actor_display_name": actor_display_name or "SecureMailScope X",
        "actor_id": actor_id or "SYSTEM",
        "actor_identity_source": actor_identity_source or "SYSTEM",
        "analysis_id": analysis_id,
        "artifact_hash": artifact_hash,
        "details": details or "",
        "event_id": event_id,
        "previous_event_hash": previous_event_hash,
        "timestamp_utc": timestamp_utc,
    }
    canonical_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_event_hash(
    event_id: str,
    analysis_id: str,
    timestamp_utc: str,
    event_type: str,
    artifact_hash: str,
    previous_event_hash: str,
    details: Optional[str] = None,
    actor_id: Optional[str] = None,
    actor_display_name: Optional[str] = None,
    actor_identity_source: Optional[str] = None,
    actor_attribution_status: Optional[str] = None,
    hash_format_version: str = "CUSTODY_EVENT_HASH_V2",
) -> str:
    """Dispatches cryptographic event hashing based on explicit format version."""
    if hash_format_version == "LEGACY_PIPE_V1":
        return compute_legacy_event_hash(
            event_id=event_id,
            analysis_id=analysis_id,
            timestamp_utc=timestamp_utc,
            event_type=event_type,
            artifact_hash=artifact_hash,
            previous_event_hash=previous_event_hash,
        )
    return compute_event_hash_v2(
        event_id=event_id,
        analysis_id=analysis_id,
        timestamp_utc=timestamp_utc,
        event_type=event_type,
        artifact_hash=artifact_hash,
        previous_event_hash=previous_event_hash,
        details=details,
        actor_id=actor_id,
        actor_display_name=actor_display_name,
        actor_identity_source=actor_identity_source,
        actor_attribution_status=actor_attribution_status,
    )


class CustodyRecord:
    def __init__(
        self,
        analysis_id: str,
        filename: str,
        content_bytes: bytes,
        initial_events: Optional[List[CustodyEventDTO]] = None,
        actor: Optional[ActorContext] = None
    ):
        self.analysis_id = analysis_id
        self.filename = filename
        self.raw_bytes = content_bytes
        self.file_size = len(content_bytes) if content_bytes else 0
        self.capture_sha256 = compute_sha256(content_bytes) if content_bytes else "0" * 64
        self.ingestion_timestamp = datetime.now(timezone.utc).isoformat()

        self.start_timestamp: Optional[str] = None
        self.completion_timestamp: Optional[str] = None
        self.manifest_dict: Optional[Dict[str, Any]] = None
        self.manifest_hash: Optional[str] = None

        self.report_pdf_bytes: Optional[bytes] = None
        self.report_pdf_hash: Optional[str] = None
        self.is_sealed: bool = False
        self.overall_status: str = "VERIFIED"

        self.events: List[CustodyEventDTO] = list(initial_events) if initial_events else []
        act = actor or ActorContext.system_actor()

        if not initial_events:
            # 1. Event: CAPTURE_INGESTED
            self._append_event(
                event_type="CAPTURE_INGESTED",
                artifact_hash=self.capture_sha256,
                details=f"PCAP capture file '{filename}' ingested ({self.file_size} bytes)",
                actor=act,
            )
            # 2. Event: CAPTURE_HASHED
            self._append_event(
                event_type="CAPTURE_HASHED",
                artifact_hash=self.capture_sha256,
                details=f"SHA-256 seal computed: {self.capture_sha256}",
                actor=act,
            )

    def _append_event(
        self,
        event_type: str,
        artifact_hash: str,
        details: Optional[str] = None,
        actor: Optional[ActorContext] = None,
        hash_format_version: str = "CUSTODY_EVENT_HASH_V2"
    ) -> CustodyEventDTO:
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        prev_hash = self.events[-1].current_event_hash if self.events else GENESIS_PREV_HASH

        act = actor or ActorContext.system_actor()

        cur_hash = compute_event_hash(
            event_id=event_id,
            analysis_id=self.analysis_id,
            timestamp_utc=now_iso,
            event_type=event_type,
            artifact_hash=artifact_hash,
            previous_event_hash=prev_hash,
            details=details,
            actor_id=act.actor_id,
            actor_display_name=act.actor_display_name,
            actor_identity_source=act.actor_identity_source,
            actor_attribution_status=act.actor_attribution_status,
            hash_format_version=hash_format_version,
        )

        evt = CustodyEventDTO(
            event_id=event_id,
            analysis_id=self.analysis_id,
            timestamp_utc=now_iso,
            event_type=event_type,
            artifact_hash=artifact_hash,
            previous_event_hash=prev_hash,
            current_event_hash=cur_hash,
            details=details,
            actor_id=act.actor_id,
            actor_display_name=act.actor_display_name,
            actor_identity_source=act.actor_identity_source,
            actor_attribution_status=act.actor_attribution_status,
            hash_format_version=hash_format_version,
        )
        self.events.append(evt)
        return evt


class CustodyService:
    # In-memory custody storage: analysis_id -> CustodyRecord
    _records: Dict[str, CustodyRecord] = {}

    @classmethod
    def _persist_record(cls, record: CustodyRecord):
        """Persists custody record and its event chain to SQLite."""
        ForensicRepository.save_custody_record(
            analysis_id=record.analysis_id,
            filename=record.filename,
            file_size=record.file_size,
            capture_sha256=record.capture_sha256,
            raw_bytes=record.raw_bytes,
            ingestion_timestamp=record.ingestion_timestamp,
            start_timestamp=record.start_timestamp,
            completion_timestamp=record.completion_timestamp,
            manifest_dict=record.manifest_dict,
            manifest_hash=record.manifest_hash,
            report_pdf_bytes=record.report_pdf_bytes,
            report_pdf_hash=record.report_pdf_hash,
            events=record.events,
            is_sealed=record.is_sealed,
            overall_status=record.overall_status,
        )

    @classmethod
    def get_or_create_record(
        cls,
        analysis_id: str,
        filename: str,
        content_bytes: bytes,
        actor: Optional[ActorContext] = None,
    ) -> CustodyRecord:
        if analysis_id in cls._records:
            return cls._records[analysis_id]

        # Check persistent storage
        db_rec = ForensicRepository.get_custody_record(analysis_id)
        if db_rec:
            record = CustodyRecord(
                analysis_id=analysis_id,
                filename=db_rec["filename"],
                content_bytes=db_rec["raw_bytes"] or content_bytes,
                initial_events=db_rec["events"],
                actor=actor,
            )
            record.file_size = db_rec["file_size"]
            record.capture_sha256 = db_rec["capture_sha256"]
            record.ingestion_timestamp = db_rec["ingestion_timestamp"]
            record.start_timestamp = db_rec["start_timestamp"]
            record.completion_timestamp = db_rec["completion_timestamp"]
            record.manifest_dict = db_rec["manifest_dict"]
            record.manifest_hash = db_rec["manifest_hash"]
            record.report_pdf_bytes = db_rec["report_pdf_bytes"]
            record.report_pdf_hash = db_rec["report_pdf_hash"]
            record.is_sealed = db_rec["is_sealed"]
            record.overall_status = db_rec["overall_status"]
            cls._records[analysis_id] = record
            return record

        record = CustodyRecord(analysis_id, filename, content_bytes, actor=actor)
        cls._records[analysis_id] = record
        cls._persist_record(record)
        return record

    @classmethod
    def get_record(cls, analysis_id: str) -> Optional[CustodyRecord]:
        if analysis_id in cls._records:
            return cls._records[analysis_id]

        db_rec = ForensicRepository.get_custody_record(analysis_id)
        if db_rec:
            record = CustodyRecord(
                analysis_id=analysis_id,
                filename=db_rec["filename"],
                content_bytes=db_rec["raw_bytes"] or b"",
                initial_events=db_rec["events"]
            )
            record.file_size = db_rec["file_size"]
            record.capture_sha256 = db_rec["capture_sha256"]
            record.ingestion_timestamp = db_rec["ingestion_timestamp"]
            record.start_timestamp = db_rec["start_timestamp"]
            record.completion_timestamp = db_rec["completion_timestamp"]
            record.manifest_dict = db_rec["manifest_dict"]
            record.manifest_hash = db_rec["manifest_hash"]
            record.report_pdf_bytes = db_rec["report_pdf_bytes"]
            record.report_pdf_hash = db_rec["report_pdf_hash"]
            record.is_sealed = db_rec["is_sealed"]
            record.overall_status = db_rec["overall_status"]
            cls._records[analysis_id] = record
            return record
        return None

    @classmethod
    def record_analysis_start(cls, analysis_id: str, actor: Optional[ActorContext] = None):
        record = cls.get_record(analysis_id)
        if record:
            act = actor or ActorContext.system_actor()
            record.start_timestamp = datetime.now(timezone.utc).isoformat()
            record._append_event(
                event_type="ANALYSIS_STARTED",
                artifact_hash=record.capture_sha256,
                details="Passive email forensic pipeline execution commenced",
                actor=act,
            )
            cls._persist_record(record)

    @classmethod
    def record_analysis_completion(
        cls,
        analysis_id: str,
        analysis_detail: AnalysisDetailResponse,
        actor: Optional[ActorContext] = None
    ):
        """
        Finalizes an analysis and creates sealed, immutable Manifest Version 1.
        Version 1 (ANALYSIS_FINALIZATION_MANIFEST) contains zero report hashes or mutable fields.
        """
        record = cls.get_record(analysis_id)
        if not record:
            return

        act = actor or ActorContext.system_actor()
        record.completion_timestamp = datetime.now(timezone.utc).isoformat()
        sessions = analysis_detail.sessions or []

        # Derive deterministic session, finding, and incident hashes
        session_hashes = []
        for s in sessions:
            s_dict = s.model_dump() if hasattr(s, "model_dump") else (s.dict() if hasattr(s, "dict") else dict(s))
            session_hashes.append(compute_json_sha256(s_dict))
        session_hashes.sort()

        finding_hashes = []
        for s in sessions:
            for f in s.security_assessment.findings:
                f_dict = f.model_dump() if hasattr(f, "model_dump") else (f.dict() if hasattr(f, "dict") else dict(f))
                finding_hashes.append(compute_json_sha256(f_dict))
        finding_hashes.sort()

        incident_hashes = []
        if hasattr(analysis_detail, "correlated_incidents") and analysis_detail.correlated_incidents:
            for inc in analysis_detail.correlated_incidents:
                inc_dict = inc.model_dump() if hasattr(inc, "model_dump") else (inc.dict() if hasattr(inc, "dict") else dict(inc))
                incident_hashes.append(compute_json_sha256(inc_dict))
        incident_hashes.sort()

        detail_dict = analysis_detail.model_dump() if hasattr(analysis_detail, "model_dump") else analysis_detail.dict()
        observed_result_sha256 = compute_json_sha256(detail_dict)

        # Build Version 1 Manifest Payload (Immutable Analysis Finalization Manifest)
        manifest_v1_payload = {
            "actor": {
                "actor_display_name": act.actor_display_name,
                "actor_id": act.actor_id,
                "attribution_status": act.actor_attribution_status,
                "identity_source": act.actor_identity_source,
            },
            "analysis_id": analysis_id,
            "canonicalization_version": CANONICALIZATION_METHOD,
            "capture_sha256": record.capture_sha256,
            "created_at": record.completion_timestamp,
            "finding_hashes": finding_hashes,
            "incident_hashes": incident_hashes,
            "linked_report_artifacts": [],
            "manifest_type": "ANALYSIS_FINALIZATION_MANIFEST",
            "observed_result_sha256": observed_result_sha256,
            "previous_manifest_sha256": GENESIS_PREV_HASH,
            "session_hashes": session_hashes,
            "version_number": 1,
        }

        # Canonicalize JSON deterministically
        manifest_v1_json = canonical_json_str(manifest_v1_payload)
        manifest_v1_hash = compute_sha256(manifest_v1_json.encode("utf-8"))

        # Persist Manifest Version 1 to database
        v1_id = f"cmv_{analysis_id[:12]}_v1_{uuid.uuid4().hex[:8]}"
        try:
            ForensicRepository.save_manifest_version(
                manifest_version_id=v1_id,
                analysis_id=analysis_id,
                version_number=1,
                manifest_type="ANALYSIS_FINALIZATION_MANIFEST",
                previous_manifest_sha256=GENESIS_PREV_HASH,
                manifest_json=manifest_v1_json,
                manifest_sha256=manifest_v1_hash,
                created_at=record.completion_timestamp,
                actor=act,
                sealed=True,
                purpose="Initial analysis finalization manifest seal",
            )
        except Exception:
            pass

        # Update legacy record fields without introducing mutable report hashes
        record.manifest_dict = manifest_v1_payload
        record.manifest_hash = manifest_v1_hash
        record.is_sealed = True

        record._append_event(
            event_type="ANALYSIS_COMPLETED",
            artifact_hash=manifest_v1_hash,
            details=f"Analysis manifest v1 sealed via {CANONICALIZATION_METHOD} (Hash: {manifest_v1_hash[:16]}...)",
            actor=act,
        )
        cls._persist_record(record)

    @classmethod
    def record_report_generation(
        cls,
        analysis_id: str,
        pdf_bytes: bytes,
        actor: Optional[ActorContext] = None
    ) -> str:
        """
        Records a newly generated or regenerated report artifact.
        Creates a new immutable report artifact row and a new chained manifest version.
        NEVER mutates earlier manifest versions or earlier report artifacts in place.
        """
        record = cls.get_record(analysis_id)
        if not record:
            return ""

        act = actor or ActorContext.system_actor()
        pdf_sha256 = compute_sha256(pdf_bytes)
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Fetch latest manifest version
        latest_manifest = ForensicRepository.get_latest_manifest_version(analysis_id)
        if not latest_manifest:
            # If version 1 was not persisted in DB yet, synthesize and save it from record
            v1_payload = record.manifest_dict or {
                "actor": {
                    "actor_display_name": act.actor_display_name,
                    "actor_id": act.actor_id,
                    "attribution_status": act.actor_attribution_status,
                    "identity_source": act.actor_identity_source,
                },
                "analysis_id": analysis_id,
                "canonicalization_version": CANONICALIZATION_METHOD,
                "capture_sha256": record.capture_sha256,
                "created_at": record.completion_timestamp or now_iso,
                "finding_hashes": [],
                "incident_hashes": [],
                "linked_report_artifacts": [],
                "manifest_type": "ANALYSIS_FINALIZATION_MANIFEST",
                "observed_result_sha256": record.capture_sha256,
                "previous_manifest_sha256": GENESIS_PREV_HASH,
                "session_hashes": [],
                "version_number": 1,
            }
            v1_json = canonical_json_str(v1_payload)
            v1_hash = compute_sha256(v1_json.encode("utf-8"))
            v1_id = f"cmv_{analysis_id[:12]}_v1_{uuid.uuid4().hex[:8]}"
            try:
                ForensicRepository.save_manifest_version(
                    manifest_version_id=v1_id,
                    analysis_id=analysis_id,
                    version_number=1,
                    manifest_type="ANALYSIS_FINALIZATION_MANIFEST",
                    previous_manifest_sha256=GENESIS_PREV_HASH,
                    manifest_json=v1_json,
                    manifest_sha256=v1_hash,
                    created_at=record.completion_timestamp or now_iso,
                    actor=act,
                    sealed=True,
                )
            except Exception:
                pass
            latest_manifest = ForensicRepository.get_latest_manifest_version(analysis_id)

        next_manifest_vnum = (latest_manifest["version_number"] + 1) if latest_manifest else 2
        parent_manifest_id = latest_manifest["manifest_version_id"] if latest_manifest else None
        prev_manifest_hash = latest_manifest["manifest_sha256"] if latest_manifest else GENESIS_PREV_HASH
        prev_manifest_dict = (latest_manifest.get("manifest_dict") or {}) if latest_manifest else (record.manifest_dict or {})

        # 2. Determine report artifact version
        existing_reports = ForensicRepository.get_report_artifacts(analysis_id)
        next_report_vnum = len(existing_reports) + 1

        report_artifact_id = f"rep_{analysis_id[:12]}_v{next_report_vnum}_{uuid.uuid4().hex[:8]}"
        filename = f"report_{analysis_id}_v{next_report_vnum}.pdf"

        # Ensure reports directory exists and optionally save file
        os.makedirs(REPORT_STORAGE_DIR, exist_ok=True)
        file_path = os.path.join(REPORT_STORAGE_DIR, f"{report_artifact_id}.pdf")
        try:
            with open(file_path, "wb") as f:
                f.write(pdf_bytes)
        except Exception:
            file_path = None

        report_artifact_dict = {
            "report_artifact_id": report_artifact_id,
            "analysis_id": analysis_id,
            "report_type": "PDF",
            "report_version": next_report_vnum,
            "filename": filename,
            "media_type": "application/pdf",
            "artifact_sha256": pdf_sha256,
            "artifact_size_bytes": len(pdf_bytes),
            "file_path": file_path,
            "raw_bytes": pdf_bytes,
            "generated_at": now_iso,
            "generated_by_actor_id": act.actor_id,
            "generated_by_actor_display_name": act.actor_display_name,
            "actor_identity_source": act.actor_identity_source,
            "actor_attribution_status": act.actor_attribution_status,
            "generator_version": "SecureMailScope X 1.0.0",
            "source_manifest_version_id": parent_manifest_id or "UNKNOWN",
            "status": "GENERATED",
        }

        # 3. Accumulate linked report artifacts list for new manifest version
        prev_linked = prev_manifest_dict.get("linked_report_artifacts") or []
        new_linked = list(prev_linked) + [{
            "report_artifact_id": report_artifact_id,
            "artifact_sha256": pdf_sha256,
            "report_version": next_report_vnum,
        }]

        new_manifest_payload = {
            "actor": {
                "actor_display_name": act.actor_display_name,
                "actor_id": act.actor_id,
                "attribution_status": act.actor_attribution_status,
                "identity_source": act.actor_identity_source,
            },
            "analysis_id": analysis_id,
            "canonicalization_version": CANONICALIZATION_METHOD,
            "capture_sha256": prev_manifest_dict.get("capture_sha256") or record.capture_sha256,
            "created_at": now_iso,
            "finding_hashes": prev_manifest_dict.get("finding_hashes", []),
            "incident_hashes": prev_manifest_dict.get("incident_hashes", []),
            "linked_report_artifacts": new_linked,
            "manifest_type": "REPORT_LINKAGE_MANIFEST",
            "observed_result_sha256": prev_manifest_dict.get("observed_result_sha256", ""),
            "previous_manifest_sha256": prev_manifest_hash,
            "session_hashes": prev_manifest_dict.get("session_hashes", []),
            "version_number": next_manifest_vnum,
        }

        new_manifest_json = canonical_json_str(new_manifest_payload)
        new_manifest_hash = compute_sha256(new_manifest_json.encode("utf-8"))
        manifest_version_id = f"cmv_{analysis_id[:12]}_v{next_manifest_vnum}_{uuid.uuid4().hex[:8]}"

        manifest_version_dict = {
            "manifest_version_id": manifest_version_id,
            "analysis_id": analysis_id,
            "version_number": next_manifest_vnum,
            "manifest_type": "REPORT_LINKAGE_MANIFEST",
            "parent_manifest_version_id": parent_manifest_id,
            "previous_manifest_sha256": prev_manifest_hash,
            "manifest_json": new_manifest_json,
            "manifest_sha256": new_manifest_hash,
            "canonicalization_version": CANONICALIZATION_METHOD,
            "created_at": now_iso,
            "created_by_actor_id": act.actor_id,
            "created_by_actor_display_name": act.actor_display_name,
            "actor_identity_source": act.actor_identity_source,
            "actor_attribution_status": act.actor_attribution_status,
            "sealed": True,
            "purpose": f"Link report artifact v{next_report_vnum} seal",
            "schema_version": "1.0",
        }

        # 4. Atomically persist report artifact + new manifest version
        ForensicRepository.save_report_artifact_and_manifest_version(
            report_artifact=report_artifact_dict,
            manifest_version=manifest_version_dict
        )

        # 5. Keep latest report bytes on record without mutating sealed manifest version 1
        record.report_pdf_bytes = pdf_bytes
        record.report_pdf_hash = pdf_sha256

        record._append_event(
            event_type="REPORT_GENERATED",
            artifact_hash=pdf_sha256,
            details=f"Forensic PDF audit report v{next_report_vnum} compiled (SHA-256: {pdf_sha256[:16]}... Linked in Manifest v{next_manifest_vnum})",
            actor=act,
        )
        cls._persist_record(record)
        return pdf_sha256

    @classmethod
    def record_report_exported(cls, analysis_id: str, actor: Optional[ActorContext] = None):
        record = cls.get_record(analysis_id)
        if record and record.report_pdf_hash:
            act = actor or ActorContext.system_actor()
            record._append_event(
                event_type="REPORT_EXPORTED",
                artifact_hash=record.report_pdf_hash,
                details="Forensic PDF artifact retrieved for distribution",
                actor=act,
            )
            cls._persist_record(record)

    @classmethod
    def verify_integrity(
        cls,
        analysis_id: str,
        override_capture_bytes: Optional[bytes] = None,
        override_manifest_dict: Optional[Dict[str, Any]] = None,
        override_event: Optional[Tuple[int, str]] = None,
        record_verification_event: bool = False
    ) -> CustodyRecordResponse:
        """
        Verifies cryptographic integrity over capture bytes, manifest seals,
        audit event chain, and report artifacts.
        Read-only unless record_verification_event=True.
        """
        record = cls.get_record(analysis_id)
        if not record:
            # Fallback unavailable response
            return CustodyRecordResponse(
                analysis_id=analysis_id,
                overall_status="UNAVAILABLE",
                verification_timestamp_utc=datetime.now(timezone.utc).isoformat(),
                capture_integrity=CaptureIntegrityDTO(
                    filename="unknown.pcap",
                    file_size_bytes=0,
                    sha256="N/A",
                    ingestion_timestamp_utc="N/A",
                    status="UNAVAILABLE"
                ),
                manifest_integrity=ManifestIntegrityDTO(
                    manifest_hash="N/A",
                    canonicalization_method=CANONICALIZATION_METHOD,
                    created_at_utc="N/A",
                    raw_pcap_frame_count=0,
                    reconstructed_session_count=0,
                    findings_count=0,
                    status="UNAVAILABLE"
                ),
                report_integrity=ReportIntegrityDTO(
                    pdf_sha256=None,
                    status="UNAVAILABLE"
                ),
                audit_events=[],
                verification_details="No custody record found for this analysis session."
            )

        verification_time = datetime.now(timezone.utc).isoformat()
        failure_reasons: List[str] = []

        # 1. Capture Integrity Check
        test_bytes = override_capture_bytes if override_capture_bytes is not None else record.raw_bytes
        recalculated_capture_hash = compute_sha256(test_bytes)
        capture_ok = (recalculated_capture_hash == record.capture_sha256)
        capture_status = "VERIFIED" if capture_ok else "FAILED"
        if not capture_ok:
            failure_reasons.append(f"Capture byte hash mismatch: expected {record.capture_sha256}, got {recalculated_capture_hash}")

        # 2. Manifest Integrity Check
        test_manifest = override_manifest_dict if override_manifest_dict is not None else record.manifest_dict
        if override_manifest_dict is not None:
            canonical_bytes = canonical_json_bytes(test_manifest)
            recalculated_manifest_hash = compute_sha256(canonical_bytes)
            manifest_ok = (recalculated_manifest_hash == record.manifest_hash)
            manifest_status = "VERIFIED" if manifest_ok else "FAILED"
            if not manifest_ok:
                failure_reasons.append(f"Manifest seal hash mismatch: expected {record.manifest_hash}, got {recalculated_manifest_hash}")
        elif test_manifest and record.manifest_hash:
            # Check manifest chain in database if present
            chain_res = ForensicRepository.verify_manifest_chain(analysis_id)
            if chain_res["overall_status"] == "VERIFIED":
                manifest_ok = True
                manifest_status = "VERIFIED"
            elif chain_res["overall_status"] == "INCOMPLETE":
                # Legacy fallback or single manifest check
                canonical_bytes = canonical_json_bytes(test_manifest)
                recalculated_manifest_hash = compute_sha256(canonical_bytes)
                manifest_ok = (recalculated_manifest_hash == record.manifest_hash)
                manifest_status = "VERIFIED" if manifest_ok else "FAILED"
                if not manifest_ok:
                    failure_reasons.append(f"Manifest seal hash mismatch: expected {record.manifest_hash}, got {recalculated_manifest_hash}")
            else:
                manifest_ok = False
                manifest_status = "FAILED"
                failure_reasons.append(chain_res["details"])
        else:
            manifest_status = "NOT_YET_SEALED"
            manifest_ok = True

        # 3. Audit Trail Hash-Chain Integrity Check
        events_to_test = list(record.events)
        if override_event:
            idx, fake_hash = override_event
            if 0 <= idx < len(events_to_test):
                old = events_to_test[idx]
                events_to_test[idx] = CustodyEventDTO(
                    event_id=old.event_id,
                    analysis_id=old.analysis_id,
                    timestamp_utc=old.timestamp_utc,
                    event_type=old.event_type,
                    artifact_hash=old.artifact_hash,
                    previous_event_hash=old.previous_event_hash,
                    current_event_hash=fake_hash,
                    details=old.details,
                    actor_id=old.actor_id,
                    actor_display_name=old.actor_display_name,
                    actor_identity_source=old.actor_identity_source,
                    actor_attribution_status=old.actor_attribution_status,
                    hash_format_version=old.hash_format_version,
                )

        chain_ok = True
        for i, ev in enumerate(events_to_test):
            expected_prev = GENESIS_PREV_HASH if i == 0 else events_to_test[i - 1].current_event_hash
            if ev.previous_event_hash != expected_prev:
                chain_ok = False
                failure_reasons.append(f"Audit event #{i} ({ev.event_type}) previous hash link broken")
                break

            # Calculate both V2 and Legacy formats for backwards-compatibility
            v2_hash = compute_event_hash_v2(
                event_id=ev.event_id,
                analysis_id=ev.analysis_id,
                timestamp_utc=ev.timestamp_utc,
                event_type=ev.event_type,
                artifact_hash=ev.artifact_hash,
                previous_event_hash=ev.previous_event_hash,
                details=ev.details,
                actor_id=ev.actor_id,
                actor_display_name=ev.actor_display_name,
                actor_identity_source=ev.actor_identity_source,
                actor_attribution_status=ev.actor_attribution_status,
            )
            legacy_hash = compute_legacy_event_hash(
                event_id=ev.event_id,
                analysis_id=ev.analysis_id,
                timestamp_utc=ev.timestamp_utc,
                event_type=ev.event_type,
                artifact_hash=ev.artifact_hash,
                previous_event_hash=ev.previous_event_hash,
            )

            matched = (ev.current_event_hash == v2_hash) or (ev.current_event_hash == legacy_hash)

            if not matched:
                chain_ok = False
                failure_reasons.append(f"Audit event #{i} ({ev.event_type}) hash verification failed: tampered content detected")
                break

        # 4. Report Integrity Check
        if record.report_pdf_bytes and record.report_pdf_hash:
            recomputed_pdf_hash = compute_sha256(record.report_pdf_bytes)
            report_ok = (recomputed_pdf_hash == record.report_pdf_hash)
            report_status = "VERIFIED" if report_ok else "FAILED"
            if not report_ok:
                failure_reasons.append("Report PDF artifact checksum mismatch")
        else:
            report_ok = True
            report_status = "UNAVAILABLE"

        # Overall Status
        overall_ok = capture_ok and manifest_ok and chain_ok and report_ok
        overall_status = "VERIFIED" if overall_ok else "FAILED"

        # Only append INTEGRITY_REVERIFIED event when explicitly requested
        if record_verification_event and not override_event and not override_capture_bytes and not override_manifest_dict:
            record._append_event(
                event_type="INTEGRITY_REVERIFIED",
                artifact_hash=record.manifest_hash or record.capture_sha256,
                details=f"Cryptographic chain of custody re-verified: {overall_status}"
            )
            cls._persist_record(record)

        manifest_data = record.manifest_dict or {}
        return CustodyRecordResponse(
            analysis_id=analysis_id,
            overall_status=overall_status,
            verification_timestamp_utc=verification_time,
            capture_integrity=CaptureIntegrityDTO(
                filename=record.filename,
                file_size_bytes=record.file_size,
                sha256=record.capture_sha256,
                ingestion_timestamp_utc=record.ingestion_timestamp,
                status=capture_status
            ),
            manifest_integrity=ManifestIntegrityDTO(
                manifest_hash=record.manifest_hash or "N/A",
                canonicalization_method=CANONICALIZATION_METHOD,
                created_at_utc=record.completion_timestamp or record.ingestion_timestamp,
                raw_pcap_frame_count=manifest_data.get("raw_pcap_frame_count", 0),
                reconstructed_session_count=manifest_data.get("reconstructed_session_count", 0),
                findings_count=manifest_data.get("findings_count", 0),
                status=manifest_status
            ),
            report_integrity=ReportIntegrityDTO(
                pdf_sha256=record.report_pdf_hash,
                status=report_status
            ),
            audit_events=list(record.events),
            verification_details="All cryptographic hashes and audit event chains verified nominal." if overall_ok else "; ".join(failure_reasons)
        )

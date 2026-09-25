"""
SecureMailScope X - Local Forensic Chain of Custody & Evidence Sealing Service
Implements append-only chained cryptographic audit trails, deterministic manifest sealing,
persistent database synchronization, and real-time tamper verification.
"""

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
    AnalysisDetailResponse
)
from app.db.repository import ForensicRepository

GENESIS_PREV_HASH = "0" * 64
CANONICALIZATION_METHOD = "SECUREMAILSCOPE_CANONICAL_JSON_V1"


def compute_sha256(data: bytes) -> str:
    """Compute standard lowercase hex SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def compute_event_hash(
    event_id: str,
    analysis_id: str,
    timestamp_utc: str,
    event_type: str,
    artifact_hash: str,
    previous_event_hash: str
) -> str:
    """Compute deterministic cryptographic hash linking this event to the previous event."""
    payload = f"{event_id}|{analysis_id}|{timestamp_utc}|{event_type}|{artifact_hash}|{previous_event_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CustodyRecord:
    def __init__(self, analysis_id: str, filename: str, content_bytes: bytes, initial_events: Optional[List[CustodyEventDTO]] = None):
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
        
        self.events: List[CustodyEventDTO] = initial_events or []
        
        if not initial_events:
            # 1. Event: CAPTURE_INGESTED
            self._append_event(
                event_type="CAPTURE_INGESTED",
                artifact_hash=self.capture_sha256,
                details=f"PCAP capture file '{filename}' ingested ({self.file_size} bytes)"
            )
            # 2. Event: CAPTURE_HASHED
            self._append_event(
                event_type="CAPTURE_HASHED",
                artifact_hash=self.capture_sha256,
                details=f"SHA-256 seal computed: {self.capture_sha256}"
            )

    def _append_event(self, event_type: str, artifact_hash: str, details: Optional[str] = None) -> CustodyEventDTO:
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        prev_hash = self.events[-1].current_event_hash if self.events else GENESIS_PREV_HASH
        
        cur_hash = compute_event_hash(
            event_id=event_id,
            analysis_id=self.analysis_id,
            timestamp_utc=now_iso,
            event_type=event_type,
            artifact_hash=artifact_hash,
            previous_event_hash=prev_hash
        )
        
        evt = CustodyEventDTO(
            event_id=event_id,
            analysis_id=self.analysis_id,
            timestamp_utc=now_iso,
            event_type=event_type,
            artifact_hash=artifact_hash,
            previous_event_hash=prev_hash,
            current_event_hash=cur_hash,
            details=details
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
        content_bytes: bytes
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

        record = CustodyRecord(analysis_id, filename, content_bytes)
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
    def record_analysis_start(cls, analysis_id: str):
        record = cls.get_record(analysis_id)
        if record:
            record.start_timestamp = datetime.now(timezone.utc).isoformat()
            record._append_event(
                event_type="ANALYSIS_STARTED",
                artifact_hash=record.capture_sha256,
                details="Passive email forensic pipeline execution commenced"
            )
            cls._persist_record(record)

    @classmethod
    def record_analysis_completion(
        cls,
        analysis_id: str,
        analysis_detail: AnalysisDetailResponse
    ):
        record = cls.get_record(analysis_id)
        if not record:
            return

        record.completion_timestamp = datetime.now(timezone.utc).isoformat()
        sessions = analysis_detail.sessions or []
        protocols = sorted(list(set(s.protocol for s in sessions))) if sessions else []
        findings_count = sum(len(s.security_assessment.findings) for s in sessions)

        # Build Canonical Analysis Manifest
        raw_frames = analysis_detail.raw_capture_packets_total or analysis_detail.total_packets_extracted
        manifest = {
            "analysis_id": analysis_id,
            "backend_version": "SecureMailScope X 1.0.0",
            "findings_count": findings_count,
            "original_capture_sha256": record.capture_sha256,
            "original_filename": record.filename,
            "original_file_size_bytes": record.file_size,
            "protocol_inventory": protocols,
            "raw_pcap_frame_count": raw_frames,
            "reconstructed_session_count": analysis_detail.email_sessions_found,
            "report_pdf_hash": record.report_pdf_hash,
            "tshark_version": analysis_detail.tshark_version
        }

        # Deterministic JSON canonicalization
        canonical_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest_hash = compute_sha256(canonical_bytes)

        record.manifest_dict = manifest
        record.manifest_hash = manifest_hash
        record.is_sealed = True

        record._append_event(
            event_type="ANALYSIS_COMPLETED",
            artifact_hash=manifest_hash,
            details=f"Analysis manifest sealed via {CANONICALIZATION_METHOD} (Hash: {manifest_hash[:16]}...)"
        )
        cls._persist_record(record)

    @classmethod
    def record_report_generation(cls, analysis_id: str, pdf_bytes: bytes) -> str:
        record = cls.get_record(analysis_id)
        if not record:
            return ""

        pdf_sha256 = compute_sha256(pdf_bytes)
        record.report_pdf_bytes = pdf_bytes
        record.report_pdf_hash = pdf_sha256

        if record.manifest_dict is not None:
            record.manifest_dict["report_pdf_hash"] = pdf_sha256
            canonical_bytes = json.dumps(record.manifest_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
            record.manifest_hash = compute_sha256(canonical_bytes)

        record._append_event(
            event_type="REPORT_GENERATED",
            artifact_hash=pdf_sha256,
            details=f"Forensic PDF audit report compiled (SHA-256: {pdf_sha256[:16]}...)"
        )
        cls._persist_record(record)
        return pdf_sha256

    @classmethod
    def record_report_exported(cls, analysis_id: str):
        record = cls.get_record(analysis_id)
        if record and record.report_pdf_hash:
            record._append_event(
                event_type="REPORT_EXPORTED",
                artifact_hash=record.report_pdf_hash,
                details="Forensic PDF artifact retrieved for distribution"
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
        if test_manifest and record.manifest_hash:
            canonical_bytes = json.dumps(test_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
            recalculated_manifest_hash = compute_sha256(canonical_bytes)
            manifest_ok = (recalculated_manifest_hash == record.manifest_hash)
            manifest_status = "VERIFIED" if manifest_ok else "FAILED"
            if not manifest_ok:
                failure_reasons.append(f"Manifest seal hash mismatch: expected {record.manifest_hash}, got {recalculated_manifest_hash}")
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
                    details=old.details
                )

        chain_ok = True
        for i, ev in enumerate(events_to_test):
            expected_prev = GENESIS_PREV_HASH if i == 0 else events_to_test[i - 1].current_event_hash
            if ev.previous_event_hash != expected_prev:
                chain_ok = False
                failure_reasons.append(f"Audit event #{i} ({ev.event_type}) previous hash link broken")
                break
            
            recomputed_hash = compute_event_hash(
                event_id=ev.event_id,
                analysis_id=ev.analysis_id,
                timestamp_utc=ev.timestamp_utc,
                event_type=ev.event_type,
                artifact_hash=ev.artifact_hash,
                previous_event_hash=ev.previous_event_hash
            )
            if ev.current_event_hash != recomputed_hash:
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

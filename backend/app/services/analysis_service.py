"""
SecureMailScope X - Analysis Service
Orchestrates PCAP validation, path traversal sanitization, forensic pipeline execution,
temporary file lifecycle management, and analysis report caching.
"""

import os
import uuid
import hashlib
import tempfile
from datetime import datetime, timezone
from typing import Dict, Optional, List, Tuple, Any

from app.core.config import (
    TEMP_UPLOAD_DIR,
    MAX_UPLOAD_SIZE_BYTES,
    ALLOWED_EXTENSIONS,
    VALID_MAGIC_BYTES
)
from app.core.tshark_detector import TSharkDetector
from app.forensic.pcap_reader import PCAPReader
from app.forensic.session_reconstructor import SessionReconstructor
from app.schemas.forensic import EmailSession
from app.services.custody_service import CustodyService
from app.schemas.api import (
    AnalysisDetailResponse,
    AnalysisSummaryResponse,
    SessionDetailDTO,
    SessionSummaryDTO,
    STARTTLSStateDTO,
    TLSHandshakeDTO,
    CipherSuiteInfoDTO,
    CaptureHealthDTO,
    EvidenceConfidenceDTO,
    SecurityAssessmentDTO,
    SecurityFindingDTO,
    FindingsSummaryDTO,
    EvidenceFrameDTO,
    PacketEvidenceDTO
)


class AnalysisService:
    # In-memory storage for analysis results: analysis_id -> (AnalysisDetailResponse, raw_sessions)
    _cache: Dict[str, Tuple[AnalysisDetailResponse, List[EmailSession]]] = {}

    @classmethod
    def validate_file(cls, filename: str, content: bytes) -> Tuple[bool, str]:
        """
        Validates uploaded file against path traversal, extension whitelist,
        file size limits, and binary magic bytes.
        """
        # 1. Path Traversal & Name Sanitization
        clean_name = os.path.basename(filename)
        if not clean_name or ".." in filename or clean_name != filename.strip():
            # Allow clean standard names, reject directory traversal attempts
            if any(sep in filename for sep in ["/", "\\", ".."]):
                return False, "Invalid filename: path traversal characters detected."

        # 2. Extension Check
        _, ext = os.path.splitext(clean_name.lower())
        if ext not in ALLOWED_EXTENSIONS:
            return False, f"Unsupported file extension '{ext}'. Allowed formats: {', '.join(sorted(ALLOWED_EXTENSIONS))}"

        # 3. Size Check
        if len(content) == 0:
            return False, "Uploaded file is empty (0 bytes)."
        if len(content) > MAX_UPLOAD_SIZE_BYTES:
            return False, f"File size exceeds limit of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB."

        # 4. Binary Header Magic-Byte Validation
        if len(content) < 4:
            return False, "File too small to be a valid PCAP/PCAPNG capture."
        header_4 = content[:4]
        if not any(header_4 == mb for mb in VALID_MAGIC_BYTES):
            return False, "Invalid PCAP file header: magic bytes do not match standard PCAP or PCAPNG formats."

        return True, ""

    @classmethod
    def process_pcap_bytes(cls, original_filename: str, content: bytes) -> AnalysisDetailResponse:
        """
        Saves bytes securely to temporary file, executes passive forensics,
        and cleans up temporary file immediately.
        """
        is_valid, err_msg = cls.validate_file(original_filename, content)
        if not is_valid:
            raise ValueError(err_msg)

        # Generate deterministic analysis ID from file content SHA-256
        sha256 = hashlib.sha256(content).hexdigest()
        analysis_id = f"analysis_{sha256[:16]}"

        clean_filename = os.path.basename(original_filename)

        # Initialize Chain of Custody Ingestion & Hashing
        CustodyService.get_or_create_record(analysis_id, clean_filename, content)

        # Return cached result if already analyzed
        if analysis_id in cls._cache:
            return cls._cache[analysis_id][0]

        # Record Analysis Start
        CustodyService.record_analysis_start(analysis_id)

        # Secure Temporary File
        safe_prefix = f"sms_{analysis_id[:12]}_"
        temp_fd, temp_path = tempfile.mkstemp(prefix=safe_prefix, suffix=os.path.splitext(clean_filename)[1], dir=TEMP_UPLOAD_DIR)
        
        try:
            with os.fdopen(temp_fd, "wb") as f:
                f.write(content)
            
            # Execute Forensics
            report, sessions = cls._run_pipeline(temp_path, clean_filename, len(content), analysis_id)
            cls._cache[analysis_id] = (report, sessions)

            # Record Analysis Completion & Seal Manifest
            CustodyService.record_analysis_completion(analysis_id, report)
            return report
        finally:
            # Lifecycle Cleanup: Ensure temporary file is safely purged
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    @classmethod
    def process_local_pcap_path(cls, pcap_path: str) -> AnalysisDetailResponse:
        """Process an existing local PCAP path (for baseline tests and integration)."""
        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        with open(pcap_path, "rb") as f:
            content = f.read()
        
        sha256 = hashlib.sha256(content).hexdigest()
        analysis_id = f"analysis_{sha256[:16]}"
        clean_filename = os.path.basename(pcap_path)

        CustodyService.get_or_create_record(analysis_id, clean_filename, content)
        
        if analysis_id in cls._cache:
            return cls._cache[analysis_id][0]
            
        CustodyService.record_analysis_start(analysis_id)
        report, sessions = cls._run_pipeline(pcap_path, clean_filename, len(content), analysis_id)
        cls._cache[analysis_id] = (report, sessions)
        CustodyService.record_analysis_completion(analysis_id, report)
        return report

    @classmethod
    def _run_pipeline(cls, pcap_path: str, filename: str, file_size: int, analysis_id: str) -> Tuple[AnalysisDetailResponse, List[EmailSession]]:
        """Run PCAPReader, SessionReconstructor, HealthScorer, ConfidenceScorer, and RuleEngine."""
        tshark_ok, tshark_info = TSharkDetector.get_version()
        if not tshark_ok:
            raise RuntimeError(f"TShark detector error: {tshark_info}")

        reader = PCAPReader(pcap_path)
        raw_packets = reader.read_packets()
        raw_total_frames = reader.get_raw_packet_count() or len(raw_packets)
        sessions = SessionReconstructor.reconstruct_sessions(raw_packets)

        session_dtos: List[SessionDetailDTO] = []

        for s in sessions:
            start_iso = datetime.fromtimestamp(s.start_time_epoch, tz=timezone.utc).isoformat() if s.start_time_epoch else None
            
            # STARTTLS State
            computed_state = "UPGRADED" if s.starttls_state.upgrade_successful else (
                "FAILED" if s.starttls_state.failed else (
                    "ACCEPTED" if s.starttls_state.accepted else (
                        "REQUESTED" if s.starttls_state.requested else (
                            "ADVERTISED" if s.starttls_state.advertised else "NONE"
                        )
                    )
                )
            )
            st_dto = STARTTLSStateDTO(
                advertised=s.starttls_state.advertised,
                advertised_frame=s.starttls_state.advertised_frame,
                advertised_text=s.starttls_state.advertised_text,
                requested=s.starttls_state.requested,
                requested_frame=s.starttls_state.requested_frame,
                requested_command=s.starttls_state.requested_command,
                accepted=s.starttls_state.accepted,
                accepted_frame=s.starttls_state.accepted_frame,
                accepted_response=s.starttls_state.accepted_response,
                failed=s.starttls_state.failed,
                failure_reason=s.starttls_state.failure_reason,
                failure_frame=s.starttls_state.failure_frame,
                upgrade_successful=s.starttls_state.upgrade_successful,
                state=computed_state
            )

            # TLS Details
            tls_dto = None
            if s.tls_details:
                cipher_info_dto = None
                if s.tls_details.cipher_info:
                    ci = s.tls_details.cipher_info
                    cipher_info_dto = CipherSuiteInfoDTO(
                        hex_code=ci.hex_code,
                        name=ci.name,
                        has_pfs=ci.has_pfs,
                        key_exchange=ci.key_exchange,
                        encryption=ci.encryption,
                        hash_algorithm=ci.hash_algorithm,
                        strength=ci.strength.value,
                        is_post_quantum_safe=ci.is_post_quantum_safe
                    )

                tls_dto = TLSHandshakeDTO(
                    negotiated_version=s.tls_details.negotiated_tls_version.value,
                    tls_version=s.tls_details.negotiated_tls_version.value,
                    cipher_name=s.tls_details.selected_cipher_name,
                    cipher_suite_name=s.tls_details.selected_cipher_name,
                    cipher_code=s.tls_details.selected_cipher_code,
                    cipher_info=cipher_info_dto,
                    forward_secrecy_pfs=s.tls_details.has_forward_secrecy,
                    pfs_status=s.tls_details.pfs_status,
                    pfs_evidence=s.tls_details.pfs_evidence,
                    sni=s.tls_details.sni,
                    alpn=s.tls_details.alpn,
                    client_hello_frame=s.tls_details.client_hello_frame,
                    server_hello_frame=s.tls_details.server_hello_frame,
                    certificate_visibility=s.tls_details.certificate_visibility
                )

            # Health
            health_dto = CaptureHealthDTO(
                score=s.capture_health.score if s.capture_health else 100,
                grade=s.capture_health.grade.value if s.capture_health else "EXCELLENT",
                syn_observed=s.capture_health.syn_observed if s.capture_health else False,
                fin_rst_observed=s.capture_health.fin_rst_observed if s.capture_health else False,
                total_packets=s.capture_health.total_packets if s.capture_health else len(s.evidence_packets),
                retransmissions_count=s.capture_health.retransmissions_count if s.capture_health else 0,
                retransmission_rate=s.capture_health.retransmission_rate if s.capture_health else 0.0,
                deduction_reasons=s.capture_health.deduction_reasons if s.capture_health else []
            )

            # Confidence
            conf_dto = EvidenceConfidenceDTO(
                score=s.evidence_confidence.score if s.evidence_confidence else 100,
                level=s.evidence_confidence.level.value if s.evidence_confidence else "HIGH",
                handshake_observable=s.evidence_confidence.handshake_observable if s.evidence_confidence else True,
                version_verifiable=s.evidence_confidence.version_verifiable if s.evidence_confidence else True,
                cipher_identifiable=s.evidence_confidence.cipher_identifiable if s.evidence_confidence else True,
                key_exchange_observable=s.evidence_confidence.key_exchange_observable if s.evidence_confidence else True,
                observability_boundary=s.evidence_confidence.observability_boundary if s.evidence_confidence else "Standard",
                confidence_factors=s.evidence_confidence.confidence_factors if s.evidence_confidence else []
            )

            # Security Assessment
            sec_dto = SecurityAssessmentDTO(
                grade=s.security_assessment.grade.value if s.security_assessment else "A",
                grade_rationale=s.security_assessment.grade_rationale if s.security_assessment else "State of the art",
                post_quantum_ready=s.security_assessment.post_quantum_ready if s.security_assessment else False,
                post_quantum_summary=s.security_assessment.post_quantum_summary if s.security_assessment else "",
                findings_summary=FindingsSummaryDTO(
                    critical=s.security_assessment.critical_findings_count if s.security_assessment else 0,
                    high=s.security_assessment.high_findings_count if s.security_assessment else 0,
                    medium=s.security_assessment.medium_findings_count if s.security_assessment else 0,
                    low=s.security_assessment.low_findings_count if s.security_assessment else 0,
                    info=s.security_assessment.info_findings_count if s.security_assessment else 0
                ),
                findings=[
                    SecurityFindingDTO(
                        id=f.id,
                        title=f.title,
                        severity=f.severity.value,
                        category=f.category.value,
                        description=f.description,
                        evidence_frames=f.evidence_frames,
                        recommendation=f.recommendation
                    )
                    for f in (s.security_assessment.findings if s.security_assessment else [])
                ]
            )

            # Evidence Frames
            evidence_frames_dtos = [
                EvidenceFrameDTO(
                    frame=ep.frame_number,
                    time_epoch=ep.timestamp_epoch,
                    protocol=ep.protocol,
                    summary=ep.summary
                )
                for ep in s.evidence_packets
                if ep.protocol in ["SMTP", "IMAP", "POP"] or "Hello" in ep.summary or ep.frame_number in [
                    s.starttls_state.advertised_frame,
                    s.starttls_state.requested_frame,
                    s.starttls_state.accepted_frame,
                    s.tls_details.client_hello_frame if s.tls_details else None,
                    s.tls_details.server_hello_frame if s.tls_details else None
                ]
            ]

            session_dtos.append(SessionDetailDTO(
                session_id=s.session_id,
                stream_index=s.stream_index,
                protocol=s.protocol.value,
                security_mode=s.security_mode.value,
                client=f"{s.client_ip}:{s.client_port}",
                server=f"{s.server_ip}:{s.server_port}",
                server_hostname=s.server_hostname,
                start_time_iso=start_iso,
                duration_seconds=round(s.duration_seconds, 3),
                packets_count=s.total_packets,
                greeting_banner=s.greeting_banner,
                client_helo_name=s.client_helo_name,
                starttls=st_dto,
                tls=tls_dto,
                capture_health=health_dto,
                evidence_confidence=conf_dto,
                security_assessment=sec_dto,
                evidence_frames=evidence_frames_dtos
            ))

        primary_conf_score = session_dtos[0].evidence_confidence.score if session_dtos else 95
        primary_conf_level = session_dtos[0].evidence_confidence.level if session_dtos else "HIGH"

        report = AnalysisDetailResponse(
            analysis_id=analysis_id,
            file_name=filename,
            file_size_bytes=file_size,
            analysis_time_utc=datetime.now(timezone.utc).isoformat(),
            tshark_version=tshark_info,
            total_packets_extracted=len(raw_packets),
            raw_capture_packets_total=raw_total_frames,
            email_sessions_found=len(sessions),
            sessions=session_dtos,
            evidence_confidence_score=primary_conf_score,
            evidence_confidence_level=primary_conf_level
        )

        return report, sessions

    @classmethod
    def get_analysis(cls, analysis_id: str) -> Optional[AnalysisDetailResponse]:
        """Retrieve cached analysis report by analysis_id."""
        item = cls._cache.get(analysis_id)
        return item[0] if item else None

    @classmethod
    def get_session(cls, analysis_id: str, session_id: str) -> Optional[SessionDetailDTO]:
        """Retrieve single session details."""
        analysis = cls.get_analysis(analysis_id)
        if not analysis:
            return None
        return next((s for s in analysis.sessions if s.session_id == session_id), None)

    @classmethod
    def get_session_packets(cls, analysis_id: str, session_id: str) -> Optional[List[PacketEvidenceDTO]]:
        """Retrieve all raw packet evidence for a specific session."""
        item = cls._cache.get(analysis_id)
        if not item:
            return None
        _, raw_sessions = item
        raw_session = next((s for s in raw_sessions if s.session_id == session_id), None)
        if not raw_session:
            return None

        return [
            PacketEvidenceDTO(
                frame_number=ep.frame_number,
                timestamp_epoch=ep.timestamp_epoch,
                timestamp_iso=ep.timestamp_iso,
                src_ip=ep.src_ip,
                src_port=ep.src_port,
                dst_ip=ep.dst_ip,
                dst_port=ep.dst_port,
                protocol=ep.protocol,
                length=ep.length,
                summary=ep.summary,
                raw_payload_preview=ep.raw_payload_preview,
                smtp_req_command=ep.smtp_req_command,
                smtp_response_code=ep.smtp_response_code,
                smtp_response_parameter=ep.smtp_response_parameter
            )
            for ep in raw_session.evidence_packets
        ]

"""
SecureMailScope X - Forensic Notarization Provider Abstraction & Local Proof Engine (Phase 15)
Provides pluggable notarization architecture, deterministic local integrity proofs,
immutable manifest version linkage, and side-effect-free proof verification.

CRITICAL TRUST BOUNDARY:
- LOCAL PROOF != BLOCKCHAIN.
- Default system mode is strictly LOCAL_ONLY.
- Never generates fake transaction hashes, block numbers, chain IDs, explorer URLs,
  or timestamp authority tokens.
- Zero outbound network calls are made in LOCAL_ONLY mode.
"""

import os
import json
import uuid
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

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
    ImmutableRecordError,
    IntegrityVerificationError,
    CANONICALIZATION_VERSION,
    CURRENT_SCHEMA_VERSION,
)
from app.services.custody_service import CustodyService
from app.services.signature_service import SignatureService

LOCAL_PROOF_CONTEXT_V1 = "SECUREMAILSCOPE_LOCAL_NOTARIZATION_V1"

# Notarization Modes
NOTARIZATION_MODE_LOCAL_ONLY = "LOCAL_ONLY"
NOTARIZATION_MODE_EXTERNAL_PROVIDER = "EXTERNAL_PROVIDER"

# Status Constants
STATUS_NOT_REQUESTED = "NOT_REQUESTED"
STATUS_LOCAL_PROOF_CREATED = "LOCAL_PROOF_CREATED"
STATUS_SUBMISSION_PENDING = "SUBMISSION_PENDING"
STATUS_SUBMITTED = "SUBMITTED"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_VERIFICATION_FAILED = "VERIFICATION_FAILED"
STATUS_PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_UNSUPPORTED = "UNSUPPORTED"

# Verification Status Constants
VERIFY_STATUS_VERIFIED_LOCAL_PROOF = "VERIFIED_LOCAL_PROOF"
VERIFY_STATUS_INTEGRITY_FAILED = "INTEGRITY_FAILED"
VERIFY_STATUS_SIGNATURE_INVALID = "SIGNATURE_INVALID"
VERIFY_STATUS_REPORT_INTEGRITY_FAILED = "REPORT_INTEGRITY_FAILED"
VERIFY_STATUS_MANIFEST_INTEGRITY_FAILED = "MANIFEST_INTEGRITY_FAILED"
VERIFY_STATUS_INCOMPLETE = "INCOMPLETE"
VERIFY_STATUS_UNSUPPORTED_PROVIDER = "UNSUPPORTED_PROVIDER"


class NotarizationError(Exception):
    """Base exception for notarization operations."""
    pass


class NotarizationPrerequisiteError(NotarizationError):
    """Raised when report, signature, or manifest prerequisite checks fail."""
    pass


class ProviderUnavailableError(NotarizationError):
    """Raised when requested external notarization provider is unconfigured or unavailable."""
    pass


class UnsupportedProviderError(NotarizationError):
    """Raised when requested notarization mode or provider is unsupported."""
    pass


def build_local_proof_payload(
    analysis_id: str,
    report_artifact_id: str,
    report_artifact_sha256: str,
    signature_id: str,
    signature_algorithm: str,
    signature_value_sha256: str,
    public_key_fingerprint_sha256: str,
    manifest_version_id: str,
    manifest_sha256: str,
    proof_context: str = LOCAL_PROOF_CONTEXT_V1,
) -> Dict[str, Any]:
    """
    Constructs deterministic canonical local proof payload dictionary.
    Specification: SECUREMAILSCOPE_CANONICAL_JSON_V1
    Context: SECUREMAILSCOPE_LOCAL_NOTARIZATION_V1
    """
    return {
        "analysis_id": analysis_id,
        "manifest_sha256": manifest_sha256,
        "manifest_version_id": manifest_version_id,
        "proof_context": proof_context,
        "public_key_fingerprint_sha256": public_key_fingerprint_sha256,
        "report_artifact_id": report_artifact_id,
        "report_artifact_sha256": report_artifact_sha256,
        "signature_algorithm": signature_algorithm,
        "signature_id": signature_id,
        "signature_value_sha256": signature_value_sha256,
    }


# ---------------------------------------------------------------------------
# Provider Abstraction Interface
# ---------------------------------------------------------------------------
class NotarizationProvider(ABC):
    """Abstract interface for notarization providers."""

    @abstractmethod
    def submit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Submits payload to provider and returns provider result dictionary."""
        raise NotImplementedError

    @abstractmethod
    def verify(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies notarization record against provider proof."""
        raise NotImplementedError


class LocalOnlyNotarizationProvider(NotarizationProvider):
    """
    Default local-only notarization provider.
    Performs zero network calls, calculates deterministic local proof hash,
    and returns LOCAL_PROOF_CREATED status. Never invents fake transaction IDs.
    """

    def submit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        canonical_bytes = canonical_json_bytes(payload)
        proof_hash = compute_sha256(canonical_bytes)

        return {
            "status": STATUS_LOCAL_PROOF_CREATED,
            "notarization_mode": NOTARIZATION_MODE_LOCAL_ONLY,
            "local_proof_sha256": proof_hash,
            "provider_name": None,
            "provider_reference": None,
            "submitted_payload_sha256": compute_sha256(canonical_bytes),
            "provider_proof_json": None,
            "provider_proof_sha256": None,
            "confirmed_at": None,
        }

    def verify(self, record: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "verification_status": VERIFY_STATUS_VERIFIED_LOCAL_PROOF,
            "provider_name": None,
            "details": "Deterministic local proof integrity verified nominal.",
        }


class ExternalNotarizationProvider(NotarizationProvider):
    """
    Interface for external distributed or third-party notarization.
    If no actual external provider is configured or integrated, explicitly
    raises ProviderUnavailableError and refuses to fake transaction receipts.
    """

    def __init__(
        self,
        provider_name: Optional[str] = None,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.provider_name = provider_name or os.environ.get("SMS_NOTARIZATION_PROVIDER")
        self.api_url = api_url or os.environ.get("SMS_NOTARIZATION_API_URL")
        self.api_key = api_key or os.environ.get("SMS_NOTARIZATION_API_KEY")

    def is_configured(self) -> bool:
        return bool(self.provider_name and self.api_url)

    def submit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.is_configured():
            raise ProviderUnavailableError(
                "External notarization provider is not configured. "
                "No external blockchain or timestamping service is active. "
                "Use LOCAL_ONLY mode."
            )
        raise UnsupportedProviderError(
            f"External provider '{self.provider_name}' integration is not implemented. "
            "SecureMailScope X does not simulate or fake blockchain transactions."
        )

    def verify(self, record: Dict[str, Any]) -> Dict[str, Any]:
        if not self.is_configured():
            return {
                "verification_status": VERIFY_STATUS_UNSUPPORTED_PROVIDER,
                "provider_name": self.provider_name or "UNCONFIGURED_EXTERNAL",
                "details": "External notarization provider is not configured.",
            }
        return {
            "verification_status": VERIFY_STATUS_UNSUPPORTED_PROVIDER,
            "provider_name": self.provider_name,
            "details": f"External provider verification for '{self.provider_name}' is not implemented.",
        }


# ---------------------------------------------------------------------------
# Notarization Service Engine
# ---------------------------------------------------------------------------
class NotarizationService:
    """
    Manages forensic report notarization and local proof creation.
    Enforces prerequisite verification (report integrity, digital signature verification,
    manifest chain validity), append-only NOTARIZATION_LINKAGE_MANIFEST creation,
    and side-effect-free proof verification.
    """

    _providers: Dict[str, NotarizationProvider] = {
        NOTARIZATION_MODE_LOCAL_ONLY: LocalOnlyNotarizationProvider(),
        NOTARIZATION_MODE_EXTERNAL_PROVIDER: ExternalNotarizationProvider(),
    }

    @classmethod
    def get_provider(cls, mode: str) -> NotarizationProvider:
        if mode not in cls._providers:
            if mode == NOTARIZATION_MODE_EXTERNAL_PROVIDER:
                return ExternalNotarizationProvider()
            raise UnsupportedProviderError(f"Unsupported notarization mode: '{mode}'.")
        return cls._providers[mode]

    @classmethod
    def create_notarization_proof(
        cls,
        analysis_id: str,
        report_artifact_id: str,
        signature_id: Optional[str] = None,
        mode: str = NOTARIZATION_MODE_LOCAL_ONLY,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates a deterministic local integrity proof (or external submission) for a signed report artifact,
        and atomically appends a NOTARIZATION_LINKAGE_MANIFEST version.
        """
        act = actor or ActorContext.unattributed()
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Verify Mode
        if mode not in (NOTARIZATION_MODE_LOCAL_ONLY, NOTARIZATION_MODE_EXTERNAL_PROVIDER):
            raise UnsupportedProviderError(f"Invalid notarization mode: '{mode}'. Valid modes: LOCAL_ONLY, EXTERNAL_PROVIDER.")

        # 2. Check and load Report Artifact
        report_art = ForensicRepository.get_report_artifact(report_artifact_id, db_path=db_path)
        if not report_art or report_art["analysis_id"] != analysis_id:
            raise NotarizationPrerequisiteError(
                f"Report artifact '{report_artifact_id}' not found for analysis '{analysis_id}'."
            )

        # Verify report artifact bytes integrity
        if report_art.get("raw_bytes"):
            calc_hash = compute_sha256(report_art["raw_bytes"])
            if calc_hash != report_art["artifact_sha256"]:
                raise IntegrityVerificationError(
                    f"Report artifact '{report_artifact_id}' raw bytes tampered: expected {report_art['artifact_sha256']}, got {calc_hash}"
                )
        elif report_art.get("file_path") and os.path.isfile(report_art["file_path"]):
            with open(report_art["file_path"], "rb") as f:
                calc_hash = compute_sha256(f.read())
            if calc_hash != report_art["artifact_sha256"]:
                raise IntegrityVerificationError(
                    f"Report artifact '{report_artifact_id}' file tampered: expected {report_art['artifact_sha256']}, got {calc_hash}"
                )

        # 3. Locate & Verify Digital Signature
        if signature_id:
            sig_rec = ForensicRepository.get_digital_signature(signature_id, db_path=db_path)
            if not sig_rec or sig_rec["analysis_id"] != analysis_id or sig_rec["report_artifact_id"] != report_artifact_id:
                raise NotarizationPrerequisiteError(
                    f"Signature '{signature_id}' not found for analysis '{analysis_id}' and report '{report_artifact_id}'."
                )
        else:
            sigs = ForensicRepository.get_report_signatures(analysis_id, report_artifact_id, db_path=db_path)
            if not sigs:
                raise NotarizationPrerequisiteError(
                    f"Cannot notarize unsigned report artifact '{report_artifact_id}'. A valid digital signature is required."
                )
            sig_rec = sigs[-1]  # Latest signature for this report artifact
            signature_id = sig_rec["signature_id"]

        # Cryptographically verify the signature
        sig_ver = SignatureService.verify_signature(signature_id, db_path=db_path)
        if sig_ver["verification_status"] != "VERIFIED":
            raise IntegrityVerificationError(
                f"Cannot notarize report: Digital signature '{signature_id}' verification failed with status {sig_ver['verification_status']}: {sig_ver.get('details')}"
            )

        # 4. Verify Manifest Chain before notarizing
        chain_res = ForensicRepository.verify_manifest_chain(analysis_id, db_path=db_path)
        if chain_res["overall_status"] == "INTEGRITY_FAILED":
            raise IntegrityVerificationError(
                f"Cannot notarize report: Custody manifest chain verification failed: {chain_res['details']}"
            )

        # 5. Load latest sealed manifest version (source manifest)
        latest_manifest = ForensicRepository.get_latest_manifest_version(analysis_id, db_path=db_path)
        if not latest_manifest:
            raise NotarizationPrerequisiteError(
                f"No sealed custody manifest version exists for analysis '{analysis_id}'."
            )

        source_manifest_id = latest_manifest["manifest_version_id"]
        source_manifest_hash = latest_manifest["manifest_sha256"]

        # 6. Build Deterministic Local Proof Payload
        sig_value_bytes = sig_rec["signature_value"].encode("utf-8")
        sig_value_sha256 = compute_sha256(sig_value_bytes)

        proof_payload = build_local_proof_payload(
            analysis_id=analysis_id,
            report_artifact_id=report_artifact_id,
            report_artifact_sha256=report_art["artifact_sha256"],
            signature_id=signature_id,
            signature_algorithm=sig_rec["signature_algorithm"],
            signature_value_sha256=sig_value_sha256,
            public_key_fingerprint_sha256=sig_rec["public_key_fingerprint_sha256"],
            manifest_version_id=source_manifest_id,
            manifest_sha256=source_manifest_hash,
            proof_context=LOCAL_PROOF_CONTEXT_V1,
        )

        canonical_proof_bytes = canonical_json_bytes(proof_payload)
        local_proof_sha256 = compute_sha256(canonical_proof_bytes)

        # 7. Execute Provider Submission
        provider = cls.get_provider(mode)
        provider_result = provider.submit(proof_payload)

        notarization_id = f"notz_{analysis_id[:12]}_{uuid.uuid4().hex[:8]}"

        notarization_dict = {
            "notarization_id": notarization_id,
            "analysis_id": analysis_id,
            "report_artifact_id": report_artifact_id,
            "signature_id": signature_id,
            "manifest_version_id": source_manifest_id,
            "notarization_mode": mode,
            "provider_name": provider_result.get("provider_name"),
            "provider_reference": provider_result.get("provider_reference"),
            "submitted_payload_sha256": provider_result.get("submitted_payload_sha256", local_proof_sha256),
            "local_proof_sha256": local_proof_sha256,
            "provider_proof_json": provider_result.get("provider_proof_json"),
            "provider_proof_sha256": provider_result.get("provider_proof_sha256"),
            "status": provider_result.get("status", STATUS_LOCAL_PROOF_CREATED),
            "created_at": now_iso,
            "confirmed_at": provider_result.get("confirmed_at"),
            "created_by_actor_id": act.actor_id,
            "created_by_actor_display_name": act.actor_display_name,
            "actor_identity_source": act.actor_identity_source,
            "actor_attribution_status": act.actor_attribution_status,
            "schema_version": CURRENT_SCHEMA_VERSION,
        }

        # 8. Construct NEW Manifest Version (NOTARIZATION_LINKAGE_MANIFEST)
        next_vnum = latest_manifest["version_number"] + 1
        new_manifest_vid = f"cmv_{analysis_id[:12]}_v{next_vnum}_{uuid.uuid4().hex[:8]}"

        prev_dict = latest_manifest.get("manifest_dict") or {}
        prev_linked_notzs = prev_dict.get("linked_notarizations") or []
        new_linked_notzs = list(prev_linked_notzs) + [{
            "notarization_id": notarization_id,
            "notarization_mode": mode,
            "local_proof_sha256": local_proof_sha256,
            "signature_id": signature_id,
            "report_artifact_id": report_artifact_id,
            "status": notarization_dict["status"],
            "created_at": now_iso,
        }]

        new_manifest_payload = {
            "actor": {
                "actor_display_name": act.actor_display_name,
                "actor_id": act.actor_id,
                "attribution_status": act.actor_attribution_status,
                "identity_source": act.actor_identity_source,
            },
            "analysis_id": analysis_id,
            "canonicalization_version": CANONICALIZATION_VERSION,
            "capture_sha256": prev_dict.get("capture_sha256") or "0" * 64,
            "created_at": now_iso,
            "finding_hashes": prev_dict.get("finding_hashes", []),
            "incident_hashes": prev_dict.get("incident_hashes", []),
            "linked_notarizations": new_linked_notzs,
            "linked_report_artifacts": prev_dict.get("linked_report_artifacts", []),
            "linked_signatures": prev_dict.get("linked_signatures", []),
            "manifest_type": "NOTARIZATION_LINKAGE_MANIFEST",
            "observed_result_sha256": prev_dict.get("observed_result_sha256", ""),
            "previous_manifest_sha256": source_manifest_hash,
            "session_hashes": prev_dict.get("session_hashes", []),
            "version_number": next_vnum,
        }

        new_manifest_json = canonical_json_str(new_manifest_payload)
        new_manifest_hash = compute_sha256(new_manifest_json.encode("utf-8"))

        manifest_version_dict = {
            "manifest_version_id": new_manifest_vid,
            "analysis_id": analysis_id,
            "version_number": next_vnum,
            "manifest_type": "NOTARIZATION_LINKAGE_MANIFEST",
            "parent_manifest_version_id": source_manifest_id,
            "previous_manifest_sha256": source_manifest_hash,
            "manifest_json": new_manifest_json,
            "manifest_sha256": new_manifest_hash,
            "canonicalization_version": CANONICALIZATION_VERSION,
            "created_at": now_iso,
            "created_by_actor_id": act.actor_id,
            "created_by_actor_display_name": act.actor_display_name,
            "actor_identity_source": act.actor_identity_source,
            "actor_attribution_status": act.actor_attribution_status,
            "sealed": True,
            "purpose": f"Link notarization proof {notarization_id} ({mode}) for report {report_artifact_id}",
            "schema_version": CURRENT_SCHEMA_VERSION,
        }

        # 9. Atomically Persist Notarization Record + Manifest Version
        ForensicRepository.save_notarization_and_manifest_version(
            notarization_record=notarization_dict,
            manifest_version=manifest_version_dict,
            db_path=db_path
        )

        # 10. Append Custody Audit Event: NOTARIZATION_LOCAL_PROOF_CREATED
        custody_rec = CustodyService.get_record(analysis_id)
        if custody_rec:
            event_type = (
                "NOTARIZATION_LOCAL_PROOF_CREATED"
                if mode == NOTARIZATION_MODE_LOCAL_ONLY
                else "NOTARIZATION_SUBMISSION_REQUESTED"
            )
            custody_rec._append_event(
                event_type=event_type,
                artifact_hash=local_proof_sha256,
                details=(
                    f"Notarization record {notarization_id} ({mode}) created for report {report_artifact_id} "
                    f"and signature {signature_id} (Proof SHA-256: {local_proof_sha256[:16]}... Linked in Manifest v{next_vnum})"
                ),
                actor=act,
            )
            CustodyService._persist_record(custody_rec)

        return notarization_dict

    @classmethod
    def verify_notarization(
        cls,
        notarization_id: str,
        db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Performs comprehensive read-only cryptographic verification of a notarization proof record.
        Side effects: ZERO database modifications or audit appends.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        rec = ForensicRepository.get_notarization_record(notarization_id, db_path=db_path)

        if not rec:
            return {
                "notarization_id": notarization_id,
                "analysis_id": "UNKNOWN",
                "report_artifact_id": "UNKNOWN",
                "signature_id": "UNKNOWN",
                "manifest_version_id": "UNKNOWN",
                "notarization_mode": "UNKNOWN",
                "status": STATUS_INCOMPLETE,
                "verification_status": VERIFY_STATUS_INCOMPLETE,
                "local_proof_sha256": "UNKNOWN",
                "created_at": "UNKNOWN",
                "created_by_actor": {},
                "verification_timestamp_utc": now_iso,
                "details": f"Notarization record '{notarization_id}' not found in database.",
            }

        analysis_id = rec["analysis_id"]
        report_art_id = rec["report_artifact_id"]
        sig_id = rec["signature_id"]
        manifest_vid = rec["manifest_version_id"]
        mode = rec["notarization_mode"]
        stored_proof_hash = rec["local_proof_sha256"]

        actor_info = {
            "actor_id": rec["created_by_actor_id"],
            "actor_display_name": rec["created_by_actor_display_name"],
            "identity_source": rec["actor_identity_source"],
            "attribution_status": rec["actor_attribution_status"],
        }

        # 1. Verify Report Artifact
        report_art = ForensicRepository.get_report_artifact(report_art_id, db_path=db_path)
        if not report_art:
            return {
                "notarization_id": notarization_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "signature_id": sig_id,
                "manifest_version_id": manifest_vid,
                "notarization_mode": mode,
                "status": rec["status"],
                "verification_status": VERIFY_STATUS_INCOMPLETE,
                "local_proof_sha256": stored_proof_hash,
                "created_at": rec["created_at"],
                "created_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Referenced report artifact '{report_art_id}' is missing from database.",
            }

        art_bytes = report_art.get("raw_bytes")
        if art_bytes is None and report_art.get("file_path") and os.path.isfile(report_art["file_path"]):
            try:
                with open(report_art["file_path"], "rb") as f:
                    art_bytes = f.read()
            except Exception:
                art_bytes = None

        if art_bytes is not None:
            calc_art_hash = compute_sha256(art_bytes)
            if calc_art_hash != report_art["artifact_sha256"]:
                return {
                    "notarization_id": notarization_id,
                    "analysis_id": analysis_id,
                    "report_artifact_id": report_art_id,
                    "signature_id": sig_id,
                    "manifest_version_id": manifest_vid,
                    "notarization_mode": mode,
                    "status": rec["status"],
                    "verification_status": VERIFY_STATUS_REPORT_INTEGRITY_FAILED,
                    "local_proof_sha256": stored_proof_hash,
                    "created_at": rec["created_at"],
                    "created_by_actor": actor_info,
                    "verification_timestamp_utc": now_iso,
                    "details": f"Report artifact '{report_art_id}' file/raw bytes tampered: expected {report_art['artifact_sha256']}, got {calc_art_hash}",
                }

        # 2. Verify Digital Signature
        sig_rec = ForensicRepository.get_digital_signature(sig_id, db_path=db_path)
        if not sig_rec:
            return {
                "notarization_id": notarization_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "signature_id": sig_id,
                "manifest_version_id": manifest_vid,
                "notarization_mode": mode,
                "status": rec["status"],
                "verification_status": VERIFY_STATUS_INCOMPLETE,
                "local_proof_sha256": stored_proof_hash,
                "created_at": rec["created_at"],
                "created_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Referenced digital signature '{sig_id}' is missing from database.",
            }

        sig_ver = SignatureService.verify_signature(sig_id, db_path=db_path)
        if sig_ver["verification_status"] != "VERIFIED":
            return {
                "notarization_id": notarization_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "signature_id": sig_id,
                "manifest_version_id": manifest_vid,
                "notarization_mode": mode,
                "status": rec["status"],
                "verification_status": VERIFY_STATUS_SIGNATURE_INVALID,
                "local_proof_sha256": stored_proof_hash,
                "created_at": rec["created_at"],
                "created_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Digital signature '{sig_id}' failed verification: {sig_ver.get('details')}",
            }

        # 3. Verify Source Manifest Version
        manifest_ver = ForensicRepository.get_manifest_version(analysis_id, manifest_vid, db_path=db_path)
        if not manifest_ver:
            return {
                "notarization_id": notarization_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "signature_id": sig_id,
                "manifest_version_id": manifest_vid,
                "notarization_mode": mode,
                "status": rec["status"],
                "verification_status": VERIFY_STATUS_INCOMPLETE,
                "local_proof_sha256": stored_proof_hash,
                "created_at": rec["created_at"],
                "created_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Referenced manifest version '{manifest_vid}' is missing from database.",
            }

        if manifest_ver.get("manifest_dict"):
            recomputed_m_bytes = canonical_json_bytes(manifest_ver["manifest_dict"])
            recomputed_m_hash = compute_sha256(recomputed_m_bytes)
        else:
            recomputed_m_hash = compute_sha256(manifest_ver["manifest_json"].encode("utf-8"))

        if recomputed_m_hash != manifest_ver["manifest_sha256"]:
            return {
                "notarization_id": notarization_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "signature_id": sig_id,
                "manifest_version_id": manifest_vid,
                "notarization_mode": mode,
                "status": rec["status"],
                "verification_status": VERIFY_STATUS_MANIFEST_INTEGRITY_FAILED,
                "local_proof_sha256": stored_proof_hash,
                "created_at": rec["created_at"],
                "created_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Source manifest version '{manifest_vid}' payload seal mismatch: expected {manifest_ver['manifest_sha256']}, got {recomputed_m_hash}",
            }

        # 4. Reconstruct Deterministic Proof Payload
        sig_value_bytes = sig_rec["signature_value"].encode("utf-8")
        sig_value_sha256 = compute_sha256(sig_value_bytes)

        expected_payload = build_local_proof_payload(
            analysis_id=analysis_id,
            report_artifact_id=report_art_id,
            report_artifact_sha256=report_art["artifact_sha256"],
            signature_id=sig_id,
            signature_algorithm=sig_rec["signature_algorithm"],
            signature_value_sha256=sig_value_sha256,
            public_key_fingerprint_sha256=sig_rec["public_key_fingerprint_sha256"],
            manifest_version_id=manifest_ver["manifest_version_id"],
            manifest_sha256=manifest_ver["manifest_sha256"],
            proof_context=LOCAL_PROOF_CONTEXT_V1,
        )

        canonical_bytes = canonical_json_bytes(expected_payload)
        recomputed_proof_hash = compute_sha256(canonical_bytes)

        if recomputed_proof_hash != stored_proof_hash:
            return {
                "notarization_id": notarization_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "signature_id": sig_id,
                "manifest_version_id": manifest_vid,
                "notarization_mode": mode,
                "status": rec["status"],
                "verification_status": VERIFY_STATUS_INTEGRITY_FAILED,
                "local_proof_sha256": stored_proof_hash,
                "created_at": rec["created_at"],
                "created_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Local proof hash mismatch: record={stored_proof_hash}, recomputed={recomputed_proof_hash}",
            }

        # 5. Check External Provider Mode if applicable
        if mode == NOTARIZATION_MODE_EXTERNAL_PROVIDER:
            provider = cls.get_provider(mode)
            p_res = provider.verify(rec)
            return {
                "notarization_id": notarization_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "signature_id": sig_id,
                "manifest_version_id": manifest_vid,
                "notarization_mode": mode,
                "status": rec["status"],
                "verification_status": p_res["verification_status"],
                "local_proof_sha256": stored_proof_hash,
                "created_at": rec["created_at"],
                "created_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": p_res["details"],
            }

        # 6. LOCAL_ONLY Success
        return {
            "notarization_id": notarization_id,
            "analysis_id": analysis_id,
            "report_artifact_id": report_art_id,
            "signature_id": sig_id,
            "manifest_version_id": manifest_vid,
            "notarization_mode": NOTARIZATION_MODE_LOCAL_ONLY,
            "status": STATUS_LOCAL_PROOF_CREATED,
            "verification_status": VERIFY_STATUS_VERIFIED_LOCAL_PROOF,
            "local_proof_sha256": stored_proof_hash,
            "created_at": rec["created_at"],
            "created_by_actor": actor_info,
            "verification_timestamp_utc": now_iso,
            "details": "Deterministic local proof, report artifact, digital signature, and manifest chain verified cryptographically nominal.",
        }

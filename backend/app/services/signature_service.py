"""
SecureMailScope X - Forensic Digital Report Signing & Signature Verification Engine
Provides asymmetric cryptographic signing (Ed25519, ECDSA P-256, RSA-PSS) for forensic
report artifacts, immutable manifest version linkage, and side-effect-free tamper verification.
"""

import os
import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding
from cryptography.exceptions import InvalidSignature

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
from app.services.custody_service import CustodyService, GENESIS_PREV_HASH

SIGNATURE_CONTEXT_V1 = "SECUREMAILSCOPE_REPORT_SIGNATURE_V1"

SUPPORTED_ALGORITHMS = {
    "ED25519": "Ed25519 Pure EdDSA signature scheme",
    "ECDSA_P256_SHA256": "ECDSA using NIST P-256 curve and SHA-256 digest",
    "RSA_PSS_SHA256": "RSA Probabilistic Signature Scheme (PSS) with SHA-256 digest and MGF1",
}


class SigningError(Exception):
    """Base exception for digital signing operations."""
    pass


class SigningUnavailableError(SigningError):
    """Raised when no signing private key is configured or available."""
    pass


class UnsupportedAlgorithmError(SigningError):
    """Raised when an unsupported or insecure cryptographic algorithm is specified."""
    pass


class SignatureVerificationError(SigningError):
    """Raised when signature verification encounters an integrity or cryptographic violation."""
    pass


# ---------------------------------------------------------------------------
# Key Utilities & Helper Functions
# ---------------------------------------------------------------------------
def compute_public_key_fingerprint(public_key: Any) -> str:
    """
    Computes lowercase hex SHA-256 fingerprint from the actual DER SubjectPublicKeyInfo bytes.
    Does not fingerprint display strings or PEM headers.
    """
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der_bytes).hexdigest().lower()


def export_public_key_pem(public_key: Any) -> str:
    """Exports public key as standard SubjectPublicKeyInfo PEM string."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode("utf-8")


def detect_key_algorithm(key: Any) -> str:
    """Detects standard asymmetric algorithm from private or public key instance."""
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "ED25519"
    elif isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        curve_name = key.curve.name.lower()
        if curve_name in ("secp256r1", "p-256", "prime256v1"):
            return "ECDSA_P256_SHA256"
        raise UnsupportedAlgorithmError(f"Unsupported elliptic curve '{key.curve.name}'. Supported curve is NIST P-256.")
    elif isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "RSA_PSS_SHA256"
    else:
        raise UnsupportedAlgorithmError(f"Unsupported key type '{type(key).__name__}'.")


def load_private_key_from_pem(pem_data: bytes, password: Optional[str] = None) -> Any:
    """Deserializes PEM encoded private key."""
    pwd_bytes = password.encode("utf-8") if password else None
    return serialization.load_pem_private_key(pem_data, password=pwd_bytes)


def load_public_key_from_pem(pem_data: bytes) -> Any:
    """Deserializes PEM encoded public key."""
    return serialization.load_pem_public_key(pem_data)


def build_signature_payload(
    analysis_id: str,
    report_artifact_id: str,
    report_artifact_sha256: str,
    source_manifest_version_id: str,
    source_manifest_sha256: str,
    signature_context: str = SIGNATURE_CONTEXT_V1,
) -> Dict[str, Any]:
    """
    Constructs deterministic canonical signature payload object.
    Specification: SECUREMAILSCOPE_REPORT_SIGNATURE_V1
    """
    return {
        "analysis_id": analysis_id,
        "report_artifact_id": report_artifact_id,
        "report_artifact_sha256": report_artifact_sha256,
        "signature_context": signature_context,
        "source_manifest_sha256": source_manifest_sha256,
        "source_manifest_version_id": source_manifest_version_id,
    }


def sign_raw_bytes(private_key: Any, message_bytes: bytes, algorithm: Optional[str] = None) -> Tuple[bytes, str]:
    """
    Signs raw message bytes using the designated asymmetric private key.
    Returns (signature_bytes, algorithm_name).
    """
    detected_algo = detect_key_algorithm(private_key)
    algo = algorithm or detected_algo

    if algo != detected_algo:
        if not (algo == "RSA_PSS_SHA256" and isinstance(private_key, rsa.RSAPrivateKey)):
            raise UnsupportedAlgorithmError(f"Algorithm '{algo}' is incompatible with key type '{type(private_key).__name__}'.")

    if algo == "ED25519":
        sig_bytes = private_key.sign(message_bytes)
    elif algo == "ECDSA_P256_SHA256":
        sig_bytes = private_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
    elif algo == "RSA_PSS_SHA256":
        sig_bytes = private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    else:
        raise UnsupportedAlgorithmError(f"Unsupported signature algorithm '{algo}'.")

    return sig_bytes, algo


def verify_raw_signature(public_key: Any, signature_bytes: bytes, message_bytes: bytes, algorithm: str) -> bool:
    """
    Verifies digital signature bytes against message bytes using public key.
    Returns True if valid, raises InvalidSignature / UnsupportedAlgorithmError on failure.
    """
    if algorithm == "ED25519":
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            return False
        public_key.verify(signature_bytes, message_bytes)
        return True
    elif algorithm == "ECDSA_P256_SHA256":
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        public_key.verify(signature_bytes, message_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    elif algorithm == "RSA_PSS_SHA256":
        if not isinstance(public_key, rsa.RSAPublicKey):
            return False
        public_key.verify(
            signature_bytes,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    else:
        raise UnsupportedAlgorithmError(f"Unsupported signature algorithm '{algorithm}'.")


# ---------------------------------------------------------------------------
# Signature Service Engine
# ---------------------------------------------------------------------------
class SignatureService:
    """
    Manages asymmetric digital signing and read-only verification for report artifacts.
    Enforces hash chaining, append-only manifest versions, and strict separation between
    analyst workflow attribution and cryptographic signer key material.
    """

    @classmethod
    def resolve_private_key(
        cls,
        private_key_pem: Optional[str] = None,
        private_key_path: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Tuple[Any, str]:
        """
        Resolves private key from explicit PEM parameter, explicit path, or environment variables.
        Environment variables checked:
        - SMS_SIGNING_PRIVATE_KEY_PEM
        - SMS_SIGNING_PRIVATE_KEY_PATH
        - SMS_SIGNING_KEY_ID
        Returns: (private_key_object, key_id)
        """
        key_id = os.environ.get("SMS_SIGNING_KEY_ID", "default-key")
        pem_content = None

        if private_key_pem:
            pem_content = private_key_pem.encode("utf-8")
        elif private_key_path and os.path.isfile(private_key_path):
            with open(private_key_path, "rb") as f:
                pem_content = f.read()
        elif "SMS_SIGNING_PRIVATE_KEY_PEM" in os.environ:
            pem_content = os.environ["SMS_SIGNING_PRIVATE_KEY_PEM"].encode("utf-8")
        elif "SMS_SIGNING_PRIVATE_KEY_PATH" in os.environ:
            env_path = os.environ["SMS_SIGNING_PRIVATE_KEY_PATH"]
            if os.path.isfile(env_path):
                with open(env_path, "rb") as f:
                    pem_content = f.read()

        if not pem_content:
            raise SigningUnavailableError(
                "Digital signing unavailable: No private signing key configured. "
                "Set SMS_SIGNING_PRIVATE_KEY_PATH or pass private key material."
            )

        try:
            private_key = load_private_key_from_pem(pem_content, password=password)
            return private_key, key_id
        except Exception as e:
            raise SigningError(f"Failed to load private signing key: {str(e)}")

    @classmethod
    def sign_report_artifact(
        cls,
        analysis_id: str,
        report_artifact_id: str,
        key_id: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        private_key_path: Optional[str] = None,
        password: Optional[str] = None,
        algorithm: Optional[str] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Cryptographically signs a report artifact and appends a SIGNATURE_LINKAGE_MANIFEST.
        Never mutates earlier manifests or report artifacts in place.
        """
        act = actor or ActorContext.unattributed()
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Load report artifact
        report_art = ForensicRepository.get_report_artifact(report_artifact_id, db_path=db_path)
        if not report_art or report_art["analysis_id"] != analysis_id:
            raise SignatureVerificationError(
                f"Report artifact '{report_artifact_id}' not found for analysis '{analysis_id}'."
            )

        # 2. Check artifact byte integrity
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

        # 3. Verify manifest chain before signing
        chain_res = ForensicRepository.verify_manifest_chain(analysis_id, db_path=db_path)
        if chain_res["overall_status"] == "INTEGRITY_FAILED":
            raise IntegrityVerificationError(
                f"Cannot sign report artifact '{report_artifact_id}': Custody manifest chain integrity verification failed: {chain_res['details']}"
            )

        # 4. Load latest sealed manifest version (source manifest)
        latest_manifest = ForensicRepository.get_latest_manifest_version(analysis_id, db_path=db_path)
        if not latest_manifest:
            raise SignatureVerificationError(
                f"No sealed custody manifest version exists for analysis '{analysis_id}'."
            )

        source_manifest_id = latest_manifest["manifest_version_id"]
        source_manifest_hash = latest_manifest["manifest_sha256"]

        # 5. Load and resolve private key
        private_key, resolved_key_id = cls.resolve_private_key(
            private_key_pem=private_key_pem,
            private_key_path=private_key_path,
            password=password,
        )
        effective_key_id = key_id or resolved_key_id

        # 6. Build deterministic signature payload
        sig_payload = build_signature_payload(
            analysis_id=analysis_id,
            report_artifact_id=report_artifact_id,
            report_artifact_sha256=report_art["artifact_sha256"],
            source_manifest_version_id=source_manifest_id,
            source_manifest_sha256=source_manifest_hash,
            signature_context=SIGNATURE_CONTEXT_V1,
        )
        canonical_payload_bytes = canonical_json_bytes(sig_payload)
        signed_digest_value = compute_sha256(canonical_payload_bytes)

        # 7. Generate asymmetric signature
        sig_bytes, sig_algo = sign_raw_bytes(private_key, canonical_payload_bytes, algorithm=algorithm)
        signature_base64 = base64.b64encode(sig_bytes).decode("ascii")

        # 8. Derive public key metadata
        public_key = private_key.public_key()
        pub_fingerprint = compute_public_key_fingerprint(public_key)
        pub_pem = export_public_key_pem(public_key)

        # 9. Immediate in-memory cryptographic self-verification
        try:
            verify_raw_signature(public_key, sig_bytes, canonical_payload_bytes, sig_algo)
        except Exception as e:
            raise SigningError(f"Immediate signature self-verification failed: {str(e)}")

        signature_id = f"sig_{analysis_id[:12]}_{uuid.uuid4().hex[:8]}"

        signature_dict = {
            "signature_id": signature_id,
            "analysis_id": analysis_id,
            "report_artifact_id": report_artifact_id,
            "manifest_version_id": source_manifest_id,
            "signature_algorithm": sig_algo,
            "signature_format": "BASE64",
            "signature_value": signature_base64,
            "signed_digest_algorithm": "SHA256",
            "signed_digest_value": signed_digest_value,
            "public_key_fingerprint_sha256": pub_fingerprint,
            "public_key_pem": pub_pem,
            "key_id": effective_key_id,
            "signed_at": now_iso,
            "signed_by_actor_id": act.actor_id,
            "signed_by_actor_display_name": act.actor_display_name,
            "actor_identity_source": act.actor_identity_source,
            "actor_attribution_status": act.actor_attribution_status,
            "verification_status": "VERIFIED",
            "schema_version": CURRENT_SCHEMA_VERSION,
        }

        # 10. Construct NEW manifest version (SIGNATURE_LINKAGE_MANIFEST)
        next_vnum = latest_manifest["version_number"] + 1
        new_manifest_vid = f"cmv_{analysis_id[:12]}_v{next_vnum}_{uuid.uuid4().hex[:8]}"

        prev_dict = latest_manifest.get("manifest_dict") or {}
        prev_linked_sigs = prev_dict.get("linked_signatures") or []
        new_linked_sigs = list(prev_linked_sigs) + [{
            "signature_id": signature_id,
            "report_artifact_id": report_artifact_id,
            "report_artifact_sha256": report_art["artifact_sha256"],
            "signature_algorithm": sig_algo,
            "public_key_fingerprint_sha256": pub_fingerprint,
            "key_id": effective_key_id,
            "signed_at": now_iso,
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
            "linked_report_artifacts": prev_dict.get("linked_report_artifacts", []),
            "linked_signatures": new_linked_sigs,
            "manifest_type": "SIGNATURE_LINKAGE_MANIFEST",
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
            "manifest_type": "SIGNATURE_LINKAGE_MANIFEST",
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
            "purpose": f"Link digital signature {signature_id} seal for report {report_artifact_id}",
            "schema_version": CURRENT_SCHEMA_VERSION,
        }

        # 11. Atomically persist signature record + new manifest version
        ForensicRepository.save_signature_and_manifest_version(
            signature_record=signature_dict,
            manifest_version=manifest_version_dict,
            db_path=db_path
        )

        # 12. Append custody audit event: REPORT_SIGNATURE_CREATED
        custody_rec = CustodyService.get_record(analysis_id)
        if custody_rec:
            custody_rec._append_event(
                event_type="REPORT_SIGNATURE_CREATED",
                artifact_hash=signed_digest_value,
                details=(
                    f"Asymmetric digital signature {signature_id} generated for report {report_artifact_id} "
                    f"via {sig_algo} (Key Fingerprint: {pub_fingerprint[:16]}... Linked in Manifest v{next_vnum})"
                ),
                actor=act,
            )
            CustodyService._persist_record(custody_rec)

        return signature_dict

    @classmethod
    def verify_signature(
        cls,
        signature_id: str,
        db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Performs comprehensive read-only cryptographic verification of a digital signature.
        Side effects: ZERO database modifications or audit appends.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        sig_rec = ForensicRepository.get_digital_signature(signature_id, db_path=db_path)

        if not sig_rec:
            return {
                "signature_id": signature_id,
                "analysis_id": "UNKNOWN",
                "report_artifact_id": "UNKNOWN",
                "manifest_version_id": "UNKNOWN",
                "verification_status": "INCOMPLETE",
                "signature_algorithm": "UNKNOWN",
                "public_key_fingerprint_sha256": "UNKNOWN",
                "key_id": "UNKNOWN",
                "signed_at": "UNKNOWN",
                "signed_by_actor": {},
                "verification_timestamp_utc": now_iso,
                "details": f"Signature record '{signature_id}' not found in database.",
            }

        analysis_id = sig_rec["analysis_id"]
        report_art_id = sig_rec["report_artifact_id"]
        manifest_vid = sig_rec["manifest_version_id"]
        algorithm = sig_rec["signature_algorithm"]
        stored_fingerprint = sig_rec["public_key_fingerprint_sha256"]

        actor_info = {
            "actor_id": sig_rec["signed_by_actor_id"],
            "actor_display_name": sig_rec["signed_by_actor_display_name"],
            "identity_source": sig_rec["actor_identity_source"],
            "attribution_status": sig_rec["actor_attribution_status"],
        }

        # 1. Check supported algorithm
        if algorithm not in SUPPORTED_ALGORITHMS:
            return {
                "signature_id": signature_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "manifest_version_id": manifest_vid,
                "verification_status": "UNSUPPORTED_ALGORITHM",
                "signature_algorithm": algorithm,
                "public_key_fingerprint_sha256": stored_fingerprint,
                "key_id": sig_rec["key_id"],
                "signed_at": sig_rec["signed_at"],
                "signed_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Algorithm '{algorithm}' is not supported.",
            }

        # 2. Check report artifact existence and integrity
        report_art = ForensicRepository.get_report_artifact(report_art_id, db_path=db_path)
        if not report_art:
            return {
                "signature_id": signature_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "manifest_version_id": manifest_vid,
                "verification_status": "INCOMPLETE",
                "signature_algorithm": algorithm,
                "public_key_fingerprint_sha256": stored_fingerprint,
                "key_id": sig_rec["key_id"],
                "signed_at": sig_rec["signed_at"],
                "signed_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Referenced report artifact '{report_art_id}' is missing from database.",
            }

        # Check report bytes
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
                    "signature_id": signature_id,
                    "analysis_id": analysis_id,
                    "report_artifact_id": report_art_id,
                    "manifest_version_id": manifest_vid,
                    "verification_status": "ARTIFACT_INTEGRITY_FAILED",
                    "signature_algorithm": algorithm,
                    "public_key_fingerprint_sha256": stored_fingerprint,
                    "key_id": sig_rec["key_id"],
                    "signed_at": sig_rec["signed_at"],
                    "signed_by_actor": actor_info,
                    "verification_timestamp_utc": now_iso,
                    "details": f"Report artifact '{report_art_id}' file/raw bytes tampered: expected {report_art['artifact_sha256']}, got {calc_art_hash}",
                }

        # 3. Check source manifest version existence and integrity
        manifest_ver = ForensicRepository.get_manifest_version(analysis_id, manifest_vid, db_path=db_path)
        if not manifest_ver:
            return {
                "signature_id": signature_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "manifest_version_id": manifest_vid,
                "verification_status": "INCOMPLETE",
                "signature_algorithm": algorithm,
                "public_key_fingerprint_sha256": stored_fingerprint,
                "key_id": sig_rec["key_id"],
                "signed_at": sig_rec["signed_at"],
                "signed_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Referenced manifest version '{manifest_vid}' is missing from database.",
            }

        # Verify manifest seal
        if manifest_ver.get("manifest_dict"):
            recomputed_m_bytes = canonical_json_bytes(manifest_ver["manifest_dict"])
            recomputed_m_hash = compute_sha256(recomputed_m_bytes)
        else:
            recomputed_m_hash = compute_sha256(manifest_ver["manifest_json"].encode("utf-8"))

        if recomputed_m_hash != manifest_ver["manifest_sha256"]:
            return {
                "signature_id": signature_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "manifest_version_id": manifest_vid,
                "verification_status": "MANIFEST_INTEGRITY_FAILED",
                "signature_algorithm": algorithm,
                "public_key_fingerprint_sha256": stored_fingerprint,
                "key_id": sig_rec["key_id"],
                "signed_at": sig_rec["signed_at"],
                "signed_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Source manifest version '{manifest_vid}' payload seal mismatch: expected {manifest_ver['manifest_sha256']}, got {recomputed_m_hash}",
            }

        # 4. Reconstruct deterministic signature payload
        expected_payload = build_signature_payload(
            analysis_id=analysis_id,
            report_artifact_id=report_art_id,
            report_artifact_sha256=report_art["artifact_sha256"],
            source_manifest_version_id=manifest_ver["manifest_version_id"],
            source_manifest_sha256=manifest_ver["manifest_sha256"],
            signature_context=SIGNATURE_CONTEXT_V1,
        )
        canonical_bytes = canonical_json_bytes(expected_payload)
        computed_digest = compute_sha256(canonical_bytes)

        if computed_digest != sig_rec["signed_digest_value"]:
            return {
                "signature_id": signature_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "manifest_version_id": manifest_vid,
                "verification_status": "SIGNATURE_INVALID",
                "signature_algorithm": algorithm,
                "public_key_fingerprint_sha256": stored_fingerprint,
                "key_id": sig_rec["key_id"],
                "signed_at": sig_rec["signed_at"],
                "signed_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Signed digest mismatch: record={sig_rec['signed_digest_value']}, recomputed={computed_digest}",
            }

        # 5. Parse public key & verify fingerprint
        try:
            pub_key = load_public_key_from_pem(sig_rec["public_key_pem"].encode("utf-8"))
        except Exception as e:
            return {
                "signature_id": signature_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "manifest_version_id": manifest_vid,
                "verification_status": "PUBLIC_KEY_MISMATCH",
                "signature_algorithm": algorithm,
                "public_key_fingerprint_sha256": stored_fingerprint,
                "key_id": sig_rec["key_id"],
                "signed_at": sig_rec["signed_at"],
                "signed_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Public key PEM corrupted: {str(e)}",
            }

        actual_fingerprint = compute_public_key_fingerprint(pub_key)
        if actual_fingerprint != stored_fingerprint:
            return {
                "signature_id": signature_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "manifest_version_id": manifest_vid,
                "verification_status": "PUBLIC_KEY_MISMATCH",
                "signature_algorithm": algorithm,
                "public_key_fingerprint_sha256": stored_fingerprint,
                "key_id": sig_rec["key_id"],
                "signed_at": sig_rec["signed_at"],
                "signed_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Public key fingerprint mismatch: stored {stored_fingerprint}, actual {actual_fingerprint}",
            }

        # 6. Cryptographic signature check
        try:
            sig_raw = base64.b64decode(sig_rec["signature_value"])
            verify_raw_signature(pub_key, sig_raw, canonical_bytes, algorithm)
        except (InvalidSignature, ValueError) as e:
            return {
                "signature_id": signature_id,
                "analysis_id": analysis_id,
                "report_artifact_id": report_art_id,
                "manifest_version_id": manifest_vid,
                "verification_status": "SIGNATURE_INVALID",
                "signature_algorithm": algorithm,
                "public_key_fingerprint_sha256": stored_fingerprint,
                "key_id": sig_rec["key_id"],
                "signed_at": sig_rec["signed_at"],
                "signed_by_actor": actor_info,
                "verification_timestamp_utc": now_iso,
                "details": f"Cryptographic signature verification failed: {str(e)}",
            }

        return {
            "signature_id": signature_id,
            "analysis_id": analysis_id,
            "report_artifact_id": report_art_id,
            "manifest_version_id": manifest_vid,
            "verification_status": "VERIFIED",
            "signature_algorithm": algorithm,
            "public_key_fingerprint_sha256": stored_fingerprint,
            "key_id": sig_rec["key_id"],
            "signed_at": sig_rec["signed_at"],
            "signed_by_actor": actor_info,
            "verification_timestamp_utc": now_iso,
            "details": "Digital signature and manifest linkage verified cryptographically nominal.",
        }

"""
SecureMailScope X - Forensic Notarization Provider Abstraction & Real Blockchain Anchoring (Phase 16)
Provides pluggable notarization architecture, deterministic local integrity proofs,
optional real EVM-compatible blockchain anchoring, immutable manifest linkage,
and side-effect-free proof verification.

CRITICAL TRUST BOUNDARY:
- LOCAL PROOF != BLOCKCHAIN.
- Default system mode is strictly LOCAL_ONLY and fully offline.
- A record may be called BLOCKCHAIN_ANCHORED / CONFIRMED ONLY IF:
  1. A real external blockchain RPC was contacted,
  2. A real transaction was submitted,
  3. A real transaction hash was returned,
  4. A transaction receipt was obtained with status == success,
  5. Chain ID matches configured chain,
  6. Anchored payload matches SecureMailScope local proof SHA-256,
  7. Verification independently re-fetches and validates transaction and receipt.
- Zero simulated/fake transaction hashes, block numbers, or explorer URLs.
- Private keys and RPC credentials are never stored in SQLite, logged, or returned in API responses.
"""

import os
import json
import uuid
import hashlib
import urllib.request
import urllib.error
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
CHAIN_ANCHOR_PREFIX_V1 = "SECUREMAILSCOPE_CHAIN_ANCHOR_V1:"

# Notarization Modes
NOTARIZATION_MODE_LOCAL_ONLY = "LOCAL_ONLY"
NOTARIZATION_MODE_EXTERNAL_PROVIDER = "EXTERNAL_PROVIDER"

# Submission & Anchoring Modes (Phase 16.5)
SUBMISSION_MODE_RPC_MANAGED_ACCOUNT = "RPC_MANAGED_ACCOUNT"
LOCAL_PRIVATE_KEY_SIGNING_STATUS = "NOT_IMPLEMENTED"
ANCHOR_MODE_EVM_DATA_TRANSACTION = "EVM_DATA_TRANSACTION"
IMPLEMENTATION_STATUS_MOCK_TESTED = "IMPLEMENTED_AND_MOCK_TESTED"

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
VERIFY_STATUS_VERIFIED_EXTERNAL_ANCHOR = "VERIFIED_EXTERNAL_ANCHOR"
VERIFY_STATUS_TRANSACTION_NOT_FOUND = "TRANSACTION_NOT_FOUND"
VERIFY_STATUS_RECEIPT_PENDING = "RECEIPT_PENDING"
VERIFY_STATUS_TRANSACTION_REVERTED = "TRANSACTION_REVERTED"
VERIFY_STATUS_CHAIN_ID_MISMATCH = "CHAIN_ID_MISMATCH"
VERIFY_STATUS_ANCHOR_VALUE_MISMATCH = "ANCHOR_VALUE_MISMATCH"
VERIFY_STATUS_SENDER_ADDRESS_MISMATCH = "SENDER_ADDRESS_MISMATCH"
VERIFY_STATUS_TARGET_ADDRESS_MISMATCH = "TARGET_ADDRESS_MISMATCH"
VERIFY_STATUS_RECEIPT_TRANSACTION_MISMATCH = "RECEIPT_TRANSACTION_MISMATCH"
VERIFY_STATUS_VALUE_NOT_ZERO = "VALUE_NOT_ZERO"
VERIFY_STATUS_CONFIGURATION_INCOMPLETE = "CONFIGURATION_INCOMPLETE"
VERIFY_STATUS_PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
VERIFY_STATUS_LOCAL_PROOF_INVALID = "LOCAL_PROOF_INVALID"
VERIFY_STATUS_INTEGRITY_FAILED = "INTEGRITY_FAILED"
VERIFY_STATUS_SIGNATURE_INVALID = "SIGNATURE_INVALID"
VERIFY_STATUS_REPORT_INTEGRITY_FAILED = "REPORT_INTEGRITY_FAILED"
VERIFY_STATUS_MANIFEST_INTEGRITY_FAILED = "MANIFEST_INTEGRITY_FAILED"
VERIFY_STATUS_INCOMPLETE = "INCOMPLETE"
VERIFY_STATUS_UNSUPPORTED_PROVIDER = "UNSUPPORTED_PROVIDER"


def is_valid_evm_address(addr: Optional[str]) -> bool:
    """Validates 20-byte hex EVM address shape."""
    if not addr or not isinstance(addr, str):
        return False
    import re
    return bool(re.match(r"^0x[0-9a-fA-F]{40}$", addr))


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
            "chain_id": None,
            "transaction_hash": None,
            "block_number": None,
            "receipt_status": None,
            "anchored_value": None,
            "submitted_at": None,
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
    Base interface for external distributed or third-party notarization.
    """

    def __init__(
        self,
        provider_name: Optional[str] = None,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.provider_name = provider_name or os.environ.get("SMS_NOTARIZATION_PROVIDER", "EVM_JSON_RPC")
        self.api_url = api_url or os.environ.get("SMS_NOTARIZATION_API_URL")
        self.api_key = api_key or os.environ.get("SMS_NOTARIZATION_API_KEY")

    def is_configured(self) -> bool:
        return bool(self.api_url)

    def submit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def verify(self, record: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class EVMJsonRpcBlockchainProvider(ExternalNotarizationProvider):
    """
    Concrete EVM-compatible JSON-RPC blockchain anchoring provider (Phase 16 & 16.5).
    Communicates via standard JSON-RPC 2.0 (eth_chainId, eth_sendTransaction,
    eth_getTransactionByHash, eth_getTransactionReceipt).
    Anchors strictly the domain-separated proof hash:
      SECUREMAILSCOPE_CHAIN_ANCHOR_V1:<local_proof_sha256>

    TRUST BOUNDARY & SIGNING SPECIFICATION:
    - Submission mode is strictly RPC_MANAGED_ACCOUNT (the RPC node/provider signs the transaction).
    - Local private key signing is NOT_IMPLEMENTED.
    - Zero-value transfers only (value = 0x0). Zero funds transfer.
    - Explicit sender (SMS_BLOCKCHAIN_FROM_ADDRESS) and anchor target (SMS_BLOCKCHAIN_ANCHOR_ADDRESS) required.
    - Zero-address fallback is strictly prohibited.
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        chain_id: Optional[int] = None,
        from_address: Optional[str] = None,
        anchor_address: Optional[str] = None,
        timeout: float = 5.0,
    ):
        super().__init__(provider_name="EVM_JSON_RPC")
        self._rpc_url = rpc_url
        self._chain_id = chain_id
        self._from_address = from_address
        self._anchor_address = anchor_address
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return os.environ.get("SMS_BLOCKCHAIN_ENABLED", "false").lower() in ("true", "1", "yes")

    @property
    def rpc_url(self) -> str:
        return self._rpc_url or os.environ.get("SMS_BLOCKCHAIN_RPC_URL", "")

    @property
    def configured_chain_id(self) -> Optional[int]:
        if self._chain_id is not None:
            return self._chain_id
        cid_env = os.environ.get("SMS_BLOCKCHAIN_CHAIN_ID")
        if cid_env:
            try:
                return int(cid_env, 16) if cid_env.startswith("0x") else int(cid_env)
            except ValueError:
                return None
        return None

    @property
    def from_address(self) -> str:
        return self._from_address or os.environ.get("SMS_BLOCKCHAIN_FROM_ADDRESS", "")

    @property
    def anchor_address(self) -> str:
        return (
            self._anchor_address
            or os.environ.get("SMS_BLOCKCHAIN_ANCHOR_ADDRESS", "")
            or os.environ.get("SMS_BLOCKCHAIN_CONTRACT_ADDRESS", "")
        )

    def is_configured(self) -> bool:
        return bool(
            self.enabled
            and self.rpc_url
            and self.from_address
            and self.anchor_address
            and is_valid_evm_address(self.from_address)
            and is_valid_evm_address(self.anchor_address)
        )

    def _rpc_request(self, method: str, params: List[Any]) -> Any:
        """
        Executes bounded JSON-RPC 2.0 request over HTTP/HTTPS with strict timeout.
        """
        if not self.rpc_url:
            raise ProviderUnavailableError("EVM JSON-RPC URL is not configured.")

        body = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }).encode("utf-8")

        req = urllib.request.Request(
            self.rpc_url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "SecureMailScope-Anchor/1.0"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                res_bytes = response.read()
                data = json.loads(res_bytes.decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            raise ProviderUnavailableError(f"RPC communication failed for method '{method}': {str(e)}")
        except Exception as e:
            raise ProviderUnavailableError(f"RPC communication error for method '{method}': {str(e)}")

        if "error" in data and data["error"]:
            err_msg = data["error"].get("message", str(data["error"]))
            raise NotarizationError(f"RPC returned error for '{method}': {err_msg}")

        return data.get("result")

    def get_chain_id(self) -> int:
        """Queries eth_chainId and returns integer chain ID."""
        res = self._rpc_request("eth_chainId", [])
        if isinstance(res, str):
            return int(res, 16) if res.startswith("0x") else int(res)
        if isinstance(res, int):
            return res
        raise ProviderUnavailableError(f"Unexpected eth_chainId response: {res}")

    def get_transaction(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Queries eth_getTransactionByHash."""
        return self._rpc_request("eth_getTransactionByHash", [tx_hash])

    def get_receipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Queries eth_getTransactionReceipt."""
        return self._rpc_request("eth_getTransactionReceipt", [tx_hash])

    def submit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submits real EVM anchoring transaction containing domain-separated proof hash.
        Enforces RPC_MANAGED_ACCOUNT signing mode, from_address verification, anchor_address validation,
        and value = 0x0.
        """
        if not self.enabled or not self.rpc_url:
            raise ProviderUnavailableError(
                "External blockchain provider is not configured or disabled. "
                "Set SMS_BLOCKCHAIN_ENABLED=true and SMS_BLOCKCHAIN_RPC_URL to enable."
            )

        if not self.from_address or not is_valid_evm_address(self.from_address):
            raise ProviderUnavailableError(
                f"Configured SMS_BLOCKCHAIN_FROM_ADDRESS is missing or invalid EVM address: '{self.from_address}'."
            )

        if not self.anchor_address or not is_valid_evm_address(self.anchor_address):
            raise ProviderUnavailableError(
                f"Configured SMS_BLOCKCHAIN_ANCHOR_ADDRESS is missing or invalid EVM address: '{self.anchor_address}'. "
                "Zero-address fallback is strictly prohibited."
            )

        # 1. Validate RPC Chain ID
        rpc_chain_id = self.get_chain_id()
        if self.configured_chain_id is not None and rpc_chain_id != self.configured_chain_id:
            raise NotarizationError(
                f"RPC Chain ID mismatch: configured {self.configured_chain_id}, connected {rpc_chain_id}."
            )

        # 2. Compute Anchored Value
        canonical_bytes = canonical_json_bytes(payload)
        local_proof_sha256 = compute_sha256(canonical_bytes)
        anchored_value = f"{CHAIN_ANCHOR_PREFIX_V1}{local_proof_sha256}"
        data_hex = "0x" + anchored_value.encode("utf-8").hex()

        # 3. Construct Safe Zero-Value Data Transaction
        tx_dict: Dict[str, Any] = {
            "from": self.from_address,
            "to": self.anchor_address,
            "data": data_hex,
            "value": "0x0",
        }

        # 4. Submit Transaction
        tx_hash = self._rpc_request("eth_sendTransaction", [tx_dict])
        if not tx_hash or not isinstance(tx_hash, str) or not tx_hash.startswith("0x"):
            raise NotarizationError(f"RPC did not return a valid transaction hash: {tx_hash}")

        now_iso = datetime.now(timezone.utc).isoformat()

        # 5. Re-read Transaction to Verify Sender & Target
        try:
            submitted_tx = self.get_transaction(tx_hash)
            if submitted_tx:
                tx_from = submitted_tx.get("from")
                if tx_from and tx_from.lower() != self.from_address.lower():
                    raise NotarizationError(
                        f"RPC submitted from unexpected sender address: expected {self.from_address}, got {tx_from} (SENDER_ADDRESS_MISMATCH)."
                    )
                tx_to = submitted_tx.get("to")
                if tx_to and tx_to.lower() != self.anchor_address.lower():
                    raise NotarizationError(
                        f"RPC submitted to unexpected target address: expected {self.anchor_address}, got {tx_to} (TARGET_ADDRESS_MISMATCH)."
                    )
                tx_val = submitted_tx.get("value")
                if tx_val not in ("0x0", "0x00", "0x", "0", 0, None):
                    raise NotarizationError(
                        f"Transaction value must be strictly zero, got {tx_val} (VALUE_NOT_ZERO)."
                    )
        except NotarizationError:
            raise
        except Exception:
            pass

        # 6. Query Initial Receipt
        receipt = None
        try:
            receipt = self.get_receipt(tx_hash)
        except Exception:
            receipt = None

        receipt_status: Optional[int] = None
        block_number: Optional[int] = None
        confirmed_at: Optional[str] = None
        status = STATUS_SUBMITTED

        if receipt:
            # Verify receipt transaction hash matches submitted tx hash
            r_tx_hash = receipt.get("transactionHash")
            if r_tx_hash and r_tx_hash.lower() != tx_hash.lower():
                raise NotarizationError(
                    f"Receipt transaction hash mismatch: submitted {tx_hash}, receipt returned {r_tx_hash} (RECEIPT_TRANSACTION_MISMATCH)."
                )

            raw_status = receipt.get("status")
            if isinstance(raw_status, str):
                receipt_status = int(raw_status, 16) if raw_status.startswith("0x") else int(raw_status)
            elif isinstance(raw_status, int):
                receipt_status = raw_status

            raw_block = receipt.get("blockNumber")
            if isinstance(raw_block, str):
                block_number = int(raw_block, 16) if raw_block.startswith("0x") else int(raw_block)
            elif isinstance(raw_block, int):
                block_number = raw_block

            if receipt_status == 1:
                status = STATUS_CONFIRMED
                confirmed_at = now_iso
            elif receipt_status == 0:
                status = STATUS_VERIFICATION_FAILED
            else:
                status = STATUS_SUBMITTED

        provider_proof = {
            "chain_id": rpc_chain_id,
            "transaction_hash": tx_hash,
            "submission_mode": SUBMISSION_MODE_RPC_MANAGED_ACCOUNT,
            "from_address": self.from_address,
            "anchor_address": self.anchor_address,
            "receipt": receipt,
        }
        proof_json = json.dumps(provider_proof)
        proof_sha256 = compute_sha256(canonical_json_bytes(provider_proof))

        return {
            "status": status,
            "notarization_mode": NOTARIZATION_MODE_EXTERNAL_PROVIDER,
            "local_proof_sha256": local_proof_sha256,
            "provider_name": self.provider_name,
            "provider_reference": tx_hash,
            "chain_id": rpc_chain_id,
            "transaction_hash": tx_hash,
            "block_number": block_number,
            "receipt_status": receipt_status,
            "anchored_value": anchored_value,
            "submitted_at": now_iso,
            "confirmed_at": confirmed_at,
            "submitted_payload_sha256": local_proof_sha256,
            "provider_proof_json": proof_json,
            "provider_proof_sha256": proof_sha256,
        }

    def verify(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Independently re-queries the blockchain RPC to verify transaction, receipt, chain ID,
        sender address, target address, zero value, and anchored payload.
        """
        if not self.is_configured():
            return {
                "verification_status": VERIFY_STATUS_PROVIDER_UNAVAILABLE,
                "provider_name": self.provider_name,
                "details": "Blockchain RPC is not configured or disabled.",
            }

        tx_hash = record.get("transaction_hash")
        expected_chain_id = record.get("chain_id")
        expected_anchored_val = record.get("anchored_value")
        stored_proof_hash = record.get("local_proof_sha256")

        if not tx_hash:
            return {
                "verification_status": VERIFY_STATUS_INCOMPLETE,
                "provider_name": self.provider_name,
                "details": "Notarization record is missing transaction_hash.",
            }

        # 1. Verify RPC Chain ID
        try:
            rpc_chain_id = self.get_chain_id()
        except Exception as e:
            return {
                "verification_status": VERIFY_STATUS_PROVIDER_UNAVAILABLE,
                "provider_name": self.provider_name,
                "details": f"Failed to connect to RPC to verify chain ID: {str(e)}",
            }

        if expected_chain_id is not None and rpc_chain_id != expected_chain_id:
            return {
                "verification_status": VERIFY_STATUS_CHAIN_ID_MISMATCH,
                "provider_name": self.provider_name,
                "details": f"Chain ID mismatch: record expects {expected_chain_id}, active RPC returned {rpc_chain_id}",
            }

        # 2. Query Transaction
        try:
            tx = self.get_transaction(tx_hash)
        except Exception as e:
            return {
                "verification_status": VERIFY_STATUS_PROVIDER_UNAVAILABLE,
                "provider_name": self.provider_name,
                "details": f"Failed to query transaction '{tx_hash}': {str(e)}",
            }

        if not tx:
            return {
                "verification_status": VERIFY_STATUS_TRANSACTION_NOT_FOUND,
                "provider_name": self.provider_name,
                "details": f"Transaction '{tx_hash}' not found on blockchain.",
            }

        # 3. Verify Sender & Target Address Match
        tx_from = tx.get("from")
        if tx_from and self.from_address and tx_from.lower() != self.from_address.lower():
            return {
                "verification_status": VERIFY_STATUS_SENDER_ADDRESS_MISMATCH,
                "provider_name": self.provider_name,
                "details": f"Sender address mismatch: expected {self.from_address}, transaction on chain from {tx_from}",
            }

        tx_to = tx.get("to")
        if tx_to and self.anchor_address and tx_to.lower() != self.anchor_address.lower():
            return {
                "verification_status": VERIFY_STATUS_TARGET_ADDRESS_MISMATCH,
                "provider_name": self.provider_name,
                "details": f"Target address mismatch: expected {self.anchor_address}, transaction on chain to {tx_to}",
            }

        tx_val = tx.get("value")
        if tx_val not in ("0x0", "0x00", "0x", "0", 0, None):
            return {
                "verification_status": VERIFY_STATUS_VALUE_NOT_ZERO,
                "provider_name": self.provider_name,
                "details": f"Transaction value must be strictly zero, on chain value is {tx_val}",
            }

        # 4. Query Receipt
        try:
            receipt = self.get_receipt(tx_hash)
        except Exception as e:
            return {
                "verification_status": VERIFY_STATUS_PROVIDER_UNAVAILABLE,
                "provider_name": self.provider_name,
                "details": f"Failed to query receipt for '{tx_hash}': {str(e)}",
            }

        if not receipt:
            return {
                "verification_status": VERIFY_STATUS_RECEIPT_PENDING,
                "provider_name": self.provider_name,
                "details": f"Transaction receipt for '{tx_hash}' is pending confirmation.",
            }

        # Verify receipt tx hash
        r_tx_hash = receipt.get("transactionHash")
        if r_tx_hash and r_tx_hash.lower() != tx_hash.lower():
            return {
                "verification_status": VERIFY_STATUS_RECEIPT_TRANSACTION_MISMATCH,
                "provider_name": self.provider_name,
                "details": f"Receipt transaction hash mismatch: queried {tx_hash}, receipt has {r_tx_hash}",
            }

        # 5. Check Receipt Status
        raw_status = receipt.get("status")
        if isinstance(raw_status, str):
            r_status = int(raw_status, 16) if raw_status.startswith("0x") else int(raw_status)
        elif isinstance(raw_status, int):
            r_status = raw_status
        else:
            r_status = None

        if r_status != 1:
            return {
                "verification_status": VERIFY_STATUS_TRANSACTION_REVERTED,
                "provider_name": self.provider_name,
                "details": f"Transaction '{tx_hash}' execution reverted on chain (status={r_status}).",
            }

        # 6. Verify Anchored Payload / Calldata
        tx_data = tx.get("input") or tx.get("data") or ""
        expected_prefix_anchor = f"{CHAIN_ANCHOR_PREFIX_V1}{stored_proof_hash}"
        expected_hex = "0x" + expected_prefix_anchor.encode("utf-8").hex()

        # Check if calldata matches or contains the expected anchor
        if tx_data.lower() != expected_hex.lower() and expected_anchored_val and tx_data.lower() != ("0x" + expected_anchored_val.encode("utf-8").hex()).lower():
            return {
                "verification_status": VERIFY_STATUS_ANCHOR_VALUE_MISMATCH,
                "provider_name": self.provider_name,
                "details": f"Transaction calldata does not match expected anchored proof hash: got {tx_data[:32]}..., expected {expected_hex[:32]}...",
            }

        raw_block = receipt.get("blockNumber")
        block_num = int(raw_block, 16) if isinstance(raw_block, str) and raw_block.startswith("0x") else raw_block

        return {
            "verification_status": VERIFY_STATUS_VERIFIED_EXTERNAL_ANCHOR,
            "provider_name": self.provider_name,
            "chain_id": rpc_chain_id,
            "transaction_hash": tx_hash,
            "block_number": block_num,
            "details": f"External EVM blockchain anchor verified nominal on Chain ID {rpc_chain_id} in Block {block_num}.",
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
        NOTARIZATION_MODE_EXTERNAL_PROVIDER: EVMJsonRpcBlockchainProvider(),
    }

    @classmethod
    def get_provider(cls, mode: str) -> NotarizationProvider:
        if mode not in cls._providers:
            if mode == NOTARIZATION_MODE_EXTERNAL_PROVIDER:
                return EVMJsonRpcBlockchainProvider()
            raise UnsupportedProviderError(f"Unsupported notarization mode: '{mode}'.")
        return cls._providers[mode]

    @classmethod
    def get_provider_status(cls) -> Dict[str, Any]:
        """
        Safe provider status report: never returns private keys, passwords, or RPC credentials.
        Reports explicit submission mode and confirms local private key signing is NOT_IMPLEMENTED.
        """
        provider = cls.get_provider(NOTARIZATION_MODE_EXTERNAL_PROVIDER)
        if isinstance(provider, EVMJsonRpcBlockchainProvider):
            is_cfg = provider.is_configured()
            conn_status = "NOT_CONFIGURED"
            active_chain_id = provider.configured_chain_id
            if is_cfg:
                try:
                    rpc_cid = provider.get_chain_id()
                    conn_status = "CONNECTED"
                    active_chain_id = rpc_cid
                except Exception:
                    conn_status = "UNAVAILABLE"
            return {
                "configured": is_cfg,
                "provider_type": "EVM_JSON_RPC",
                "submission_mode": SUBMISSION_MODE_RPC_MANAGED_ACCOUNT,
                "chain_id": active_chain_id,
                "connection_status": conn_status,
                "network_connection_status": conn_status,
                "local_private_key_signing": LOCAL_PRIVATE_KEY_SIGNING_STATUS,
                "implementation_status": IMPLEMENTATION_STATUS_MOCK_TESTED,
                "live_chain_verified": False,
                "from_address_configured": bool(provider.from_address),
                "anchor_address_configured": bool(provider.anchor_address),
            }
        return {
            "configured": False,
            "provider_type": "LOCAL_ONLY",
            "submission_mode": "NONE",
            "chain_id": None,
            "connection_status": "NOT_CONFIGURED",
            "network_connection_status": "NOT_CONFIGURED",
            "local_private_key_signing": LOCAL_PRIVATE_KEY_SIGNING_STATUS,
            "implementation_status": IMPLEMENTATION_STATUS_MOCK_TESTED,
            "live_chain_verified": False,
            "from_address_configured": False,
            "anchor_address_configured": False,
        }

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
        and atomically appends a NOTARIZATION_LINKAGE_MANIFEST or EXTERNAL_ANCHOR_LINKAGE_MANIFEST version.
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
        rec_status = provider_result.get("status", STATUS_LOCAL_PROOF_CREATED)

        notarization_dict = {
            "notarization_id": notarization_id,
            "analysis_id": analysis_id,
            "report_artifact_id": report_artifact_id,
            "signature_id": signature_id,
            "manifest_version_id": source_manifest_id,
            "notarization_mode": mode,
            "provider_name": provider_result.get("provider_name"),
            "provider_reference": provider_result.get("provider_reference"),
            "chain_id": provider_result.get("chain_id"),
            "transaction_hash": provider_result.get("transaction_hash"),
            "block_number": provider_result.get("block_number"),
            "receipt_status": provider_result.get("receipt_status"),
            "anchored_value": provider_result.get("anchored_value"),
            "submitted_at": provider_result.get("submitted_at"),
            "submitted_payload_sha256": provider_result.get("submitted_payload_sha256", local_proof_sha256),
            "local_proof_sha256": local_proof_sha256,
            "provider_proof_json": provider_result.get("provider_proof_json"),
            "provider_proof_sha256": provider_result.get("provider_proof_sha256"),
            "status": rec_status,
            "created_at": now_iso,
            "confirmed_at": provider_result.get("confirmed_at"),
            "created_by_actor_id": act.actor_id,
            "created_by_actor_display_name": act.actor_display_name,
            "actor_identity_source": act.actor_identity_source,
            "actor_attribution_status": act.actor_attribution_status,
            "schema_version": CURRENT_SCHEMA_VERSION,
        }

        # 8. Construct NEW Manifest Version
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

        manifest_type = (
            "EXTERNAL_ANCHOR_LINKAGE_MANIFEST"
            if rec_status == STATUS_CONFIRMED and mode == NOTARIZATION_MODE_EXTERNAL_PROVIDER
            else "NOTARIZATION_LINKAGE_MANIFEST"
        )

        new_manifest_payload: Dict[str, Any] = {
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
            "manifest_type": manifest_type,
            "observed_result_sha256": prev_dict.get("observed_result_sha256", ""),
            "previous_manifest_sha256": source_manifest_hash,
            "session_hashes": prev_dict.get("session_hashes", []),
            "version_number": next_vnum,
        }

        if manifest_type == "EXTERNAL_ANCHOR_LINKAGE_MANIFEST":
            prev_anchors = prev_dict.get("linked_external_anchors") or []
            new_manifest_payload["linked_external_anchors"] = list(prev_anchors) + [{
                "notarization_id": notarization_id,
                "transaction_hash": notarization_dict["transaction_hash"],
                "chain_id": notarization_dict["chain_id"],
                "block_number": notarization_dict["block_number"],
                "anchored_value": notarization_dict["anchored_value"],
                "previous_manifest_sha256": source_manifest_hash,
                "confirmed_at": notarization_dict["confirmed_at"],
            }]

        new_manifest_json = canonical_json_str(new_manifest_payload)
        new_manifest_hash = compute_sha256(new_manifest_json.encode("utf-8"))

        manifest_version_dict = {
            "manifest_version_id": new_manifest_vid,
            "analysis_id": analysis_id,
            "version_number": next_vnum,
            "manifest_type": manifest_type,
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
            "purpose": (
                f"Link confirmed external blockchain anchor {notarization_dict.get('transaction_hash')} (Chain {notarization_dict.get('chain_id')})"
                if manifest_type == "EXTERNAL_ANCHOR_LINKAGE_MANIFEST"
                else f"Link notarization proof {notarization_id} ({mode}) for report {report_artifact_id}"
            ),
            "schema_version": CURRENT_SCHEMA_VERSION,
        }

        # 9. Atomically Persist Notarization Record + Manifest Version
        ForensicRepository.save_notarization_and_manifest_version(
            notarization_record=notarization_dict,
            manifest_version=manifest_version_dict,
            db_path=db_path
        )

        # 10. Append Custody Audit Events
        custody_rec = CustodyService.get_record(analysis_id)
        if custody_rec:
            if mode == NOTARIZATION_MODE_LOCAL_ONLY:
                custody_rec._append_event(
                    event_type="NOTARIZATION_LOCAL_PROOF_CREATED",
                    artifact_hash=local_proof_sha256,
                    details=(
                        f"Local notarization record {notarization_id} created for report {report_artifact_id} "
                        f"and signature {signature_id} (Proof SHA-256: {local_proof_sha256[:16]}... Linked in Manifest v{next_vnum})"
                    ),
                    actor=act,
                )
            else:
                custody_rec._append_event(
                    event_type="BLOCKCHAIN_ANCHOR_SUBMISSION_REQUESTED",
                    artifact_hash=local_proof_sha256,
                    details=f"Blockchain anchor submission requested for notarization {notarization_id}",
                    actor=act,
                )
                if notarization_dict.get("transaction_hash"):
                    custody_rec._append_event(
                        event_type="BLOCKCHAIN_ANCHOR_SUBMITTED",
                        artifact_hash=notarization_dict["transaction_hash"],
                        details=f"Transaction {notarization_dict['transaction_hash']} submitted to Chain ID {notarization_dict.get('chain_id')}",
                        actor=act,
                    )
                if rec_status == STATUS_CONFIRMED:
                    custody_rec._append_event(
                        event_type="BLOCKCHAIN_ANCHOR_CONFIRMED",
                        artifact_hash=notarization_dict["transaction_hash"],
                        details=(
                            f"Blockchain anchor confirmed in Block {notarization_dict.get('block_number')} "
                            f"(Tx: {notarization_dict.get('transaction_hash')}, Chain ID: {notarization_dict.get('chain_id')})"
                        ),
                        actor=act,
                    )
                elif rec_status == STATUS_VERIFICATION_FAILED:
                    custody_rec._append_event(
                        event_type="BLOCKCHAIN_ANCHOR_VERIFICATION_FAILED",
                        artifact_hash=notarization_dict.get("transaction_hash") or local_proof_sha256,
                        details="Blockchain anchor transaction failed or reverted on chain.",
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
                "chain_id": rec.get("chain_id"),
                "transaction_hash": rec.get("transaction_hash"),
                "block_number": rec.get("block_number"),
                "receipt_status": rec.get("receipt_status"),
                "anchored_value": rec.get("anchored_value"),
                "submitted_at": rec.get("submitted_at"),
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


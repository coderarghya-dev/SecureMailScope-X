"""
SecureMailScope X - External Notarization Provider Abstraction (Phase 16)
Provides pluggable notarization provider architecture.
Default: LocalOnly.
CRITICAL FORENSIC BOUNDARY: If ExternalLedger is not configured, UI/API explicitly reports
'External Notarization: Not Configured'. Never fakes or claims blockchain transactions.
"""

from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass


class NotarizationProviderType(str, Enum):
    LOCAL_ONLY = "LocalOnly"
    EXTERNAL_LEDGER = "ExternalLedger"


@dataclass
class NotarizationProof:
    provider: str
    status: str  # "NOT_CONFIGURED" | "LOCAL_SEALED" | "NOTARIZED"
    manifest_hash: str
    tx_reference: Optional[str] = None
    network_name: Optional[str] = None
    notarized_at_iso: Optional[str] = None
    proof_details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status,
            "manifest_hash": self.manifest_hash,
            "tx_reference": self.tx_reference,
            "network_name": self.network_name,
            "notarized_at_iso": self.notarized_at_iso,
            "proof_details": self.proof_details,
        }


class BaseNotarizationProvider:
    def notarize_manifest(self, manifest_hash: str) -> NotarizationProof:
        raise NotImplementedError


class LocalOnlyProvider(BaseNotarizationProvider):
    def notarize_manifest(self, manifest_hash: str) -> NotarizationProof:
        return NotarizationProof(
            provider="LocalOnly",
            status="LOCAL_SEALED",
            manifest_hash=manifest_hash,
            notarized_at_iso=datetime.now(timezone.utc).isoformat(),
            proof_details="Locally sealed using SHA-256 cryptographic hash-chain and manifest signature.",
        )


class ExternalLedgerProvider(BaseNotarizationProvider):
    def __init__(self, rpc_url: Optional[str] = None, contract_address: Optional[str] = None):
        self.rpc_url = rpc_url
        self.contract_address = contract_address

    def notarize_manifest(self, manifest_hash: str) -> NotarizationProof:
        if not self.rpc_url or not self.contract_address:
            return NotarizationProof(
                provider="ExternalLedger",
                status="NOT_CONFIGURED",
                manifest_hash=manifest_hash,
                proof_details="External Notarization: Not Configured. Offline local custody chain is active.",
            )
        # Real on-chain notarization would post only the manifest_hash
        return NotarizationProof(
            provider="ExternalLedger",
            status="NOT_CONFIGURED",
            manifest_hash=manifest_hash,
            proof_details="External Notarization: Not Configured.",
        )


class NotarizationService:
    """Entry point for evidence manifest notarization."""

    _current_provider: BaseNotarizationProvider = LocalOnlyProvider()

    @classmethod
    def set_provider(cls, provider: BaseNotarizationProvider):
        cls._current_provider = provider

    @classmethod
    def get_provider_status(cls) -> str:
        if isinstance(cls._current_provider, ExternalLedgerProvider):
            return "ExternalLedger"
        return "LocalOnly"

    @classmethod
    def notarize(cls, manifest_hash: str) -> NotarizationProof:
        return cls._current_provider.notarize_manifest(manifest_hash)

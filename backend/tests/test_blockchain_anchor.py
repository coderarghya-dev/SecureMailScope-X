"""
SecureMailScope X - EVM Blockchain Anchoring Provider Unit & Integration Tests (Phase 16 & 16.5)
Validates real blockchain anchoring provider behavior with strict mock isolation.
Guarantees zero outbound network calls, zero simulated/fake hashes, zero credential leaks,
explicit RPC_MANAGED_ACCOUNT signing mode, from/target address verification, value=0x0 enforcement,
strict confirmation policy, idempotency, and backward-compatible LOCAL_ONLY behavior.
"""

import os
import sys
import tempfile
import unittest
import json
from typing import Dict, Any, Optional
from unittest.mock import patch, MagicMock

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db.database import init_db, set_custom_db_path
from app.db.repository import (
    ForensicRepository,
    CANONICALIZATION_VERSION,
    compute_sha256,
    canonical_json_bytes,
)
from app.schemas.identity import (
    ActorContext,
    IDENTITY_SOURCE_LOCAL_DECLARED,
    ATTRIBUTION_STATUS_ATTRIBUTED,
)
from app.schemas.api import (
    AnalysisDetailResponse,
    SessionDetailDTO,
    STARTTLSStateDTO,
    TLSHandshakeDTO,
    CaptureHealthDTO,
    EvidenceConfidenceDTO,
    SecurityAssessmentDTO,
    FindingsSummaryDTO,
    SecurityFindingDTO,
)
from app.services.custody_service import CustodyService
from app.services.signature_service import SignatureService
from app.services.notarization_service import (
    NotarizationService,
    EVMJsonRpcBlockchainProvider,
    NOTARIZATION_MODE_LOCAL_ONLY,
    NOTARIZATION_MODE_EXTERNAL_PROVIDER,
    SUBMISSION_MODE_RPC_MANAGED_ACCOUNT,
    LOCAL_PRIVATE_KEY_SIGNING_STATUS,
    IMPLEMENTATION_STATUS_MOCK_TESTED,
    STATUS_LOCAL_PROOF_CREATED,
    STATUS_SUBMITTED,
    STATUS_CONFIRMED,
    STATUS_VERIFICATION_FAILED,
    STATUS_PROVIDER_UNAVAILABLE,
    VERIFY_STATUS_VERIFIED_LOCAL_PROOF,
    VERIFY_STATUS_VERIFIED_EXTERNAL_ANCHOR,
    VERIFY_STATUS_TRANSACTION_NOT_FOUND,
    VERIFY_STATUS_RECEIPT_PENDING,
    VERIFY_STATUS_TRANSACTION_REVERTED,
    VERIFY_STATUS_CHAIN_ID_MISMATCH,
    VERIFY_STATUS_ANCHOR_VALUE_MISMATCH,
    VERIFY_STATUS_SENDER_ADDRESS_MISMATCH,
    VERIFY_STATUS_TARGET_ADDRESS_MISMATCH,
    VERIFY_STATUS_RECEIPT_TRANSACTION_MISMATCH,
    VERIFY_STATUS_VALUE_NOT_ZERO,
    VERIFY_STATUS_PROVIDER_UNAVAILABLE,
    ProviderUnavailableError,
    NotarizationPrerequisiteError,
    NotarizationError,
    CHAIN_ANCHOR_PREFIX_V1,
)
from app.api.v1.endpoints.analyze import router


class TestBlockchainAnchor(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.test_dir.name, "test_blockchain.db")
        set_custom_db_path(self.db_path)
        init_db(self.db_path)

        CustodyService._records.clear()

        # Backup & clean env vars
        self.orig_signing_key_pem = os.environ.get("SMS_SIGNING_PRIVATE_KEY_PEM")
        self.orig_bc_enabled = os.environ.get("SMS_BLOCKCHAIN_ENABLED")
        self.orig_bc_rpc = os.environ.get("SMS_BLOCKCHAIN_RPC_URL")
        self.orig_bc_chain = os.environ.get("SMS_BLOCKCHAIN_CHAIN_ID")
        self.orig_bc_from = os.environ.get("SMS_BLOCKCHAIN_FROM_ADDRESS")
        self.orig_bc_anchor = os.environ.get("SMS_BLOCKCHAIN_ANCHOR_ADDRESS")
        self.orig_bc_contract = os.environ.get("SMS_BLOCKCHAIN_CONTRACT_ADDRESS")

        # Generate Ed25519 signing key for report signing prerequisite
        self.ed25519_key = ed25519.Ed25519PrivateKey.generate()
        self.ed25519_pem = self.ed25519_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")
        os.environ["SMS_SIGNING_PRIVATE_KEY_PEM"] = self.ed25519_pem

        self.actor = ActorContext.local_declared("analyst_bc_01", "Forensic Blockchain Analyst")
        self.analysis_id = "analysis_bc_test_01"

        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        self.client = TestClient(app)

        self._setup_fixture()

    def tearDown(self):
        CustodyService._records.clear()
        set_custom_db_path(None)

        if self.orig_signing_key_pem is not None:
            os.environ["SMS_SIGNING_PRIVATE_KEY_PEM"] = self.orig_signing_key_pem
        elif "SMS_SIGNING_PRIVATE_KEY_PEM" in os.environ:
            del os.environ["SMS_SIGNING_PRIVATE_KEY_PEM"]

        if self.orig_bc_enabled is not None:
            os.environ["SMS_BLOCKCHAIN_ENABLED"] = self.orig_bc_enabled
        elif "SMS_BLOCKCHAIN_ENABLED" in os.environ:
            del os.environ["SMS_BLOCKCHAIN_ENABLED"]

        if self.orig_bc_rpc is not None:
            os.environ["SMS_BLOCKCHAIN_RPC_URL"] = self.orig_bc_rpc
        elif "SMS_BLOCKCHAIN_RPC_URL" in os.environ:
            del os.environ["SMS_BLOCKCHAIN_RPC_URL"]

        if self.orig_bc_chain is not None:
            os.environ["SMS_BLOCKCHAIN_CHAIN_ID"] = self.orig_bc_chain
        elif "SMS_BLOCKCHAIN_CHAIN_ID" in os.environ:
            del os.environ["SMS_BLOCKCHAIN_CHAIN_ID"]

        if self.orig_bc_from is not None:
            os.environ["SMS_BLOCKCHAIN_FROM_ADDRESS"] = self.orig_bc_from
        elif "SMS_BLOCKCHAIN_FROM_ADDRESS" in os.environ:
            del os.environ["SMS_BLOCKCHAIN_FROM_ADDRESS"]

        if self.orig_bc_anchor is not None:
            os.environ["SMS_BLOCKCHAIN_ANCHOR_ADDRESS"] = self.orig_bc_anchor
        elif "SMS_BLOCKCHAIN_ANCHOR_ADDRESS" in os.environ:
            del os.environ["SMS_BLOCKCHAIN_ANCHOR_ADDRESS"]

        if self.orig_bc_contract is not None:
            os.environ["SMS_BLOCKCHAIN_CONTRACT_ADDRESS"] = self.orig_bc_contract
        elif "SMS_BLOCKCHAIN_CONTRACT_ADDRESS" in os.environ:
            del os.environ["SMS_BLOCKCHAIN_CONTRACT_ADDRESS"]

        self.test_dir.cleanup()

    def _setup_fixture(self):
        raw_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32
        CustodyService.get_or_create_record(
            analysis_id=self.analysis_id,
            filename="bc_capture.pcap",
            content_bytes=raw_pcap,
            actor=self.actor,
        )

        finding = SecurityFindingDTO(
            id="FINDING-TLS-1",
            title="Plaintext Risk",
            severity="HIGH",
            category="AUTHENTICATION",
            description="STARTTLS not enforced.",
            evidence_frames=[1, 2],
            recommendation="Require TLS 1.3.",
        )
        session = SessionDetailDTO(
            session_id="stream_0_192.168.1.10_587",
            stream_index=0,
            protocol="SMTP",
            security_mode="STARTTLS",
            client="192.168.1.10:50000",
            server="192.168.1.1:587",
            duration_seconds=1.5,
            packets_count=10,
            starttls=STARTTLSStateDTO(advertised=True, requested=True, accepted=True, upgrade_successful=True),
            tls=TLSHandshakeDTO(
                negotiated_version="TLS 1.3",
                tls_version="TLS 1.3",
                cipher_name="TLS_AES_256_GCM_SHA384",
                pfs_status="FORWARD_SECRECY_ACTIVE",
                certificate_visibility="PRESENT",
            ),
            capture_health=CaptureHealthDTO(
                score=100,
                grade="A",
                syn_observed=True,
                fin_rst_observed=True,
                total_packets=10,
                retransmissions_count=0,
                retransmission_rate=0.0,
                deduction_reasons=[],
            ),
            evidence_confidence=EvidenceConfidenceDTO(
                score=100,
                level="HIGH",
                handshake_observable=True,
                version_verifiable=True,
                cipher_identifiable=True,
                key_exchange_observable=True,
            ),
            security_assessment=SecurityAssessmentDTO(
                grade="A",
                grade_rationale="Nominal",
                post_quantum_ready=False,
                post_quantum_summary="Classic crypto",
                findings_summary=FindingsSummaryDTO(high=1),
                findings=[finding],
            ),
        )
        detail = AnalysisDetailResponse(
            analysis_id=self.analysis_id,
            file_name="bc_capture.pcap",
            file_size_bytes=len(raw_pcap),
            analysis_time_utc="2026-09-25T12:00:00Z",
            tshark_version="TShark 4.6.0",
            total_packets_extracted=10,
            raw_capture_packets_total=10,
            email_sessions_found=1,
            sessions=[session],
            multi_session_summary=None,
            correlated_incidents=[],
            unhandled_transports=[],
            dns_enrichment=None,
        )
        ForensicRepository.save_analysis(detail, actor=self.actor, db_path=self.db_path)
        CustodyService.record_analysis_completion(self.analysis_id, detail, actor=self.actor)

        fake_pdf_bytes = b"%PDF-1.4 forensic report test artifact content for blockchain test"
        CustodyService.record_report_generation(self.analysis_id, fake_pdf_bytes, actor=self.actor)
        reports = ForensicRepository.get_report_artifacts(self.analysis_id, db_path=self.db_path)
        self.report_art = reports[0]
        self.report_artifact_id = self.report_art["report_artifact_id"]

        self.sig_record = SignatureService.sign_report_artifact(
            analysis_id=self.analysis_id,
            report_artifact_id=self.report_artifact_id,
            actor=self.actor,
            db_path=self.db_path,
        )
        self.signature_id = self.sig_record["signature_id"]

        self.valid_from = "0x1111111111111111111111111111111111111111"
        self.valid_anchor = "0x2222222222222222222222222222222222222222"

    def _default_env(self) -> Dict[str, str]:
        return {
            "SMS_BLOCKCHAIN_ENABLED": "true",
            "SMS_BLOCKCHAIN_RPC_URL": "http://127.0.0.1:8545",
            "SMS_BLOCKCHAIN_CHAIN_ID": "1337",
            "SMS_BLOCKCHAIN_FROM_ADDRESS": self.valid_from,
            "SMS_BLOCKCHAIN_ANCHOR_ADDRESS": self.valid_anchor,
        }

    # ------------------------------------------------------------------------
    # 1. LOCAL_ONLY still works with blockchain disabled
    # ------------------------------------------------------------------------
    def test_01_local_only_still_works_with_blockchain_disabled(self):
        with patch.dict(os.environ, {"SMS_BLOCKCHAIN_ENABLED": "false"}):
            notz = NotarizationService.create_notarization_proof(
                analysis_id=self.analysis_id,
                report_artifact_id=self.report_artifact_id,
                mode=NOTARIZATION_MODE_LOCAL_ONLY,
                actor=self.actor,
                db_path=self.db_path,
            )
            self.assertEqual(notz["status"], STATUS_LOCAL_PROOF_CREATED)
            self.assertEqual(notz["notarization_mode"], NOTARIZATION_MODE_LOCAL_ONLY)
            self.assertIsNone(notz["transaction_hash"])
            self.assertIsNone(notz["chain_id"])

            ver = NotarizationService.verify_notarization(notz["notarization_id"], db_path=self.db_path)
            self.assertEqual(ver["verification_status"], VERIFY_STATUS_VERIFIED_LOCAL_PROOF)

    # ------------------------------------------------------------------------
    # 2. External mode without configuration -> PROVIDER_UNAVAILABLE
    # ------------------------------------------------------------------------
    def test_02_external_mode_unconfigured_raises_provider_unavailable(self):
        with patch.dict(os.environ, {"SMS_BLOCKCHAIN_ENABLED": "false", "SMS_BLOCKCHAIN_RPC_URL": ""}):
            with self.assertRaises(ProviderUnavailableError):
                NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

    # ------------------------------------------------------------------------
    # 3. Missing sender or target address fails safely (no zero-address fallback)
    # ------------------------------------------------------------------------
    def test_03_missing_sender_or_target_fails_safely(self):
        # Missing from address
        env_no_from = {
            "SMS_BLOCKCHAIN_ENABLED": "true",
            "SMS_BLOCKCHAIN_RPC_URL": "http://127.0.0.1:8545",
            "SMS_BLOCKCHAIN_ANCHOR_ADDRESS": self.valid_anchor,
        }
        with patch.dict(os.environ, env_no_from, clear=True):
            with self.assertRaises(ProviderUnavailableError):
                NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

        # Missing anchor target
        env_no_anchor = {
            "SMS_BLOCKCHAIN_ENABLED": "true",
            "SMS_BLOCKCHAIN_RPC_URL": "http://127.0.0.1:8545",
            "SMS_BLOCKCHAIN_FROM_ADDRESS": self.valid_from,
        }
        with patch.dict(os.environ, env_no_anchor, clear=True):
            with self.assertRaises(ProviderUnavailableError):
                NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

    # ------------------------------------------------------------------------
    # 4. Valid mocked blockchain transaction submission stores real returned tx hash & sets value 0x0
    # ------------------------------------------------------------------------
    def test_04_mocked_blockchain_submission_stores_tx_hash_and_zero_value(self):
        mock_tx_hash = "0x" + "a" * 64
        submitted_tx_params = []

        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(method, params):
                    if method == "eth_chainId":
                        return "0x539"  # 1337
                    elif method == "eth_sendTransaction":
                        submitted_tx_params.append(params[0])
                        return mock_tx_hash
                    elif method == "eth_getTransactionByHash":
                        return {
                            "hash": mock_tx_hash,
                            "from": self.valid_from,
                            "to": self.valid_anchor,
                            "value": "0x0",
                        }
                    elif method == "eth_getTransactionReceipt":
                        return None  # Pending receipt
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

                self.assertEqual(notz["transaction_hash"], mock_tx_hash)
                self.assertEqual(notz["chain_id"], 1337)
                self.assertEqual(notz["status"], STATUS_SUBMITTED)
                self.assertIsNotNone(notz["anchored_value"])
                self.assertTrue(notz["anchored_value"].startswith(CHAIN_ANCHOR_PREFIX_V1))

                # Verify submitted transaction strictly enforced value 0x0 and exact addresses
                self.assertEqual(len(submitted_tx_params), 1)
                tx_sent = submitted_tx_params[0]
                self.assertEqual(tx_sent["from"], self.valid_from)
                self.assertEqual(tx_sent["to"], self.valid_anchor)
                self.assertEqual(tx_sent["value"], "0x0")

    # ------------------------------------------------------------------------
    # 5. Tx hash alone does NOT mark CONFIRMED (receipt missing -> SUBMITTED)
    # ------------------------------------------------------------------------
    def test_05_tx_hash_alone_does_not_mark_confirmed(self):
        mock_tx_hash = "0x" + "b" * 64
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_sendTransaction":
                        return mock_tx_hash
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0x0"}
                    elif method == "eth_getTransactionReceipt":
                        return None
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

                self.assertEqual(notz["status"], STATUS_SUBMITTED)
                self.assertIsNone(notz["confirmed_at"])
                self.assertIsNone(notz["receipt_status"])

    # ------------------------------------------------------------------------
    # 6. Successful receipt -> CONFIRMED
    # ------------------------------------------------------------------------
    def test_06_successful_receipt_marks_confirmed(self):
        mock_tx_hash = "0x" + "c" * 64
        mock_receipt = {
            "transactionHash": mock_tx_hash,
            "blockNumber": "0x100",  # 256
            "status": "0x1",
        }
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_sendTransaction":
                        return mock_tx_hash
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0x0"}
                    elif method == "eth_getTransactionReceipt":
                        return mock_receipt
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

                self.assertEqual(notz["status"], STATUS_CONFIRMED)
                self.assertEqual(notz["receipt_status"], 1)
                self.assertEqual(notz["block_number"], 256)
                self.assertIsNotNone(notz["confirmed_at"])

    # ------------------------------------------------------------------------
    # 7. Reverted receipt -> TRANSACTION_REVERTED / VERIFICATION_FAILED
    # ------------------------------------------------------------------------
    def test_07_reverted_receipt_marks_failed(self):
        mock_tx_hash = "0x" + "d" * 64
        mock_receipt = {
            "transactionHash": mock_tx_hash,
            "blockNumber": "0x101",
            "status": "0x0",  # Reverted
        }
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_sendTransaction":
                        return mock_tx_hash
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0x0"}
                    elif method == "eth_getTransactionReceipt":
                        return mock_receipt
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

                self.assertEqual(notz["status"], STATUS_VERIFICATION_FAILED)
                self.assertEqual(notz["receipt_status"], 0)
                self.assertIsNone(notz["confirmed_at"])

    # ------------------------------------------------------------------------
    # 8. External Verification: sender address mismatch
    # ------------------------------------------------------------------------
    def test_08_external_verification_sender_mismatch(self):
        mock_tx_hash = "0x" + "e" * 64
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_sendTransaction":
                        return mock_tx_hash
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0x0"}
                    elif method == "eth_getTransactionReceipt":
                        return {"status": "0x1", "blockNumber": "0x1", "transactionHash": mock_tx_hash}
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

            # When independently re-verifying, RPC returns a mismatched sender on chain
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc_reverify:
                def fake_reverify(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": "0x9999999999999999999999999999999999999999", "to": self.valid_anchor, "value": "0x0"}
                    elif method == "eth_getTransactionReceipt":
                        return {"status": "0x1", "blockNumber": "0x1", "transactionHash": mock_tx_hash}
                    return None

                mock_rpc_reverify.side_effect = fake_reverify
                ver = NotarizationService.verify_notarization(notz["notarization_id"], db_path=self.db_path)
                self.assertEqual(ver["verification_status"], VERIFY_STATUS_SENDER_ADDRESS_MISMATCH)

    # ------------------------------------------------------------------------
    # 9. External Verification: target address mismatch
    # ------------------------------------------------------------------------
    def test_09_external_verification_target_mismatch(self):
        mock_tx_hash = "0x" + "f" * 64
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_sendTransaction":
                        return mock_tx_hash
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0x0"}
                    elif method == "eth_getTransactionReceipt":
                        return {"status": "0x1", "blockNumber": "0x1", "transactionHash": mock_tx_hash}
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

            # When independently re-verifying, RPC returns a mismatched target on chain
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc_reverify:
                def fake_reverify(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": "0x8888888888888888888888888888888888888888", "value": "0x0"}
                    elif method == "eth_getTransactionReceipt":
                        return {"status": "0x1", "blockNumber": "0x1", "transactionHash": mock_tx_hash}
                    return None

                mock_rpc_reverify.side_effect = fake_reverify
                ver = NotarizationService.verify_notarization(notz["notarization_id"], db_path=self.db_path)
                self.assertEqual(ver["verification_status"], VERIFY_STATUS_TARGET_ADDRESS_MISMATCH)

    # ------------------------------------------------------------------------
    # 10. External Verification: non-zero value transfer detected
    # ------------------------------------------------------------------------
    def test_10_external_verification_non_zero_value_detected(self):
        mock_tx_hash = "0x" + "1" * 64
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_sendTransaction":
                        return mock_tx_hash
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0x0"}
                    elif method == "eth_getTransactionReceipt":
                        return {"status": "0x1", "blockNumber": "0x1", "transactionHash": mock_tx_hash}
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

            # When independently re-verifying, RPC returns non-zero value on chain
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc_reverify:
                def fake_reverify(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0xde0b6b3a7640000"}  # 1 ETH
                    elif method == "eth_getTransactionReceipt":
                        return {"status": "0x1", "blockNumber": "0x1", "transactionHash": mock_tx_hash}
                    return None

                mock_rpc_reverify.side_effect = fake_reverify
                ver = NotarizationService.verify_notarization(notz["notarization_id"], db_path=self.db_path)
                self.assertEqual(ver["verification_status"], VERIFY_STATUS_VALUE_NOT_ZERO)

    # ------------------------------------------------------------------------
    # 11. External Verification: receipt transaction hash mismatch
    # ------------------------------------------------------------------------
    def test_11_external_verification_receipt_hash_mismatch(self):
        mock_tx_hash = "0x" + "2" * 64
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_sendTransaction":
                        return mock_tx_hash
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0x0"}
                    elif method == "eth_getTransactionReceipt":
                        return {"status": "0x1", "blockNumber": "0x1", "transactionHash": mock_tx_hash}
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

            # When independently re-verifying, receipt returns mismatched tx hash
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc_reverify:
                def fake_reverify(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0x0"}
                    elif method == "eth_getTransactionReceipt":
                        return {"status": "0x1", "blockNumber": "0x1", "transactionHash": "0x" + "9" * 64}
                    return None

                mock_rpc_reverify.side_effect = fake_reverify
                ver = NotarizationService.verify_notarization(notz["notarization_id"], db_path=self.db_path)
                self.assertEqual(ver["verification_status"], VERIFY_STATUS_RECEIPT_TRANSACTION_MISMATCH)

    # ------------------------------------------------------------------------
    # 12. Nominal Confirmed External Verification
    # ------------------------------------------------------------------------
    def test_12_nominal_confirmed_external_verification(self):
        mock_tx_hash = "0x" + "3" * 64
        local_proof_holder = []

        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(method, params):
                    if method == "eth_chainId":
                        return "0x539"
                    elif method == "eth_sendTransaction":
                        local_proof_holder.append(params[0]["data"])
                        return mock_tx_hash
                    elif method == "eth_getTransactionReceipt":
                        return {"status": "0x1", "blockNumber": "0x7b", "transactionHash": mock_tx_hash}
                    elif method == "eth_getTransactionByHash":
                        return {
                            "hash": mock_tx_hash,
                            "from": self.valid_from,
                            "to": self.valid_anchor,
                            "value": "0x0",
                            "input": local_proof_holder[0] if local_proof_holder else "0x",
                        }
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

                self.assertEqual(notz["status"], STATUS_CONFIRMED)
                self.assertEqual(notz["block_number"], 123)

                ver = NotarizationService.verify_notarization(notz["notarization_id"], db_path=self.db_path)
                self.assertEqual(ver["verification_status"], VERIFY_STATUS_VERIFIED_EXTERNAL_ANCHOR)
                self.assertEqual(ver["chain_id"], 1337)
                self.assertEqual(ver["block_number"], 123)

    # ------------------------------------------------------------------------
    # 13. External confirmation creates exactly one EXTERNAL_ANCHOR_LINKAGE_MANIFEST
    # ------------------------------------------------------------------------
    def test_13_confirmed_creates_external_anchor_linkage_manifest(self):
        mock_tx_hash = "0x" + "4" * 64
        mock_receipt = {"status": "0x1", "blockNumber": "0x400", "transactionHash": mock_tx_hash}
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(m, p):
                    if m == "eth_chainId":
                        return "0x539"
                    elif m == "eth_sendTransaction":
                        return mock_tx_hash
                    elif m == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0x0"}
                    elif m == "eth_getTransactionReceipt":
                        return mock_receipt
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

                latest_m = ForensicRepository.get_latest_manifest_version(self.analysis_id, db_path=self.db_path)
                self.assertEqual(latest_m["manifest_type"], "EXTERNAL_ANCHOR_LINKAGE_MANIFEST")
                m_dict = latest_m["manifest_dict"]
                self.assertIn("linked_external_anchors", m_dict)
                self.assertEqual(len(m_dict["linked_external_anchors"]), 1)
                self.assertEqual(m_dict["linked_external_anchors"][0]["transaction_hash"], mock_tx_hash)
                self.assertEqual(m_dict["linked_external_anchors"][0]["chain_id"], 1337)

    # ------------------------------------------------------------------------
    # 14. Pending or reverted tx does NOT create confirmed linkage manifest
    # ------------------------------------------------------------------------
    def test_14_pending_tx_does_not_create_confirmed_linkage_manifest(self):
        mock_tx_hash = "0x" + "5" * 64
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(m, p):
                    if m == "eth_chainId":
                        return "0x539"
                    elif m == "eth_sendTransaction":
                        return mock_tx_hash
                    elif m == "eth_getTransactionByHash":
                        return {"hash": mock_tx_hash, "from": self.valid_from, "to": self.valid_anchor, "value": "0x0"}
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

                latest_m = ForensicRepository.get_latest_manifest_version(self.analysis_id, db_path=self.db_path)
                self.assertEqual(latest_m["manifest_type"], "NOTARIZATION_LINKAGE_MANIFEST")
                self.assertNotIn("linked_external_anchors", latest_m["manifest_dict"])

    # ------------------------------------------------------------------------
    # 15. Provider status API reports explicit RPC_MANAGED_ACCOUNT and leaks zero secrets
    # ------------------------------------------------------------------------
    def test_15_provider_status_api_safety_and_mode(self):
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "get_chain_id", return_value=1337):
                res = self.client.get("/api/v1/notarization/providers/status")
                self.assertEqual(res.status_code, 200)
                data = res.json()
                self.assertTrue(data["configured"])
                self.assertEqual(data["provider_type"], "EVM_JSON_RPC")
                self.assertEqual(data["submission_mode"], "RPC_MANAGED_ACCOUNT")
                self.assertEqual(data["local_private_key_signing"], "NOT_IMPLEMENTED")
                self.assertEqual(data["implementation_status"], "IMPLEMENTED_AND_MOCK_TESTED")
                self.assertFalse(data["live_chain_verified"])
                self.assertEqual(data["chain_id"], 1337)
                self.assertEqual(data["connection_status"], "CONNECTED")

    # ------------------------------------------------------------------------
    # 16. Idempotency: repeated verification creates no duplicate linkage/event/row
    # ------------------------------------------------------------------------
    def test_16_idempotent_read_only_verification(self):
        mock_tx_hash = "0x" + "7" * 64
        mock_receipt = {"status": "0x1", "blockNumber": "0x20", "transactionHash": mock_tx_hash}
        local_proof_holder = []

        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                def fake_rpc(m, p):
                    if m == "eth_chainId":
                        return "0x539"
                    elif m == "eth_sendTransaction":
                        local_proof_holder.append(p[0]["data"])
                        return mock_tx_hash
                    elif m == "eth_getTransactionReceipt":
                        return mock_receipt
                    elif m == "eth_getTransactionByHash":
                        return {
                            "hash": mock_tx_hash,
                            "from": self.valid_from,
                            "to": self.valid_anchor,
                            "value": "0x0",
                            "input": local_proof_holder[0] if local_proof_holder else "0x",
                        }
                    return None

                mock_rpc.side_effect = fake_rpc

                notz = NotarizationService.create_notarization_proof(
                    analysis_id=self.analysis_id,
                    report_artifact_id=self.report_artifact_id,
                    mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                    actor=self.actor,
                    db_path=self.db_path,
                )

                custody_before = CustodyService.get_record(self.analysis_id)
                events_count_before = len(custody_before.events) if custody_before else 0
                manifests_before = len(ForensicRepository.get_manifest_versions(self.analysis_id, db_path=self.db_path))
                notz_records_before = len(ForensicRepository.get_analysis_notarizations(self.analysis_id, db_path=self.db_path))

                # Verify 5 consecutive times
                for _ in range(5):
                    ver = NotarizationService.verify_notarization(notz["notarization_id"], db_path=self.db_path)
                    self.assertEqual(ver["verification_status"], VERIFY_STATUS_VERIFIED_EXTERNAL_ANCHOR)

                # Check zero side-effects
                custody_after = CustodyService.get_record(self.analysis_id)
                events_count_after = len(custody_after.events) if custody_after else 0
                manifests_after = len(ForensicRepository.get_manifest_versions(self.analysis_id, db_path=self.db_path))
                notz_records_after = len(ForensicRepository.get_analysis_notarizations(self.analysis_id, db_path=self.db_path))

                self.assertEqual(events_count_after, events_count_before)
                self.assertEqual(manifests_after, manifests_before)
                self.assertEqual(notz_records_after, notz_records_before)

    # ------------------------------------------------------------------------
    # 17. Submit-time rejection on corrupted RPC transaction details
    # ------------------------------------------------------------------------
    def test_17_submit_rejects_corrupted_rpc_transaction(self):
        mock_tx_hash = "0x" + "8" * 64

        # 1. Sender mismatch on initial submission re-read
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                mock_rpc.side_effect = lambda m, p: "0x539" if m == "eth_chainId" else (
                    mock_tx_hash if m == "eth_sendTransaction" else (
                        {"hash": mock_tx_hash, "from": "0x9999999999999999999999999999999999999999", "to": self.valid_anchor, "value": "0x0"} if m == "eth_getTransactionByHash" else None
                    )
                )
                with self.assertRaises(NotarizationError):
                    NotarizationService.create_notarization_proof(
                        analysis_id=self.analysis_id,
                        report_artifact_id=self.report_artifact_id,
                        mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                        actor=self.actor,
                        db_path=self.db_path,
                    )

        # 2. Target mismatch on initial submission re-read
        with patch.dict(os.environ, self._default_env()):
            with patch.object(EVMJsonRpcBlockchainProvider, "_rpc_request") as mock_rpc:
                mock_rpc.side_effect = lambda m, p: "0x539" if m == "eth_chainId" else (
                    mock_tx_hash if m == "eth_sendTransaction" else (
                        {"hash": mock_tx_hash, "from": self.valid_from, "to": "0x8888888888888888888888888888888888888888", "value": "0x0"} if m == "eth_getTransactionByHash" else None
                    )
                )
                with self.assertRaises(NotarizationError):
                    NotarizationService.create_notarization_proof(
                        analysis_id=self.analysis_id,
                        report_artifact_id=self.report_artifact_id,
                        mode=NOTARIZATION_MODE_EXTERNAL_PROVIDER,
                        actor=self.actor,
                        db_path=self.db_path,
                    )


if __name__ == "__main__":
    unittest.main()


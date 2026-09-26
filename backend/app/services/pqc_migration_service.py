"""
SecureMailScope X - Post-Quantum Cryptography Migration Planner Service (Phase 24)

Deterministic, evidence-backed PQC readiness evaluation, quantum exposure modeling,
gap analysis, and 7-phase hybrid transition roadmap engine.
"""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from app.db.database import get_db_connection
from app.db.repository import ForensicRepository
from app.forensic.pqc_analyzer import lookup_named_group, NAMED_GROUPS_DATABASE
from app.schemas.identity import ActorContext
from app.schemas.pqc_migration import (
    CryptoAssetInventoryResponse,
    CryptoAssetItem,
    DataSensitivityLifetime,
    GapSeverity,
    MigrationPhaseName,
    MigrationStepStatus,
    PQCExposureAssessmentResponse,
    PQCGapAnalysisResponse,
    PQCGapFindingItem,
    PQCMigrationStepItem,
    PQCReadinessClassification,
    PQCRoadmapApprovalRequest,
    PQCRoadmapCreateRequest,
    PQCRoadmapListResponse,
    PQCRoadmapResponse,
    PQCRoadmapStatus,
    PQCRoadmapUpdateRequest,
    PQCTransitionTargetArchitecture,
    QuantumExposureLevel,
)
from app.schemas.rbac import AnalystRole, Capability
from app.services.rbac_service import AuthorizationService


def _classify_kex(kex_str: Optional[str]) -> Tuple[PQCReadinessClassification, bool]:
    """Helper to classify key exchange string into PQC readiness and hybrid status."""
    if not kex_str:
        return PQCReadinessClassification.UNKNOWN, False
    grp = lookup_named_group(kex_str)
    if grp:
        if grp.group_type == "HYBRID":
            return PQCReadinessClassification.HYBRID_READY, True
        elif grp.group_type == "PQC_STANDALONE":
            return PQCReadinessClassification.PQC_READY, False
        else:
            return PQCReadinessClassification.CLASSICAL_ONLY, False

    kex_upper = kex_str.upper()
    if "MLKEM" in kex_upper or "KYBER" in kex_upper:
        if "X25519" in kex_upper or "SECP" in kex_upper or "PRIME" in kex_upper:
            return PQCReadinessClassification.HYBRID_READY, True
        return PQCReadinessClassification.PQC_READY, False
    elif "ECDHE" in kex_upper or "DHE" in kex_upper or "RSA" in kex_upper:
        return PQCReadinessClassification.CLASSICAL_ONLY, False
    return PQCReadinessClassification.UNKNOWN, False


class PQCMigrationService:
    """Core domain service for PQC asset discovery, quantum risk modeling, and migration roadmaps."""

    @classmethod
    def extract_or_get_inventory(
        cls,
        analysis_id: Optional[str] = None,
        target_id: Optional[str] = None,
        case_id: Optional[str] = None,
        db_path: Optional[str] = None,
    ) -> CryptoAssetInventoryResponse:
        """
        Extract cryptographic assets from forensic analysis sessions or active scan snapshots.
        Persists newly discovered assets into pqc_crypto_assets table.
        """
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        # Query existing persisted assets first
        query = "SELECT * FROM pqc_crypto_assets WHERE 1=1"
        params: List[Any] = []
        if analysis_id:
            query += " AND analysis_id = ?"
            params.append(analysis_id)
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        assets: List[CryptoAssetItem] = []
        for r in rows:
            rd = dict(r)
            assets.append(
                CryptoAssetItem(
                    asset_id=rd["asset_id"],
                    analysis_id=rd.get("analysis_id"),
                    case_id=rd.get("case_id"),
                    target_id=rd.get("target_id"),
                    protocol=rd["protocol"],
                    endpoint=rd["endpoint"],
                    crypto_layer=rd["crypto_layer"],
                    algorithm_family=rd["algorithm_family"],
                    algorithm_name=rd["algorithm_name"],
                    key_size=rd.get("key_size"),
                    certificate_fingerprint=rd.get("certificate_fingerprint"),
                    certificate_key_algorithm=rd.get("certificate_key_algorithm"),
                    kex_type=rd.get("kex_type"),
                    signature_algorithm=rd.get("signature_algorithm"),
                    pqc_status=PQCReadinessClassification(rd["pqc_status"]),
                    hybrid_status=bool(rd["hybrid_status"]),
                    evidence_reference=rd["evidence_reference"],
                    observed_at=rd["observed_at"],
                )
            )

        # If no assets persisted yet, extract dynamically from forensic evidence
        if not assets:
            now_iso = datetime.now(timezone.utc).isoformat()

            # 1. Try extracting from sessions if analysis_id provided
            if analysis_id:
                cursor.execute(
                    "SELECT * FROM sessions WHERE analysis_id = ?;",
                    (analysis_id,),
                )
                session_rows = cursor.fetchall()
                for s in session_rows:
                    sd = dict(s)
                    session_id = sd.get("session_id", "session")
                    server_ip = sd.get("server") or sd.get("server_ip") or sd.get("dst_ip") or "unknown_host"
                    server_port = sd.get("server_port") or sd.get("dst_port") or 25
                    endpoint = f"{server_ip}:{server_port}" if ":" not in str(server_ip) else str(server_ip)
                    proto = sd.get("protocol", "SMTP")
                    tls_ver = sd.get("tls_version") or "TLS 1.2"
                    cipher = sd.get("cipher_suite") or "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                    kex = sd.get("key_exchange") or "ECDHE"

                    res_json_str = sd.get("session_result_json")
                    if res_json_str:
                        try:
                            res_obj = json.loads(res_json_str)
                            tls_det = res_obj.get("tls_handshake_details") or {}
                            if tls_det.get("negotiated_tls_version"):
                                tls_ver = tls_det["negotiated_tls_version"]
                            if tls_det.get("cipher_suite"):
                                cipher = tls_det["cipher_suite"]
                            if tls_det.get("key_exchange_group"):
                                kex = tls_det["key_exchange_group"]
                        except Exception:
                            pass

                    # Evaluate KEX asset
                    kex_pqc_status, is_hybrid = _classify_kex(kex)

                    kex_asset_id = f"asset-{uuid.uuid4().hex[:8]}"
                    kex_item = CryptoAssetItem(
                        asset_id=kex_asset_id,
                        analysis_id=analysis_id,
                        case_id=case_id,
                        target_id=target_id,
                        protocol=proto,
                        endpoint=endpoint,
                        crypto_layer="KEY_EXCHANGE",
                        algorithm_family=kex,
                        algorithm_name=kex,
                        kex_type=kex,
                        pqc_status=kex_pqc_status,
                        hybrid_status=is_hybrid,
                        evidence_reference=f"analysis:{analysis_id}/session:{session_id}",
                        observed_at=now_iso,
                    )
                    assets.append(kex_item)

                    # Evaluate Cipher asset
                    cipher_asset_id = f"asset-{uuid.uuid4().hex[:8]}"
                    cipher_item = CryptoAssetItem(
                        asset_id=cipher_asset_id,
                        analysis_id=analysis_id,
                        case_id=case_id,
                        target_id=target_id,
                        protocol=proto,
                        endpoint=endpoint,
                        crypto_layer="CIPHER",
                        algorithm_family="SYMMETRIC",
                        algorithm_name=cipher,
                        pqc_status=PQCReadinessClassification.CLASSICAL_ONLY,
                        hybrid_status=False,
                        evidence_reference=f"analysis:{analysis_id}/session:{session_id}",
                        observed_at=now_iso,
                    )
                    assets.append(cipher_item)

            # 2. Try extracting from posture_snapshots if target_id provided
            elif target_id:
                cursor.execute(
                    "SELECT * FROM posture_snapshots WHERE target_id = ? ORDER BY scanned_at DESC LIMIT 1;",
                    (target_id,),
                )
                snap_row = cursor.fetchone()
                if snap_row:
                    snap = dict(snap_row)
                    endpoint = f"{target_id}"
                    proto = snap.get("protocol", "SMTP")
                    tls_ver = snap.get("tls_version") or "TLS 1.3"
                    cipher = snap.get("cipher_suite") or "TLS_AES_256_GCM_SHA384"
                    cert_fp = snap.get("certificate_fingerprint")

                    kex_pqc_status, is_hybrid = _classify_kex(snap.get("pqc_status") or cipher)

                    kex_asset_id = f"asset-{uuid.uuid4().hex[:8]}"
                    assets.append(
                        CryptoAssetItem(
                            asset_id=kex_asset_id,
                            analysis_id=None,
                            case_id=case_id,
                            target_id=target_id,
                            protocol=proto,
                            endpoint=endpoint,
                            crypto_layer="KEY_EXCHANGE",
                            algorithm_family="ECDHE",
                            algorithm_name=cipher,
                            certificate_fingerprint=cert_fp,
                            pqc_status=kex_pqc_status,
                            hybrid_status=is_hybrid,
                            evidence_reference=f"target:{target_id}/snapshot:{snap['snapshot_id']}",
                            observed_at=now_iso,
                        )
                    )

            # Persist newly extracted assets
            for a in assets:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO pqc_crypto_assets (
                        asset_id, analysis_id, case_id, target_id, protocol, endpoint,
                        crypto_layer, algorithm_family, algorithm_name, key_size,
                        certificate_fingerprint, certificate_key_algorithm, kex_type,
                        signature_algorithm, pqc_status, hybrid_status, evidence_reference, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        a.asset_id,
                        a.analysis_id,
                        a.case_id,
                        a.target_id,
                        a.protocol,
                        a.endpoint,
                        a.crypto_layer,
                        a.algorithm_family,
                        a.algorithm_name,
                        a.key_size,
                        a.certificate_fingerprint,
                        a.certificate_key_algorithm,
                        a.kex_type,
                        a.signature_algorithm,
                        a.pqc_status.value,
                        1 if a.hybrid_status else 0,
                        a.evidence_reference,
                        a.observed_at,
                    ),
                )
            conn.commit()

        conn.close()

        # Count classifications
        classical_c = sum(1 for a in assets if a.pqc_status == PQCReadinessClassification.CLASSICAL_ONLY)
        hybrid_c = sum(1 for a in assets if a.pqc_status == PQCReadinessClassification.HYBRID_READY)
        pqc_c = sum(1 for a in assets if a.pqc_status == PQCReadinessClassification.PQC_READY)
        unknown_c = sum(1 for a in assets if a.pqc_status in (PQCReadinessClassification.UNKNOWN, PQCReadinessClassification.NOT_ASSESSED))

        return CryptoAssetInventoryResponse(
            total_assets=len(assets),
            classical_count=classical_c,
            hybrid_count=hybrid_c,
            pqc_ready_count=pqc_c,
            unknown_count=unknown_c,
            assets=assets,
        )

    @classmethod
    def evaluate_quantum_exposure(
        cls,
        analysis_id: Optional[str] = None,
        target_id: Optional[str] = None,
        case_id: Optional[str] = None,
        data_sensitivity: DataSensitivityLifetime = DataSensitivityLifetime.UNKNOWN,
        db_path: Optional[str] = None,
    ) -> PQCExposureAssessmentResponse:
        """
        Evaluate Harvest-Now-Decrypt-Later (HNDL) quantum exposure level deterministically.
        Rules:
        - Non-PFS or static RSA KEX: CRITICAL exposure
        - Classical ECDHE / DHE without PQC: HIGH exposure (for encrypted mail traffic)
        - Hybrid (e.g. X25519MLKEM768): LOW exposure
        - Pure PQC (e.g. ML-KEM): LOW exposure
        - Unknown/empty: UNKNOWN
        """
        inv = cls.extract_or_get_inventory(
            analysis_id=analysis_id,
            target_id=target_id,
            case_id=case_id,
            db_path=db_path,
        )

        if not inv.assets:
            return PQCExposureAssessmentResponse(
                overall_exposure=QuantumExposureLevel.UNKNOWN,
                hndl_vulnerability_level=QuantumExposureLevel.UNKNOWN,
                data_sensitivity=data_sensitivity,
                forward_secrecy_present=False,
                vulnerable_kex_algorithms=[],
                vulnerable_signature_algorithms=[],
                risk_summary="No cryptographic assets observed to evaluate quantum exposure.",
                evidence_references=[],
            )

        vulnerable_kex: List[str] = []
        vulnerable_sig: List[str] = []
        evidence_refs: List[str] = []
        has_pfs = False
        has_critical = False
        has_high = False
        has_hybrid_or_pqc = False

        for a in inv.assets:
            evidence_refs.append(a.evidence_reference)
            alg = a.algorithm_name.upper()

            if a.crypto_layer == "KEY_EXCHANGE":
                if "RSA" in alg and "ECDHE" not in alg and "DHE" not in alg:
                    vulnerable_kex.append(a.algorithm_name)
                    has_critical = True
                elif "ECDHE" in alg or "DHE" in alg or "X25519" in alg:
                    has_pfs = True
                    if a.pqc_status in (PQCReadinessClassification.HYBRID_READY, PQCReadinessClassification.PQC_READY):
                        has_hybrid_or_pqc = True
                    else:
                        vulnerable_kex.append(a.algorithm_name)
                        has_high = True
                elif "ML-KEM" in alg or "KYBER" in alg:
                    has_pfs = True
                    has_hybrid_or_pqc = True
                else:
                    vulnerable_kex.append(a.algorithm_name)
                    has_high = True

            elif a.crypto_layer in ("SIGNATURE", "CERTIFICATE"):
                if any(x in alg for x in ("RSA", "ECDSA", "ED25519", "SHA1", "MD5")):
                    vulnerable_sig.append(a.algorithm_name)

        if has_critical:
            overall = QuantumExposureLevel.CRITICAL
            hndl_level = QuantumExposureLevel.CRITICAL
            summary = "Critical quantum exposure: Static or non-PFS key exchange in use. Harvested traffic can be decrypted immediately by a CRQC."
        elif has_high and not has_hybrid_or_pqc:
            overall = QuantumExposureLevel.HIGH
            hndl_level = QuantumExposureLevel.HIGH
            summary = "High quantum exposure: Classical discrete-log/elliptic-curve key exchange in use without post-quantum hybrid encapsulation (vulnerable to Harvest-Now-Decrypt-Later attacks)."
        elif has_hybrid_or_pqc:
            overall = QuantumExposureLevel.LOW
            hndl_level = QuantumExposureLevel.LOW
            summary = "Low quantum exposure: Hybrid post-quantum key encapsulation (ML-KEM/Kyber) observed, protecting confidentiality against CRQC interception."
        else:
            overall = QuantumExposureLevel.MODERATE
            hndl_level = QuantumExposureLevel.MODERATE
            summary = "Moderate quantum exposure: Cryptographic parameters require transitional hardening."

        return PQCExposureAssessmentResponse(
            overall_exposure=overall,
            hndl_vulnerability_level=hndl_level,
            data_sensitivity=data_sensitivity,
            forward_secrecy_present=has_pfs,
            vulnerable_kex_algorithms=list(set(vulnerable_kex)),
            vulnerable_signature_algorithms=list(set(vulnerable_sig)),
            risk_summary=summary,
            evidence_references=list(set(evidence_refs)),
        )

    @classmethod
    def run_gap_analysis(
        cls,
        analysis_id: Optional[str] = None,
        target_id: Optional[str] = None,
        case_id: Optional[str] = None,
        target_architecture: PQCTransitionTargetArchitecture = PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET,
        db_path: Optional[str] = None,
    ) -> PQCGapAnalysisResponse:
        """
        Compare observed cryptographic assets against target architecture and identify concrete gaps.
        """
        inv = cls.extract_or_get_inventory(
            analysis_id=analysis_id,
            target_id=target_id,
            case_id=case_id,
            db_path=db_path,
        )

        gaps: List[PQCGapFindingItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        if not inv.assets:
            gaps.append(
                PQCGapFindingItem(
                    gap_id=f"gap-{uuid.uuid4().hex[:8]}",
                    gap_type="NO_OBSERVED_CRYPTO_ASSETS",
                    severity=GapSeverity.INFO,
                    description="No observed cryptographic assets found for target. Inventory discovery required.",
                    evidence_reference="inventory:empty",
                    remediation_action="Execute forensic PCAP session analysis or active security scan to discover endpoints.",
                    created_at=now_iso,
                )
            )
            return PQCGapAnalysisResponse(
                target_architecture=target_architecture,
                current_readiness=PQCReadinessClassification.UNKNOWN,
                total_gaps=len(gaps),
                gaps=gaps,
                readiness_summary="Discovery required before gap remediation.",
            )

        # Check for Hybrid KEM gaps
        has_hybrid_kem = any(a.hybrid_status for a in inv.assets if a.crypto_layer == "KEY_EXCHANGE")
        if target_architecture in (
            PQCTransitionTargetArchitecture.HYBRID_KEM_TARGET,
            PQCTransitionTargetArchitecture.PQC_CAPABLE_MAIL_GATEWAY,
            PQCTransitionTargetArchitecture.PQC_AWARE_TLS_TERMINATOR,
        ):
            if not has_hybrid_kem:
                gaps.append(
                    PQCGapFindingItem(
                        gap_id=f"gap-{uuid.uuid4().hex[:8]}",
                        gap_type="LACK_OF_HYBRID_KEM",
                        severity=GapSeverity.HIGH,
                        description="Observed TLS sessions do not negotiate hybrid post-quantum key exchange (e.g., X25519MLKEM768 or SecP256r1MLKEM768).",
                        evidence_reference=inv.assets[0].evidence_reference if inv.assets else "inventory",
                        remediation_action="Configure mail transfer agent / TLS proxy to enable hybrid ML-KEM-768 key encapsulation.",
                        created_at=now_iso,
                    )
                )

        # Check for Classical-only signatures / certificates
        has_classical_rsa = any("RSA" in a.algorithm_name.upper() for a in inv.assets)
        if has_classical_rsa:
            gaps.append(
                PQCGapFindingItem(
                    gap_id=f"gap-{uuid.uuid4().hex[:8]}",
                    gap_type="CLASSICAL_RSA_SIGNATURE",
                    severity=GapSeverity.MEDIUM,
                    description="Classical RSA signatures/certificates observed in authentication layer.",
                    evidence_reference=inv.assets[0].evidence_reference if inv.assets else "inventory",
                    remediation_action="Plan dual-signature or composite certificate migration (ML-DSA-65 / Falcon) for long-term authentication.",
                    created_at=now_iso,
                )
            )

        # Determine overall readiness classification
        if has_hybrid_kem:
            readiness = PQCReadinessClassification.HYBRID_READY
            summary = "Target environment has established hybrid post-quantum KEX capabilities."
        elif inv.classical_count > 0:
            readiness = PQCReadinessClassification.CLASSICAL_ONLY
            summary = "Target environment is classical-only; post-quantum migration required."
        else:
            readiness = PQCReadinessClassification.UNKNOWN
            summary = "Target environment readiness status is unassessed."

        return PQCGapAnalysisResponse(
            target_architecture=target_architecture,
            current_readiness=readiness,
            total_gaps=len(gaps),
            gaps=gaps,
            readiness_summary=summary,
        )

    @classmethod
    def generate_roadmap_steps(
        cls,
        roadmap_id: str,
        target_architecture: PQCTransitionTargetArchitecture,
    ) -> List[PQCMigrationStepItem]:
        """
        Generate deterministic 7-Phase migration steps (Phase A through Phase G).
        Phase F is explicitly named PHASE_F_PQC_PRIMARY_TRANSITION (TARGET / ADVISORY).
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        steps = [
            PQCMigrationStepItem(
                step_id=f"step-{uuid.uuid4().hex[:8]}",
                roadmap_id=roadmap_id,
                phase_name=MigrationPhaseName.PHASE_A_INVENTORY,
                sequence_order=1,
                objective="Comprehensive Cryptographic Asset Discovery & Categorization",
                recommended_actions=[
                    "Analyze forensic session captures and active scan probes across all mail transfer endpoints.",
                    "Catalogue TLS versions, cipher suites, key exchange algorithms, and certificate chains.",
                    "Record observed cryptographic assets into the immutable forensic database.",
                ],
                validation_criteria=[
                    "100% of SMTP, IMAP, and POP3 gateways inventoried with evidence references.",
                    "Zero uncatalogued TLS listener endpoints.",
                ],
                rollback_considerations=[
                    "Read-only discovery phase; no rollback required.",
                ],
                blocking_issues=[],
                status=MigrationStepStatus.PENDING,
                created_at=now_iso,
            ),
            PQCMigrationStepItem(
                step_id=f"step-{uuid.uuid4().hex[:8]}",
                roadmap_id=roadmap_id,
                phase_name=MigrationPhaseName.PHASE_B_RISK_ASSESSMENT,
                sequence_order=2,
                objective="Quantum Exposure & HNDL Risk Evaluation",
                recommended_actions=[
                    "Evaluate Harvest-Now-Decrypt-Later (HNDL) exposure for sensitive email transit paths.",
                    "Identify non-forward-secret ciphers and legacy RSA key exchange mechanisms.",
                    "Prioritize high-exposure external mail relays for immediate hybrid encapsulation.",
                ],
                validation_criteria=[
                    "Deterministic quantum exposure level calculated for all observed communication channels.",
                    "High and critical exposure endpoints documented with forensic citations.",
                ],
                rollback_considerations=[
                    "Assessment only; no operational impact.",
                ],
                blocking_issues=[],
                status=MigrationStepStatus.PENDING,
                created_at=now_iso,
            ),
            PQCMigrationStepItem(
                step_id=f"step-{uuid.uuid4().hex[:8]}",
                roadmap_id=roadmap_id,
                phase_name=MigrationPhaseName.PHASE_C_TARGET_ARCHITECTURE_SELECTION,
                sequence_order=3,
                objective="Target Post-Quantum Architecture & Parameter Selection",
                recommended_actions=[
                    f"Select {target_architecture.value} as the advisory target architecture.",
                    "Define hybrid KEM curve pairings (e.g., X25519 + ML-KEM-768 per NIST FIPS 203).",
                    "Establish cryptographic peer review requirements for transitional configuration updates.",
                ],
                validation_criteria=[
                    "Target profile approved by lead investigator.",
                    "Cryptographic parameter specification aligned with organizational security policy.",
                ],
                rollback_considerations=[
                    "Architecture drafting; modify target profile if compatibility constraints arise.",
                ],
                blocking_issues=[],
                status=MigrationStepStatus.PENDING,
                created_at=now_iso,
            ),
            PQCMigrationStepItem(
                step_id=f"step-{uuid.uuid4().hex[:8]}",
                roadmap_id=roadmap_id,
                phase_name=MigrationPhaseName.PHASE_D_PILOT_HYBRID_KEM,
                sequence_order=4,
                objective="Pilot Dual Classical + ML-KEM Hybrid Key Exchange",
                recommended_actions=[
                    "Configure pilot MTA staging endpoints to offer X25519MLKEM768 hybrid key exchange.",
                    "Enable classical TLS 1.3/1.2 fallback for legacy mail partners.",
                    "Monitor handshake latency, packet fragmentation, and successful negotiation rates.",
                ],
                validation_criteria=[
                    "Successful hybrid handshake negotiation verified by active probes.",
                    "Zero handshake drops or connectivity regressions for legacy TLS peers.",
                ],
                rollback_considerations=[
                    "Revert MTA cipher and KEX preferences to classical X25519/ECDHE if partner MTAs fail negotiation.",
                ],
                blocking_issues=[],
                status=MigrationStepStatus.PENDING,
                created_at=now_iso,
            ),
            PQCMigrationStepItem(
                step_id=f"step-{uuid.uuid4().hex[:8]}",
                roadmap_id=roadmap_id,
                phase_name=MigrationPhaseName.PHASE_E_HYBRID_SIGNATURES,
                sequence_order=5,
                objective="Dual-Signature & Composite Certificate Transition",
                recommended_actions=[
                    "Evaluate ML-DSA-65 (FIPS 204) and Falcon dual-signature validation in test harness.",
                    "Pilot S/MIME dual-signing with classical RSA/ECDSA alongside post-quantum signatures.",
                    "Validate recipient client signature verification without trust errors.",
                ],
                validation_criteria=[
                    "Dual-signature S/MIME messages verified by both legacy and PQC-aware mail clients.",
                ],
                rollback_considerations=[
                    "Maintain primary classical X.509 certificates to ensure backward verification compatibility.",
                ],
                blocking_issues=[],
                status=MigrationStepStatus.PENDING,
                created_at=now_iso,
            ),
            PQCMigrationStepItem(
                step_id=f"step-{uuid.uuid4().hex[:8]}",
                roadmap_id=roadmap_id,
                phase_name=MigrationPhaseName.PHASE_F_PQC_PRIMARY_TRANSITION,
                sequence_order=6,
                objective="Target Production Hybrid/PQC Mail Routing Transition (Advisory)",
                recommended_actions=[
                    "Deploy hybrid ML-KEM-768 as default key exchange across primary MX and outbound submission relays.",
                    "Enforce strict PFS with hybrid fallback for all inter-gateway mail traffic.",
                    "Log quantum-resistant negotiation telemetry to SIEM / forensic audit ledger.",
                ],
                validation_criteria=[
                    "Over 90% of inbound/outbound TLS connections negotiate hybrid post-quantum KEX.",
                    "Continuous posture monitoring verifies zero unencrypted or static-KEX fallback.",
                ],
                rollback_considerations=[
                    "Switch default cipher list back to classical ECDHE priority if routing anomaly detected.",
                ],
                blocking_issues=[],
                status=MigrationStepStatus.PENDING,
                created_at=now_iso,
            ),
            PQCMigrationStepItem(
                step_id=f"step-{uuid.uuid4().hex[:8]}",
                roadmap_id=roadmap_id,
                phase_name=MigrationPhaseName.PHASE_G_VERIFICATION,
                sequence_order=7,
                objective="Forensic Verification & Continuous Posture Monitoring",
                recommended_actions=[
                    "Perform recurring active scans and PCAP capture analysis to verify ongoing PQC compliance.",
                    "Audit posture drift events for any regression to classical-only or weak ciphers.",
                    "Cryptographically sign verified compliance manifests in the forensic ledger.",
                ],
                validation_criteria=[
                    "Continuous automated drift detection shows zero unauthorized cryptographic downgrades.",
                    "Audit chain of custody records cryptographic sign-offs from lead investigators.",
                ],
                rollback_considerations=[
                    "Continuous verification; flag drift alerts for immediate remediation planning.",
                ],
                blocking_issues=[],
                status=MigrationStepStatus.PENDING,
                created_at=now_iso,
            ),
        ]
        return steps

    @classmethod
    def create_roadmap(
        cls,
        req: PQCRoadmapCreateRequest,
        creator_actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> PQCRoadmapResponse:
        """Create a new 7-phase PQC migration roadmap with evidence-based gap analysis."""
        roadmap_id = f"pqc-rdm-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        creator_id = creator_actor.actor_id if creator_actor and creator_actor.actor_id else "analyst-01"

        # Evaluate exposure & gaps
        exposure_resp = cls.evaluate_quantum_exposure(
            analysis_id=req.analysis_id,
            target_id=req.target_id,
            case_id=req.case_id,
            data_sensitivity=req.data_sensitivity,
            db_path=db_path,
        )

        gap_resp = cls.run_gap_analysis(
            analysis_id=req.analysis_id,
            target_id=req.target_id,
            case_id=req.case_id,
            target_architecture=req.target_architecture,
            db_path=db_path,
        )

        # Generate 7-phase steps
        steps = cls.generate_roadmap_steps(roadmap_id, req.target_architecture)

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        # Insert roadmap
        cursor.execute(
            """
            INSERT INTO pqc_migration_roadmaps (
                roadmap_id, case_id, target_id, analysis_id, title, description,
                current_readiness, target_profile, exposure_level, status, version,
                created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?);
            """,
            (
                roadmap_id,
                req.case_id,
                req.target_id,
                req.analysis_id,
                req.title,
                req.description,
                gap_resp.current_readiness.value,
                req.target_architecture.value,
                exposure_resp.overall_exposure.value,
                PQCRoadmapStatus.DRAFT.value,
                creator_id,
                now_iso,
                now_iso,
            ),
        )

        # Insert steps
        for s in steps:
            cursor.execute(
                """
                INSERT INTO pqc_migration_steps (
                    step_id, roadmap_id, phase_name, sequence_order, objective,
                    recommended_actions_json, validation_criteria_json,
                    rollback_considerations_json, blocking_issues_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    s.step_id,
                    roadmap_id,
                    s.phase_name.value,
                    s.sequence_order,
                    s.objective,
                    json.dumps(s.recommended_actions),
                    json.dumps(s.validation_criteria),
                    json.dumps(s.rollback_considerations),
                    json.dumps(s.blocking_issues),
                    s.status.value,
                    now_iso,
                ),
            )

        # Insert gap findings
        for g in gap_resp.gaps:
            cursor.execute(
                """
                INSERT INTO pqc_gap_findings (
                    gap_id, roadmap_id, asset_id, gap_type, severity, description,
                    evidence_reference, remediation_action, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    g.gap_id,
                    roadmap_id,
                    g.asset_id,
                    g.gap_type,
                    g.severity.value,
                    g.description,
                    g.evidence_reference,
                    g.remediation_action,
                    now_iso,
                ),
            )

        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="PQC_ROADMAP_CREATED",
            object_type="PQC_ROADMAP",
            object_id=roadmap_id,
            details=f"Created PQC roadmap '{req.title}' targeting {req.target_architecture.value}",
            actor=creator_actor,
            db_path=db_path,
        )

        return cls.get_roadmap(roadmap_id, db_path=db_path)

    @classmethod
    def get_roadmap(cls, roadmap_id: str, db_path: Optional[str] = None) -> Optional[PQCRoadmapResponse]:
        """Retrieve full details of a migration roadmap including steps and gap findings."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM pqc_migration_roadmaps WHERE roadmap_id = ?;", (roadmap_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        rd = dict(row)

        # Fetch steps
        cursor.execute(
            "SELECT * FROM pqc_migration_steps WHERE roadmap_id = ? ORDER BY sequence_order ASC;",
            (roadmap_id,),
        )
        step_rows = cursor.fetchall()
        steps = []
        for s in step_rows:
            sd = dict(s)
            steps.append(
                PQCMigrationStepItem(
                    step_id=sd["step_id"],
                    roadmap_id=roadmap_id,
                    phase_name=MigrationPhaseName(sd["phase_name"]),
                    sequence_order=sd["sequence_order"],
                    objective=sd["objective"],
                    recommended_actions=json.loads(sd.get("recommended_actions_json") or "[]"),
                    validation_criteria=json.loads(sd.get("validation_criteria_json") or "[]"),
                    rollback_considerations=json.loads(sd.get("rollback_considerations_json") or "[]"),
                    blocking_issues=json.loads(sd.get("blocking_issues_json") or "[]"),
                    status=MigrationStepStatus(sd["status"]),
                    created_at=sd["created_at"],
                )
            )

        # Fetch gap findings
        cursor.execute("SELECT * FROM pqc_gap_findings WHERE roadmap_id = ?;", (roadmap_id,))
        gap_rows = cursor.fetchall()
        gaps = []
        for g in gap_rows:
            gd = dict(g)
            gaps.append(
                PQCGapFindingItem(
                    gap_id=gd["gap_id"],
                    roadmap_id=roadmap_id,
                    asset_id=gd.get("asset_id"),
                    gap_type=gd["gap_type"],
                    severity=GapSeverity(gd["severity"]),
                    description=gd["description"],
                    evidence_reference=gd["evidence_reference"],
                    remediation_action=gd["remediation_action"],
                    created_at=gd["created_at"],
                )
            )

        conn.close()

        return PQCRoadmapResponse(
            roadmap_id=rd["roadmap_id"],
            case_id=rd.get("case_id"),
            target_id=rd.get("target_id"),
            analysis_id=rd.get("analysis_id"),
            title=rd["title"],
            description=rd.get("description") or "",
            current_readiness=PQCReadinessClassification(rd["current_readiness"]),
            target_profile=PQCTransitionTargetArchitecture(rd["target_profile"]),
            exposure_level=QuantumExposureLevel(rd["exposure_level"]),
            status=PQCRoadmapStatus(rd["status"]),
            version=rd.get("version", 1),
            steps=steps,
            gaps=gaps,
            approved_by=rd.get("approved_by"),
            approved_at=rd.get("approved_at"),
            approval_signature=rd.get("approval_signature"),
            created_by=rd["created_by"],
            created_at=rd["created_at"],
            updated_at=rd["updated_at"],
        )

    @classmethod
    def list_roadmaps(cls, db_path: Optional[str] = None) -> PQCRoadmapListResponse:
        """List all migration roadmaps."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT roadmap_id FROM pqc_migration_roadmaps ORDER BY created_at DESC;")
        rows = cursor.fetchall()
        conn.close()

        roadmaps: List[PQCRoadmapResponse] = []
        for r in rows:
            rm = cls.get_roadmap(r["roadmap_id"], db_path=db_path)
            if rm:
                roadmaps.append(rm)

        return PQCRoadmapListResponse(
            total=len(roadmaps),
            roadmaps=roadmaps,
        )

    @classmethod
    def update_roadmap(
        cls,
        roadmap_id: str,
        req: PQCRoadmapUpdateRequest,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> PQCRoadmapResponse:
        """Update roadmap metadata or step progress."""
        rm = cls.get_roadmap(roadmap_id, db_path=db_path)
        if not rm:
            raise ValueError(f"Roadmap '{roadmap_id}' not found")

        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        new_title = req.title if req.title is not None else rm.title
        new_desc = req.description if req.description is not None else rm.description
        new_status = req.status.value if req.status is not None else rm.status.value

        cursor.execute(
            """
            UPDATE pqc_migration_roadmaps
            SET title = ?, description = ?, status = ?, updated_at = ?, version = version + 1
            WHERE roadmap_id = ?;
            """,
            (new_title, new_desc, new_status, now_iso, roadmap_id),
        )

        if req.step_updates:
            for step_id, st in req.step_updates.items():
                cursor.execute(
                    "UPDATE pqc_migration_steps SET status = ? WHERE step_id = ? AND roadmap_id = ?;",
                    (st.value, step_id, roadmap_id),
                )

        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="PQC_ROADMAP_UPDATED",
            object_type="PQC_ROADMAP",
            object_id=roadmap_id,
            details=f"Updated roadmap status={new_status}",
            actor=actor,
            db_path=db_path,
        )

        return cls.get_roadmap(roadmap_id, db_path=db_path)

    @classmethod
    def approve_roadmap(
        cls,
        req: PQCRoadmapApprovalRequest,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> PQCRoadmapResponse:
        """
        Cryptographically sign and approve a PQC migration roadmap.
        Validates digital signature (Ed25519 or RSA-PSS) against roadmap canonical manifest.
        Requires APPROVE_PQC_ROADMAP capability.
        """
        rm = cls.get_roadmap(req.roadmap_id, db_path=db_path)
        if not rm:
            raise ValueError(f"Roadmap '{req.roadmap_id}' not found")

        # Verify RBAC capability of the reviewer
        reviewer = AuthorizationService.get_analyst(req.reviewer_analyst_id, db_path=db_path)
        reviewer_role = reviewer.role if reviewer else AnalystRole.REVIEWER
        if not AuthorizationService.can(reviewer_role, Capability.APPROVE_PQC_ROADMAP):
            raise PermissionError(
                f"Analyst '{req.reviewer_analyst_id}' with role '{reviewer_role.value}' lacks capability APPROVE_PQC_ROADMAP"
            )

        # Compute canonical payload of the roadmap
        canonical_dict = {
            "roadmap_id": rm.roadmap_id,
            "title": rm.title,
            "target_profile": rm.target_profile.value,
            "current_readiness": rm.current_readiness.value,
            "exposure_level": rm.exposure_level.value,
            "total_steps": len(rm.steps),
            "reviewer_analyst_id": req.reviewer_analyst_id,
        }
        canonical_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # Verify signature
        try:
            pubkey_bytes = bytes.fromhex(req.public_key_hex) if all(c in "0123456789abcdefABCDEF" for c in req.public_key_hex) else req.public_key_hex.encode("utf-8")
            sig_bytes = bytes.fromhex(req.signature_hex) if all(c in "0123456789abcdefABCDEF" for c in req.signature_hex) else base64.b64decode(req.signature_hex)

            if req.signature_algorithm.upper() == "ED25519":
                if len(pubkey_bytes) == 32:
                    public_key = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
                else:
                    public_key = load_pem_public_key(pubkey_bytes)
                public_key.verify(sig_bytes, canonical_bytes)
            elif "RSA" in req.signature_algorithm.upper():
                public_key = load_pem_public_key(pubkey_bytes)
                public_key.verify(
                    sig_bytes,
                    canonical_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            else:
                raise ValueError(f"Unsupported signature algorithm: {req.signature_algorithm}")
        except (InvalidSignature, Exception) as e:
            raise ValueError(f"Cryptographic signature verification failed for roadmap approval: {str(e)}")

        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE pqc_migration_roadmaps
            SET status = 'APPROVED', approved_by = ?, approved_at = ?, approval_signature = ?, updated_at = ?
            WHERE roadmap_id = ?;
            """,
            (req.reviewer_analyst_id, now_iso, req.signature_hex, now_iso, req.roadmap_id),
        )
        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="PQC_ROADMAP_APPROVED",
            object_type="PQC_ROADMAP",
            object_id=req.roadmap_id,
            details=f"Roadmap cryptographically signed and approved by {req.reviewer_analyst_id} using {req.signature_algorithm}",
            actor=actor,
            db_path=db_path,
        )

        return cls.get_roadmap(req.roadmap_id, db_path=db_path)

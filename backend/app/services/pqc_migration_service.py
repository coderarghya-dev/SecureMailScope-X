# ==============================================================================
# SecureMailScope X — Phase 24 / 25: Post-Quantum Cryptography Migration Service
# ==============================================================================
"""Service for discovering cryptographic assets, modeling categorical HNDL exposure,
generating 7-phase transition roadmaps, assessing PQC gaps, and executing
cryptographic peer sign-offs.
"""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
)

from app.db.database import get_db_connection
from app.schemas.pqc_migration import (
    DataSensitivityLifetime,
    GapSeverity,
    MigrationPhaseName,
    MigrationStepStatus,
    PQCCryptoAssetDTO,
    PQCDiscoveryResult,
    PQCGapFindingDTO,
    PQCMigrationRoadmapDTO,
    PQCMigrationStepDTO,
    PQCMigrationStepUpdate,
    PQCReadinessClassification,
    PQCRoadmapCreateRequest,
    PQCRoadmapStatus,
    PQCTransitionTargetArchitecture,
    QuantumExposureLevel,
)


class PQCMigrationService:

    @staticmethod
    def discover_assets(
        analysis_id: Optional[str] = None,
        target_id: Optional[str] = None,
        lifetime: DataSensitivityLifetime = DataSensitivityLifetime.UNKNOWN,
    ) -> PQCDiscoveryResult:
        """Discovers cryptographic assets from observed PCAP sessions or active probe snapshots."""
        discovered: List[PQCCryptoAssetDTO] = []
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. From Sessions (Passive Analysis)
        if analysis_id:
            cursor.execute("SELECT * FROM sessions WHERE analysis_id = ?;", (analysis_id,))
            sessions = cursor.fetchall()
            for s in sessions:
                session_dict = {}
                if "session_result_json" in s.keys() and s["session_result_json"]:
                    try:
                        session_dict = json.loads(s["session_result_json"])
                    except Exception:
                        session_dict = {}

                tls_details = session_dict.get("tls_details", {}) if isinstance(session_dict, dict) else {}
                c_suite = "UNKNOWN"
                if isinstance(tls_details, dict):
                    c_info = tls_details.get("negotiated_cipher_suite")
                    if isinstance(c_info, dict):
                        c_suite = c_info.get("cipher_name", "UNKNOWN")
                    elif isinstance(c_info, str):
                        c_suite = c_info
                    elif "cipher_suite" in tls_details:
                        c_suite = str(tls_details["cipher_suite"])

                k_exchange = tls_details.get("selected_group") or tls_details.get("key_exchange") or "UNKNOWN"
                sig_algo = tls_details.get("signature_algorithm") or "UNKNOWN"
                pfs = bool(tls_details.get("has_forward_secrecy", False))

                pqc_readiness = PQCReadinessClassification.CLASSICAL_ONLY
                if any(x in str(k_exchange).upper() for x in ["ML-KEM", "MLKEM", "0X11EC", "KYBER"]):
                    pqc_readiness = PQCReadinessClassification.HYBRID_READY
                elif c_suite == "UNKNOWN" and k_exchange == "UNKNOWN":
                    pqc_readiness = PQCReadinessClassification.UNKNOWN

                if not pfs and c_suite != "UNKNOWN":
                    exposure = QuantumExposureLevel.CRITICAL if lifetime == DataSensitivityLifetime.OVER_10_YEARS else QuantumExposureLevel.HIGH
                elif pqc_readiness == PQCReadinessClassification.HYBRID_READY:
                    exposure = QuantumExposureLevel.LOW
                elif pfs:
                    if lifetime == DataSensitivityLifetime.OVER_10_YEARS:
                        exposure = QuantumExposureLevel.HIGH
                    elif lifetime == DataSensitivityLifetime.BETWEEN_5_AND_10_YEARS:
                        exposure = QuantumExposureLevel.MODERATE
                    elif lifetime == DataSensitivityLifetime.UNDER_5_YEARS:
                        exposure = QuantumExposureLevel.LOW
                    else:
                        exposure = QuantumExposureLevel.MODERATE
                else:
                    exposure = QuantumExposureLevel.UNKNOWN

                asset_id = f"asset-{uuid.uuid4().hex[:12]}"
                cursor.execute(
                    """
                    INSERT INTO pqc_crypto_assets (
                        asset_id, analysis_id, target_id, asset_type, identifier,
                        key_exchange_algorithm, cipher_algorithm, signature_algorithm,
                        key_length_bits, has_forward_secrecy, pqc_readiness,
                        hndl_exposure, data_sensitivity_lifetime, first_observed_at,
                        last_observed_at, evidence_reference
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        asset_id,
                        analysis_id,
                        None,
                        "TLS_CIPHER_SUITE",
                        c_suite,
                        str(k_exchange),
                        c_suite,
                        str(sig_algo),
                        256 if "256" in c_suite else (128 if "128" in c_suite else 0),
                        1 if pfs else 0,
                        pqc_readiness.value,
                        exposure.value,
                        lifetime.value,
                        now,
                        now,
                        f"Session {s['session_id']}",
                    ),
                )
                discovered.append(
                    PQCCryptoAssetDTO(
                        asset_id=asset_id,
                        analysis_id=analysis_id,
                        target_id=None,
                        asset_type="TLS_CIPHER_SUITE",
                        identifier=c_suite,
                        key_exchange_algorithm=str(k_exchange),
                        cipher_algorithm=c_suite,
                        signature_algorithm=str(sig_algo),
                        key_length_bits=256 if "256" in c_suite else 128,
                        has_forward_secrecy=pfs,
                        pqc_readiness=pqc_readiness,
                        hndl_exposure=exposure,
                        data_sensitivity_lifetime=lifetime,
                        first_observed_at=now,
                        last_observed_at=now,
                        evidence_reference=f"Session {s['session_id']}",
                    )
                )

        # 2. From Posture Snapshots (Continuous Monitoring)
        if target_id:
            cursor.execute(
                "SELECT * FROM posture_snapshots WHERE target_id = ? ORDER BY scanned_at DESC LIMIT 1;",
                (target_id,),
            )
            snap = cursor.fetchone()
            if snap:
                c_suite = snap["cipher_suite"] or "UNKNOWN"
                pfs_str = snap["pfs_status"] or "NO"
                pfs = "YES" in pfs_str.upper()
                pqc_str = snap["pqc_status"] or "UNKNOWN"
                pqc_readiness = PQCReadinessClassification.HYBRID_READY if "HYBRID" in pqc_str.upper() else PQCReadinessClassification.CLASSICAL_ONLY

                exposure = QuantumExposureLevel.LOW if pqc_readiness == PQCReadinessClassification.HYBRID_READY else (
                    QuantumExposureLevel.HIGH if not pfs else QuantumExposureLevel.MODERATE
                )

                asset_id = f"asset-{uuid.uuid4().hex[:12]}"
                cursor.execute(
                    """
                    INSERT INTO pqc_crypto_assets (
                        asset_id, analysis_id, target_id, asset_type, identifier,
                        key_exchange_algorithm, cipher_algorithm, signature_algorithm,
                        key_length_bits, has_forward_secrecy, pqc_readiness,
                        hndl_exposure, data_sensitivity_lifetime, first_observed_at,
                        last_observed_at, evidence_reference
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        asset_id,
                        None,
                        target_id,
                        "POSTURE_PROBE_CIPHER",
                        c_suite,
                        "ECDHE" if pfs else "RSA",
                        c_suite,
                        "RSA-SHA256",
                        256,
                        1 if pfs else 0,
                        pqc_readiness.value,
                        exposure.value,
                        lifetime.value,
                        now,
                        now,
                        f"Snapshot {snap['snapshot_id']}",
                    ),
                )
                discovered.append(
                    PQCCryptoAssetDTO(
                        asset_id=asset_id,
                        analysis_id=None,
                        target_id=target_id,
                        asset_type="POSTURE_PROBE_CIPHER",
                        identifier=c_suite,
                        key_exchange_algorithm="ECDHE" if pfs else "RSA",
                        cipher_algorithm=c_suite,
                        signature_algorithm="RSA-SHA256",
                        key_length_bits=256,
                        has_forward_secrecy=pfs,
                        pqc_readiness=pqc_readiness,
                        hndl_exposure=exposure,
                        data_sensitivity_lifetime=lifetime,
                        first_observed_at=now,
                        last_observed_at=now,
                        evidence_reference=f"Snapshot {snap['snapshot_id']}",
                    )
                )

        conn.commit()
        conn.close()

        overall_readiness = PQCReadinessClassification.CLASSICAL_ONLY
        if any(a.pqc_readiness == PQCReadinessClassification.HYBRID_READY for a in discovered):
            overall_readiness = PQCReadinessClassification.HYBRID_READY
        elif not discovered:
            overall_readiness = PQCReadinessClassification.UNKNOWN

        highest_exposure = QuantumExposureLevel.LOW
        exposure_ranks = {
            QuantumExposureLevel.CRITICAL: 5,
            QuantumExposureLevel.HIGH: 4,
            QuantumExposureLevel.MODERATE: 3,
            QuantumExposureLevel.LOW: 2,
            QuantumExposureLevel.UNKNOWN: 1,
        }
        for a in discovered:
            if exposure_ranks.get(a.hndl_exposure, 0) > exposure_ranks.get(highest_exposure, 0):
                highest_exposure = a.hndl_exposure

        return PQCDiscoveryResult(
            discovered_assets=discovered,
            overall_pqc_readiness=overall_readiness,
            highest_exposure=highest_exposure,
        )

    @staticmethod
    def create_roadmap(req: PQCRoadmapCreateRequest, created_by: str = "analyst-01") -> PQCMigrationRoadmapDTO:
        """Creates a standardized 7-phase post-quantum migration roadmap with gap findings."""
        roadmap_id = f"pqc-map-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        all_assets: List[PQCCryptoAssetDTO] = []
        if req.analysis_ids:
            for a_id in req.analysis_ids:
                res = PQCMigrationService.discover_assets(analysis_id=a_id)
                all_assets.extend(res.discovered_assets)
        if req.target_ids:
            for t_id in req.target_ids:
                res = PQCMigrationService.discover_assets(target_id=t_id)
                all_assets.extend(res.discovered_assets)

        current_readiness = PQCReadinessClassification.CLASSICAL_ONLY
        if any(a.pqc_readiness == PQCReadinessClassification.HYBRID_READY for a in all_assets):
            current_readiness = PQCReadinessClassification.HYBRID_READY

        highest_exposure = QuantumExposureLevel.HIGH if not any(a.pqc_readiness == PQCReadinessClassification.HYBRID_READY for a in all_assets) else QuantumExposureLevel.LOW

        phase_specs = [
            (
                1,
                MigrationPhaseName.PHASE_A_DISCOVERY,
                "Cryptographic Inventory & Asset Classification",
                "Catalog all classical cryptographic assets, TLS ciphers, key exchanges, and certificates across all email infrastructure.",
                ["NIST SP 800-57", "RFC 8446"],
                ["Cryptographic bill of materials (CBOM)", "Asset exposure registry"],
            ),
            (
                2,
                MigrationPhaseName.PHASE_B_POLICY_GOVERNANCE,
                "Post-Quantum Migration Policy & Governance",
                "Define institutional cryptographic agility policies, deprecation schedules for RSA-2048, and mandate hybrid PQC standards.",
                ["NIST SP 800-227", "CNSA 2.0"],
                ["Cryptographic policy document", "Compliance milestone charter"],
            ),
            (
                3,
                MigrationPhaseName.PHASE_C_HYBRID_KEM,
                "Hybrid Key Encapsulation Mechanism (KEM) Transition",
                "Deploy hybrid key exchange combining classical ECDHE (X25519) with post-quantum ML-KEM-768 for all STARTTLS sessions.",
                ["NIST FIPS 203 (ML-KEM)", "IETF draft-ietf-tls-hybrid-design"],
                ["Hybrid KEM mail server configuration", "HNDL exposure mitigation verification"],
            ),
            (
                4,
                MigrationPhaseName.PHASE_D_PQC_AUTH,
                "Post-Quantum Authentication & Digital Signatures",
                "Pilot post-quantum digital signature algorithms (ML-DSA-65 / Falcon) for server certificates and DKIM signing.",
                ["NIST FIPS 204 (ML-DSA)", "NIST FIPS 205 (SLH-DSA)"],
                ["Post-quantum DKIM signer prototype", "Hybrid PKI certificate chain"],
            ),
            (
                5,
                MigrationPhaseName.PHASE_E_QUANTUM_RESISTANT_TRANSPORT,
                "Quantum-Resistant Protocol Stack & Transport",
                "Enforce quantum-resistant TLS 1.3 across all incoming and outgoing MTA boundaries, disabling non-PFS legacy ciphers.",
                ["RFC 8446", "NIST FIPS 203"],
                ["Hardened MTA transport profiles", "Automated TLS posture regression monitoring"],
            ),
            (
                6,
                MigrationPhaseName.PHASE_F_PQC_PRIMARY_TRANSITION,
                "PQC Primary Transition & Classical Deprecation",
                "Transition primary key exchange to pure NIST ML-KEM and begin phase-out of classical RSA/ECDHE cipher suites.",
                ["NIST FIPS 203", "CNSA 2.0"],
                ["Pure PQC transport benchmarks", "Classical cipher deprecation notice"],
            ),
            (
                7,
                MigrationPhaseName.PHASE_G_COMPLIANCE_AUDIT,
                "Continuous Post-Quantum Compliance & Auditing",
                "Maintain continuous posture auditing, automated drift alerting, and cryptographic chain-of-custody verification.",
                ["ISO/IEC 27001", "NIST CSF 2.0"],
                ["Quarterly PQC compliance audits", "Automated SIEM telemetry feed"],
            ),
        ]

        gap_specs = [
            (
                GapSeverity.HIGH,
                "Classical-Only Key Exchange Exposed to HNDL",
                "Observed mail traffic utilizes classical ECDHE/RSA without post-quantum hybrid protection, exposing long-term confidentiality.",
                "MTA STARTTLS Key Exchange",
                "Deploy X25519MLKEM768 Hybrid Key Exchange",
                "NIST FIPS 203",
            ),
            (
                GapSeverity.MEDIUM,
                "Classical RSA/ECDSA Server Authentication",
                "Server identity certificates utilize classical signatures vulnerable to Shor's algorithm on Cryptanalytically Relevant Quantum Computers (CRQCs).",
                "X.509 Certificate Hierarchy",
                "Migrate to ML-DSA-65 / Hybrid Certificate Authority",
                "NIST FIPS 204",
            ),
        ]

        canonical_dict = {
            "roadmap_id": roadmap_id,
            "title": req.title,
            "target_architecture": req.target_architecture.value,
            "created_by": created_by,
            "created_at": now,
            "phases": [p[1].value for p in phase_specs],
        }
        canonical_json = json.dumps(canonical_dict, sort_keys=True)
        canonical_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO pqc_migration_roadmaps (
                roadmap_id, title, target_architecture, current_readiness,
                highest_exposure, status, total_steps, completed_steps,
                canonical_roadmap_sha256, created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                roadmap_id,
                req.title,
                req.target_architecture.value,
                current_readiness.value,
                highest_exposure.value,
                PQCRoadmapStatus.PROPOSED.value,
                len(phase_specs),
                0,
                canonical_sha256,
                created_by,
                now,
                now,
            ),
        )

        for num, name, title, desc, standards, deliverables in phase_specs:
            step_id = f"step-{uuid.uuid4().hex[:12]}"
            cursor.execute(
                """
                INSERT INTO pqc_migration_steps (
                    step_id, roadmap_id, phase_number, phase_name, title,
                    description, target_standards_json, deliverables_json,
                    status, order_index
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    step_id,
                    roadmap_id,
                    num,
                    name.value,
                    title,
                    desc,
                    json.dumps(standards),
                    json.dumps(deliverables),
                    MigrationStepStatus.NOT_STARTED.value,
                    num,
                ),
            )

        for sev, g_title, g_desc, comp, repl, std_ref in gap_specs:
            gap_id = f"gap-{uuid.uuid4().hex[:12]}"
            cursor.execute(
                """
                INSERT INTO pqc_gap_findings (
                    gap_id, roadmap_id, severity, title, description,
                    affected_component, recommended_pqc_replacement, nist_standard_ref
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    gap_id,
                    roadmap_id,
                    sev.value,
                    g_title,
                    g_desc,
                    comp,
                    repl,
                    std_ref,
                ),
            )

        conn.commit()
        conn.close()
        return PQCMigrationService.get_roadmap(roadmap_id)  # type: ignore

    @staticmethod
    def get_roadmap(roadmap_id: str) -> Optional[PQCMigrationRoadmapDTO]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pqc_migration_roadmaps WHERE roadmap_id = ?;", (roadmap_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        cursor.execute(
            "SELECT * FROM pqc_migration_steps WHERE roadmap_id = ? ORDER BY order_index ASC;",
            (roadmap_id,),
        )
        step_rows = cursor.fetchall()
        steps = [
            PQCMigrationStepDTO(
                step_id=s["step_id"],
                roadmap_id=s["roadmap_id"],
                phase_number=s["phase_number"],
                phase_name=MigrationPhaseName(s["phase_name"]),
                title=s["title"],
                description=s["description"],
                target_standards=json.loads(s["target_standards_json"] or "[]"),
                deliverables=json.loads(s["deliverables_json"] or "[]"),
                status=MigrationStepStatus(s["status"]),
                order_index=s["order_index"],
                notes=s["notes"],
                completed_at=s["completed_at"],
            )
            for s in step_rows
        ]

        cursor.execute(
            "SELECT * FROM pqc_gap_findings WHERE roadmap_id = ?;",
            (roadmap_id,),
        )
        gap_rows = cursor.fetchall()
        gaps = [
            PQCGapFindingDTO(
                gap_id=g["gap_id"],
                roadmap_id=g["roadmap_id"],
                asset_id=g["asset_id"],
                severity=GapSeverity(g["severity"]),
                title=g["title"],
                description=g["description"],
                affected_component=g["affected_component"],
                recommended_pqc_replacement=g["recommended_pqc_replacement"],
                nist_standard_ref=g["nist_standard_ref"],
            )
            for g in gap_rows
        ]

        completed_count = sum(1 for s in steps if s.status == MigrationStepStatus.COMPLETED)
        conn.close()

        return PQCMigrationRoadmapDTO(
            roadmap_id=row["roadmap_id"],
            title=row["title"],
            target_architecture=PQCTransitionTargetArchitecture(row["target_architecture"]),
            current_readiness=PQCReadinessClassification(row["current_readiness"]),
            highest_exposure=QuantumExposureLevel(row["highest_exposure"]),
            status=PQCRoadmapStatus(row["status"]),
            total_steps=row["total_steps"],
            completed_steps=completed_count,
            canonical_roadmap_sha256=row["canonical_roadmap_sha256"],
            signed_by_analyst_id=row["signed_by_analyst_id"],
            signed_by_analyst_name=row["signed_by_analyst_name"],
            signature_algorithm=row["signature_algorithm"],
            signature_value=row["signature_value"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            steps=steps,
            gaps=gaps,
        )

    @staticmethod
    def list_roadmaps() -> List[PQCMigrationRoadmapDTO]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT roadmap_id FROM pqc_migration_roadmaps ORDER BY created_at DESC;")
        rows = cursor.fetchall()
        conn.close()
        roadmaps = []
        for r in rows:
            dto = PQCMigrationService.get_roadmap(r["roadmap_id"])
            if dto:
                roadmaps.append(dto)
        return roadmaps

    @staticmethod
    def update_step(step_id: str, update: PQCMigrationStepUpdate) -> Optional[PQCMigrationStepDTO]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pqc_migration_steps WHERE step_id = ?;", (step_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        now = datetime.now(timezone.utc).isoformat()
        status_val = update.status.value if update.status is not None else row["status"]
        notes_val = update.notes if update.notes is not None else row["notes"]
        completed_at = now if update.status == MigrationStepStatus.COMPLETED else (None if update.status is not None else row["completed_at"])

        cursor.execute(
            """
            UPDATE pqc_migration_steps
            SET status = ?, notes = ?, completed_at = ?
            WHERE step_id = ?;
            """,
            (status_val, notes_val, completed_at, step_id),
        )

        roadmap_id = row["roadmap_id"]
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM pqc_migration_steps WHERE roadmap_id = ? AND status = 'COMPLETED';",
            (roadmap_id,),
        )
        cnt = cursor.fetchone()["cnt"]
        cursor.execute(
            "UPDATE pqc_migration_roadmaps SET completed_steps = ?, updated_at = ? WHERE roadmap_id = ?;",
            (cnt, now, roadmap_id),
        )

        conn.commit()
        cursor.execute("SELECT * FROM pqc_migration_steps WHERE step_id = ?;", (step_id,))
        updated_row = cursor.fetchone()
        conn.close()

        return PQCMigrationStepDTO(
            step_id=updated_row["step_id"],
            roadmap_id=updated_row["roadmap_id"],
            phase_number=updated_row["phase_number"],
            phase_name=MigrationPhaseName(updated_row["phase_name"]),
            title=updated_row["title"],
            description=updated_row["description"],
            target_standards=json.loads(updated_row["target_standards_json"] or "[]"),
            deliverables=json.loads(updated_row["deliverables_json"] or "[]"),
            status=MigrationStepStatus(updated_row["status"]),
            order_index=updated_row["order_index"],
            notes=updated_row["notes"],
            completed_at=updated_row["completed_at"],
        )

    @staticmethod
    def sign_roadmap(
        roadmap_id: str,
        analyst_id: str,
        analyst_name: str,
        private_key_pem: Optional[str] = None,
        key_id: Optional[str] = None,
    ) -> Optional[PQCMigrationRoadmapDTO]:
        """Digitally signs the canonical post-quantum migration roadmap using Ed25519 / RSA-PSS."""
        roadmap = PQCMigrationService.get_roadmap(roadmap_id)
        if not roadmap:
            return None

        payload = roadmap.canonical_roadmap_sha256.encode("utf-8")
        if private_key_pem:
            priv_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
            if isinstance(priv_key, ed25519.Ed25519PrivateKey):
                sig_bytes = priv_key.sign(payload)
                sig_val = base64.b64encode(sig_bytes).decode("utf-8")
                sig_algo = "Ed25519"
            elif isinstance(priv_key, rsa.RSAPrivateKey):
                sig_bytes = priv_key.sign(
                    payload,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256(),
                )
                sig_val = base64.b64encode(sig_bytes).decode("utf-8")
                sig_algo = "RSA-PSS-SHA256"
            else:
                sig_val = f"LOCAL_SIG_{hashlib.sha256(payload).hexdigest()[:16]}"
                sig_algo = "LOCAL_MOCK_SIGNATURE"
        else:
            priv_key = ed25519.Ed25519PrivateKey.generate()
            sig_bytes = priv_key.sign(payload)
            sig_val = base64.b64encode(sig_bytes).decode("utf-8")
            sig_algo = "Ed25519"

        now = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE pqc_migration_roadmaps
            SET status = ?, signed_by_analyst_id = ?, signed_by_analyst_name = ?,
                signature_algorithm = ?, signature_value = ?, updated_at = ?
            WHERE roadmap_id = ?;
            """,
            (
                PQCRoadmapStatus.SIGNED.value,
                analyst_id,
                analyst_name,
                sig_algo,
                sig_val,
                now,
                roadmap_id,
            ),
        )
        conn.commit()
        conn.close()
        return PQCMigrationService.get_roadmap(roadmap_id)

# ==============================================================================
# SecureMailScope X — Phase 21: Posture Monitoring & Drift Detection Service
# ==============================================================================
"""Service implementing continuous mail security posture monitoring, deterministic
snapshot canonical hashing, baseline pinning, configuration drift detection,
and local schedule evaluation.
"""

import json
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from app.db.database import get_db_connection
from app.db.repository import ForensicRepository
from app.schemas.identity import ActorContext
from app.scanner.mail_posture_scanner import MailPostureScanner, PortProbeResult
from app.scanner.target_validator import TargetValidator, ALLOWED_MAIL_PORTS, PORT_PROTOCOL_MAP
from app.schemas.monitoring import (
    MonitoredTarget,
    TargetCreateRequest,
    TargetUpdateRequest,
    PostureSnapshot,
    PostureDriftEvent,
    MonitoringSummaryResponse,
    ScheduleType,
    MonitoredProtocol,
    MonitoredSecurityMode,
    DriftType,
    DriftClassification,
)
from app.schemas.siem import (
    NormalizedSOCEvent,
    SOCEventType,
    SOCEventSeverity,
)


class PostureMonitoringService:
    """Core service for Phase 21 Mail Posture Monitoring & Drift Engine."""

    @staticmethod
    def compute_canonical_snapshot_sha256(data: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 hash over canonical snapshot properties."""
        canonical_dict = {
            "target_id": str(data.get("target_id", "")),
            "reachable": bool(data.get("reachable", False)),
            "protocol": str(data.get("protocol", "")),
            "security_mode": str(data.get("security_mode", "")),
            "starttls_supported": data.get("starttls_supported"),
            "starttls_accepted": data.get("starttls_accepted"),
            "tls_version": data.get("tls_version"),
            "cipher_suite": data.get("cipher_suite"),
            "certificate_fingerprint": data.get("certificate_fingerprint"),
            "certificate_subject": data.get("certificate_subject"),
            "certificate_issuer": data.get("certificate_issuer"),
            "certificate_valid": data.get("certificate_valid"),
            "pfs_status": data.get("pfs_status"),
            "pqc_status": data.get("pqc_status"),
            "scan_result_sha256": str(data.get("scan_result_sha256", "")),
        }
        canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @staticmethod
    def _evaluate_pfs(tls_version: Optional[str], cipher_suite: Optional[str]) -> str:
        """Determines Perfect Forward Secrecy support from TLS version and cipher."""
        if not tls_version:
            return "UNKNOWN"
        ver = tls_version.upper()
        if "1.3" in ver or "TLSV1.3" in ver:
            return "SUPPORTED"
        if not cipher_suite:
            return "UNKNOWN"
        c_upper = cipher_suite.upper()
        if any(p in c_upper for p in ("ECDHE", "DHE", "ED25519", "X25519")):
            return "SUPPORTED"
        if "RSA" in c_upper and not any(p in c_upper for p in ("ECDHE", "DHE")):
            return "NOT_SUPPORTED"
        return "UNKNOWN"

    @staticmethod
    def _evaluate_pqc(cipher_suite: Optional[str]) -> str:
        """Determines Post-Quantum Cryptography status from cipher details."""
        if not cipher_suite:
            return "UNKNOWN"
        c_upper = cipher_suite.upper()
        if any(k in c_upper for k in ("KYBER", "MLKEM", "ML-KEM", "X25519KYBER768", "SECP256R1KYBER768")):
            return "HYBRID_READY"
        return "CLASSICAL_ONLY"

    @classmethod
    def create_target(
        cls,
        req: TargetCreateRequest,
        actor_id: str = "analyst-01",
        db_path: Optional[str] = None,
    ) -> MonitoredTarget:
        """Registers a new monitored mail server target with validation."""
        if req.port not in ALLOWED_MAIL_PORTS:
            raise ValueError(f"Port {req.port} is not an allowed mail service port. Allowed: {sorted(list(ALLOWED_MAIL_PORTS))}")

        # Derive protocol & security mode if omitted
        default_proto_str, default_mode_str = PORT_PROTOCOL_MAP.get(req.port, ("SMTP", "STARTTLS"))
        protocol = req.protocol or MonitoredProtocol(default_proto_str)
        if req.security_mode:
            security_mode = req.security_mode
        else:
            if "DIRECT" in default_mode_str.upper():
                security_mode = MonitoredSecurityMode.DIRECT_TLS
            else:
                security_mode = MonitoredSecurityMode.PLAIN_WITH_STARTTLS

        target_id = f"target-{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO monitored_targets (
                target_id, display_name, hostname, port, protocol, security_mode,
                enabled, schedule_type, schedule_value, baseline_snapshot_id,
                baseline_pinned_by, baseline_pinned_at, last_scanned_at, next_scan_due_at,
                created_at, updated_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?, ?)
            """,
            (
                target_id,
                req.display_name.strip(),
                req.hostname.strip(),
                req.port,
                protocol.value,
                security_mode.value,
                1 if req.enabled else 0,
                req.schedule_type.value,
                req.schedule_value,
                now_iso,
                now_iso,
                actor_id,
            ),
        )
        conn.commit()
        conn.close()

        # Audit event
        ForensicRepository.record_audit_event(
            event_type="MONITORED_TARGET_CREATED",
            object_type="MONITORED_TARGET",
            object_id=target_id,
            details=f"Created monitored target {req.display_name} ({req.hostname}:{req.port})",
            actor=ActorContext.local_declared(actor_id, actor_id),
            db_path=db_path,
        )

        return cls.get_target(target_id, db_path=db_path)  # type: ignore

    @classmethod
    def get_target(cls, target_id: str, db_path: Optional[str] = None) -> Optional[MonitoredTarget]:
        """Retrieves a single monitored target by ID."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM monitored_targets WHERE target_id = ?", (target_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return MonitoredTarget(
            target_id=row["target_id"],
            display_name=row["display_name"],
            hostname=row["hostname"],
            port=row["port"],
            protocol=MonitoredProtocol(row["protocol"]),
            security_mode=MonitoredSecurityMode(row["security_mode"]),
            enabled=bool(row["enabled"]),
            schedule_type=ScheduleType(row["schedule_type"]),
            schedule_value=row["schedule_value"],
            baseline_snapshot_id=row["baseline_snapshot_id"],
            baseline_pinned_by=row["baseline_pinned_by"],
            baseline_pinned_at=row["baseline_pinned_at"],
            last_scanned_at=row["last_scanned_at"],
            next_scan_due_at=row["next_scan_due_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            created_by=row["created_by"],
        )

    @classmethod
    def list_targets(cls, enabled_only: bool = False, db_path: Optional[str] = None) -> List[MonitoredTarget]:
        """Lists all registered monitored targets."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        if enabled_only:
            cursor.execute("SELECT * FROM monitored_targets WHERE enabled = 1 ORDER BY created_at DESC")
        else:
            cursor.execute("SELECT * FROM monitored_targets ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()

        targets = []
        for row in rows:
            targets.append(
                MonitoredTarget(
                    target_id=row["target_id"],
                    display_name=row["display_name"],
                    hostname=row["hostname"],
                    port=row["port"],
                    protocol=MonitoredProtocol(row["protocol"]),
                    security_mode=MonitoredSecurityMode(row["security_mode"]),
                    enabled=bool(row["enabled"]),
                    schedule_type=ScheduleType(row["schedule_type"]),
                    schedule_value=row["schedule_value"],
                    baseline_snapshot_id=row["baseline_snapshot_id"],
                    baseline_pinned_by=row["baseline_pinned_by"],
                    baseline_pinned_at=row["baseline_pinned_at"],
                    last_scanned_at=row["last_scanned_at"],
                    next_scan_due_at=row["next_scan_due_at"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    created_by=row["created_by"],
                )
            )
        return targets

    @classmethod
    def update_target(
        cls,
        target_id: str,
        req: TargetUpdateRequest,
        actor_id: str = "analyst-01",
        db_path: Optional[str] = None,
    ) -> Optional[MonitoredTarget]:
        """Updates properties of an existing monitored target."""
        target = cls.get_target(target_id, db_path=db_path)
        if not target:
            return None

        if req.port is not None and req.port not in ALLOWED_MAIL_PORTS:
            raise ValueError(f"Port {req.port} is not an allowed mail service port.")

        display_name = req.display_name if req.display_name is not None else target.display_name
        hostname = req.hostname if req.hostname is not None else target.hostname
        port = req.port if req.port is not None else target.port
        protocol = req.protocol.value if req.protocol is not None else target.protocol.value
        security_mode = req.security_mode.value if req.security_mode is not None else target.security_mode.value
        enabled = (1 if req.enabled else 0) if req.enabled is not None else (1 if target.enabled else 0)
        schedule_type = req.schedule_type.value if req.schedule_type is not None else target.schedule_type.value
        schedule_value = req.schedule_value if req.schedule_value is not None else target.schedule_value
        now_iso = datetime.now(timezone.utc).isoformat()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE monitored_targets
            SET display_name = ?, hostname = ?, port = ?, protocol = ?, security_mode = ?,
                enabled = ?, schedule_type = ?, schedule_value = ?, updated_at = ?
            WHERE target_id = ?
            """,
            (
                display_name,
                hostname,
                port,
                protocol,
                security_mode,
                enabled,
                schedule_type,
                schedule_value,
                now_iso,
                target_id,
            ),
        )
        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="MONITORED_TARGET_UPDATED",
            object_type="MONITORED_TARGET",
            object_id=target_id,
            details=f"Updated monitored target {target_id}",
            actor=ActorContext.local_declared(actor_id, actor_id),
            db_path=db_path,
        )

        return cls.get_target(target_id, db_path=db_path)

    @classmethod
    def delete_target(
        cls,
        target_id: str,
        actor_id: str = "analyst-01",
        db_path: Optional[str] = None,
    ) -> bool:
        """Deletes a monitored target along with cascaded snapshots and drift events."""
        target = cls.get_target(target_id, db_path=db_path)
        if not target:
            return False

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM monitored_targets WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM posture_snapshots WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM posture_drift_events WHERE target_id = ?", (target_id,))
        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="MONITORED_TARGET_DELETED",
            object_type="MONITORED_TARGET",
            object_id=target_id,
            details=f"Deleted monitored target {target_id} ({target.hostname})",
            actor=ActorContext.local_declared(actor_id, actor_id),
            db_path=db_path,
        )
        return True

    @classmethod
    def pin_baseline(
        cls,
        target_id: str,
        snapshot_id: str,
        actor_id: str = "analyst-01",
        db_path: Optional[str] = None,
    ) -> Optional[MonitoredTarget]:
        """Pins a specific verified posture snapshot as the authoritative baseline."""
        target = cls.get_target(target_id, db_path=db_path)
        if not target:
            raise ValueError(f"Target {target_id} not found.")

        snapshot = cls.get_snapshot(snapshot_id, db_path=db_path)
        if not snapshot or snapshot.target_id != target_id:
            raise ValueError(f"Snapshot {snapshot_id} does not exist or does not belong to target {target_id}.")

        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE monitored_targets
            SET baseline_snapshot_id = ?, baseline_pinned_by = ?, baseline_pinned_at = ?, updated_at = ?
            WHERE target_id = ?
            """,
            (snapshot_id, actor_id, now_iso, now_iso, target_id),
        )
        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="POSTURE_BASELINE_PINNED",
            object_type="MONITORED_TARGET",
            object_id=target_id,
            details=f"Pinned baseline snapshot {snapshot_id} for target {target_id}",
            actor=ActorContext.local_declared(actor_id, actor_id),
            db_path=db_path,
        )

        return cls.get_target(target_id, db_path=db_path)

    @classmethod
    def get_snapshot(cls, snapshot_id: str, db_path: Optional[str] = None) -> Optional[PostureSnapshot]:
        """Retrieves a single posture snapshot by ID."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM posture_snapshots WHERE snapshot_id = ?", (snapshot_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return cls._row_to_snapshot(row)

    @classmethod
    def list_snapshots(
        cls, target_id: str, limit: int = 50, db_path: Optional[str] = None
    ) -> List[PostureSnapshot]:
        """Lists posture snapshots for a specific target ordered by time descending."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM posture_snapshots WHERE target_id = ? ORDER BY scanned_at DESC LIMIT ?",
            (target_id, limit),
        )
        rows = cursor.fetchall()
        conn.close()
        return [cls._row_to_snapshot(r) for r in rows]

    @classmethod
    def get_latest_snapshot(cls, target_id: str, db_path: Optional[str] = None) -> Optional[PostureSnapshot]:
        """Retrieves the most recent posture snapshot for a target."""
        snaps = cls.list_snapshots(target_id, limit=1, db_path=db_path)
        return snaps[0] if snaps else None

    @classmethod
    def list_drift_events(
        cls, target_id: Optional[str] = None, limit: int = 100, db_path: Optional[str] = None
    ) -> List[PostureDriftEvent]:
        """Lists posture drift events across one or all targets."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        if target_id:
            cursor.execute(
                "SELECT * FROM posture_drift_events WHERE target_id = ? ORDER BY detected_at DESC LIMIT ?",
                (target_id, limit),
            )
        else:
            cursor.execute(
                "SELECT * FROM posture_drift_events ORDER BY detected_at DESC LIMIT ?",
                (limit,),
            )
        rows = cursor.fetchall()
        conn.close()

        events = []
        for r in rows:
            events.append(
                PostureDriftEvent(
                    event_id=r["event_id"],
                    target_id=r["target_id"],
                    prior_snapshot_id=r["prior_snapshot_id"],
                    current_snapshot_id=r["current_snapshot_id"],
                    drift_type=DriftType(r["drift_type"]),
                    classification=DriftClassification(r["classification"]),
                    old_value=r["old_value"],
                    new_value=r["new_value"],
                    details=r["details"],
                    detected_at=r["detected_at"],
                    compared_against_baseline=bool(r["compared_against_baseline"]),
                )
            )
        return events

    @classmethod
    def detect_drift(
        cls,
        prior: Optional[PostureSnapshot],
        current: PostureSnapshot,
        is_baseline_comparison: bool = False,
    ) -> List[PostureDriftEvent]:
        """Compares current snapshot against prior snapshot or pinned baseline."""
        if prior is None:
            return []

        events: List[PostureDriftEvent] = []
        now_iso = current.scanned_at
        tid = current.target_id
        pid = prior.snapshot_id
        cid = current.snapshot_id

        # Helper to append an event
        def _add(
            dtype: DriftType,
            dclass: DriftClassification,
            old_val: Optional[str],
            new_val: Optional[str],
            msg: str,
        ):
            events.append(
                PostureDriftEvent(
                    event_id=f"drift-{uuid.uuid4().hex[:12]}",
                    target_id=tid,
                    prior_snapshot_id=pid,
                    current_snapshot_id=cid,
                    drift_type=dtype,
                    classification=dclass,
                    old_value=old_val,
                    new_value=new_val,
                    details=msg,
                    detected_at=now_iso,
                    compared_against_baseline=is_baseline_comparison,
                )
            )

        # 1. Reachability drift
        if prior.reachable and not current.reachable:
            _add(
                DriftType.ENDPOINT_BECAME_UNREACHABLE,
                DriftClassification.REGRESSION,
                "reachable=True",
                "reachable=False",
                "Mail service endpoint is no longer reachable or connection refused.",
            )
        elif not prior.reachable and current.reachable:
            _add(
                DriftType.ENDPOINT_RECOVERED,
                DriftClassification.IMPROVEMENT,
                "reachable=False",
                "reachable=True",
                "Mail service endpoint recovered and is now reachable.",
            )

        # If current is unreachable, further TLS/cert comparisons are skipped
        if not current.reachable or not prior.reachable:
            return events

        # 2. TLS Version drift
        if prior.tls_version != current.tls_version and current.tls_version:
            tls_order = {"TLSv1.3": 3, "TLSv1.2": 2, "TLSv1.1": 1, "TLSv1": 0, "SSLv3": -1}
            p_rank = tls_order.get(prior.tls_version or "", 0)
            c_rank = tls_order.get(current.tls_version or "", 0)

            if c_rank < p_rank:
                _add(
                    DriftType.TLS_DOWNGRADE,
                    DriftClassification.REGRESSION,
                    prior.tls_version,
                    current.tls_version,
                    f"Negotiated TLS version downgraded from {prior.tls_version} to {current.tls_version}.",
                )
            elif c_rank > p_rank:
                _add(
                    DriftType.TLS_UPGRADE,
                    DriftClassification.IMPROVEMENT,
                    prior.tls_version,
                    current.tls_version,
                    f"Negotiated TLS version upgraded from {prior.tls_version} to {current.tls_version}.",
                )
            else:
                _add(
                    DriftType.TLS_VERSION_CHANGED,
                    DriftClassification.NEUTRAL,
                    prior.tls_version,
                    current.tls_version,
                    f"Negotiated TLS version changed from {prior.tls_version} to {current.tls_version}.",
                )

        # 3. STARTTLS status drift
        p_stls = bool(prior.starttls_supported)
        c_stls = bool(current.starttls_supported)
        if p_stls and not c_stls:
            _add(
                DriftType.STARTTLS_DISABLED,
                DriftClassification.REGRESSION,
                "starttls=True",
                "starttls=False",
                "STARTTLS advertisement is no longer offered by the mail server.",
            )
        elif not p_stls and c_stls:
            _add(
                DriftType.STARTTLS_ENABLED,
                DriftClassification.IMPROVEMENT,
                "starttls=False",
                "starttls=True",
                "STARTTLS advertisement was enabled on the mail server.",
            )

        # 4. Cipher suite drift
        if prior.cipher_suite and current.cipher_suite and prior.cipher_suite != current.cipher_suite:
            _add(
                DriftType.CIPHER_CHANGED,
                DriftClassification.NEUTRAL,
                prior.cipher_suite,
                current.cipher_suite,
                f"Active cipher suite changed from {prior.cipher_suite} to {current.cipher_suite}.",
            )

        # 5. Certificate drift
        if prior.certificate_fingerprint and current.certificate_fingerprint:
            if prior.certificate_fingerprint != current.certificate_fingerprint:
                # Fingerprint changed
                if current.certificate_valid is False:
                    _add(
                        DriftType.CERTIFICATE_EXPIRED,
                        DriftClassification.REGRESSION,
                        prior.certificate_fingerprint,
                        current.certificate_fingerprint,
                        "Server presented a new certificate that is expired or invalid.",
                    )
                elif prior.certificate_valid is False and current.certificate_valid is True:
                    _add(
                        DriftType.CERTIFICATE_RENEWED,
                        DriftClassification.IMPROVEMENT,
                        prior.certificate_fingerprint,
                        current.certificate_fingerprint,
                        "Expired certificate was renewed with a valid new certificate.",
                    )
                else:
                    _add(
                        DriftType.CERTIFICATE_CHANGED,
                        DriftClassification.NEUTRAL,
                        prior.certificate_fingerprint,
                        current.certificate_fingerprint,
                        "Server presented a different certificate fingerprint.",
                    )
            elif prior.certificate_valid is True and current.certificate_valid is False:
                _add(
                    DriftType.CERTIFICATE_EXPIRED,
                    DriftClassification.REGRESSION,
                    "valid=True",
                    "valid=False",
                    "Certificate validity window expired since last observation.",
                )

        # 6. PFS drift
        if prior.pfs_status and current.pfs_status and prior.pfs_status != current.pfs_status:
            if prior.pfs_status == "SUPPORTED" and current.pfs_status != "SUPPORTED":
                _add(
                    DriftType.PFS_STATUS_CHANGED,
                    DriftClassification.REGRESSION,
                    prior.pfs_status,
                    current.pfs_status,
                    f"Perfect Forward Secrecy was lost (changed from {prior.pfs_status} to {current.pfs_status}).",
                )
            elif prior.pfs_status != "SUPPORTED" and current.pfs_status == "SUPPORTED":
                _add(
                    DriftType.PFS_STATUS_CHANGED,
                    DriftClassification.IMPROVEMENT,
                    prior.pfs_status,
                    current.pfs_status,
                    "Perfect Forward Secrecy was enabled.",
                )

        # 7. PQC drift
        if prior.pqc_status and current.pqc_status and prior.pqc_status != current.pqc_status:
            if current.pqc_status == "HYBRID_READY":
                _add(
                    DriftType.PQC_STATUS_CHANGED,
                    DriftClassification.IMPROVEMENT,
                    prior.pqc_status,
                    current.pqc_status,
                    "Post-Quantum Cryptography readiness achieved with hybrid key exchange.",
                )
            elif prior.pqc_status == "HYBRID_READY":
                _add(
                    DriftType.PQC_STATUS_CHANGED,
                    DriftClassification.REGRESSION,
                    prior.pqc_status,
                    current.pqc_status,
                    "Post-Quantum Cryptography hybrid support was removed.",
                )

        return events

    @classmethod
    def scan_target(
        cls,
        target_id: str,
        actor_id: str = "analyst-01",
        allow_local_testing: bool = False,
        validate_cert_trust: bool = False,
        socket_factory=None,
        db_path: Optional[str] = None,
    ) -> Tuple[PostureSnapshot, List[PostureDriftEvent]]:
        """Executes active posture scan against target, generates canonical snapshot and drift ledger."""
        target = cls.get_target(target_id, db_path=db_path)
        if not target:
            raise ValueError(f"Monitored target {target_id} does not exist.")

        prior_snapshot = cls.get_latest_snapshot(target_id, db_path=db_path)
        baseline_snapshot = (
            cls.get_snapshot(target.baseline_snapshot_id, db_path=db_path)
            if target.baseline_snapshot_id
            else None
        )

        now_iso = datetime.now(timezone.utc).isoformat()
        snapshot_id = f"snap-{uuid.uuid4().hex[:12]}"

        # 1. Target validation and SSRF safe resolution
        is_safe, resolved_ip, err_reason, _ = TargetValidator.is_safe_public_target(
            target.hostname, allow_local_testing=allow_local_testing
        )

        probe_res: Optional[PortProbeResult] = None
        if not is_safe:
            # Unsafe or unresolvable
            probe_dict = {
                "connection_status": "RESOLUTION_FAILED",
                "error": err_reason,
                "timestamp": now_iso,
            }
            probe_raw_json = json.dumps(probe_dict, sort_keys=True)
            scan_result_sha = hashlib.sha256(probe_raw_json.encode("utf-8")).hexdigest()

            snapshot = PostureSnapshot(
                snapshot_id=snapshot_id,
                target_id=target_id,
                scanned_at=now_iso,
                reachable=False,
                protocol=target.protocol.value,
                security_mode=target.security_mode.value,
                starttls_supported=False,
                starttls_accepted=False,
                tls_version=None,
                cipher_suite=None,
                certificate_fingerprint=None,
                certificate_subject=None,
                certificate_issuer=None,
                certificate_not_before=None,
                certificate_not_after=None,
                certificate_valid=None,
                pfs_status="UNKNOWN",
                pqc_status="UNKNOWN",
                auth_posture=None,
                raw_evidence_reference=probe_raw_json,
                scan_result_sha256=scan_result_sha,
                canonical_snapshot_sha256="",
            )
        else:
            # Execute safe probe
            probe_res = MailPostureScanner.probe_port(
                target=target.hostname,
                resolved_ip=resolved_ip,
                port=target.port,
                timeout_sec=5.0,
                validate_cert_trust=validate_cert_trust,
                socket_factory=socket_factory,
            )

            probe_dict = probe_res.to_dict()
            probe_raw_json = json.dumps(probe_dict, sort_keys=True)
            scan_result_sha = hashlib.sha256(probe_raw_json.encode("utf-8")).hexdigest()

            is_reachable = probe_res.connection_status == "SUCCESS" or (
                probe_res.tls is not None and probe_res.tls.negotiated_version is not None
            )

            tls_ver = probe_res.tls.negotiated_version if probe_res.tls else None
            cipher = probe_res.tls.selected_cipher if probe_res.tls else None

            cert_fp = probe_res.certificate.sha256_fingerprint if probe_res.certificate else None
            cert_subj = probe_res.certificate.subject if probe_res.certificate else None
            cert_iss = probe_res.certificate.issuer if probe_res.certificate else None
            cert_nb = probe_res.certificate.not_before if probe_res.certificate else None
            cert_na = probe_res.certificate.not_after if probe_res.certificate else None
            cert_val = (not probe_res.certificate.is_expired) if probe_res.certificate else None

            pfs = cls._evaluate_pfs(tls_ver, cipher)
            pqc = cls._evaluate_pqc(cipher)

            stls_supp = (
                probe_res.starttls_advertised
                or probe_res.starttls_status in ("STARTTLS_ADVERTISED", "STARTTLS_ACCEPTED")
            )
            stls_acc = probe_res.starttls_accepted

            snapshot = PostureSnapshot(
                snapshot_id=snapshot_id,
                target_id=target_id,
                scanned_at=now_iso,
                reachable=is_reachable,
                protocol=target.protocol.value,
                security_mode=target.security_mode.value,
                starttls_supported=stls_supp,
                starttls_accepted=stls_acc,
                tls_version=tls_ver,
                cipher_suite=cipher,
                certificate_fingerprint=cert_fp,
                certificate_subject=cert_subj,
                certificate_issuer=cert_iss,
                certificate_not_before=cert_nb,
                certificate_not_after=cert_na,
                certificate_valid=cert_val,
                pfs_status=pfs,
                pqc_status=pqc,
                auth_posture=None,
                raw_evidence_reference=probe_raw_json,
                scan_result_sha256=scan_result_sha,
                canonical_snapshot_sha256="",
            )

        # 2. Compute canonical snapshot SHA-256
        snap_dict = snapshot.model_dump() if hasattr(snapshot, "model_dump") else snapshot.dict()
        canonical_sha = cls.compute_canonical_snapshot_sha256(snap_dict)
        snapshot.canonical_snapshot_sha256 = canonical_sha

        # 3. Persist snapshot to database
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO posture_snapshots (
                snapshot_id, target_id, scanned_at, reachable, protocol, security_mode,
                starttls_supported, starttls_accepted, tls_version, cipher_suite,
                certificate_fingerprint, certificate_subject, certificate_issuer,
                certificate_not_before, certificate_not_after, certificate_valid,
                pfs_status, pqc_status, auth_posture, raw_evidence_reference,
                scan_result_sha256, canonical_snapshot_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot.snapshot_id,
                snapshot.target_id,
                snapshot.scanned_at,
                1 if snapshot.reachable else 0,
                snapshot.protocol,
                snapshot.security_mode,
                1 if snapshot.starttls_supported else (0 if snapshot.starttls_supported is False else None),
                1 if snapshot.starttls_accepted else (0 if snapshot.starttls_accepted is False else None),
                snapshot.tls_version,
                snapshot.cipher_suite,
                snapshot.certificate_fingerprint,
                snapshot.certificate_subject,
                snapshot.certificate_issuer,
                snapshot.certificate_not_before,
                snapshot.certificate_not_after,
                1 if snapshot.certificate_valid else (0 if snapshot.certificate_valid is False else None),
                snapshot.pfs_status,
                snapshot.pqc_status,
                snapshot.auth_posture,
                snapshot.raw_evidence_reference,
                snapshot.scan_result_sha256,
                snapshot.canonical_snapshot_sha256,
            ),
        )

        # 4. Compute next scan due timestamp if scheduled
        next_due_iso = None
        if target.schedule_type != ScheduleType.MANUAL and target.enabled:
            sched = target.schedule_type
            scan_dt = datetime.fromisoformat(now_iso)
            if sched == ScheduleType.HOURLY:
                next_due_iso = (scan_dt + timedelta(hours=1)).isoformat()
            elif sched == ScheduleType.DAILY:
                next_due_iso = (scan_dt + timedelta(days=1)).isoformat()
            elif sched == ScheduleType.WEEKLY:
                next_due_iso = (scan_dt + timedelta(days=7)).isoformat()

        cursor.execute(
            """
            UPDATE monitored_targets
            SET last_scanned_at = ?, next_scan_due_at = ?, updated_at = ?
            WHERE target_id = ?
            """,
            (now_iso, next_due_iso, now_iso, target_id),
        )
        conn.commit()

        # 5. Detect drift against prior snapshot
        drift_events = cls.detect_drift(prior_snapshot, snapshot, is_baseline_comparison=False)

        # 6. Detect drift against baseline if baseline exists and is distinct from prior snapshot
        if baseline_snapshot and (not prior_snapshot or prior_snapshot.snapshot_id != baseline_snapshot.snapshot_id):
            baseline_drifts = cls.detect_drift(baseline_snapshot, snapshot, is_baseline_comparison=True)
            drift_events.extend(baseline_drifts)

        # 7. Persist drift events
        for dev in drift_events:
            cursor.execute(
                """
                INSERT INTO posture_drift_events (
                    event_id, target_id, prior_snapshot_id, current_snapshot_id,
                    drift_type, classification, old_value, new_value, details,
                    detected_at, compared_against_baseline
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dev.event_id,
                    dev.target_id,
                    dev.prior_snapshot_id,
                    dev.current_snapshot_id,
                    dev.drift_type.value,
                    dev.classification.value,
                    dev.old_value,
                    dev.new_value,
                    dev.details,
                    dev.detected_at,
                    1 if dev.compared_against_baseline else 0,
                ),
            )
        conn.commit()
        conn.close()

        # 8. Record audit log
        ForensicRepository.record_audit_event(
            event_type="POSTURE_SCAN_COMPLETED",
            object_type="MONITORED_TARGET",
            object_id=target_id,
            details=f"Completed scan on {target.hostname}:{target.port} -> snapshot {snapshot.snapshot_id}, detected {len(drift_events)} drift events",
            actor=ActorContext.local_declared(actor_id, actor_id),
            db_path=db_path,
        )

        return snapshot, drift_events

    @classmethod
    def is_scan_due(cls, target: MonitoredTarget, as_of: Optional[datetime] = None) -> bool:
        """Determines if a target is due for a scheduled scan."""
        if not target.enabled or target.schedule_type == ScheduleType.MANUAL:
            return False

        if not target.last_scanned_at:
            return True

        ref_time = as_of or datetime.now(timezone.utc)
        try:
            last_dt = datetime.fromisoformat(target.last_scanned_at)
        except Exception:
            return True

        if target.schedule_type == ScheduleType.HOURLY:
            return (ref_time - last_dt) >= timedelta(hours=1)
        elif target.schedule_type == ScheduleType.DAILY:
            return (ref_time - last_dt) >= timedelta(days=1)
        elif target.schedule_type == ScheduleType.WEEKLY:
            return (ref_time - last_dt) >= timedelta(days=7)

        return False

    @classmethod
    def run_due_scans(
        cls,
        actor_id: str = "scheduler",
        allow_local_testing: bool = False,
        validate_cert_trust: bool = False,
        socket_factory=None,
        as_of: Optional[datetime] = None,
        db_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Runs scheduled posture scans for all due enabled targets."""
        all_targets = cls.list_targets(enabled_only=True, db_path=db_path)
        due_targets = [t for t in all_targets if cls.is_scan_due(t, as_of=as_of)]

        scanned_count = 0
        drift_count = 0
        results = []

        for t in due_targets:
            try:
                snap, drifts = cls.scan_target(
                    t.target_id,
                    actor_id=actor_id,
                    allow_local_testing=allow_local_testing,
                    validate_cert_trust=validate_cert_trust,
                    socket_factory=socket_factory,
                    db_path=db_path,
                )
                scanned_count += 1
                drift_count += len(drifts)
                results.append({
                    "target_id": t.target_id,
                    "hostname": t.hostname,
                    "snapshot_id": snap.snapshot_id,
                    "drift_events_count": len(drifts),
                    "status": "SUCCESS",
                })
            except Exception as ex:
                results.append({
                    "target_id": t.target_id,
                    "hostname": t.hostname,
                    "status": "ERROR",
                    "error": str(ex),
                })

        return {
            "total_due": len(due_targets),
            "scanned_count": scanned_count,
            "total_drift_events": drift_count,
            "results": results,
            "evaluated_at": (as_of or datetime.now(timezone.utc)).isoformat(),
        }

    @classmethod
    def derive_siem_events_from_drift(
        cls,
        drift_event: PostureDriftEvent,
        target: Optional[MonitoredTarget] = None,
    ) -> NormalizedSOCEvent:
        """Derives a normalized SIEM / SOC event from a posture drift event without network transmission."""
        severity_map = {
            DriftClassification.REGRESSION: SOCEventSeverity.HIGH,
            DriftClassification.IMPROVEMENT: SOCEventSeverity.LOW,
            DriftClassification.NEUTRAL: SOCEventSeverity.INFO,
            DriftClassification.UNKNOWN: SOCEventSeverity.INFO,
        }

        sev = severity_map.get(drift_event.classification, SOCEventSeverity.INFO)
        host_str = target.hostname if target else drift_event.target_id
        port_num = target.port if target else None
        proto_str = target.protocol.value if target else None

        return NormalizedSOCEvent(
            event_id=f"soc-drift-{drift_event.event_id}",
            event_type=SOCEventType.POSTURE_DRIFT_OBSERVED,
            timestamp=drift_event.detected_at,
            severity=sev,
            source_component="POSTURE_MONITOR",
            protocol=proto_str,
            dst_ip=host_str,
            dst_port=port_num,
            finding_code=drift_event.drift_type.value,
            message=f"Posture drift detected on {host_str}:{port_num}: {drift_event.details}",
            mitigation="Review server TLS/certificate configuration against target security baseline.",
            raw_details={
                "drift_event_id": drift_event.event_id,
                "target_id": drift_event.target_id,
                "prior_snapshot_id": drift_event.prior_snapshot_id,
                "current_snapshot_id": drift_event.current_snapshot_id,
                "classification": drift_event.classification.value,
                "old_value": drift_event.old_value,
                "new_value": drift_event.new_value,
                "compared_against_baseline": drift_event.compared_against_baseline,
            },
        )

    @classmethod
    def get_monitoring_summary(cls, db_path: Optional[str] = None) -> MonitoringSummaryResponse:
        """Aggregates overall statistics on monitored targets, snapshots, and drift."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as c FROM monitored_targets")
        total_targets = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM monitored_targets WHERE enabled = 1")
        enabled_targets = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM posture_snapshots")
        total_snapshots = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM posture_drift_events")
        total_drift_events = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM posture_drift_events WHERE classification = 'REGRESSION'")
        regressions_count = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM posture_drift_events WHERE classification = 'IMPROVEMENT'")
        improvements_count = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM posture_drift_events WHERE classification = 'NEUTRAL'")
        neutral_count = cursor.fetchone()["c"]

        cursor.execute("SELECT MAX(scanned_at) as last_scan FROM posture_snapshots")
        last_scan_row = cursor.fetchone()
        last_scan_ts = last_scan_row["last_scan"] if last_scan_row else None

        conn.close()

        return MonitoringSummaryResponse(
            total_targets=total_targets,
            enabled_targets=enabled_targets,
            total_snapshots=total_snapshots,
            total_drift_events=total_drift_events,
            regressions_count=regressions_count,
            improvements_count=improvements_count,
            neutral_count=neutral_count,
            last_scan_timestamp=last_scan_ts,
        )

    @staticmethod
    def _row_to_snapshot(row: Any) -> PostureSnapshot:
        """Converts an SQLite row to a PostureSnapshot model."""
        return PostureSnapshot(
            snapshot_id=row["snapshot_id"],
            target_id=row["target_id"],
            scanned_at=row["scanned_at"],
            reachable=bool(row["reachable"]),
            protocol=row["protocol"],
            security_mode=row["security_mode"],
            starttls_supported=bool(row["starttls_supported"]) if row["starttls_supported"] is not None else None,
            starttls_accepted=bool(row["starttls_accepted"]) if row["starttls_accepted"] is not None else None,
            tls_version=row["tls_version"],
            cipher_suite=row["cipher_suite"],
            certificate_fingerprint=row["certificate_fingerprint"],
            certificate_subject=row["certificate_subject"],
            certificate_issuer=row["certificate_issuer"],
            certificate_not_before=row["certificate_not_before"],
            certificate_not_after=row["certificate_not_after"],
            certificate_valid=bool(row["certificate_valid"]) if row["certificate_valid"] is not None else None,
            pfs_status=row["pfs_status"],
            pqc_status=row["pqc_status"],
            auth_posture=row["auth_posture"],
            raw_evidence_reference=row["raw_evidence_reference"],
            scan_result_sha256=row["scan_result_sha256"],
            canonical_snapshot_sha256=row["canonical_snapshot_sha256"],
        )

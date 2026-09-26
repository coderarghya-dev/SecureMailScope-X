# ==============================================================================
# SecureMailScope X — Phase 20/21: Multi-Analyst RBAC & Peer Sign-Off Service
# ==============================================================================
"""Core service implementing role-based access control (RBAC), capability checks,
multi-analyst case assignments, manifest-bound review lifecycles, cryptographic
peer sign-offs (Ed25519/RSA), M-of-N case sealing policies, and posture monitoring capabilities.
"""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from app.db.database import get_db_connection
from app.db.repository import ForensicRepository, compute_sha256
from app.schemas.identity import ActorContext
from app.schemas.rbac import (
    AnalystRecord,
    AnalystRole,
    AssignAnalystRequest,
    AssignmentRole,
    Capability,
    CaseAssignment,
    CaseAuthorizationStatus,
    CaseReview,
    CaseReviewPolicy,
    CaseReviewPolicyUpdate,
    ReviewStatus,
    SignatureVerificationResponse,
)


ROLE_CAPABILITIES: Dict[AnalystRole, Set[Capability]] = {
    AnalystRole.FORENSIC_ANALYST: {
        Capability.VIEW_CASE,
        Capability.EDIT_CASE,
        Capability.REQUEST_REVIEW,
        Capability.VIEW_MONITORING,
        Capability.RUN_MONITOR_SCAN,
        Capability.VIEW_DRIFT_HISTORY,
        Capability.VIEW_REMEDIATION,
        Capability.CREATE_REMEDIATION_PLAN,
        Capability.EDIT_REMEDIATION_PLAN,
        Capability.RUN_SIMULATION,
        Capability.MARK_APPLIED,
        Capability.VIEW_ALERTS,
        Capability.EVALUATE_ALERTS,
        Capability.ACKNOWLEDGE_ALERT,
        Capability.RESOLVE_ALERT,
        Capability.VIEW_PQC_ROADMAP,
        Capability.CREATE_PQC_ROADMAP,
        Capability.EDIT_PQC_ROADMAP,
    },
    AnalystRole.LEAD_INVESTIGATOR: {
        Capability.VIEW_CASE,
        Capability.EDIT_CASE,
        Capability.ASSIGN_ANALYST,
        Capability.REQUEST_REVIEW,
        Capability.SUBMIT_REVIEW,
        Capability.SIGN_OFF,
        Capability.SEAL_CASE,
        Capability.VIEW_MONITORING,
        Capability.MANAGE_MONITORED_TARGETS,
        Capability.RUN_MONITOR_SCAN,
        Capability.PIN_POSTURE_BASELINE,
        Capability.VIEW_DRIFT_HISTORY,
        Capability.VIEW_REMEDIATION,
        Capability.CREATE_REMEDIATION_PLAN,
        Capability.EDIT_REMEDIATION_PLAN,
        Capability.RUN_SIMULATION,
        Capability.MARK_APPLIED,
        Capability.VERIFY_REMEDIATION,
        Capability.VIEW_ALERTS,
        Capability.MANAGE_ALERT_RULES,
        Capability.EVALUATE_ALERTS,
        Capability.ACKNOWLEDGE_ALERT,
        Capability.RESOLVE_ALERT,
        Capability.VIEW_PQC_ROADMAP,
        Capability.CREATE_PQC_ROADMAP,
        Capability.EDIT_PQC_ROADMAP,
        Capability.SIGN_PQC_ROADMAP,
    },
    AnalystRole.REVIEWER: {
        Capability.VIEW_CASE,
        Capability.SUBMIT_REVIEW,
        Capability.SIGN_OFF,
        Capability.VIEW_MONITORING,
        Capability.VIEW_DRIFT_HISTORY,
        Capability.VIEW_REMEDIATION,
        Capability.RUN_SIMULATION,
        Capability.VERIFY_REMEDIATION,
        Capability.VIEW_ALERTS,
        Capability.VIEW_PQC_ROADMAP,
        Capability.SIGN_PQC_ROADMAP,
    },
    AnalystRole.AUDITOR: {
        Capability.VIEW_CASE,
        Capability.VIEW_MONITORING,
        Capability.VIEW_DRIFT_HISTORY,
        Capability.VIEW_REMEDIATION,
        Capability.VIEW_ALERTS,
        Capability.VIEW_PQC_ROADMAP,
    },
    AnalystRole.ADMIN: {
        Capability.VIEW_CASE,
        Capability.EDIT_CASE,
        Capability.ASSIGN_ANALYST,
        Capability.REQUEST_REVIEW,
        Capability.SUBMIT_REVIEW,
        Capability.SIGN_OFF,
        Capability.SEAL_CASE,
        Capability.OVERRIDE_POLICY,
        Capability.MANAGE_ROLES,
        Capability.VIEW_MONITORING,
        Capability.MANAGE_MONITORED_TARGETS,
        Capability.RUN_MONITOR_SCAN,
        Capability.PIN_POSTURE_BASELINE,
        Capability.VIEW_DRIFT_HISTORY,
        Capability.VIEW_REMEDIATION,
        Capability.CREATE_REMEDIATION_PLAN,
        Capability.EDIT_REMEDIATION_PLAN,
        Capability.RUN_SIMULATION,
        Capability.MARK_APPLIED,
        Capability.VERIFY_REMEDIATION,
        Capability.VIEW_ALERTS,
        Capability.MANAGE_ALERT_RULES,
        Capability.EVALUATE_ALERTS,
        Capability.ACKNOWLEDGE_ALERT,
        Capability.RESOLVE_ALERT,
        Capability.VIEW_PQC_ROADMAP,
        Capability.CREATE_PQC_ROADMAP,
        Capability.EDIT_PQC_ROADMAP,
        Capability.SIGN_PQC_ROADMAP,
    },
}


class AuthorizationService:
    """Centralized RBAC authorization evaluator and analyst registry manager."""

    @classmethod
    def can(cls, role: AnalystRole, capability: Capability) -> bool:
        """Check if an analyst role possesses a given capability."""
        allowed = ROLE_CAPABILITIES.get(role, set())
        return capability in allowed

    @classmethod
    def get_analyst(cls, analyst_id: str, db_path: Optional[str] = None) -> Optional[AnalystRecord]:
        """Retrieve an analyst profile from the registry."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analysts WHERE analyst_id = ?;", (analyst_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None
        row_dict = dict(row)
        return AnalystRecord(
            analyst_id=row_dict["analyst_id"],
            display_name=row_dict["display_name"],
            email_or_label=row_dict.get("email_or_label"),
            role=AnalystRole(row_dict.get("role", AnalystRole.FORENSIC_ANALYST.value)),
            identity_source=row_dict.get("identity_source", "LOCAL_DECLARED"),
            attribution_status=row_dict.get("attribution_status", "ATTRIBUTED"),
            is_active=bool(row_dict.get("is_active", 1)),
            created_at=row_dict["created_at"],
            updated_at=row_dict["updated_at"],
        )

    @classmethod
    def list_analysts(cls, db_path: Optional[str] = None) -> List[AnalystRecord]:
        """List all analysts registered in the system."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analysts ORDER BY created_at ASC;")
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            rd = dict(r)
            results.append(
                AnalystRecord(
                    analyst_id=rd["analyst_id"],
                    display_name=rd["display_name"],
                    email_or_label=rd.get("email_or_label"),
                    role=AnalystRole(rd.get("role", AnalystRole.FORENSIC_ANALYST.value)),
                    identity_source=rd.get("identity_source", "LOCAL_DECLARED"),
                    attribution_status=rd.get("attribution_status", "ATTRIBUTED"),
                    is_active=bool(rd.get("is_active", 1)),
                    created_at=rd["created_at"],
                    updated_at=rd["updated_at"],
                )
            )
        return results

    @classmethod
    def create_or_update_analyst(
        cls,
        analyst_id: str,
        display_name: str,
        role: AnalystRole = AnalystRole.FORENSIC_ANALYST,
        email_or_label: Optional[str] = None,
        identity_source: str = "LOCAL_DECLARED",
        attribution_status: str = "ATTRIBUTED",
        db_path: Optional[str] = None,
    ) -> AnalystRecord:
        """Register or update an analyst record."""
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM analysts WHERE analyst_id = ?;", (analyst_id,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                """
                UPDATE analysts
                SET display_name = ?, email_or_label = ?, role = ?, updated_at = ?
                WHERE analyst_id = ?;
                """,
                (display_name, email_or_label, role.value, now_iso, analyst_id),
            )
        else:
            cursor.execute(
                """
                INSERT INTO analysts (
                    analyst_id, display_name, email_or_label, role, identity_source,
                    attribution_status, created_at, updated_at, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1);
                """,
                (analyst_id, display_name, email_or_label, role.value, identity_source, attribution_status, now_iso, now_iso),
            )

        conn.commit()
        conn.close()
        return cls.get_analyst(analyst_id, db_path=db_path)

    @classmethod
    def set_analyst_role(
        cls,
        analyst_id: str,
        new_role: AnalystRole,
        reason: Optional[str] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> AnalystRecord:
        """Change an analyst's RBAC role and record an audit event."""
        analyst = cls.get_analyst(analyst_id, db_path=db_path)
        if not analyst:
            raise ValueError(f"Analyst '{analyst_id}' not found")

        old_role = analyst.role
        now_iso = datetime.now(timezone.utc).isoformat()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE analysts SET role = ?, updated_at = ? WHERE analyst_id = ?;",
            (new_role.value, now_iso, analyst_id),
        )
        conn.commit()
        conn.close()

        # Record hash-chained audit event
        ForensicRepository.record_audit_event(
            event_type="ROLE_CHANGED",
            object_type="ANALYST",
            object_id=analyst_id,
            details=f"Role changed from {old_role.value} to {new_role.value}. Reason: {reason or 'Administrative update'}",
            actor=actor,
            db_path=db_path,
        )

        return cls.get_analyst(analyst_id, db_path=db_path)


class CaseAssignmentService:
    """Manages assignment of primary investigators, analysts, and reviewers to cases."""

    @classmethod
    def assign_analyst(
        cls,
        case_id: str,
        analyst_id: str,
        role: AssignmentRole = AssignmentRole.ASSIGNED_ANALYST,
        assigned_by: str = "analyst-01",
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> CaseAssignment:
        """Assign an analyst to a forensic case."""
        case = ForensicRepository.get_case(case_id, db_path=db_path)
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        analyst = AuthorizationService.get_analyst(analyst_id, db_path=db_path)
        analyst_name = analyst.display_name if analyst else analyst_id

        assignment_id = f"asgn-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO case_assignments (
                assignment_id, case_id, analyst_id, analyst_name, role, assigned_by, assigned_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1);
            """,
            (assignment_id, case_id, analyst_id, analyst_name, role.value, assigned_by, now_iso),
        )
        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="CASE_ASSIGNED",
            object_type="CASE",
            object_id=case_id,
            details=f"Assigned analyst '{analyst_name}' ({analyst_id}) with role {role.value}",
            actor=actor,
            db_path=db_path,
        )

        return CaseAssignment(
            assignment_id=assignment_id,
            case_id=case_id,
            analyst_id=analyst_id,
            analyst_name=analyst_name,
            role=role,
            assigned_by=assigned_by,
            assigned_at=now_iso,
            is_active=True,
        )

    @classmethod
    def remove_assignment(
        cls,
        case_id: str,
        assignment_id: str,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> bool:
        """Deactivate a case assignment."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE case_assignments SET is_active = 0 WHERE assignment_id = ? AND case_id = ?;",
            (assignment_id, case_id),
        )
        affected = cursor.rowcount
        conn.commit()
        conn.close()

        if affected > 0:
            ForensicRepository.record_audit_event(
                event_type="CASE_UNASSIGNED",
                object_type="CASE",
                object_id=case_id,
                details=f"Deactivated assignment {assignment_id}",
                actor=actor,
                db_path=db_path,
            )
            return True
        return False

    @classmethod
    def list_assignments(
        cls,
        case_id: str,
        active_only: bool = True,
        db_path: Optional[str] = None,
    ) -> List[CaseAssignment]:
        """List all assignments for a given case."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        if active_only:
            cursor.execute("SELECT * FROM case_assignments WHERE case_id = ? AND is_active = 1 ORDER BY assigned_at ASC;", (case_id,))
        else:
            cursor.execute("SELECT * FROM case_assignments WHERE case_id = ? ORDER BY assigned_at ASC;", (case_id,))
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            rd = dict(r)
            results.append(
                CaseAssignment(
                    assignment_id=rd["assignment_id"],
                    case_id=rd["case_id"],
                    analyst_id=rd["analyst_id"],
                    analyst_name=rd["analyst_name"],
                    role=AssignmentRole(rd["role"]),
                    assigned_by=rd["assigned_by"],
                    assigned_at=rd["assigned_at"],
                    is_active=bool(rd["is_active"]),
                )
            )
        return results


class CaseManifestService:
    """Computes deterministic canonical SHA-256 manifests representing exact case state."""

    @classmethod
    def compute_case_manifest_sha256(cls, case_id: str, db_path: Optional[str] = None) -> str:
        """Compute authoritative SHA-256 hash of a case's current content."""
        case = ForensicRepository.get_case(case_id, db_path=db_path)
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        # Canonicalize artifacts
        raw_artifacts = case.get("artifacts", [])
        norm_artifacts = []
        for a in raw_artifacts:
            norm_artifacts.append({
                "type": a.get("artifact_type", ""),
                "filename": a.get("filename", ""),
                "sha256": a.get("sha256", ""),
            })
        norm_artifacts.sort(key=lambda x: (x["type"], x["filename"], x["sha256"]))

        # Canonicalize notes
        raw_notes = case.get("analyst_notes", [])
        norm_notes = []
        for n in raw_notes:
            author = n.get("author") or n.get("analyst_name") or ""
            note_sha = n.get("note_sha256")
            if not note_sha:
                note_sha = compute_sha256((n.get("note_text", "")).encode("utf-8"))
            norm_notes.append({
                "author": author,
                "note_sha256": note_sha,
            })
        norm_notes.sort(key=lambda x: x["note_sha256"])

        # Canonicalize analysis IDs
        analysis_ids = sorted(case.get("analysis_ids", []))

        canonical_dict = {
            "case_id": case["id"],
            "title": case.get("title", ""),
            "description": case.get("description", ""),
            "analysis_ids": analysis_ids,
            "artifacts": norm_artifacts,
            "notes": norm_notes,
        }

        canonical_json_bytes = json.dumps(
            canonical_dict,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

        return hashlib.sha256(canonical_json_bytes).hexdigest()


class PeerReviewService:
    """Manages review requests, cryptographic sign-offs, M-of-N policies, and seal authorization."""

    @classmethod
    def get_or_create_policy(cls, case_id: str, db_path: Optional[str] = None) -> CaseReviewPolicy:
        """Retrieve existing review policy for a case or initialize default."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM case_review_policies WHERE case_id = ?;", (case_id,))
        row = cursor.fetchone()

        if row:
            rd = dict(row)
            conn.close()
            return CaseReviewPolicy(
                policy_id=rd["policy_id"],
                case_id=rd["case_id"],
                min_approvals_required=rd["min_approvals_required"],
                require_lead_investigator_approval=bool(rd["require_lead_investigator_approval"]),
                allow_self_review=bool(rd["allow_self_review"]),
                created_at=rd["created_at"],
                updated_at=rd["updated_at"],
            )

        # Create default policy
        policy_id = f"pol-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT INTO case_review_policies (
                policy_id, case_id, min_approvals_required, require_lead_investigator_approval,
                allow_self_review, created_at, updated_at
            ) VALUES (?, ?, 1, 0, 0, ?, ?);
            """,
            (policy_id, case_id, now_iso, now_iso),
        )
        conn.commit()
        conn.close()

        return CaseReviewPolicy(
            policy_id=policy_id,
            case_id=case_id,
            min_approvals_required=1,
            require_lead_investigator_approval=False,
            allow_self_review=False,
            created_at=now_iso,
            updated_at=now_iso,
        )

    @classmethod
    def update_policy(
        cls,
        case_id: str,
        update: CaseReviewPolicyUpdate,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> CaseReviewPolicy:
        """Update case review and sealing policy."""
        policy = cls.get_or_create_policy(case_id, db_path=db_path)
        now_iso = datetime.now(timezone.utc).isoformat()

        min_app = update.min_approvals_required if update.min_approvals_required is not None else policy.min_approvals_required
        req_lead = int(update.require_lead_investigator_approval) if update.require_lead_investigator_approval is not None else int(policy.require_lead_investigator_approval)
        allow_self = int(update.allow_self_review) if update.allow_self_review is not None else int(policy.allow_self_review)

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE case_review_policies
            SET min_approvals_required = ?, require_lead_investigator_approval = ?, allow_self_review = ?, updated_at = ?
            WHERE case_id = ?;
            """,
            (min_app, req_lead, allow_self, now_iso, case_id),
        )
        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="CASE_REVIEW_POLICY_UPDATED",
            object_type="CASE",
            object_id=case_id,
            details=f"Policy updated: min_approvals={min_app}, req_lead={bool(req_lead)}, allow_self={bool(allow_self)}",
            actor=actor,
            db_path=db_path,
        )

        return cls.get_or_create_policy(case_id, db_path=db_path)

    @classmethod
    def request_review(
        cls,
        case_id: str,
        requested_by: str,
        target_reviewer_ids: Optional[List[str]] = None,
        comments: Optional[str] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Initiate peer review request on current case state."""
        case = ForensicRepository.get_case(case_id, db_path=db_path)
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        current_manifest_sha = CaseManifestService.compute_case_manifest_sha256(case_id, db_path=db_path)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Update case status to IN_REVIEW if OPEN
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE cases SET status = 'IN_REVIEW', updated_at = ? WHERE id = ?;",
            (now_iso, case_id),
        )
        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="CASE_REVIEW_REQUESTED",
            object_type="CASE",
            object_id=case_id,
            details=f"Review requested by {requested_by} on manifest {current_manifest_sha}. Comments: {comments or 'None'}",
            actor=actor,
            db_path=db_path,
        )

        return {
            "case_id": case_id,
            "status": "IN_REVIEW",
            "manifest_sha256": current_manifest_sha,
            "requested_by": requested_by,
            "target_reviewer_ids": target_reviewer_ids or [],
            "requested_at": now_iso,
        }

    @classmethod
    def submit_review(
        cls,
        case_id: str,
        reviewer_id: str,
        decision: ReviewStatus,
        comments: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        key_id: Optional[str] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> CaseReview:
        """Submit a peer review decision, optionally bound by a cryptographic digital signature."""
        case = ForensicRepository.get_case(case_id, db_path=db_path)
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        # Fetch reviewer profile & verify capability
        reviewer = AuthorizationService.get_analyst(reviewer_id, db_path=db_path)
        reviewer_role = reviewer.role if reviewer else AnalystRole.REVIEWER
        reviewer_name = reviewer.display_name if reviewer else reviewer_id

        if not AuthorizationService.can(reviewer_role, Capability.SUBMIT_REVIEW):
            raise PermissionError(f"Role '{reviewer_role.value}' lacks capability SUBMIT_REVIEW")

        # Evaluate self-review policy
        policy = cls.get_or_create_policy(case_id, db_path=db_path)
        if not policy.allow_self_review:
            is_creator = (case.get("analyst_id") == reviewer_id or case.get("created_by_actor_id") == reviewer_id)
            if is_creator:
                raise PermissionError(f"Self-review not permitted: analyst '{reviewer_id}' is the primary case investigator")

        current_manifest_sha = CaseManifestService.compute_case_manifest_sha256(case_id, db_path=db_path)
        now_iso = datetime.now(timezone.utc).isoformat()
        review_id = f"rev-{uuid.uuid4().hex[:8]}"

        # Cryptographic sign-off if private key provided
        signature_id = None
        signature_value = None
        signed_payload_sha256 = None
        pubkey_pem_str = None
        pubkey_fingerprint = None

        if private_key_pem:
            canonical_payload = {
                "case_id": case_id,
                "manifest_sha256": current_manifest_sha,
                "reviewer_id": reviewer_id,
                "decision": decision.value,
                "timestamp": now_iso,
            }
            payload_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            signed_payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()

            # Load private key and sign
            priv_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
            pub_key = priv_key.public_key()
            pubkey_pem_bytes = pub_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
            pubkey_pem_str = pubkey_pem_bytes.decode("utf-8")
            pubkey_fingerprint = hashlib.sha256(pubkey_pem_bytes).hexdigest()

            if isinstance(priv_key, ed25519.Ed25519PrivateKey):
                sig_raw = priv_key.sign(payload_bytes)
            elif isinstance(priv_key, rsa.RSAPrivateKey):
                sig_raw = priv_key.sign(
                    payload_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            else:
                raise ValueError("Unsupported key type for sign-off")

            signature_value = base64.b64encode(sig_raw).decode("utf-8")
            signature_id = f"sig-rev-{uuid.uuid4().hex[:8]}"

            ForensicRepository.record_audit_event(
                event_type="CASE_SIGNOFF_VERIFIED",
                object_type="CASE_REVIEW",
                object_id=review_id,
                details=f"Cryptographic sign-off generated for {reviewer_name} ({reviewer_id}) with key {key_id or 'default'}",
                actor=actor,
                db_path=db_path,
            )

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO case_reviews (
                review_id, case_id, manifest_sha256_at_review, reviewer_id, reviewer_name,
                reviewer_role, decision, comments, signature_id, signature_value,
                signed_payload_sha256, public_key_pem, public_key_fingerprint,
                reviewed_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1);
            """,
            (
                review_id,
                case_id,
                current_manifest_sha,
                reviewer_id,
                reviewer_name,
                reviewer_role.value,
                decision.value,
                comments,
                signature_id,
                signature_value,
                signed_payload_sha256,
                pubkey_pem_str,
                pubkey_fingerprint,
                now_iso,
            ),
        )
        conn.commit()
        conn.close()

        event_type = "CASE_REVIEW_APPROVED" if decision == ReviewStatus.APPROVED else "CASE_REVIEW_REJECTED"
        ForensicRepository.record_audit_event(
            event_type=event_type,
            object_type="CASE",
            object_id=case_id,
            details=f"Review decision {decision.value} by {reviewer_name} on manifest {current_manifest_sha}",
            actor=actor,
            db_path=db_path,
        )

        return CaseReview(
            review_id=review_id,
            case_id=case_id,
            manifest_sha256_at_review=current_manifest_sha,
            reviewer_id=reviewer_id,
            reviewer_name=reviewer_name,
            reviewer_role=reviewer_role,
            decision=decision,
            comments=comments,
            signature_id=signature_id,
            signature_value=signature_value,
            signed_payload_sha256=signed_payload_sha256,
            public_key_pem=pubkey_pem_str,
            public_key_fingerprint=pubkey_fingerprint,
            reviewed_at=now_iso,
            is_active=True,
            manifest_matches_current=True,
        )

    @classmethod
    def list_reviews(cls, case_id: str, db_path: Optional[str] = None) -> List[CaseReview]:
        """List all historical and active reviews for a case with current manifest match evaluation."""
        current_manifest_sha = CaseManifestService.compute_case_manifest_sha256(case_id, db_path=db_path)
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM case_reviews WHERE case_id = ? ORDER BY reviewed_at DESC;", (case_id,))
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            rd = dict(r)
            manifest_at_review = rd["manifest_sha256_at_review"]
            results.append(
                CaseReview(
                    review_id=rd["review_id"],
                    case_id=rd["case_id"],
                    manifest_sha256_at_review=manifest_at_review,
                    reviewer_id=rd["reviewer_id"],
                    reviewer_name=rd["reviewer_name"],
                    reviewer_role=AnalystRole(rd["reviewer_role"]),
                    decision=ReviewStatus(rd["decision"]),
                    comments=rd.get("comments"),
                    signature_id=rd.get("signature_id"),
                    signature_value=rd.get("signature_value"),
                    signed_payload_sha256=rd.get("signed_payload_sha256"),
                    public_key_pem=rd.get("public_key_pem"),
                    public_key_fingerprint=rd.get("public_key_fingerprint"),
                    reviewed_at=rd["reviewed_at"],
                    is_active=bool(rd["is_active"]),
                    manifest_matches_current=(manifest_at_review == current_manifest_sha),
                )
            )
        return results

    @classmethod
    def get_case_authorization_status(cls, case_id: str, db_path: Optional[str] = None) -> CaseAuthorizationStatus:
        """Evaluate whether a case satisfies M-of-N peer approval policies to permit sealing."""
        policy = cls.get_or_create_policy(case_id, db_path=db_path)
        current_manifest_sha = CaseManifestService.compute_case_manifest_sha256(case_id, db_path=db_path)
        reviews = cls.list_reviews(case_id, db_path=db_path)

        valid_approved = [
            r for r in reviews
            if r.is_active and r.decision == ReviewStatus.APPROVED and r.manifest_matches_current
        ]

        unmet_reasons = []
        approvals_count = len(valid_approved)
        required_approvals = policy.min_approvals_required

        if approvals_count < required_approvals:
            unmet_reasons.append(
                f"Quorum unmet: requires {required_approvals} valid approval(s) on current manifest, but found {approvals_count}."
            )

        if policy.require_lead_investigator_approval:
            has_lead_approval = any(
                r.reviewer_role in (AnalystRole.LEAD_INVESTIGATOR, AnalystRole.ADMIN)
                for r in valid_approved
            )
            if not has_lead_approval:
                unmet_reasons.append("Lead Investigator sign-off required by policy.")

        can_seal = (len(unmet_reasons) == 0)

        # Determine aggregate status
        if any(r.is_active and r.decision == ReviewStatus.REJECTED and r.manifest_matches_current for r in reviews):
            agg_status = ReviewStatus.REJECTED
        elif any(r.is_active and r.decision == ReviewStatus.CHANGES_REQUESTED and r.manifest_matches_current for r in reviews):
            agg_status = ReviewStatus.CHANGES_REQUESTED
        elif can_seal:
            agg_status = ReviewStatus.APPROVED
        elif len(reviews) > 0:
            agg_status = ReviewStatus.PENDING_REVIEW
        else:
            agg_status = ReviewStatus.NOT_REQUESTED

        return CaseAuthorizationStatus(
            case_id=case_id,
            current_manifest_sha256=current_manifest_sha,
            review_status=agg_status,
            policy=policy,
            approvals_count=approvals_count,
            required_approvals=required_approvals,
            can_seal=can_seal,
            unmet_reasons=unmet_reasons,
            reviews=reviews,
        )

    @classmethod
    def verify_review_signature(
        cls,
        case_id: str,
        review_id: str,
        db_path: Optional[str] = None,
    ) -> SignatureVerificationResponse:
        """Cryptographically verify an Ed25519 or RSA sign-off signature."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM case_reviews WHERE review_id = ? AND case_id = ?;", (review_id, case_id))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return SignatureVerificationResponse(
                valid=False,
                manifest_matches_current=False,
                verification_details=f"Review '{review_id}' not found",
            )

        rd = dict(row)
        sig_val = rd.get("signature_value")
        pubkey_pem = rd.get("public_key_pem")
        manifest_at_review = rd["manifest_sha256_at_review"]

        if not sig_val or not pubkey_pem:
            return SignatureVerificationResponse(
                valid=False,
                manifest_matches_current=False,
                verification_details="Review does not contain a digital signature",
            )

        current_manifest_sha = CaseManifestService.compute_case_manifest_sha256(case_id, db_path=db_path)
        manifest_matches = (manifest_at_review == current_manifest_sha)

        canonical_payload = {
            "case_id": case_id,
            "manifest_sha256": manifest_at_review,
            "reviewer_id": rd["reviewer_id"],
            "decision": rd["decision"],
            "timestamp": rd["reviewed_at"],
        }
        payload_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig_bytes = base64.b64decode(sig_val)

        try:
            pub_key = load_pem_public_key(pubkey_pem.encode("utf-8"))
            if isinstance(pub_key, ed25519.Ed25519PublicKey):
                pub_key.verify(sig_bytes, payload_bytes)
            elif isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(
                    sig_bytes,
                    payload_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            else:
                return SignatureVerificationResponse(
                    valid=False,
                    manifest_matches_current=manifest_matches,
                    verification_details="Unsupported public key type",
                )

            return SignatureVerificationResponse(
                valid=True,
                manifest_matches_current=manifest_matches,
                public_key_fingerprint=rd.get("public_key_fingerprint"),
                verification_details="Signature cryptographically valid and authentic",
            )
        except InvalidSignature:
            return SignatureVerificationResponse(
                valid=False,
                manifest_matches_current=manifest_matches,
                verification_details="Cryptographic signature verification failed",
            )
        except Exception as ex:
            return SignatureVerificationResponse(
                valid=False,
                manifest_matches_current=manifest_matches,
                verification_details=f"Verification error: {str(ex)}",
            )

    @classmethod
    def authorize_and_seal_case(
        cls,
        case_id: str,
        actor_id: str,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Authorize and seal a case if RBAC capabilities and M-of-N sign-offs are satisfied."""
        analyst = AuthorizationService.get_analyst(actor_id, db_path=db_path)
        role = analyst.role if analyst else AnalystRole.FORENSIC_ANALYST

        if not AuthorizationService.can(role, Capability.SEAL_CASE):
            raise PermissionError(f"Actor '{actor_id}' with role '{role.value}' lacks capability SEAL_CASE")

        auth_status = cls.get_case_authorization_status(case_id, db_path=db_path)
        if not auth_status.can_seal:
            raise PermissionError(f"Case seal not authorized: {'; '.join(auth_status.unmet_reasons)}")

        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE cases SET status = 'SEALED', updated_at = ? WHERE id = ?;",
            (now_iso, case_id),
        )
        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="CASE_SEAL_AUTHORIZED",
            object_type="CASE",
            object_id=case_id,
            details=f"Case sealed by {actor_id} ({role.value}) with {auth_status.approvals_count} valid peer sign-offs on manifest {auth_status.current_manifest_sha256}",
            actor=actor,
            db_path=db_path,
        )

        return ForensicRepository.get_case(case_id, db_path=db_path)

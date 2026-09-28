"""
SecureMailScope X - Case Management Service (Phase 11 / Phase 17)
Manages forensic investigative cases, grouping multiple PCAPs, EMLs, analyses, and additive analyst notes.
"""

import uuid
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from app.db.database import get_db_connection
from app.db.repository import ForensicRepository
from app.schemas.identity import ActorContext


@dataclass
class CaseArtifact:
    artifact_id: str
    artifact_type: str  # "PCAP" | "EML" | "REPORT" | "ACTIVE_SCAN"
    filename: str
    sha256: str
    added_at_iso: str
    analysis_id: Optional[str] = None


@dataclass
class ForensicCase:
    id: str
    title: str
    description: str
    status: str  # "OPEN" | "IN_REVIEW" | "CLOSED" | "ARCHIVED"
    analyst_id: str
    analyst_name: str
    tags: List[str] = field(default_factory=list)
    artifacts: List[CaseArtifact] = field(default_factory=list)
    analysis_ids: List[str] = field(default_factory=list)
    analyst_notes: List[Dict[str, Any]] = field(default_factory=list)
    created_at_iso: str = ""
    updated_at_iso: str = ""
    is_archived: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "analyst_id": self.analyst_id,
            "analyst_name": self.analyst_name,
            "tags": self.tags,
            "artifacts": [a.__dict__ if hasattr(a, "__dict__") else a for a in self.artifacts],
            "analysis_ids": self.analysis_ids,
            "analyst_notes": self.analyst_notes,
            "created_at_iso": self.created_at_iso,
            "updated_at_iso": self.updated_at_iso,
            "is_archived": self.is_archived,
        }


class CaseService:
    """Provides persistent operations and artifact linking for forensic cases."""

    @classmethod
    def create_case(
        cls,
        title: str,
        description: str = "",
        analyst_id: Optional[str] = None,
        analyst_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> ForensicCase:
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        case_dict = ForensicRepository.create_case(
            case_id=case_id,
            title=title,
            description=description,
            analyst_id=analyst_id,
            analyst_name=analyst_name,
            tags=tags or ["Email-Forensics"],
            actor=actor,
            db_path=db_path,
        )
        return ForensicCase(
            id=case_dict["id"],
            title=case_dict["title"],
            description=case_dict["description"],
            status=case_dict["status"],
            analyst_id=case_dict["analyst_id"],
            analyst_name=case_dict["analyst_name"],
            tags=case_dict["tags"],
            artifacts=[],
            analysis_ids=[],
            analyst_notes=[],
            created_at_iso=case_dict["created_at_iso"],
            updated_at_iso=case_dict["updated_at_iso"],
            is_archived=case_dict["is_archived"],
        )

    @classmethod
    def list_cases(cls, include_archived: bool = False, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """List cases with attached analyses and notes."""
        return ForensicRepository.list_cases(include_archived=include_archived, db_path=db_path)

    @classmethod
    def get_case(cls, case_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve full case details."""
        return ForensicRepository.get_case(case_id, db_path=db_path)

    @classmethod
    def attach_analysis_to_case(
        cls,
        case_id: str,
        analysis_id: str,
        analyst_id: Optional[str] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Attaches an analysis to a case."""
        success = ForensicRepository.attach_analysis_to_case(case_id, analysis_id, analyst_id=analyst_id, actor=actor, db_path=db_path)
        if not success:
            return None
        return ForensicRepository.get_case(case_id, db_path=db_path)

    @classmethod
    def detach_analysis_from_case(
        cls,
        case_id: str,
        analysis_id: str,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Detaches an analysis from a case."""
        success = ForensicRepository.detach_analysis_from_case(case_id, analysis_id, actor=actor, db_path=db_path)
        if not success:
            return None
        return ForensicRepository.get_case(case_id, db_path=db_path)

    @classmethod
    def add_artifact_to_case(
        cls,
        case_id: str,
        artifact_type: str,
        filename: str,
        sha256: str,
        analysis_id: Optional[str] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Adds an artifact link to a case."""
        case_dict = ForensicRepository.get_case(case_id, db_path=db_path)
        if not case_dict:
            return None

        art_id = f"art_{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        attached_by = actor.actor_id if actor else "analyst"

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO case_artifacts (artifact_id, case_id, artifact_type, filename, sha256, analysis_id, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (art_id, case_id, artifact_type, filename, sha256, analysis_id, now_iso)
        )
        if analysis_id:
            cursor.execute(
                "INSERT INTO case_analyses (case_id, analysis_id, attached_at, attached_by) VALUES (?, ?, ?, ?) ON CONFLICT (case_id, analysis_id) DO NOTHING",
                (case_id, analysis_id, now_iso, attached_by)
            )
        cursor.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now_iso, case_id))
        conn.commit()
        conn.close()

        return ForensicRepository.get_case(case_id, db_path=db_path)

    @classmethod
    def add_note_to_case(
        cls,
        case_id: str,
        author: Optional[str] = None,
        note_text: str = "",
        analyst_id: Optional[str] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Appends an immutable analyst note to a case."""
        case_dict = ForensicRepository.get_case(case_id, db_path=db_path)
        if not case_dict:
            return None

        note_id = f"note_{uuid.uuid4().hex[:8]}"
        ForensicRepository.add_analyst_note(
            note_id=note_id,
            target_type="CASE",
            target_id=case_id,
            analyst_id=analyst_id,
            analyst_name=author,
            note_text=note_text,
            actor=actor,
            db_path=db_path,
        )
        return ForensicRepository.get_case(case_id, db_path=db_path)

    @classmethod
    def add_note_to_analysis(
        cls,
        analysis_id: str,
        author: Optional[str] = None,
        note_text: str = "",
        analyst_id: Optional[str] = None,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Appends an immutable analyst note to an analysis."""
        analysis = ForensicRepository.get_analysis(analysis_id, db_path=db_path)
        if not analysis:
            return None

        note_id = f"note_{uuid.uuid4().hex[:8]}"
        return ForensicRepository.add_analyst_note(
            note_id=note_id,
            target_type="ANALYSIS",
            target_id=analysis_id,
            analyst_id=analyst_id,
            analyst_name=author,
            note_text=note_text,
            actor=actor,
            db_path=db_path,
        )

    @classmethod
    def archive_case(
        cls,
        case_id: str,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Soft-archives a case without erasing linked evidence."""
        return ForensicRepository.archive_case(case_id, actor=actor, db_path=db_path)


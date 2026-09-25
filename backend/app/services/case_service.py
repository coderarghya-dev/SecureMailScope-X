"""
SecureMailScope X - Case Management Service (Phase 17)
Manages forensic investigative cases, grouping multiple PCAPs, EMLs, analyses, and analyst notes.
"""

import uuid
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from app.db.database import get_db_connection


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
    status: str  # "OPEN" | "IN_PROGRESS" | "CLOSED" | "ARCHIVED"
    analyst_id: str
    analyst_name: str
    tags: List[str] = field(default_factory=list)
    artifacts: List[CaseArtifact] = field(default_factory=list)
    analysis_ids: List[str] = field(default_factory=list)
    analyst_notes: List[Dict[str, Any]] = field(default_factory=list)
    created_at_iso: str = ""
    updated_at_iso: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "analyst_id": self.analyst_id,
            "analyst_name": self.analyst_name,
            "tags": self.tags,
            "artifacts": [a.__dict__ for a in self.artifacts],
            "analysis_ids": self.analysis_ids,
            "analyst_notes": self.analyst_notes,
            "created_at_iso": self.created_at_iso,
            "updated_at_iso": self.updated_at_iso,
        }


class CaseService:
    """Provides CRUD operations and artifact linking for forensic cases."""

    @classmethod
    def create_case(
        cls,
        title: str,
        description: str = "",
        analyst_id: str = "analyst-01",
        analyst_name: str = "Default Local Analyst",
        tags: Optional[List[str]] = None,
    ) -> ForensicCase:
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        new_case = ForensicCase(
            id=case_id,
            title=title,
            description=description,
            status="OPEN",
            analyst_id=analyst_id,
            analyst_name=analyst_name,
            tags=tags or ["Email-Forensics"],
            created_at_iso=now_iso,
            updated_at_iso=now_iso,
        )

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO cases (id, title, description, status, analyst_id, analyst_name, tags_json, created_at, updated_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_case.id,
                new_case.title,
                new_case.description,
                new_case.status,
                new_case.analyst_id,
                new_case.analyst_name,
                json.dumps(new_case.tags),
                new_case.created_at_iso,
                new_case.updated_at_iso,
                json.dumps(new_case.to_dict()),
            ),
        )
        conn.commit()
        conn.close()
        return new_case

    @classmethod
    def list_cases(cls) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT payload_json FROM cases ORDER BY updated_at DESC")
        rows = cursor.fetchall()
        conn.close()
        cases = []
        for r in rows:
            try:
                cases.append(json.loads(r["payload_json"]))
            except Exception:
                pass
        return cases

    @classmethod
    def get_case(cls, case_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT payload_json FROM cases WHERE id = ?", (case_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            try:
                return json.loads(row["payload_json"])
            except Exception:
                return None
        return None

    @classmethod
    def add_artifact_to_case(
        cls,
        case_id: str,
        artifact_type: str,
        filename: str,
        sha256: str,
        analysis_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        case_dict = cls.get_case(case_id)
        if not case_dict:
            return None

        art_id = f"art_{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        artifact = {
            "artifact_id": art_id,
            "artifact_type": artifact_type,
            "filename": filename,
            "sha256": sha256,
            "added_at_iso": now_iso,
            "analysis_id": analysis_id,
        }
        case_dict["artifacts"].append(artifact)
        if analysis_id and analysis_id not in case_dict["analysis_ids"]:
            case_dict["analysis_ids"].append(analysis_id)
        case_dict["updated_at_iso"] = now_iso

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE cases SET updated_at = ?, payload_json = ? WHERE id = ?",
            (now_iso, json.dumps(case_dict), case_id),
        )
        conn.commit()
        conn.close()
        return case_dict

    @classmethod
    def add_note_to_case(cls, case_id: str, author: str, note_text: str) -> Optional[Dict[str, Any]]:
        case_dict = cls.get_case(case_id)
        if not case_dict:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        note = {
            "note_id": f"note_{uuid.uuid4().hex[:8]}",
            "author": author,
            "text": note_text,
            "timestamp_iso": now_iso,
        }
        case_dict["analyst_notes"].append(note)
        case_dict["updated_at_iso"] = now_iso

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE cases SET updated_at = ?, payload_json = ? WHERE id = ?",
            (now_iso, json.dumps(case_dict), case_id),
        )
        conn.commit()
        conn.close()
        return case_dict

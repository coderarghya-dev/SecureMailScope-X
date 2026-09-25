"""
SecureMailScope X - Analyst Identity & Action Attribution Schemas (Phase 12)
Provides structured, non-repudiable audit attribution without claiming unverified authentication or fake RBAC.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


# Identity Source & Attribution Status Definitions
IDENTITY_SOURCE_LOCAL_DECLARED = "LOCAL_DECLARED"
IDENTITY_SOURCE_API_HEADER_DECLARED = "API_HEADER_DECLARED"
IDENTITY_SOURCE_SYSTEM = "SYSTEM"
IDENTITY_SOURCE_UNKNOWN = "UNKNOWN"

ATTRIBUTION_STATUS_ATTRIBUTED = "ATTRIBUTED"
ATTRIBUTION_STATUS_UNATTRIBUTED = "UNATTRIBUTED"
ATTRIBUTION_STATUS_SYSTEM_GENERATED = "SYSTEM_GENERATED"

AUTHORIZATION_STATUS_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

# Validation pattern: alphanumeric, hyphen, underscore, period, at-sign, pipe. No control chars or path separators.
VALID_ACTOR_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.@|]{1,64}$")


def sanitize_display_name(name: Optional[str], max_len: int = 128) -> str:
    """Strips control characters, normalizes whitespace, and limits length of analyst display names."""
    if not name:
        return "Unattributed Analyst"
    # Replace newlines, tabs, and carriage returns with spaces
    replaced = re.sub(r"[\r\n\t]+", " ", name)
    # Remove control characters (ASCII 0-31 and 127)
    cleaned = "".join(ch for ch in replaced if ord(ch) >= 32 and ord(ch) != 127)
    # Normalize multiple whitespace characters
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return "Unattributed Analyst"
    return cleaned[:max_len]


def validate_actor_id(actor_id: Optional[str]) -> str:
    """Validates and bounds actor IDs. Rejects invalid characters and path injections."""
    if not actor_id:
        return "UNATTRIBUTED"
    cleaned = actor_id.strip()
    if not cleaned or not VALID_ACTOR_ID_PATTERN.match(cleaned):
        raise ValueError(
            f"Invalid actor_id '{actor_id}'. Must be 1-64 characters matching pattern [a-zA-Z0-9_-.@]."
        )
    return cleaned


@dataclass
class ActorContext:
    """
    Explicit, immutable actor context passed through service and repository calls.
    Represents attribution metadata, NOT cryptographic login authentication.
    """
    actor_id: str = "UNATTRIBUTED"
    actor_display_name: str = "Unattributed Analyst"
    actor_identity_source: str = IDENTITY_SOURCE_UNKNOWN
    actor_attribution_status: str = ATTRIBUTION_STATUS_UNATTRIBUTED
    authorization_status: str = AUTHORIZATION_STATUS_NOT_IMPLEMENTED
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        actor_id: str = "UNATTRIBUTED",
        actor_display_name: str = "Unattributed Analyst",
        actor_identity_source: Optional[str] = None,
        actor_attribution_status: Optional[str] = None,
        identity_source: Optional[str] = None,
        attribution_status: Optional[str] = None,
        authorization_status: str = AUTHORIZATION_STATUS_NOT_IMPLEMENTED,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.actor_id = actor_id
        self.actor_display_name = actor_display_name
        self.actor_identity_source = actor_identity_source or identity_source or IDENTITY_SOURCE_UNKNOWN
        self.actor_attribution_status = actor_attribution_status or attribution_status or (
            ATTRIBUTION_STATUS_ATTRIBUTED if actor_id and actor_id != "UNATTRIBUTED" else ATTRIBUTION_STATUS_UNATTRIBUTED
        )
        self.authorization_status = authorization_status
        self.metadata = metadata or {}

    @property
    def identity_source(self) -> str:
        return self.actor_identity_source

    @property
    def attribution_status(self) -> str:
        return self.actor_attribution_status

    @classmethod
    def system_actor(cls) -> "ActorContext":
        """Factory for automated system background processes."""
        return cls(
            actor_id="SYSTEM",
            actor_display_name="SecureMailScope X",
            actor_identity_source=IDENTITY_SOURCE_SYSTEM,
            actor_attribution_status=ATTRIBUTION_STATUS_SYSTEM_GENERATED,
            authorization_status=AUTHORIZATION_STATUS_NOT_IMPLEMENTED,
        )

    @classmethod
    def unattributed(cls) -> "ActorContext":
        """Factory for requests without supplied analyst attribution."""
        return cls(
            actor_id="UNATTRIBUTED",
            actor_display_name="Unattributed Analyst",
            actor_identity_source=IDENTITY_SOURCE_UNKNOWN,
            actor_attribution_status=ATTRIBUTION_STATUS_UNATTRIBUTED,
            authorization_status=AUTHORIZATION_STATUS_NOT_IMPLEMENTED,
        )

    @classmethod
    def from_headers(
        cls,
        x_analyst_id: Optional[str] = None,
        x_analyst_name: Optional[str] = None,
    ) -> "ActorContext":
        """
        Creates an ActorContext from declared HTTP headers.
        Treated strictly as API_HEADER_DECLARED attribution, NOT authenticated identity.
        """
        if not x_analyst_id:
            return cls.unattributed()

        valid_id = validate_actor_id(x_analyst_id)
        valid_name = sanitize_display_name(x_analyst_name or valid_id)

        return cls(
            actor_id=valid_id,
            actor_display_name=valid_name,
            actor_identity_source=IDENTITY_SOURCE_API_HEADER_DECLARED,
            actor_attribution_status=ATTRIBUTION_STATUS_ATTRIBUTED,
            authorization_status=AUTHORIZATION_STATUS_NOT_IMPLEMENTED,
        )


    @classmethod
    def local_declared(
        cls,
        analyst_id: str,
        display_name: Optional[str] = None,
    ) -> "ActorContext":
        """Factory for local CLI / service-level declared analyst context."""
        valid_id = validate_actor_id(analyst_id)
        valid_name = sanitize_display_name(display_name or valid_id)
        return cls(
            actor_id=valid_id,
            actor_display_name=valid_name,
            actor_identity_source=IDENTITY_SOURCE_LOCAL_DECLARED,
            actor_attribution_status=ATTRIBUTION_STATUS_ATTRIBUTED,
            authorization_status=AUTHORIZATION_STATUS_NOT_IMPLEMENTED,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "actor_display_name": self.actor_display_name,
            "actor_identity_source": self.actor_identity_source,
            "actor_attribution_status": self.actor_attribution_status,
            "authorization_status": self.authorization_status,
            "metadata": self.metadata,
        }


class AnalystIdentityDTO(BaseModel):
    """Analyst registry record representation (Attribution metadata only - no credentials)."""
    analyst_id: str = Field(..., description="Unique analyst identifier (1-64 alphanumeric)")
    display_name: str = Field(..., description="Human-readable analyst display name")
    email_or_label: Optional[str] = Field(None, description="Optional organizational label or contact email")
    identity_source: str = Field(IDENTITY_SOURCE_LOCAL_DECLARED, description="Source of identity declaration")
    attribution_status: str = Field(ATTRIBUTION_STATUS_ATTRIBUTED, description="Attribution verification state")
    created_at: str = Field(..., description="ISO 8601 UTC creation timestamp")
    updated_at: str = Field(..., description="ISO 8601 UTC last profile update timestamp")
    is_active: bool = Field(True, description="Whether this analyst profile is active for new attributions")


class RegisterAnalystRequest(BaseModel):
    """Request schema for registering a declared analyst profile."""
    analyst_id: str
    display_name: str
    email_or_label: Optional[str] = None
    identity_source: Optional[str] = IDENTITY_SOURCE_LOCAL_DECLARED


class UpdateAnalystProfileRequest(BaseModel):
    """Request schema for updating analyst display name or label."""
    display_name: str
    email_or_label: Optional[str] = None
    is_active: Optional[bool] = True

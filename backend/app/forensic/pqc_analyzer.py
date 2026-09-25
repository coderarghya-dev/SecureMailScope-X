"""
SecureMailScope X - Post-Quantum Cryptography (PQC) & HNDL Risk Analyzer
Strict, evidence-bounded analysis of observable TLS key-establishment parameters
for Post-Quantum readiness and Harvest Now, Decrypt Later (HNDL) exposure (NIST FIPS 203 ML-KEM).
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

from ..schemas.forensic import (
    EmailSession,
    TLSHandshakeDetails,
    TLSVersion,
    SecurityMode
)


class PQCStatus(str, Enum):
    PQC_PROTECTED = "PQC_PROTECTED"
    HYBRID_OBSERVED = "HYBRID_OBSERVED"
    CLASSICAL_ONLY = "CLASSICAL_ONLY"
    ASSESSMENT_INCOMPLETE = "ASSESSMENT_INCOMPLETE"


class HNDLStatus(str, Enum):
    INCOMPLETE = "INCOMPLETE"
    EXPOSURE_PRESENT = "EXPOSURE_PRESENT"
    MITIGATED_BY_OBSERVED_HYBRID = "MITIGATED_BY_OBSERVED_HYBRID"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    # Legacy aliases for backward compatibility
    LOW = "MITIGATED_BY_OBSERVED_HYBRID"
    HIGH = "EXPOSURE_PRESENT"


class RegistryStatus(str, Enum):
    IANA_STANDARD = "IANA_STANDARD"
    IANA_OBSOLETE = "IANA_OBSOLETE"
    EXPERIMENTAL = "EXPERIMENTAL"
    IMPLEMENTATION_SPECIFIC = "IMPLEMENTATION_SPECIFIC"
    UNKNOWN = "UNKNOWN"


class SpecificationStatus(str, Enum):
    RFC = "RFC"
    IETF_DRAFT = "IETF_DRAFT"
    NIST_ALGORITHM = "NIST_ALGORITHM"
    VENDOR = "VENDOR"
    UNKNOWN = "UNKNOWN"


@dataclass
class NamedGroupInfo:
    """Metadata and provenance for TLS Named Groups."""
    group_id: str
    name: str
    group_type: str  # "HYBRID", "PQC_STANDALONE", "CLASSICAL"
    is_standard: bool
    registry_status: RegistryStatus
    specification_status: SpecificationStatus
    standard_ref: str


# Authoritative Knowledge Base of Named Groups (IANA TLS Supported Groups Registry)
NAMED_GROUPS_DATABASE: Dict[str, NamedGroupInfo] = {
    # -----------------------------------------------------------------------
    # 1. Standard Hybrid Classical + ML-KEM Groups (IANA Assigned / NIST FIPS 203)
    # -----------------------------------------------------------------------
    "0x11eb": NamedGroupInfo(
        group_id="0x11eb",
        name="SecP256r1MLKEM768",
        group_type="HYBRID",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.IETF_DRAFT,
        standard_ref="IANA TLS Supported Groups (4587 / 0x11EB); algorithm standardized in NIST FIPS 203 (ML-KEM)"
    ),
    "0x11ec": NamedGroupInfo(
        group_id="0x11ec",
        name="X25519MLKEM768",
        group_type="HYBRID",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.IETF_DRAFT,
        standard_ref="IANA TLS Supported Groups (4588 / 0x11EC); algorithm standardized in NIST FIPS 203 (ML-KEM)"
    ),
    "0x11ed": NamedGroupInfo(
        group_id="0x11ed",
        name="SecP384r1MLKEM1024",
        group_type="HYBRID",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.IETF_DRAFT,
        standard_ref="IANA TLS Supported Groups (4589 / 0x11ED); algorithm standardized in NIST FIPS 203 (ML-KEM)"
    ),

    # -----------------------------------------------------------------------
    # 2. Standard Standalone ML-KEM Groups (IANA Assigned / NIST FIPS 203)
    # -----------------------------------------------------------------------
    "0x0200": NamedGroupInfo(
        group_id="0x0200",
        name="MLKEM512",
        group_type="PQC_STANDALONE",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.NIST_ALGORITHM,
        standard_ref="IANA TLS Supported Groups (512 / 0x0200); algorithm standardized in NIST FIPS 203"
    ),
    "0x0201": NamedGroupInfo(
        group_id="0x0201",
        name="MLKEM768",
        group_type="PQC_STANDALONE",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.NIST_ALGORITHM,
        standard_ref="IANA TLS Supported Groups (513 / 0x0201); algorithm standardized in NIST FIPS 203"
    ),
    "0x0202": NamedGroupInfo(
        group_id="0x0202",
        name="MLKEM1024",
        group_type="PQC_STANDALONE",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.NIST_ALGORITHM,
        standard_ref="IANA TLS Supported Groups (514 / 0x0202); algorithm standardized in NIST FIPS 203"
    ),

    # -----------------------------------------------------------------------
    # 3. Obsolete IANA Registrations (Pre-Standard Drafts)
    # -----------------------------------------------------------------------
    "0x6399": NamedGroupInfo(
        group_id="0x6399",
        name="X25519Kyber768Draft00",
        group_type="HYBRID",
        is_standard=False,
        registry_status=RegistryStatus.IANA_OBSOLETE,
        specification_status=SpecificationStatus.IETF_DRAFT,
        standard_ref="Obsolete pre-standard IANA registration (25497 / 0x6399 CECPQ2b / draft-ietf-tls-hybrid-design-00)"
    ),
    "0x639a": NamedGroupInfo(
        group_id="0x639a",
        name="SecP256r1Kyber768Draft00",
        group_type="HYBRID",
        is_standard=False,
        registry_status=RegistryStatus.IANA_OBSOLETE,
        specification_status=SpecificationStatus.IETF_DRAFT,
        standard_ref="Obsolete pre-standard IANA registration (25498 / 0x639A)"
    ),

    # -----------------------------------------------------------------------
    # 4. Experimental / Vendor Drafts (Private Compatibility)
    # -----------------------------------------------------------------------
    "0x2f39": NamedGroupInfo(
        group_id="0x2f39",
        name="X25519MLKEM768Draft00",
        group_type="HYBRID",
        is_standard=False,
        registry_status=RegistryStatus.EXPERIMENTAL,
        specification_status=SpecificationStatus.VENDOR,
        standard_ref="Experimental / vendor-specific private identifier (12089 / 0x2F39 Chromium draft)"
    ),
    "0x2f3a": NamedGroupInfo(
        group_id="0x2f3a",
        name="SecP256r1MLKEM768Draft00",
        group_type="HYBRID",
        is_standard=False,
        registry_status=RegistryStatus.EXPERIMENTAL,
        specification_status=SpecificationStatus.VENDOR,
        standard_ref="Experimental / vendor-specific private identifier (12090 / 0x2F3A Chromium draft)"
    ),

    # -----------------------------------------------------------------------
    # 5. Historical / Implementation-Specific Pre-Standard Identifiers (Non-IANA)
    # -----------------------------------------------------------------------
    "0x023a": NamedGroupInfo(
        group_id="0x023a",
        name="Kyber768",
        group_type="PQC_STANDALONE",
        is_standard=False,
        registry_status=RegistryStatus.IMPLEMENTATION_SPECIFIC,
        specification_status=SpecificationStatus.UNKNOWN,
        standard_ref="Historical / implementation-specific pre-standard identifier (570 / 0x023A Round 3 Kyber768, non-IANA)"
    ),
    "0x023c": NamedGroupInfo(
        group_id="0x023c",
        name="Kyber1024",
        group_type="PQC_STANDALONE",
        is_standard=False,
        registry_status=RegistryStatus.IMPLEMENTATION_SPECIFIC,
        specification_status=SpecificationStatus.UNKNOWN,
        standard_ref="Historical / implementation-specific pre-standard identifier (572 / 0x023C Round 3 Kyber1024, non-IANA)"
    ),
    "0x023d": NamedGroupInfo(
        group_id="0x023d",
        name="Kyber512",
        group_type="PQC_STANDALONE",
        is_standard=False,
        registry_status=RegistryStatus.IMPLEMENTATION_SPECIFIC,
        specification_status=SpecificationStatus.UNKNOWN,
        standard_ref="Historical / implementation-specific pre-standard identifier (573 / 0x023D Round 3 Kyber512, non-IANA)"
    ),
    "0x0239": NamedGroupInfo(
        group_id="0x0239",
        name="Kyber512",
        group_type="PQC_STANDALONE",
        is_standard=False,
        registry_status=RegistryStatus.IMPLEMENTATION_SPECIFIC,
        specification_status=SpecificationStatus.UNKNOWN,
        standard_ref="Historical / implementation-specific pre-standard identifier (569 / 0x0239 Round 3 Kyber512, non-IANA)"
    ),

    # -----------------------------------------------------------------------
    # 6. Standard Classical Groups (RFC 8422, RFC 8446, RFC 7919)
    # -----------------------------------------------------------------------
    "0x001d": NamedGroupInfo(
        group_id="0x001d",
        name="x25519",
        group_type="CLASSICAL",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.RFC,
        standard_ref="RFC 8422 / RFC 8446"
    ),
    "0x0017": NamedGroupInfo(
        group_id="0x0017",
        name="secp256r1",
        group_type="CLASSICAL",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.RFC,
        standard_ref="RFC 8422 / RFC 8446"
    ),
    "0x0018": NamedGroupInfo(
        group_id="0x0018",
        name="secp384r1",
        group_type="CLASSICAL",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.RFC,
        standard_ref="RFC 8422 / RFC 8446"
    ),
    "0x0019": NamedGroupInfo(
        group_id="0x0019",
        name="secp521r1",
        group_type="CLASSICAL",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.RFC,
        standard_ref="RFC 8422 / RFC 8446"
    ),
    "0x001e": NamedGroupInfo(
        group_id="0x001e",
        name="x448",
        group_type="CLASSICAL",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.RFC,
        standard_ref="RFC 8446"
    ),
    "0x0100": NamedGroupInfo(
        group_id="0x0100",
        name="ffdhe2048",
        group_type="CLASSICAL",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.RFC,
        standard_ref="RFC 7919"
    ),
    "0x0101": NamedGroupInfo(
        group_id="0x0101",
        name="ffdhe3072",
        group_type="CLASSICAL",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.RFC,
        standard_ref="RFC 7919"
    ),
    "0x0102": NamedGroupInfo(
        group_id="0x0102",
        name="ffdhe4096",
        group_type="CLASSICAL",
        is_standard=True,
        registry_status=RegistryStatus.IANA_STANDARD,
        specification_status=SpecificationStatus.RFC,
        standard_ref="RFC 7919"
    ),
}


def lookup_named_group(identifier: Optional[str]) -> Optional[NamedGroupInfo]:
    """Resolves hex codepoints, decimal strings, or canonical group names."""
    if not identifier:
        return None
    val = str(identifier).strip().lower()

    # 1. Direct key match (e.g. "0x11ec", "0x001d", "0x0201")
    if val in NAMED_GROUPS_DATABASE:
        return NAMED_GROUPS_DATABASE[val]

    # 2. Decimal string to hex conversion (e.g. "4588" -> "0x11ec", "513" -> "0x0201", "29" -> "0x001d")
    if val.isdigit():
        hex_key = f"0x{int(val):04x}"
        if hex_key in NAMED_GROUPS_DATABASE:
            return NAMED_GROUPS_DATABASE[hex_key]

    # 3. Match without 0x prefix if hex chars
    if len(val) in (4, 6) and all(c in "0123456789abcdef" for c in val):
        hex_key = f"0x{val[-4:]}"
        if hex_key in NAMED_GROUPS_DATABASE:
            return NAMED_GROUPS_DATABASE[hex_key]

    # 4. Search by canonical group name match
    val_clean = val.replace("_", "").replace("-", "")
    for info in NAMED_GROUPS_DATABASE.values():
        info_clean = info.name.lower().replace("_", "").replace("-", "")
        if info_clean == val_clean or info.name.lower() == val:
            return info

    # 5. Fuzzy substring matches for ML-KEM / Kyber variants
    # Hybrid ML-KEM
    if "secp384" in val_clean and "mlkem" in val_clean:
        return NAMED_GROUPS_DATABASE["0x11ed"]
    if "secp256" in val_clean and "mlkem" in val_clean:
        return NAMED_GROUPS_DATABASE["0x11eb"]
    if "x25519" in val_clean and "mlkem" in val_clean:
        return NAMED_GROUPS_DATABASE["0x11ec"]

    # Obsolete hybrid Kyber drafts
    if "x25519" in val_clean and "kyber" in val_clean:
        return NAMED_GROUPS_DATABASE["0x6399"]
    if "secp256" in val_clean and "kyber" in val_clean:
        return NAMED_GROUPS_DATABASE["0x639a"]

    # Standalone ML-KEM
    if "mlkem512" in val_clean or "ml-kem-512" in val_clean:
        return NAMED_GROUPS_DATABASE["0x0200"]
    if "mlkem768" in val_clean or "ml-kem-768" in val_clean:
        return NAMED_GROUPS_DATABASE["0x0201"]
    if "mlkem1024" in val_clean or "ml-kem-1024" in val_clean:
        return NAMED_GROUPS_DATABASE["0x0202"]

    # Historical standalone Kyber
    if "kyber512" in val_clean:
        return NAMED_GROUPS_DATABASE["0x023d"]
    if "kyber768" in val_clean:
        return NAMED_GROUPS_DATABASE["0x023a"]
    if "kyber1024" in val_clean:
        return NAMED_GROUPS_DATABASE["0x023c"]

    # Classical groups
    if "x25519" in val_clean:
        return NAMED_GROUPS_DATABASE["0x001d"]
    if "secp256r1" in val_clean or "prime256v1" in val_clean:
        return NAMED_GROUPS_DATABASE["0x0017"]
    if "secp384r1" in val_clean:
        return NAMED_GROUPS_DATABASE["0x0018"]
    if "secp521r1" in val_clean:
        return NAMED_GROUPS_DATABASE["0x0019"]

    return None


@dataclass
class PQCAssessmentResult:
    """Structured, evidence-bounded Post-Quantum assessment output."""
    pqc_status: PQCStatus
    pqc_ready: bool = False
    hybrid_observed: bool = False
    observed_groups: List[str] = field(default_factory=list)
    selected_group: Optional[str] = None
    selected_group_info: Optional[NamedGroupInfo] = None
    evidence_frames: List[int] = field(default_factory=list)
    evidence_summary: str = ""
    hndl_status: HNDLStatus = HNDLStatus.INCOMPLETE
    hndl_reason: str = ""
    recommendation: Optional[str] = None

    @property
    def is_hybrid(self) -> bool:
        """Compatibility property for legacy test assertions."""
        return self.hybrid_observed

    @property
    def summary(self) -> str:
        """Compatibility property for legacy test assertions."""
        return self.evidence_summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pqc_status": self.pqc_status.value,
            "pqc_ready": self.pqc_ready,
            "hybrid_observed": self.hybrid_observed,
            "observed_groups": self.observed_groups,
            "selected_group": self.selected_group,
            "evidence_frames": self.evidence_frames,
            "evidence_summary": self.evidence_summary,
            "hndl_status": self.hndl_status.value,
            "hndl_reason": self.hndl_reason,
            "recommendation": self.recommendation,
        }


class PQCAnalyzer:
    """Evaluates TLS key-establishment evidence for Post-Quantum readiness and HNDL exposure."""

    @classmethod
    def analyze_session(cls, session: EmailSession) -> PQCAssessmentResult:
        tls = session.tls_details

        # Frame evidence collection
        frames: List[int] = []
        if tls:
            if tls.server_hello_frame and tls.server_hello_frame not in frames:
                frames.append(tls.server_hello_frame)
            if tls.client_hello_frame and tls.client_hello_frame not in frames:
                frames.append(tls.client_hello_frame)

        # -------------------------------------------------------------------
        # CASE 1: Unencrypted Plaintext or Missing TLS Handshake
        # -------------------------------------------------------------------
        if not tls or tls.negotiated_tls_version == TLSVersion.UNKNOWN or session.security_mode == SecurityMode.PLAINTEXT:
            return PQCAssessmentResult(
                pqc_status=PQCStatus.ASSESSMENT_INCOMPLETE,
                pqc_ready=False,
                hybrid_observed=False,
                observed_groups=[],
                selected_group=None,
                evidence_frames=frames,
                evidence_summary="TLS handshake unobserved or session is plaintext; PQC evaluation incomplete.",
                hndl_status=HNDLStatus.INCOMPLETE,
                hndl_reason="No TLS key-establishment negotiation present in passive capture.",
                recommendation="Enforce transport encryption with TLS 1.3 and hybrid ML-KEM key exchange."
            )

        # -------------------------------------------------------------------
        # CASE 2: Selected Group is Observable (e.g. TLS 1.3 key_share)
        # -------------------------------------------------------------------
        selected_raw = tls.selected_group
        group_info = lookup_named_group(selected_raw) if selected_raw else None

        if group_info:
            observed_names = [group_info.name]
            if tls.supported_groups:
                for sg in tls.supported_groups:
                    gi = lookup_named_group(sg)
                    if gi and gi.name not in observed_names:
                        observed_names.append(gi.name)

            # Strict policy: Only current IANA_STANDARD groups qualify for verified PQC / Hybrid
            if group_info.registry_status == RegistryStatus.IANA_STANDARD:
                if group_info.group_type == "HYBRID":
                    std_desc = group_info.standard_ref
                    return PQCAssessmentResult(
                        pqc_status=PQCStatus.HYBRID_OBSERVED,
                        pqc_ready=True,
                        hybrid_observed=True,
                        observed_groups=observed_names,
                        selected_group=group_info.name,
                        selected_group_info=group_info,
                        evidence_frames=frames,
                        evidence_summary=(
                            f"Observable hybrid key exchange ({group_info.name}) combines classical "
                            f"ECDHE with ML-KEM ({std_desc})."
                        ),
                        hndl_status=HNDLStatus.MITIGATED_BY_OBSERVED_HYBRID,
                        hndl_reason="Observed hybrid key exchange provides post-quantum confidentiality against retroactive decryption.",
                        recommendation=None
                    )

                elif group_info.group_type == "PQC_STANDALONE":
                    return PQCAssessmentResult(
                        pqc_status=PQCStatus.PQC_PROTECTED,
                        pqc_ready=True,
                        hybrid_observed=False,
                        observed_groups=observed_names,
                        selected_group=group_info.name,
                        selected_group_info=group_info,
                        evidence_frames=frames,
                        evidence_summary=f"Observable standalone post-quantum key exchange ({group_info.name}) verified ({group_info.standard_ref}).",
                        hndl_status=HNDLStatus.MITIGATED_BY_OBSERVED_HYBRID,
                        hndl_reason="Observed post-quantum key exchange protects against retroactive decryption.",
                        recommendation=None
                    )

                elif group_info.group_type == "CLASSICAL":
                    return PQCAssessmentResult(
                        pqc_status=PQCStatus.CLASSICAL_ONLY,
                        pqc_ready=False,
                        hybrid_observed=False,
                        observed_groups=observed_names,
                        selected_group=group_info.name,
                        selected_group_info=group_info,
                        evidence_frames=frames,
                        evidence_summary=f"Observable classical key exchange ({group_info.name}) without post-quantum protection.",
                        hndl_status=HNDLStatus.EXPOSURE_PRESENT,
                        hndl_reason="Session negotiates classical key establishment; vulnerable to Harvest Now, Decrypt Later (HNDL).",
                        recommendation="Upgrade to hybrid classical + ML-KEM key exchange (NIST FIPS 203)."
                    )

            else:
                # Obsolete / experimental / historical pre-standard identifier
                return PQCAssessmentResult(
                    pqc_status=PQCStatus.ASSESSMENT_INCOMPLETE,
                    pqc_ready=False,
                    hybrid_observed=False,
                    observed_groups=observed_names,
                    selected_group=group_info.name,
                    selected_group_info=group_info,
                    evidence_frames=frames,
                    evidence_summary=f"Observed non-standard/historical key-exchange identifier: {group_info.name} ({group_info.standard_ref}). Post-quantum readiness assessment incomplete.",
                    hndl_status=HNDLStatus.INCOMPLETE,
                    hndl_reason=f"Key exchange uses a non-standard or obsolete identifier ({group_info.name} - {group_info.registry_status.value}); post-quantum protection cannot be certified.",
                    recommendation="Migrate to standardized IANA ML-KEM hybrid parameters (e.g., X25519MLKEM768 / 0x11EC)."
                )

        # -------------------------------------------------------------------
        # CASE 3: Unrecognized Raw Group Identifier
        # -------------------------------------------------------------------
        if selected_raw and not group_info:
            return PQCAssessmentResult(
                pqc_status=PQCStatus.ASSESSMENT_INCOMPLETE,
                pqc_ready=False,
                hybrid_observed=False,
                observed_groups=[str(selected_raw)],
                selected_group=str(selected_raw),
                evidence_frames=frames,
                evidence_summary=f"Unrecognized or private key-exchange group identifier ({selected_raw}); PQC readiness unverified.",
                hndl_status=HNDLStatus.INCOMPLETE,
                hndl_reason="Group identifier is not recognized as an established classical or post-quantum standard.",
                recommendation="Ensure standardized IANA / NIST FIPS 203 ML-KEM group parameters are used."
            )

        # -------------------------------------------------------------------
        # CASE 4: TLS 1.2 with Verified Cipher Evidence (Static RSA / ECDHE)
        # -------------------------------------------------------------------
        if tls.negotiated_tls_version == TLSVersion.TLSv1_2 and tls.cipher_info:
            ci = tls.cipher_info
            if ci.has_pfs is False or "rsa" in ci.name.lower():
                return PQCAssessmentResult(
                    pqc_status=PQCStatus.CLASSICAL_ONLY,
                    pqc_ready=False,
                    hybrid_observed=False,
                    observed_groups=[],
                    selected_group=None,
                    evidence_frames=frames,
                    evidence_summary=f"Static RSA key exchange ({ci.name}) is classical-only and lacks forward secrecy.",
                    hndl_status=HNDLStatus.EXPOSURE_PRESENT,
                    hndl_reason="Static RSA allows retroactive decryption if the private key is compromised.",
                    recommendation="Migrate to TLS 1.3 with hybrid ML-KEM key exchange."
                )
            elif ci.has_pfs is True:
                return PQCAssessmentResult(
                    pqc_status=PQCStatus.CLASSICAL_ONLY,
                    pqc_ready=False,
                    hybrid_observed=False,
                    observed_groups=[],
                    selected_group=None,
                    evidence_frames=frames,
                    evidence_summary=f"Classical ephemeral cipher suite ({ci.name}) without post-quantum protection.",
                    hndl_status=HNDLStatus.EXPOSURE_PRESENT,
                    hndl_reason="Classical ephemeral key exchange (ECDHE/DHE) is vulnerable to future quantum cryptanalysis (HNDL).",
                    recommendation="Upgrade to TLS 1.3 with hybrid ML-KEM key exchange."
                )

        # -------------------------------------------------------------------
        # CASE 5: TLS 1.3 with Unobserved Key Share
        # (TLS 1.3 cipher suite alone does NOT imply key exchange or PQC)
        # -------------------------------------------------------------------
        return PQCAssessmentResult(
            pqc_status=PQCStatus.ASSESSMENT_INCOMPLETE,
            pqc_ready=False,
            hybrid_observed=False,
            observed_groups=[],
            selected_group=None,
            evidence_frames=frames,
            evidence_summary="TLS 1.3 negotiated, but key_share extension was unobserved in passive capture; PQC readiness assessment incomplete.",
            hndl_status=HNDLStatus.INCOMPLETE,
            hndl_reason="No observable key_share or key-exchange group parameters present in passive capture.",
            recommendation="Capture complete TLS 1.3 handshake with ClientHello and ServerHello key_share extensions."
        )

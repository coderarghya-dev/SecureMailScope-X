"""
SecureMailScope X - Post-Quantum Cryptography (PQC) & HNDL Risk Analyzer
Analyzes observable TLS key-establishment evidence for Post-Quantum readiness
and Harvest Now, Decrypt Later (HNDL) exposure according to NIST FIPS 203 (ML-KEM).
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from app.schemas.forensic import EmailSession, TLSHandshakeDetails, TLSVersion


class PQCStatus(str, Enum):
    PQC_PROTECTED = "PQC_PROTECTED"
    HYBRID_OBSERVED = "HYBRID_OBSERVED"
    CLASSICAL_ONLY = "CLASSICAL_ONLY"
    ASSESSMENT_INCOMPLETE = "ASSESSMENT_INCOMPLETE"


class HNDLStatus(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    INCOMPLETE = "INCOMPLETE"


# Standardized and draft Post-Quantum / Hybrid Named Groups
PQC_NAMED_GROUPS = {
    # NIST FIPS 203 / IETF Standards
    "0x11ec": "X25519MLKEM768",
    "0x11ed": "SecP256r1MLKEM768",
    "4588": "X25519MLKEM768",
    "4589": "SecP256r1MLKEM768",
    "x25519mlkem768": "X25519MLKEM768",
    "secp256r1mlkem768": "SecP256r1MLKEM768",
    # Legacy drafts & experimental identifiers
    "0x6399": "X25519Kyber768Draft00",
    "25497": "X25519Kyber768Draft00",
    "x25519kyber768draft00": "X25519Kyber768Draft00",
    "0x023a": "Kyber768",
    "570": "Kyber768",
    "kyber768": "Kyber768",
    "0x0239": "Kyber512",
    "569": "Kyber512",
    "kyber512": "Kyber512",
    "0x023c": "Kyber1024",
    "572": "Kyber1024",
    "kyber1024": "Kyber1024",
}

CLASSICAL_NAMED_GROUPS = {
    "0x001d": "x25519",
    "29": "x25519",
    "x25519": "x25519",
    "0x0017": "secp256r1",
    "23": "secp256r1",
    "secp256r1": "secp256r1",
    "0x0018": "secp384r1",
    "24": "secp384r1",
    "secp384r1": "secp384r1",
    "0x0019": "secp521r1",
    "25": "secp521r1",
    "secp521r1": "secp521r1",
    "ffdhe2048": "ffdhe2048",
    "ffdhe3072": "ffdhe3072",
    "ffdhe4096": "ffdhe4096",
}


@dataclass
class PQCAssessmentResult:
    pqc_status: PQCStatus
    hndl_status: HNDLStatus
    observable_group: Optional[str] = None
    is_hybrid: bool = False
    evidence_frames: List[int] = field(default_factory=list)
    evidence_source: str = ""
    summary: str = ""
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pqc_status": self.pqc_status.value,
            "hndl_status": self.hndl_status.value,
            "observable_group": self.observable_group,
            "is_hybrid": self.is_hybrid,
            "evidence_frames": self.evidence_frames,
            "evidence_source": self.evidence_source,
            "summary": self.summary,
            "recommendation": self.recommendation,
        }


class PQCAnalyzer:
    """Evaluates TLS session key-establishment evidence for Post-Quantum Cryptography readiness."""

    @classmethod
    def is_pqc_group(cls, group_identifier: Optional[str]) -> bool:
        if not group_identifier:
            return False
        clean = group_identifier.strip().lower()
        if clean in PQC_NAMED_GROUPS:
            return True
        for key in PQC_NAMED_GROUPS:
            if key.lower() in clean or "mlkem" in clean or "kyber" in clean:
                return True
        return False

    @classmethod
    def is_classical_group(cls, group_identifier: Optional[str]) -> bool:
        if not group_identifier:
            return False
        clean = group_identifier.strip().lower()
        if clean in CLASSICAL_NAMED_GROUPS:
            return True
        for key in CLASSICAL_NAMED_GROUPS:
            if key.lower() in clean:
                return True
        return False

    @classmethod
    def analyze_session(cls, session: EmailSession) -> PQCAssessmentResult:
        tls = session.tls_details
        if not tls or tls.negotiated_tls_version == TLSVersion.UNKNOWN:
            return PQCAssessmentResult(
                pqc_status=PQCStatus.ASSESSMENT_INCOMPLETE,
                hndl_status=HNDLStatus.INCOMPLETE,
                evidence_source="No TLS handshake details available in session",
                summary="TLS handshake unobserved or plaintext session. Post-quantum evaluation incomplete.",
                recommendation="Enforce modern TLS with hybrid ML-KEM key exchange.",
            )

        frames: List[int] = []
        if tls.server_hello_frame:
            frames.append(tls.server_hello_frame)
        elif tls.client_hello_frame:
            frames.append(tls.client_hello_frame)

        # Check selected group from key_share or cipher info
        group_candidate = tls.selected_group
        if not group_candidate and tls.cipher_info:
            if "mlkem" in tls.cipher_info.key_exchange.lower() or "kyber" in tls.cipher_info.key_exchange.lower():
                group_candidate = tls.cipher_info.key_exchange

        # 1. PQC / Hybrid check
        if group_candidate and cls.is_pqc_group(group_candidate):
            is_hybrid = "x25519" in group_candidate.lower() or "secp" in group_candidate.lower() or "hybrid" in group_candidate.lower()
            status = PQCStatus.HYBRID_OBSERVED if is_hybrid else PQCStatus.PQC_PROTECTED
            return PQCAssessmentResult(
                pqc_status=status,
                hndl_status=HNDLStatus.LOW,
                observable_group=group_candidate,
                is_hybrid=is_hybrid,
                evidence_frames=frames,
                evidence_source="Observable TLS Key Share / Supported Groups extension",
                summary=f"Post-Quantum key establishment verified with observable group: {group_candidate}.",
                recommendation=None,
            )

        # Check supported groups offered by client
        if tls.supported_groups:
            pqc_offered = [g for g in tls.supported_groups if cls.is_pqc_group(g)]
            if pqc_offered:
                # Client offered PQC group, but server didn't negotiate it or selected classical
                return PQCAssessmentResult(
                    pqc_status=PQCStatus.CLASSICAL_ONLY,
                    hndl_status=HNDLStatus.HIGH,
                    observable_group=group_candidate or tls.supported_groups[0],
                    is_hybrid=False,
                    evidence_frames=frames,
                    evidence_source="Observable ClientHello Supported Groups (Server did not select PQC)",
                    summary=f"Client offered PQ groups ({', '.join(pqc_offered)}) but session negotiated classical key exchange.",
                    recommendation="Configure server to prioritize NIST FIPS 203 ML-KEM hybrid key exchange (e.g. X25519MLKEM768).",
                )

        # 2. Classical group observed
        if group_candidate and cls.is_classical_group(group_candidate):
            return PQCAssessmentResult(
                pqc_status=PQCStatus.CLASSICAL_ONLY,
                hndl_status=HNDLStatus.HIGH,
                observable_group=group_candidate,
                is_hybrid=False,
                evidence_frames=frames,
                evidence_source="Observable Classical TLS Key Share / Key Exchange",
                summary=f"Classical key exchange observed ({group_candidate}). Vulnerable to Harvest Now, Decrypt Later (HNDL).",
                recommendation="Upgrade to hybrid classical + ML-KEM key exchange (NIST FIPS 203).",
            )

        # 3. TLS 1.3 / TLS 1.2 with classical cipher suite, no explicit group observed
        if tls.cipher_info:
            return PQCAssessmentResult(
                pqc_status=PQCStatus.CLASSICAL_ONLY,
                hndl_status=HNDLStatus.HIGH,
                observable_group=None,
                is_hybrid=False,
                evidence_frames=frames,
                evidence_source=f"Negotiated Cipher Suite: {tls.cipher_info.name}",
                summary=f"Classical cipher suite {tls.cipher_info.name} negotiated without observable PQ key-share.",
                recommendation="Enforce hybrid key establishment combining classical ECDHE with ML-KEM.",
            )

        return PQCAssessmentResult(
            pqc_status=PQCStatus.ASSESSMENT_INCOMPLETE,
            hndl_status=HNDLStatus.INCOMPLETE,
            evidence_source="Key exchange parameters unobserved in passive capture",
            summary="Key-exchange evidence was not observable in passive capture. PQC assessment incomplete.",
            recommendation="Capture complete TLS handshake with ClientHello and ServerHello extensions.",
        )

"""
SecureMailScope X - Cryptographic Rules & PQC Catalog Endpoint
"""

from fastapi import APIRouter
from app.schemas.api import RulesCatalogResponse, RuleMetadataDTO

router = APIRouter()

ACTIVE_RULES = [
    RuleMetadataDTO(
        id="RULE-PLAIN-001",
        title="Plaintext Email Protocol Communication",
        category="PROTOCOL_SECURITY",
        default_severity="CRITICAL",
        standard_reference="NIST SP 800-52r2 / RFC 8314",
        description="Session executed entirely in unencrypted plaintext, exposing credentials and message contents.",
        mitigation="Enforce mandatory TLS (STARTTLS or Direct TLS) on standard secure submission ports."
    ),
    RuleMetadataDTO(
        id="RULE-DEP-TLS-002",
        title="Deprecated TLS Protocol Version (TLS 1.0 / 1.1)",
        category="CRYPTOGRAPHIC_STRENGTH",
        default_severity="HIGH",
        standard_reference="RFC 8996 / NIST SP 800-52r2",
        description="Negotiated deprecated TLS version vulnerable to POODLE, BEAST, and SWEET32 attacks.",
        mitigation="Disable TLS 1.0 and TLS 1.1 server-side; enforce TLS 1.2 minimum with TLS 1.3 preferred."
    ),
    RuleMetadataDTO(
        id="RULE-NO-PFS-003",
        title="Static Key Exchange / Missing Forward Secrecy",
        category="FORWARD_SECRECY",
        default_severity="HIGH",
        standard_reference="NIST SP 800-52r2 Section 3.3.1",
        description="Cipher suite uses static RSA key exchange without ephemeral Diffie-Hellman (ECDHE/DHE).",
        mitigation="Disable static RSA key exchange; mandate ECDHE (X25519, secp256r1) key exchange."
    ),
    RuleMetadataDTO(
        id="RULE-WEAK-CIPHER-004",
        title="Insecure / Weak Cipher Suite Negotiated",
        category="CRYPTOGRAPHIC_STRENGTH",
        default_severity="CRITICAL",
        standard_reference="NIST SP 800-52r2 / RFC 7540",
        description="Negotiated legacy cipher suite utilizing RC4, 3DES, CBC mode without EtM, or NULL encryption.",
        mitigation="Configure AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) exclusively."
    ),
    RuleMetadataDTO(
        id="RULE-PQC-HNDL-005",
        title="Post-Quantum Classical Key Exchange Exposure (HNDL Risk)",
        category="POST_QUANTUM_READINESS",
        default_severity="MEDIUM",
        standard_reference="NIST FIPS 203 (ML-KEM) / NSA CNSA 2.0",
        description="Session relies on classical ECC/DH vulnerable to Harvest Now, Decrypt Later adversaries with CRQCs.",
        mitigation="Deploy hybrid post-quantum key encapsulation (e.g. X25519MLKEM768 or draft-ietf-tls-hybrid-design)."
    ),
    RuleMetadataDTO(
        id="RULE-TLS13-SOTA-006",
        title="State-of-the-Art TLS 1.3 Cryptography",
        category="CRYPTOGRAPHIC_STRENGTH",
        default_severity="INFO",
        standard_reference="RFC 8446",
        description="Session successfully negotiated modern TLS 1.3 with authenticated encryption and forward secrecy.",
        mitigation="Maintain current configuration and prepare for post-quantum hybrid KEM migration."
    )
]


@router.get(
    "/rules",
    response_model=RulesCatalogResponse,
    summary="Cryptographic Rules & NIST SP 800-52r2 Catalog",
    description="Returns the list of active cryptographic forensic rules, security thresholds, and post-quantum readiness criteria."
)
def get_rules() -> RulesCatalogResponse:
    return RulesCatalogResponse(
        total_rules=len(ACTIVE_RULES),
        rules=ACTIVE_RULES
    )

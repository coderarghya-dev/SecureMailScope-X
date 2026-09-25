"""
SecureMailScope X - IANA Cipher Suite Knowledge Base
Maps cipher suite hex identifiers to cryptographic properties, PFS, security strength, and PQC status.
"""

from typing import Dict, Optional
from ..schemas.forensic import CipherSuiteInfo, SecurityStrength


# Common IANA Cipher Suites mapped by hex code (e.g. "0x1301", "0xc02f")
CIPHER_SUITE_DATABASE: Dict[str, CipherSuiteInfo] = {
    # TLS 1.3 Ciphers (Symmetric AEAD ciphers; key exchange is negotiated independently in Key Share)
    "0x1301": CipherSuiteInfo(
        hex_code="0x1301",
        name="TLS_AES_128_GCM_SHA256",
        has_pfs=None,
        key_exchange="Key Share (TLS 1.3)",
        encryption="AES-128-GCM (AEAD)",
        hash_algorithm="SHA-256",
        strength=SecurityStrength.STATE_OF_THE_ART,
        is_post_quantum_safe=False
    ),
    "0x1302": CipherSuiteInfo(
        hex_code="0x1302",
        name="TLS_AES_256_GCM_SHA384",
        has_pfs=None,
        key_exchange="Key Share (TLS 1.3)",
        encryption="AES-256-GCM (AEAD)",
        hash_algorithm="SHA-384",
        strength=SecurityStrength.STATE_OF_THE_ART,
        is_post_quantum_safe=False
    ),
    "0x1303": CipherSuiteInfo(
        hex_code="0x1303",
        name="TLS_CHACHA20_POLY1305_SHA256",
        has_pfs=None,
        key_exchange="Key Share (TLS 1.3)",
        encryption="CHACHA20-POLY1305 (AEAD)",
        hash_algorithm="SHA-256",
        strength=SecurityStrength.STATE_OF_THE_ART,
        is_post_quantum_safe=False
    ),
    "0x1304": CipherSuiteInfo(
        hex_code="0x1304",
        name="TLS_AES_128_CCM_SHA256",
        has_pfs=None,
        key_exchange="Key Share (TLS 1.3)",
        encryption="AES-128-CCM (AEAD)",
        hash_algorithm="SHA-256",
        strength=SecurityStrength.STRONG,
        is_post_quantum_safe=False
    ),

    # TLS 1.2 Modern ECDHE (Forward Secrecy = True)
    "0xc02f": CipherSuiteInfo(
        hex_code="0xc02f",
        name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        has_pfs=True,
        key_exchange="ECDHE-RSA",
        encryption="AES-128-GCM (AEAD)",
        hash_algorithm="SHA-256",
        strength=SecurityStrength.STRONG,
        is_post_quantum_safe=False
    ),
    "0xc030": CipherSuiteInfo(
        hex_code="0xc030",
        name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        has_pfs=True,
        key_exchange="ECDHE-RSA",
        encryption="AES-256-GCM (AEAD)",
        hash_algorithm="SHA-384",
        strength=SecurityStrength.STRONG,
        is_post_quantum_safe=False
    ),
    "0xc02b": CipherSuiteInfo(
        hex_code="0xc02b",
        name="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        has_pfs=True,
        key_exchange="ECDHE-ECDSA",
        encryption="AES-128-GCM (AEAD)",
        hash_algorithm="SHA-256",
        strength=SecurityStrength.STRONG,
        is_post_quantum_safe=False
    ),
    "0xc02c": CipherSuiteInfo(
        hex_code="0xc02c",
        name="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        has_pfs=True,
        key_exchange="ECDHE-ECDSA",
        encryption="AES-256-GCM (AEAD)",
        hash_algorithm="SHA-384",
        strength=SecurityStrength.STRONG,
        is_post_quantum_safe=False
    ),
    "0xcca8": CipherSuiteInfo(
        hex_code="0xcca8",
        name="TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        has_pfs=True,
        key_exchange="ECDHE-RSA",
        encryption="CHACHA20-POLY1305 (AEAD)",
        hash_algorithm="SHA-256",
        strength=SecurityStrength.STRONG,
        is_post_quantum_safe=False
    ),
    "0xcca9": CipherSuiteInfo(
        hex_code="0xcca9",
        name="TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        has_pfs=True,
        key_exchange="ECDHE-ECDSA",
        encryption="CHACHA20-POLY1305 (AEAD)",
        hash_algorithm="SHA-256",
        strength=SecurityStrength.STRONG,
        is_post_quantum_safe=False
    ),

    # TLS 1.2 DHE (Forward Secrecy = True)
    "0x009e": CipherSuiteInfo(
        hex_code="0x009e",
        name="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        has_pfs=True,
        key_exchange="DHE-RSA",
        encryption="AES-128-GCM (AEAD)",
        hash_algorithm="SHA-256",
        strength=SecurityStrength.STRONG,
        is_post_quantum_safe=False
    ),
    "0x009f": CipherSuiteInfo(
        hex_code="0x009f",
        name="TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        has_pfs=True,
        key_exchange="DHE-RSA",
        encryption="AES-256-GCM (AEAD)",
        hash_algorithm="SHA-384",
        strength=SecurityStrength.STRONG,
        is_post_quantum_safe=False
    ),

    # Static RSA Key Exchange (NO FORWARD SECRECY - Weakness finding!)
    "0x009c": CipherSuiteInfo(
        hex_code="0x009c",
        name="TLS_RSA_WITH_AES_128_GCM_SHA256",
        has_pfs=False,
        key_exchange="RSA (Static)",
        encryption="AES-128-GCM (AEAD)",
        hash_algorithm="SHA-256",
        strength=SecurityStrength.ACCEPTABLE,
        is_post_quantum_safe=False
    ),
    "0x009d": CipherSuiteInfo(
        hex_code="0x009d",
        name="TLS_RSA_WITH_AES_256_GCM_SHA384",
        has_pfs=False,
        key_exchange="RSA (Static)",
        encryption="AES-256-GCM (AEAD)",
        hash_algorithm="SHA-384",
        strength=SecurityStrength.ACCEPTABLE,
        is_post_quantum_safe=False
    ),
    "0x002f": CipherSuiteInfo(
        hex_code="0x002f",
        name="TLS_RSA_WITH_AES_128_CBC_SHA",
        has_pfs=False,
        key_exchange="RSA (Static)",
        encryption="AES-128-CBC",
        hash_algorithm="SHA-1",
        strength=SecurityStrength.DEPRECATED,
        is_post_quantum_safe=False
    ),
    "0x0035": CipherSuiteInfo(
        hex_code="0x0035",
        name="TLS_RSA_WITH_AES_256_CBC_SHA",
        has_pfs=False,
        key_exchange="RSA (Static)",
        encryption="AES-256-CBC",
        hash_algorithm="SHA-1",
        strength=SecurityStrength.DEPRECATED,
        is_post_quantum_safe=False
    ),

    # Legacy / Insecure Ciphers (3DES, RC4, DES, NULL)
    "0x000a": CipherSuiteInfo(
        hex_code="0x000a",
        name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        has_pfs=False,
        key_exchange="RSA (Static)",
        encryption="3DES-EDE-CBC",
        hash_algorithm="SHA-1",
        strength=SecurityStrength.INSECURE,
        is_post_quantum_safe=False
    ),
    "0x0004": CipherSuiteInfo(
        hex_code="0x0004",
        name="TLS_RSA_WITH_RC4_128_MD5",
        has_pfs=False,
        key_exchange="RSA (Static)",
        encryption="RC4-128",
        hash_algorithm="MD5",
        strength=SecurityStrength.INSECURE,
        is_post_quantum_safe=False
    ),
    "0x0005": CipherSuiteInfo(
        hex_code="0x0005",
        name="TLS_RSA_WITH_RC4_128_SHA",
        has_pfs=False,
        key_exchange="RSA (Static)",
        encryption="RC4-128",
        hash_algorithm="SHA-1",
        strength=SecurityStrength.INSECURE,
        is_post_quantum_safe=False
    ),
    "0x0000": CipherSuiteInfo(
        hex_code="0x0000",
        name="TLS_NULL_WITH_NULL_NULL",
        has_pfs=False,
        key_exchange="NULL",
        encryption="NULL",
        hash_algorithm="NULL",
        strength=SecurityStrength.INSECURE,
        is_post_quantum_safe=False
    )
}


def lookup_cipher_suite(code_or_name: str) -> Optional[CipherSuiteInfo]:
    """Look up a cipher suite by its hex representation or name."""
    if not code_or_name:
        return None

    # Normalize hex representation (e.g. 0x1301 or 4865 or 0x00001301)
    val = code_or_name.strip().lower()
    
    # Try exact match first
    if val in CIPHER_SUITE_DATABASE:
        return CIPHER_SUITE_DATABASE[val]

    # Convert decimal string to hex if purely numeric
    if val.isdigit():
        hex_val = f"0x{int(val):04x}"
        if hex_val in CIPHER_SUITE_DATABASE:
            return CIPHER_SUITE_DATABASE[hex_val]

    # Handle hex without 0x
    if len(val) == 4 and all(c in "0123456789abcdef" for c in val):
        hex_val = f"0x{val}"
        if hex_val in CIPHER_SUITE_DATABASE:
            return CIPHER_SUITE_DATABASE[hex_val]

    # Search by name match
    for cipher in CIPHER_SUITE_DATABASE.values():
        if cipher.name.lower() == val or cipher.name.lower() == f"tls_{val}":
            return cipher

    # Unknown or unmapped cipher
    if "ecdhe" in val or "dhe" in val:
        has_pfs = True
        kex_str = "ECDHE/DHE"
        strength = SecurityStrength.ACCEPTABLE
    elif "rsa" in val:
        has_pfs = False
        kex_str = "RSA (Static)"
        strength = SecurityStrength.ACCEPTABLE
    else:
        has_pfs = None
        kex_str = "Unknown"
        strength = SecurityStrength.DEPRECATED

    return CipherSuiteInfo(
        hex_code=val if val.startswith("0x") else f"0x{val}",
        name=code_or_name,
        has_pfs=has_pfs,
        key_exchange=kex_str,
        encryption="Unknown",
        hash_algorithm="Unknown",
        strength=strength,
        is_post_quantum_safe=False
    )

"""
SecureMailScope X - Local Cryptographic Report Signing Module
Uses asymmetric public-key cryptography (RSA-PSS with SHA-256) to sign PDF reports and forensic manifests.
CRITICAL BOUNDARY: Distinguishes between local cryptographic digital signature and external legal notarization.
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "report_signing_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "report_verification_key.pem")


class ReportSigner:
    """Manages local cryptographic signing keys and generates verifiable digital signatures."""

    @classmethod
    def _ensure_keys_exist(cls) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        os.makedirs(KEYS_DIR, exist_ok=True)
        if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
            with open(PRIVATE_KEY_PATH, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(PUBLIC_KEY_PATH, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            return private_key, public_key

        # Generate fresh 2048-bit RSA key pair for local report signing
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

        return private_key, public_key

    @classmethod
    def sign_hash(cls, sha256_hex: str, analyst_name: str = "Local Forensic Analyst") -> Dict[str, Any]:
        private_key, public_key = cls._ensure_keys_exist()
        data_to_sign = bytes.fromhex(sha256_hex)

        signature = private_key.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        now_iso = datetime.now(timezone.utc).isoformat()

        return {
            "content_sha256": sha256_hex,
            "signature_hex": signature.hex(),
            "algorithm": "RSA-PSS-2048 / SHA-256",
            "signed_at_iso": now_iso,
            "analyst_name": analyst_name,
            "public_key_pem": pub_pem,
            "signature_status": "VALID_LOCAL_SIGNATURE",
            "disclaimer": "Local cryptographic digital signature verified with public key. Not a qualified PKI trust-anchor signature.",
        }

    @classmethod
    def verify_signature(cls, sha256_hex: str, signature_hex: str, public_key_pem: str) -> bool:
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode())
            data = bytes.fromhex(sha256_hex)
            sig = bytes.fromhex(signature_hex)
            pub_key.verify(
                sig,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

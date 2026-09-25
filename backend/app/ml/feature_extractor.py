"""
SecureMailScope X - ML Feature Extractor
Extracts deterministic numerical and categorical vectors from EmailSession and TLS evidence.
"""

from typing import Dict, Any, List
from app.schemas.forensic import EmailSession, SecurityMode, TLSVersion, SecurityStrength


FEATURE_NAMES = [
    "tls_version_ord",        # -1=None, 0=SSL, 1=TLS1.0, 2=TLS1.1, 3=TLS1.2, 4=TLS1.3
    "cipher_strength_ord",    # -1=None, 0=INSECURE, 1=DEPRECATED, 2=ACCEPTABLE, 3=STRONG, 4=STATE_OF_THE_ART
    "security_mode_ord",      # 0=PLAINTEXT, 1=FAILED, 2=ADVERTISED, 3=ACCEPTED, 4=DIRECT_TLS
    "has_forward_secrecy",    # 0.0=No, 0.5=Unknown/Unobserved, 1.0=Yes
    "has_post_quantum",       # 0.0=Classical/Vulnerable, 0.5=Unknown, 1.0=PQC Hybrid
    "has_plaintext_exposure", # 1.0=Exposed cleartext commands, 0.0=No
    "capture_confidence",     # 0.0 to 1.0 normalized
    "capture_health",         # 0.0 to 1.0 normalized
]


class MLFeatureExtractor:
    """Transforms EmailSession evidence into normalized feature dictionaries and vectors."""

    @classmethod
    def extract_features(cls, session: EmailSession) -> Dict[str, float]:
        # 1. TLS Version
        tls = session.tls_details
        tls_ver = tls.negotiated_tls_version if tls else TLSVersion.UNKNOWN
        tls_ver_map = {
            TLSVersion.SSLv2: 0.0,
            TLSVersion.SSLv3: 0.0,
            TLSVersion.TLSv1_0: 1.0,
            TLSVersion.TLSv1_1: 2.0,
            TLSVersion.TLSv1_2: 3.0,
            TLSVersion.TLSv1_3: 4.0,
            TLSVersion.UNKNOWN: -1.0,
        }
        tls_version_ord = tls_ver_map.get(tls_ver, -1.0)

        # 2. Cipher Strength
        cipher = tls.cipher_info if tls else None
        strength = cipher.strength if cipher else None
        strength_map = {
            SecurityStrength.INSECURE: 0.0,
            SecurityStrength.DEPRECATED: 1.0,
            SecurityStrength.ACCEPTABLE: 2.0,
            SecurityStrength.STRONG: 3.0,
            SecurityStrength.STATE_OF_THE_ART: 4.0,
        }
        cipher_strength_ord = strength_map.get(strength, -1.0)

        # 3. Security Mode
        mode_map = {
            SecurityMode.PLAINTEXT: 0.0,
            SecurityMode.STARTTLS_FAILED: 1.0,
            SecurityMode.STARTTLS_ADVERTISED: 2.0,
            SecurityMode.STARTTLS_REQUESTED: 2.5,
            SecurityMode.STARTTLS_ACCEPTED: 3.0,
            SecurityMode.DIRECT_TLS: 4.0,
            SecurityMode.UNKNOWN: 0.0,
        }
        security_mode_ord = mode_map.get(session.security_mode, 0.0)

        # 4. Forward Secrecy
        if tls:
            if tls.has_forward_secrecy is True:
                has_forward_secrecy = 1.0
            elif tls.has_forward_secrecy is False:
                has_forward_secrecy = 0.0
            else:
                has_forward_secrecy = 0.5
        else:
            has_forward_secrecy = 0.0 if session.security_mode == SecurityMode.PLAINTEXT else 0.5

        # 5. Post Quantum
        if cipher and cipher.is_post_quantum_safe:
            has_post_quantum = 1.0
        elif tls and tls.selected_group and ("mlkem" in tls.selected_group.lower() or "kyber" in tls.selected_group.lower()):
            has_post_quantum = 1.0
        elif tls and tls.negotiated_tls_version in [TLSVersion.TLSv1_2, TLSVersion.TLSv1_3]:
            has_post_quantum = 0.0
        else:
            has_post_quantum = 0.5

        # 6. Plaintext Exposure
        has_plaintext_exposure = 1.0 if (session.observed_commands or session.security_mode == SecurityMode.PLAINTEXT) else 0.0

        # 7. Confidence Score
        conf_score = (session.evidence_confidence.score / 100.0) if session.evidence_confidence else 0.8

        # 8. Health Score
        health_score = (session.capture_health.score / 100.0) if session.capture_health else 0.8

        return {
            "tls_version_ord": tls_version_ord,
            "cipher_strength_ord": cipher_strength_ord,
            "security_mode_ord": security_mode_ord,
            "has_forward_secrecy": has_forward_secrecy,
            "has_post_quantum": has_post_quantum,
            "has_plaintext_exposure": has_plaintext_exposure,
            "capture_confidence": conf_score,
            "capture_health": health_score,
        }

    @classmethod
    def to_vector(cls, features: Dict[str, float]) -> List[float]:
        return [features[name] for name in FEATURE_NAMES]

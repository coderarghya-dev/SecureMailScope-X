"""
SecureMailScope X - Local Explainable AI-Assisted Cryptographic Risk Model (Phase 27)
Provides an advisory, explainable machine-learning layer for secondary risk classification.
Deterministic forensic engine rules and cryptographic findings remain authoritative.
"""

import os
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression
import joblib

from app.schemas.forensic import (
    EmailSession,
    EmailProtocol,
    SecurityMode,
    TLSVersion,
    SecurityStrength,
    CertificateVisibility,
    CertificateValidityStatus,
    FindingSeverity
)
from app.forensic.anomaly_detector import TLSAnomalyDetector

logger = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
MODEL_METADATA_FILE = os.path.join(MODEL_DIR, "ai_risk_model_v1.json")
MODEL_JOBLIB_FILE = os.path.join(MODEL_DIR, "ai_risk_model_v1.joblib")

# 22 Canonical Forensic Feature Names
FEATURE_NAMES: List[str] = [
    "protocol_ord",               # 0=UNKNOWN, 1=SMTP, 2=IMAP, 3=POP3
    "port_class",                 # 0=OTHER, 1=STANDARD_CLEARTEXT, 2=SUBMISSION, 3=IMPLICIT_TLS
    "plaintext_flag",             # 1.0=Cleartext payload/commands observed, 0.0=Encrypted
    "starttls_advertised",        # 1.0=STARTTLS/STLS advertised
    "starttls_requested",         # 1.0=STARTTLS/STLS requested
    "starttls_accepted",          # 1.0=STARTTLS/STLS accepted/upgraded
    "direct_tls_flag",            # 1.0=Direct implicit TLS
    "tls_version_ord",            # -1=None, 0=SSL, 1=TLS1.0, 2=TLS1.1, 3=TLS1.2, 4=TLS1.3
    "weak_tls_flag",              # 1.0=Negotiated <= TLS 1.1 or SSL
    "weak_cipher_flag",           # 1.0=Insecure/deprecated cipher (3DES, RC4, NULL, etc.)
    "pfs_observed_flag",          # 1.0=PFS verified (ECDHE/DHE/KeyShare)
    "pfs_unknown_flag",           # 1.0=PFS unobserved/unknown
    "cert_observable_flag",       # 1.0=Observable certificate in handshake
    "cert_expired_flag",          # 1.0=Certificate validity is EXPIRED
    "cert_weak_key_flag",         # 1.0=RSA public key < 2048 bits
    "cert_weak_sig_flag",         # 1.0=MD5 or SHA-1 digest in certificate signature
    "anomaly_count",              # Count of heuristic TLS anomalies
    "critical_finding_count",     # Count of CRITICAL deterministic findings
    "high_finding_count",         # Count of HIGH deterministic findings
    "medium_finding_count",       # Count of MEDIUM deterministic findings
    "capture_health_norm",        # 0.0 to 1.0 normalized TCP capture health
    "evidence_confidence_norm",   # 0.0 to 1.0 normalized forensic evidence confidence
]

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "protocol_ord": "Email Transport Protocol (SMTP / IMAP / POP3)",
    "port_class": "Server Port Classification (Cleartext / Submission / Implicit TLS)",
    "plaintext_flag": "Unencrypted Cleartext Payload / Command Exposure",
    "starttls_advertised": "STARTTLS / STLS Upgrade Capability Advertised",
    "starttls_requested": "STARTTLS / STLS Upgrade Command Issued",
    "starttls_accepted": "STARTTLS / STLS Upgrade Command Accepted",
    "direct_tls_flag": "Direct Implicit TLS Handshake Negotiation",
    "tls_version_ord": "Negotiated TLS Protocol Version",
    "weak_tls_flag": "Deprecated / Vulnerable TLS Version (SSL / TLS 1.0 / 1.1)",
    "weak_cipher_flag": "Insecure / Deprecated Cipher Suite (3DES, RC4, NULL)",
    "pfs_observed_flag": "Verified Ephemeral Key Exchange (PFS)",
    "pfs_unknown_flag": "Unverified / Insufficient Passive PFS Evidence",
    "cert_observable_flag": "Observable Handshake Certificate Details",
    "cert_expired_flag": "Expired X.509 Server Certificate",
    "cert_weak_key_flag": "Sub-2048 Bit RSA Public Key",
    "cert_weak_sig_flag": "Deprecated Digest in Certificate Signature (MD5 / SHA-1)",
    "anomaly_count": "Total Forensic TLS Anomalies Detected",
    "critical_finding_count": "Total Critical Deterministic Security Findings",
    "high_finding_count": "Total High Deterministic Security Findings",
    "medium_finding_count": "Total Medium Deterministic Security Findings",
    "capture_health_norm": "TCP Capture Stream Integrity & Completeness",
    "evidence_confidence_norm": "Forensic Capture Observability Confidence",
}

CLASS_NAMES_MAP: Dict[int, str] = {
    0: "LOW",
    1: "MODERATE",
    2: "HIGH",
    3: "CRITICAL"
}

# Controlled Synthetic Training Dataset (32 Representative Forensic Scenarios)
# Features format: [22 numerical values per sample]
# Target labels: 0=LOW, 1=MODERATE, 2=HIGH, 3=CRITICAL
CONTROLLED_TRAINING_FIXTURES: List[Tuple[List[float], int]] = [
    # -----------------------------------------------------------------------------------------
    # 0: LOW RISK — State-of-the-art TLS 1.3 / Post-Quantum / Clean handshakes, 0 findings
    # -----------------------------------------------------------------------------------------
    # 1. SMTP Port 587 STARTTLS -> TLS 1.3, AES-256-GCM, PFS, no anomalies
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 4.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0 ], 0),
    # 2. IMAP Port 993 Direct TLS 1.3, AES-256-GCM, PFS
    ([ 2.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.0, 4.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0 ], 0),
    # 3. POP3S Port 995 Direct TLS 1.3, AES-256-GCM, PFS
    ([ 3.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.0, 4.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0 ], 0),
    # 4. SMTP SMTPS Port 465 Direct TLS 1.3, ChaCha20-Poly1305, PFS
    ([ 1.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.0, 4.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.95, 0.95 ], 0),
    # 5. POP3 Port 110 STLS -> TLS 1.3, AES-128-GCM, PFS
    ([ 3.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0, 4.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.9 ], 0),
    # 6. IMAP Port 143 STARTTLS -> TLS 1.3, AES-256-GCM, PFS
    ([ 2.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0, 4.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9, 0.9 ], 0),
    # 7. Modern TLS 1.2 with valid 2048-bit cert, ECDHE-GCM, 0 findings
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 3.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.95 ], 0),
    # 8. Direct TLS 1.3 with minor TCP retransmission but pristine crypto
    ([ 1.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.0, 4.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 0.85 ], 0),

    # -----------------------------------------------------------------------------------------
    # 1: MODERATE RISK — TLS 1.2/1.3 Classical (HNDL exposure / Harvest Now Decrypt Later), minor medium findings
    # -----------------------------------------------------------------------------------------
    # 9. TLS 1.2 ECDHE-RSA-AES256-GCM (Classical, 1 medium finding for PQC/HNDL)
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 3.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.9 ], 1),
    # 10. TLS 1.3 with unobserved key-share (PFS unknown flag)
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 4.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.8, 0.7 ], 1),
    # 11. IMAP Direct TLS 1.2 Classical ECDHE with self-issued certificate
    ([ 2.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.0, 3.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.9, 0.85 ], 1),
    # 12. POP3S Direct TLS 1.2 Classical ECDHE-SHA384
    ([ 3.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.0, 3.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.95, 0.9 ], 1),
    # 13. SMTP TLS 1.2 with 1 low and 1 medium finding
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 3.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 0.9, 0.8 ], 1),
    # 14. TLS 1.3 with partial capture observability
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 4.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.7, 0.6 ], 1),

    # -----------------------------------------------------------------------------------------
    # 2: HIGH RISK — Deprecated TLS (1.0/1.1), Static RSA without PFS, Weak 3DES ciphers, Expired certs
    # -----------------------------------------------------------------------------------------
    # 15. TLS 1.0 Deprecated protocol version (RFC 8996)
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.9, 0.9 ], 2),
    # 16. TLS 1.1 Deprecated protocol version
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 2.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.9, 0.9 ], 2),
    # 17. TLS 1.2 Static RSA (No PFS, vulnerable to retrospective decryption)
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.95, 0.95 ], 2),
    # 18. TLS 1.2 Weak 3DES cipher suite
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 3.0, 0.0, 1.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.9, 0.9 ], 2),
    # 19. Expired X.509 Certificate in handshake
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 3.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.95, 0.95 ], 2),
    # 20. Sub-2048 Bit RSA Public Key (1024-bit key)
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 3.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.9, 0.9 ], 2),
    # 21. Deprecated MD5/SHA-1 Certificate Signature Digest
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 3.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 1.0, 1.0, 0.0, 1.0, 0.0, 0.9, 0.9 ], 2),
    # 22. IMAP Port 143 TLS 1.0 legacy version with high finding
    ([ 2.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.9, 0.9 ], 2),
    # 23. POP3S Port 995 TLS 1.1 legacy version
    ([ 3.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.0, 2.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.9, 0.9 ], 2),

    # -----------------------------------------------------------------------------------------
    # 3: CRITICAL RISK — Cleartext email traffic, SSLv2/SSLv3, Downgrade stripping, Critical findings
    # -----------------------------------------------------------------------------------------
    # 24. POP3 Port 110 Pure Plaintext exposure (Real capture pop3-stls-test.pcapng scenario)
    ([ 3.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0 ], 3),
    # 25. SMTP Port 25 Pure Plaintext stream with credentials
    ([ 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0 ], 3),
    # 26. IMAP Port 143 Pure Plaintext exposure
    ([ 2.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0 ], 3),
    # 27. STARTTLS Stripping / Downgrade Attack (Advertised but not requested)
    ([ 1.0, 2.0, 1.0, 1.0, 0.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 1.0, 1.0, 0.0, 0.95, 0.9 ], 3),
    # 28. STARTTLS Upgrade Rejected with plaintext fallback
    ([ 1.0, 2.0, 1.0, 1.0, 1.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 1.0, 1.0, 0.0, 0.9, 0.9 ], 3),
    # 29. SSLv3 Protocol Negotiated with RC4/DES
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 2.0, 1.0, 1.0, 0.0, 0.9, 0.9 ], 3),
    # 30. SSLv2 Direct TLS Handshake
    ([ 1.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 2.0, 1.0, 1.0, 0.0, 0.8, 0.8 ], 3),
    # 31. Port Incongruity: Cleartext commands on dedicated implicit TLS port 993/995/465
    ([ 2.0, 3.0, 1.0, 0.0, 0.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 1.0, 0.0, 0.0, 1.0, 1.0 ], 3),
    # 32. Multiple Critical findings combined with expired cert and legacy cipher
    ([ 1.0, 2.0, 0.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 4.0, 2.0, 2.0, 1.0, 0.85, 0.9 ], 3)
]


@dataclass
class AIRiskFactor:
    feature: str
    description: str
    observed_value: float
    contribution: float
    direction: str  # "INCREASES_RISK" or "REDUCES_RISK"
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "description": self.description,
            "observed_value": self.observed_value,
            "contribution": round(self.contribution, 4),
            "direction": self.direction,
            "explanation": self.explanation
        }


@dataclass
class AIRiskPrediction:
    risk_class: str  # "LOW", "MODERATE", "HIGH", "CRITICAL"
    confidence: float  # 0.0 to 1.0
    model_name: str
    model_version: str
    training_source: str
    authoritative: bool
    disclaimer: str
    feature_vector: Dict[str, float]
    class_probabilities: Dict[str, float]
    top_risk_factors: List[AIRiskFactor] = field(default_factory=list)
    top_mitigating_factors: List[AIRiskFactor] = field(default_factory=list)
    explanation: str = ""
    limitations: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_class": self.risk_class,
            "confidence": round(self.confidence, 4),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "training_source": self.training_source,
            "authoritative": self.authoritative,
            "disclaimer": self.disclaimer,
            "feature_vector": self.feature_vector,
            "class_probabilities": {k: round(v, 4) for k, v in self.class_probabilities.items()},
            "top_risk_factors": [rf.to_dict() for rf in self.top_risk_factors],
            "top_mitigating_factors": [mf.to_dict() for mf in self.top_mitigating_factors],
            "explanation": self.explanation,
            "limitations": self.limitations,
            # Backwards compatibility fields
            "advisory_risk_class": self.risk_class,
            "risk_probability": round(self.confidence, 4),
            "model_status": "EXPLAINABLE_LOCAL_MODEL",
            "model_type": "LogisticRegression",
            "top_risk_contributors": [rf.to_dict() for rf in self.top_risk_factors],
            "top_protective_factors": [mf.to_dict() for mf in self.top_mitigating_factors]
        }


class AIRiskModel:
    """
    Local, deterministic, explainable LogisticRegression risk classifier.
    Advisory only. Does not replace deterministic forensic evidence or rule verdicts.
    """

    _model: Optional[LogisticRegression] = None
    _metadata: Optional[Dict[str, Any]] = None

    @classmethod
    def train_model(cls) -> Tuple[LogisticRegression, Dict[str, Any]]:
        """Trains the local LogisticRegression model deterministically on the controlled training fixtures."""
        os.makedirs(MODEL_DIR, exist_ok=True)
        X = np.array([sample[0] for sample in CONTROLLED_TRAINING_FIXTURES], dtype=np.float64)
        y = np.array([sample[1] for sample in CONTROLLED_TRAINING_FIXTURES], dtype=np.int32)

        # Train multinomial LogisticRegression with fixed random_state for exact reproducibility
        clf = LogisticRegression(
            solver="lbfgs",
            C=1.0,
            max_iter=1000,
            random_state=42
        )
        clf.fit(X, y)

        metadata = {
            "model_name": "LogisticRegression (Multinomial / L-BFGS)",
            "model_version": "v1.0.0-synthetic-controlled",
            "training_source": "Controlled synthetic training dataset for functional demonstration",
            "training_sample_count": len(CONTROLLED_TRAINING_FIXTURES),
            "feature_names": FEATURE_NAMES,
            "classes": [CLASS_NAMES_MAP[c] for c in clf.classes_],
            "random_state": 42,
            "authoritative": False,
            "disclaimer": "AI-Assisted Risk Classification is advisory only. Deterministic forensic rules and packet evidence remain authoritative."
        }

        # Persist model and metadata
        joblib.dump(clf, MODEL_JOBLIB_FILE)
        with open(MODEL_METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        cls._model = clf
        cls._metadata = metadata
        return clf, metadata

    @classmethod
    def _ensure_loaded(cls) -> bool:
        if cls._model is None:
            if os.path.exists(MODEL_JOBLIB_FILE) and os.path.exists(MODEL_METADATA_FILE):
                try:
                    cls._model = joblib.load(MODEL_JOBLIB_FILE)
                    with open(MODEL_METADATA_FILE, "r", encoding="utf-8") as f:
                        cls._metadata = json.load(f)
                except Exception as e:
                    logger.warning("Failed loading cached AI risk model, retraining: %s", e)
                    cls.train_model()
            else:
                cls.train_model()
        return cls._model is not None

    @classmethod
    def extract_feature_dict(cls, session: EmailSession) -> Dict[str, float]:
        """Extracts strictly evidence-backed feature values from an EmailSession."""
        tls = getattr(session, "tls_details", None)
        st = getattr(session, "starttls_state", None)
        cert = getattr(session, "certificate_details", None) or (getattr(tls, "certificate_details", None) if tls else None)
        sec_assess = getattr(session, "security_assessment", None)
        health = getattr(session, "capture_health", None)
        conf = getattr(session, "evidence_confidence", None)

        # 1. Protocol ordinal
        proto_map = {EmailProtocol.UNKNOWN: 0.0, EmailProtocol.SMTP: 1.0, EmailProtocol.IMAP: 2.0, EmailProtocol.POP3: 3.0}
        proto_ord = proto_map.get(session.protocol, 0.0)

        # 2. Port class
        port = session.server_port
        if port in [25, 110, 143]:
            port_class = 1.0
        elif port == 587:
            port_class = 2.0
        elif port in [465, 993, 995]:
            port_class = 3.0
        else:
            port_class = 0.0

        # 3. Plaintext flag
        plaintext_flag = 1.0 if (session.security_mode == SecurityMode.PLAINTEXT or not tls or bool(getattr(session, "observed_commands", []))) else 0.0

        # 4-6. STARTTLS states
        st_adv = 1.0 if (st and st.advertised) else 0.0
        st_req = 1.0 if (st and st.requested) else 0.0
        st_acc = 1.0 if (st and st.accepted and st.upgrade_successful) else 0.0

        # 7. Direct TLS flag
        direct_tls_flag = 1.0 if session.security_mode == SecurityMode.DIRECT_TLS else 0.0

        # 8-9. TLS version & weak TLS flag
        tls_ver = tls.negotiated_tls_version if tls else TLSVersion.UNKNOWN
        tls_ver_map = {
            TLSVersion.UNKNOWN: -1.0,
            TLSVersion.SSLv2: 0.0,
            TLSVersion.SSLv3: 0.0,
            TLSVersion.TLSv1_0: 1.0,
            TLSVersion.TLSv1_1: 2.0,
            TLSVersion.TLSv1_2: 3.0,
            TLSVersion.TLSv1_3: 4.0,
        }
        tls_version_ord = tls_ver_map.get(tls_ver, -1.0)
        weak_tls_flag = 1.0 if (tls and tls_ver in [TLSVersion.SSLv2, TLSVersion.SSLv3, TLSVersion.TLSv1_0, TLSVersion.TLSv1_1]) else 0.0

        # 10. Weak cipher flag
        weak_cipher_flag = 0.0
        if tls and tls.cipher_info:
            ci = tls.cipher_info
            if ci.strength in [SecurityStrength.INSECURE, SecurityStrength.DEPRECATED] or any(w in ci.name.lower() for w in ["3des", "rc4", "null", "des"]):
                weak_cipher_flag = 1.0

        # 11-12. PFS flags
        pfs_observed_flag = 1.0 if (tls and tls.has_forward_secrecy is True) else 0.0
        pfs_unknown_flag = 1.0 if (tls and tls.has_forward_secrecy is None and tls.negotiated_tls_version == TLSVersion.TLSv1_3) else 0.0

        # 13-16. Certificate flags
        cert_observable_flag = 1.0 if (cert and cert.visibility == CertificateVisibility.OBSERVABLE) else 0.0
        cert_expired_flag = 1.0 if (cert and cert.validity_status == CertificateValidityStatus.EXPIRED) else 0.0
        cert_weak_key_flag = 1.0 if (cert and cert.public_key_bits and cert.public_key_bits < 2048) else 0.0
        cert_weak_sig_flag = 1.0 if (cert and cert.signature_algorithm and any(d in cert.signature_algorithm.lower() for d in ["md5", "sha1", "sha-1", "md2"])) else 0.0

        # 17. Anomaly count
        anom_report = TLSAnomalyDetector.detect_session_anomalies(session)
        anomaly_count = float(anom_report.total_anomalies)

        # 18-20. Finding severity counts
        crit_count = 0.0
        high_count = 0.0
        med_count = 0.0
        if sec_assess:
            crit_count = float(sec_assess.critical_findings_count)
            high_count = float(sec_assess.high_findings_count)
            med_count = float(sec_assess.medium_findings_count)

        # 21-22. Health & Confidence normalized
        health_norm = (health.score / 100.0) if health else 1.0
        conf_norm = (conf.score / 100.0) if conf else 1.0

        return {
            "protocol_ord": proto_ord,
            "port_class": port_class,
            "plaintext_flag": plaintext_flag,
            "starttls_advertised": st_adv,
            "starttls_requested": st_req,
            "starttls_accepted": st_acc,
            "direct_tls_flag": direct_tls_flag,
            "tls_version_ord": tls_version_ord,
            "weak_tls_flag": weak_tls_flag,
            "weak_cipher_flag": weak_cipher_flag,
            "pfs_observed_flag": pfs_observed_flag,
            "pfs_unknown_flag": pfs_unknown_flag,
            "cert_observable_flag": cert_observable_flag,
            "cert_expired_flag": cert_expired_flag,
            "cert_weak_key_flag": cert_weak_key_flag,
            "cert_weak_sig_flag": cert_weak_sig_flag,
            "anomaly_count": anomaly_count,
            "critical_finding_count": crit_count,
            "high_finding_count": high_count,
            "medium_finding_count": med_count,
            "capture_health_norm": health_norm,
            "evidence_confidence_norm": conf_norm,
        }

    @classmethod
    def predict_session(cls, session: EmailSession) -> AIRiskPrediction:
        """Runs explainable LogisticRegression risk prediction with exact feature attribution."""
        cls._ensure_loaded()
        features = cls.extract_feature_dict(session)
        vec = np.array([features[name] for name in FEATURE_NAMES], dtype=np.float64)

        if cls._model is None:
            # Safe deterministic rule fallback if model could not be loaded
            return cls._rule_fallback(session, features)

        probs = cls._model.predict_proba([vec])[0]
        best_idx = int(np.argmax(probs))
        pred_label = int(cls._model.classes_[best_idx])
        risk_class = CLASS_NAMES_MAP.get(pred_label, "MODERATE")
        confidence = float(probs[best_idx])

        class_probs = {
            CLASS_NAMES_MAP.get(int(c), str(c)): float(p)
            for c, p in zip(cls._model.classes_, probs)
        }

        # Linear Explainability: Feature contribution = w_{class, i} * x_i
        # In multi-class LogisticRegression, logit_k = b_k + sum_i (w_{k, i} * x_i)
        coefs = cls._model.coef_[best_idx]  # array of shape (n_features,)
        
        risk_factors: List[AIRiskFactor] = []
        mitigating_factors: List[AIRiskFactor] = []

        for idx, feat_name in enumerate(FEATURE_NAMES):
            val = vec[idx]
            weight = float(coefs[idx])
            contrib = float(weight * val)
            desc = FEATURE_DESCRIPTIONS.get(feat_name, feat_name)

            if abs(contrib) < 0.001 and val == 0.0:
                continue

            if contrib > 0.05:
                # Positive contribution increases the likelihood of the predicted class
                direction = "INCREASES_RISK" if pred_label >= 2 else "SUPPORTS_LOW_RISK"
                explanation_str = f"Positive coefficient ({weight:+.2f}) with observed value {val} supports {risk_class} risk classification."
                factor = AIRiskFactor(
                    feature=feat_name,
                    description=desc,
                    observed_value=val,
                    contribution=contrib,
                    direction=direction,
                    explanation=explanation_str
                )
                if pred_label >= 2:
                    risk_factors.append(factor)
                else:
                    mitigating_factors.append(factor)
            elif contrib < -0.05:
                # Negative contribution reduces the likelihood of the predicted class
                direction = "REDUCES_RISK" if pred_label >= 2 else "OPPOSES_LOW_RISK"
                explanation_str = f"Negative contribution ({contrib:+.2f}) acts against {risk_class} classification."
                factor = AIRiskFactor(
                    feature=feat_name,
                    description=desc,
                    observed_value=val,
                    contribution=contrib,
                    direction=direction,
                    explanation=explanation_str
                )
                if pred_label >= 2:
                    mitigating_factors.append(factor)
                else:
                    risk_factors.append(factor)

        risk_factors.sort(key=lambda x: abs(x.contribution), reverse=True)
        mitigating_factors.sort(key=lambda x: abs(x.contribution), reverse=True)

        explanation = (
            f"Advisory classification '{risk_class}' determined by Logistic Regression with {confidence*100:.1f}% confidence. "
            f"Key risk factors: {', '.join([rf.description for rf in risk_factors[:3]]) if risk_factors else 'None'}. "
            f"Mitigating factors: {', '.join([mf.description for mf in mitigating_factors[:3]]) if mitigating_factors else 'None'}."
        )

        limitations = (
            "Advisory ML classification trained on controlled synthetic protocol fixtures. "
            "Not a substitute for deterministic forensic verification. Deterministic findings and cryptographic rule engine remain authoritative."
        )

        return AIRiskPrediction(
            risk_class=risk_class,
            confidence=confidence,
            model_name="LogisticRegression (Multinomial / L-BFGS)",
            model_version="v1.0.0-synthetic-controlled",
            training_source="Controlled synthetic training dataset for functional demonstration",
            authoritative=False,
            disclaimer="AI-Assisted Risk Classification is advisory only. Deterministic forensic rules and packet evidence remain authoritative.",
            feature_vector=features,
            class_probabilities=class_probs,
            top_risk_factors=risk_factors[:5],
            top_mitigating_factors=mitigating_factors[:5],
            explanation=explanation,
            limitations=limitations
        )

    @classmethod
    def _rule_fallback(cls, session: EmailSession, features: Dict[str, float]) -> AIRiskPrediction:
        """Deterministic fallback if scikit-learn is unavailable."""
        if features.get("plaintext_flag", 0) > 0.5 or features.get("critical_finding_count", 0) > 0:
            risk_class = "CRITICAL"
        elif features.get("weak_tls_flag", 0) > 0.5 or features.get("high_finding_count", 0) > 0 or features.get("cert_expired_flag", 0) > 0:
            risk_class = "HIGH"
        elif features.get("medium_finding_count", 0) > 0 or features.get("pfs_unknown_flag", 0) > 0:
            risk_class = "MODERATE"
        else:
            risk_class = "LOW"

        return AIRiskPrediction(
            risk_class=risk_class,
            confidence=0.90,
            model_name="DeterministicRuleFallback",
            model_version="fallback-v1",
            training_source="Heuristic security rules",
            authoritative=False,
            disclaimer="Advisory classification generated via deterministic fallback.",
            feature_vector=features,
            class_probabilities={risk_class: 1.0},
            top_risk_factors=[],
            top_mitigating_factors=[],
            explanation=f"Fallback heuristic classification '{risk_class}'.",
            limitations="Fallback heuristic triage."
        )

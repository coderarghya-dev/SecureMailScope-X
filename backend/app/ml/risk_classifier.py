"""
SecureMailScope X - ML-Assisted Risk Classifier & XAI Explainability Engine
Advisory risk classification and feature attribution. Deterministic forensic rules remain authoritative.
"""

import os
import json
from typing import Dict, Any, List, Optional
import joblib
import numpy as np

from app.schemas.forensic import EmailSession
from app.ml.feature_extractor import MLFeatureExtractor, FEATURE_NAMES


MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_METADATA_FILE = os.path.join(MODEL_DIR, "risk_model_v1.json")
MODEL_JOBLIB_FILE = os.path.join(MODEL_DIR, "risk_model_v1.joblib")


FEATURE_DESCRIPTIONS = {
    "tls_version_ord": "Negotiated TLS Protocol Version",
    "cipher_strength_ord": "Cryptographic Cipher Suite Strength",
    "security_mode_ord": "Transport Security Protocol Mode (STARTTLS / Direct TLS)",
    "has_forward_secrecy": "Perfect Forward Secrecy (PFS) Key Exchange Status",
    "has_post_quantum": "Post-Quantum Cryptography / Hybrid KEM Readiness",
    "has_plaintext_exposure": "Cleartext Command / Credential Exposure",
    "capture_confidence": "Forensic Capture Observability Confidence",
    "capture_health": "TCP Stream Completeness & Integrity",
}


class MLRiskClassifier:
    """Provides advisory risk classification with local feature attribution (XAI)."""

    _model = None
    _metadata = None

    @classmethod
    def _load_model_if_needed(cls):
        if cls._model is None:
            if os.path.exists(MODEL_JOBLIB_FILE):
                try:
                    cls._model = joblib.load(MODEL_JOBLIB_FILE)
                except Exception as e:
                    cls._model = None
        if cls._metadata is None:
            if os.path.exists(MODEL_METADATA_FILE):
                try:
                    with open(MODEL_METADATA_FILE, "r", encoding="utf-8") as f:
                        cls._metadata = json.load(f)
                except Exception:
                    cls._metadata = None

    @classmethod
    def classify_session(cls, session: EmailSession) -> Dict[str, Any]:
        cls._load_model_if_needed()
        features = MLFeatureExtractor.extract_features(session)
        feature_vec = MLFeatureExtractor.to_vector(features)

        classes = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

        if cls._model is not None:
            try:
                probs = cls._model.predict_proba([feature_vec])[0]
                pred_idx = int(np.argmax(probs))
                risk_class = classes[pred_idx] if pred_idx < len(classes) else "MEDIUM"
                confidence = float(probs[pred_idx])

                # Explainability: Feature contribution estimation based on importance * feature delta from optimal
                importances = cls._metadata.get("feature_importances", {}) if cls._metadata else {}
            except Exception:
                risk_class, confidence, importances = cls._deterministic_fallback(features)
        else:
            risk_class, confidence, importances = cls._deterministic_fallback(features)

        # Calculate XAI feature contributions
        top_risk_contributors = []
        top_protective_factors = []

        # Baseline optimal reference values
        optimal_values = {
            "tls_version_ord": 4.0,       # TLS 1.3
            "cipher_strength_ord": 4.0,   # State of the art
            "security_mode_ord": 4.0,     # Direct TLS / Accepted
            "has_forward_secrecy": 1.0,   # PFS Verified
            "has_post_quantum": 1.0,      # PQ Ready
            "has_plaintext_exposure": 0.0,# No plaintext
            "capture_confidence": 1.0,    # High confidence
            "capture_health": 1.0,        # Pristine stream
        }

        for feat_name, val in features.items():
            imp = importances.get(feat_name, 0.125)
            optimal = optimal_values.get(feat_name, 1.0)
            desc = FEATURE_DESCRIPTIONS.get(feat_name, feat_name)

            if feat_name == "has_plaintext_exposure":
                delta = val - optimal
            else:
                delta = optimal - val

            impact = round(float(delta * imp * 100), 2)

            if impact > 0.05:
                top_risk_contributors.append({
                    "feature": feat_name,
                    "description": desc,
                    "value": val,
                    "contribution": impact,
                })
            else:
                top_protective_factors.append({
                    "feature": feat_name,
                    "description": desc,
                    "value": val,
                    "contribution": abs(impact),
                })

        # Sort by contribution
        top_risk_contributors.sort(key=lambda x: x["contribution"], reverse=True)
        top_protective_factors.sort(key=lambda x: x["contribution"], reverse=True)

        return {
            "advisory_risk_class": risk_class,
            "model_confidence": round(confidence, 3),
            "model_version": cls._metadata.get("model_version", "v1.0.0") if cls._metadata else "fallback-v1",
            "model_type": cls._metadata.get("model_type", "RuleBasedFallback") if cls._metadata else "RuleBasedFallback",
            "disclaimer": "Experimental ML triage model — not production calibrated. Deterministic forensic findings remain authoritative.",
            "features": features,
            "top_risk_contributors": top_risk_contributors,
            "top_protective_factors": top_protective_factors,
        }

    @classmethod
    def _deterministic_fallback(cls, features: Dict[str, float]):
        if features.get("has_plaintext_exposure", 0) > 0.5 or features.get("security_mode_ord", 0) == 0.0:
            return "CRITICAL", 0.95, {}
        if features.get("tls_version_ord", 0) in [1.0, 2.0] or features.get("has_forward_secrecy", 0) == 0.0:
            return "HIGH", 0.90, {}
        if features.get("has_post_quantum", 0) == 0.0:
            return "MEDIUM", 0.85, {}
        return "LOW", 0.95, {}

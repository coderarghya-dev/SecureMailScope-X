"""
SecureMailScope X - ML-Assisted Risk Classifier & XAI Explainability Engine
Advisory risk classification and feature attribution. Deterministic forensic rules remain authoritative.
"""

import os
import json
from typing import Dict, Any, List, Optional, Tuple
import joblib
import numpy as np

from app.schemas.forensic import EmailSession
from app.ml.feature_extractor import MLFeatureExtractor, FEATURE_NAMES


MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_METADATA_FILE = os.path.join(MODEL_DIR, "risk_model_v1.json")
MODEL_JOBLIB_FILE = os.path.join(MODEL_DIR, "risk_model_v1.joblib")

CLASS_NAMES_MAP = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}

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

OPTIMAL_REFERENCE_VALUES = {
    "tls_version_ord": 4.0,        # TLS 1.3
    "cipher_strength_ord": 4.0,    # State-of-the-Art AEAD
    "security_mode_ord": 4.0,      # Direct TLS / Accepted STARTTLS
    "has_forward_secrecy": 1.0,    # PFS Verified
    "has_post_quantum": 1.0,       # PQ Hybrid Verified
    "has_plaintext_exposure": 0.0, # Zero cleartext exposure
    "capture_confidence": 1.0,     # Full observability (100%)
    "capture_health": 1.0,         # Pristine TCP stream (100%)
}


class MLRiskClassifier:
    """Provides advisory risk classification with local perturbation feature attribution."""

    _model = None
    _metadata = None

    @classmethod
    def _load_model_if_needed(cls) -> bool:
        if cls._model is None and os.path.exists(MODEL_JOBLIB_FILE):
            try:
                loaded = joblib.load(MODEL_JOBLIB_FILE)
                cls._model = loaded
            except Exception:
                cls._model = None

        if cls._metadata is None and os.path.exists(MODEL_METADATA_FILE):
            try:
                with open(MODEL_METADATA_FILE, "r", encoding="utf-8") as f:
                    cls._metadata = json.load(f)
            except Exception:
                cls._metadata = None

        # Validate feature order integrity
        if cls._metadata:
            stored_features = cls._metadata.get("feature_names", [])
            if stored_features != FEATURE_NAMES:
                cls._model = None
                return False

        return cls._model is not None

    @classmethod
    def classify_session(cls, session: EmailSession) -> Dict[str, Any]:
        has_ml = cls._load_model_if_needed()
        features = MLFeatureExtractor.extract_features(session)
        feature_vec = MLFeatureExtractor.to_vector(features)

        if has_ml and cls._model is not None:
            try:
                probs = cls._model.predict_proba([feature_vec])[0]
                best_idx = int(np.argmax(probs))
                pred_label = int(cls._model.classes_[best_idx])
                risk_class = CLASS_NAMES_MAP.get(pred_label, "MEDIUM")
                risk_prob = float(probs[best_idx])

                class_probs = {
                    CLASS_NAMES_MAP.get(int(c), str(c)): round(float(p), 4)
                    for c, p in zip(cls._model.classes_, probs)
                }

                # Local Explainability: One-Feature Counterfactual Perturbation
                top_risk, top_prot = cls._compute_perturbation_explanation(
                    feature_vec, features, best_idx, risk_prob
                )

                return {
                    "enabled": True,
                    "inference_mode": "ML_MODEL",
                    "model_status": "EXPERIMENTAL_ENGINEERING_MODEL",
                    "advisory_risk_class": risk_class,
                    "risk_probability": round(risk_prob, 4),
                    "class_probabilities": class_probs,
                    "model_version": cls._metadata.get("model_version", "v1.0.0") if cls._metadata else "v1.0.0",
                    "model_type": "RandomForestClassifier",
                    "authoritative": False,
                    "disclaimer": "Experimental ML triage model — not production calibrated. Deterministic forensic findings remain authoritative.",
                    "explanation_method": "ONE_FEATURE_PERTURBATION",
                    "explanation_disclaimer": "Local feature sensitivity computed via single-feature counterfactual perturbation against optimal security baselines. Not Shapley / SHAP causal attribution.",
                    "feature_vector": features,
                    "top_risk_contributors": top_risk,
                    "top_protective_factors": top_prot,
                    # Legacy compatibility
                    "model_confidence": round(risk_prob, 4),
                    "features": features,
                }
            except Exception:
                return cls._deterministic_fallback_response(features)
        else:
            return cls._deterministic_fallback_response(features)

    @classmethod
    def _compute_perturbation_explanation(
        cls,
        feature_vec: List[float],
        features: Dict[str, float],
        best_idx: int,
        orig_prob: float
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Computes true local feature sensitivity by single-feature counterfactual perturbation."""
        top_risk_contributors = []
        top_protective_factors = []

        for idx, feat_name in enumerate(FEATURE_NAMES):
            ref_val = OPTIMAL_REFERENCE_VALUES.get(feat_name, 1.0)
            obs_val = feature_vec[idx]
            desc = FEATURE_DESCRIPTIONS.get(feat_name, feat_name)

            if abs(obs_val - ref_val) < 1e-4:
                # Feature is already at optimal baseline; acts as protective factor
                top_protective_factors.append({
                    "feature": feat_name,
                    "description": desc,
                    "value": obs_val,
                    "reference_value": ref_val,
                    "probability_impact": 0.0,
                    "contribution": 0.0,
                })
                continue

            # Perturb single feature to reference value
            perturbed_vec = list(feature_vec)
            perturbed_vec[idx] = ref_val

            try:
                pert_probs = cls._model.predict_proba([perturbed_vec])[0]
                pert_prob = float(pert_probs[best_idx])
                delta_prob = round(float(orig_prob - pert_prob), 4)
            except Exception:
                delta_prob = 0.0

            item = {
                "feature": feat_name,
                "description": desc,
                "value": obs_val,
                "reference_value": ref_val,
                "probability_impact": delta_prob,
                "contribution": round(abs(delta_prob) * 100, 2),
            }

            if delta_prob > 0.01:
                top_risk_contributors.append(item)
            else:
                top_protective_factors.append(item)

        top_risk_contributors.sort(key=lambda x: x["contribution"], reverse=True)
        top_protective_factors.sort(key=lambda x: x["contribution"], reverse=True)
        return top_risk_contributors, top_protective_factors

    @classmethod
    def _deterministic_fallback_response(cls, features: Dict[str, float]) -> Dict[str, Any]:
        """Graceful fallback when ML model artifact is unavailable."""
        if features.get("has_plaintext_exposure", 0) > 0.5 or features.get("security_mode_ord", 0) == 0.0:
            risk_class = "CRITICAL"
        elif features.get("tls_version_ord", 0) in [1.0, 2.0] or features.get("has_forward_secrecy", 0) == 0.0:
            risk_class = "HIGH"
        elif features.get("has_post_quantum", 0) == 0.0:
            risk_class = "MEDIUM"
        else:
            risk_class = "LOW"

        top_risk = []
        top_prot = []
        for feat_name, val in features.items():
            ref = OPTIMAL_REFERENCE_VALUES.get(feat_name, 1.0)
            desc = FEATURE_DESCRIPTIONS.get(feat_name, feat_name)
            if abs(val - ref) > 1e-4:
                top_risk.append({"feature": feat_name, "description": desc, "value": val, "contribution": 10.0})
            else:
                top_prot.append({"feature": feat_name, "description": desc, "value": val, "contribution": 0.0})

        return {
            "enabled": True,
            "inference_mode": "DETERMINISTIC_FALLBACK",
            "model_status": "EXPERIMENTAL_ENGINEERING_MODEL",
            "advisory_risk_class": risk_class,
            "risk_probability": 0.5,
            "class_probabilities": {risk_class: 1.0},
            "model_version": "fallback-v1",
            "model_type": "RuleBasedFallback",
            "authoritative": False,
            "disclaimer": "Fallback rule-based triage — ML model artifact unavailable. Deterministic forensic findings remain authoritative.",
            "explanation_method": "DETERMINISTIC_FALLBACK_RULES",
            "explanation_disclaimer": "Heuristic fallback rules based on deterministic security state.",
            "feature_vector": features,
            "top_risk_contributors": top_risk,
            "top_protective_factors": top_prot,
            "model_confidence": 0.5,
            "features": features,
        }

"""
SecureMailScope X - Offline ML Model Training Script
Generates a controlled synthetic training dataset strictly for engineering validation of the triage pipeline.
Metadata explicitly marks: 'Experimental ML triage model — not production calibrated'.
"""

import json
import os
from typing import Dict, Any, List
from sklearn.ensemble import RandomForestClassifier
import joblib

from app.ml.feature_extractor import FEATURE_NAMES


MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_METADATA_FILE = os.path.join(MODEL_DIR, "risk_model_v1.json")
MODEL_JOBLIB_FILE = os.path.join(MODEL_DIR, "risk_model_v1.joblib")


# Controlled validation dataset across known security patterns
SYNTHETIC_DATASET = [
    # [tls_ver, cipher_strength, sec_mode, pfs, pqc, plaintext, conf, health] -> Label: 0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL
    # Critical: Plaintext sessions
    ([ -1.0, -1.0, 0.0, 0.0, 0.5, 1.0, 1.0, 1.0 ], 3),
    ([ -1.0, -1.0, 1.0, 0.0, 0.5, 1.0, 0.9, 0.9 ], 3),
    ([  0.0,  0.0, 3.0, 0.0, 0.0, 0.0, 0.9, 0.9 ], 3), # SSLv3 / Insecure cipher

    # High: Deprecated TLS 1.0/1.1 or No PFS (static RSA)
    ([  1.0,  1.0, 3.0, 0.0, 0.0, 0.0, 0.95, 0.95 ], 2), # TLS 1.0
    ([  2.0,  1.0, 3.0, 0.0, 0.0, 0.0, 0.95, 0.95 ], 2), # TLS 1.1
    ([  3.0,  2.0, 3.0, 0.0, 0.0, 0.0, 0.95, 0.95 ], 2), # TLS 1.2 Static RSA (No PFS)
    ([  3.0,  1.0, 3.0, 1.0, 0.0, 0.0, 0.95, 0.95 ], 2), # TLS 1.2 Deprecated Cipher

    # Medium: TLS 1.2 with PFS, or TLS 1.3 Classical (HNDL exposure)
    ([  3.0,  3.0, 3.0, 1.0, 0.0, 0.0, 0.95, 0.95 ], 1), # TLS 1.2 Modern ECDHE-GCM
    ([  4.0,  4.0, 3.0, 1.0, 0.0, 0.0, 0.95, 0.95 ], 1), # TLS 1.3 Classical (no PQC)
    ([  4.0,  4.0, 4.0, 1.0, 0.0, 0.0, 0.95, 0.95 ], 1), # TLS 1.3 Direct TLS Classical

    # Low: TLS 1.3 with PFS and Post-Quantum hybrid protection
    ([  4.0,  4.0, 3.0, 1.0, 1.0, 0.0, 0.95, 0.95 ], 0), # TLS 1.3 STARTTLS + PQC
    ([  4.0,  4.0, 4.0, 1.0, 1.0, 0.0, 1.0, 1.0 ], 0),   # TLS 1.3 Direct TLS + PQC
]


def train_and_save_model():
    os.makedirs(MODEL_DIR, exist_ok=True)
    X = [sample[0] for sample in SYNTHETIC_DATASET]
    y = [sample[1] for sample in SYNTHETIC_DATASET]

    clf = RandomForestClassifier(n_estimators=20, max_depth=4, random_state=42)
    clf.fit(X, y)

    # Save joblib binary
    joblib.dump(clf, MODEL_JOBLIB_FILE)

    # Export metadata and feature importances
    metadata: Dict[str, Any] = {
        "model_version": "v1.0.0",
        "model_type": "RandomForestClassifier",
        "description": "Experimental ML triage model — not production calibrated",
        "dataset_type": "Synthetic validation dataset for engineering testing",
        "feature_names": FEATURE_NAMES,
        "classes": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "feature_importances": dict(zip(FEATURE_NAMES, clf.feature_importances_.tolist())),
        "training_samples_count": len(X),
    }

    with open(MODEL_METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Model trained and saved successfully to {MODEL_DIR}")


if __name__ == "__main__":
    train_and_save_model()

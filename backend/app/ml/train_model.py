"""
SecureMailScope X - Offline ML Model Training Script
Generates a controlled synthetic training dataset strictly for engineering validation of the triage pipeline.
Metadata explicitly marks: 'Synthetic validation dataset for engineering testing only — not real-world generalization data'.
"""

import json
import os
import sys
from typing import Dict, Any, List

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from sklearn.ensemble import RandomForestClassifier
import joblib

from app.ml.feature_extractor import FEATURE_NAMES


MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_METADATA_FILE = os.path.join(MODEL_DIR, "risk_model_v1.json")
MODEL_JOBLIB_FILE = os.path.join(MODEL_DIR, "risk_model_v1.joblib")


# Controlled validation dataset: 24 distinct engineering fixtures
# Features: [tls_ver, cipher_strength, sec_mode, pfs, pqc, plaintext, conf, health]
# Labels: 0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL
SYNTHETIC_DATASET = [
    # -----------------------------------------------------------------------
    # CRITICAL (Class 3): Plaintext exposure, SSLv2/SSLv3, downgrade attacks
    # -----------------------------------------------------------------------
    ([ -1.0, -1.0, 0.0, 0.0, 0.5, 1.0, 1.0, 1.0 ], 3),  # Plaintext SMTP stream
    ([ -1.0, -1.0, 1.0, 0.0, 0.5, 1.0, 0.9, 0.9 ], 3),  # STARTTLS Failed with cleartext fallback
    ([  0.0,  0.0, 3.0, 0.0, 0.0, 0.0, 0.9, 0.9 ], 3),  # SSLv3 Insecure cipher
    ([  0.0,  0.0, 4.0, 0.0, 0.0, 0.0, 0.8, 0.8 ], 3),  # SSLv2 Direct TLS
    ([ -1.0, -1.0, 2.0, 0.0, 0.5, 1.0, 0.9, 0.9 ], 3),  # STARTTLS advertised but plaintext used
    ([ -1.0, -1.0, 0.0, 0.0, 0.5, 1.0, 0.5, 0.5 ], 3),  # Plaintext with degraded stream

    # -----------------------------------------------------------------------
    # HIGH (Class 2): Deprecated TLS (1.0/1.1), Static RSA without PFS, Weak ciphers
    # -----------------------------------------------------------------------
    ([  1.0,  1.0, 3.0, 0.0, 0.0, 0.0, 0.95, 0.95 ], 2), # TLS 1.0 Deprecated
    ([  2.0,  1.0, 3.0, 0.0, 0.0, 0.0, 0.95, 0.95 ], 2), # TLS 1.1 Deprecated
    ([  3.0,  2.0, 3.0, 0.0, 0.0, 0.0, 0.95, 0.95 ], 2), # TLS 1.2 Static RSA (No PFS)
    ([  3.0,  1.0, 3.0, 1.0, 0.0, 0.0, 0.95, 0.95 ], 2), # TLS 1.2 3DES Cipher
    ([  1.0,  2.0, 4.0, 0.0, 0.0, 0.0, 0.90, 0.90 ], 2), # TLS 1.0 Direct TLS
    ([  3.0,  0.0, 3.0, 0.0, 0.0, 0.0, 0.85, 0.85 ], 2), # TLS 1.2 NULL/Insecure cipher

    # -----------------------------------------------------------------------
    # MEDIUM (Class 1): TLS 1.2 with PFS, TLS 1.3 Classical (HNDL exposure)
    # -----------------------------------------------------------------------
    ([  3.0,  3.0, 3.0, 1.0, 0.0, 0.0, 0.95, 0.95 ], 1), # TLS 1.2 Modern ECDHE-GCM
    ([  4.0,  4.0, 3.0, 1.0, 0.0, 0.0, 0.95, 0.95 ], 1), # TLS 1.3 Classical (no PQC)
    ([  4.0,  4.0, 4.0, 1.0, 0.0, 0.0, 0.95, 0.95 ], 1), # TLS 1.3 Direct TLS Classical
    ([  4.0,  4.0, 3.0, 0.5, 0.5, 0.0, 0.80, 1.00 ], 1), # TLS 1.3 Unobserved key-share
    ([  3.0,  3.0, 4.0, 1.0, 0.0, 0.0, 0.90, 0.90 ], 1), # TLS 1.2 IMAP Direct TLS ECDHE
    ([  4.0,  4.0, 3.0, 0.5, 0.0, 0.0, 0.85, 0.90 ], 1), # TLS 1.3 Missing key_share Classical

    # -----------------------------------------------------------------------
    # LOW (Class 0): State-of-the-Art TLS 1.3 + PFS + Post-Quantum Hybrid KEM
    # -----------------------------------------------------------------------
    ([  4.0,  4.0, 3.0, 1.0, 1.0, 0.0, 0.95, 0.95 ], 0), # TLS 1.3 STARTTLS + PQC Hybrid
    ([  4.0,  4.0, 4.0, 1.0, 1.0, 0.0, 1.00, 1.00 ], 0), # TLS 1.3 Direct TLS + ML-KEM
    ([  4.0,  4.0, 4.0, 1.0, 1.0, 0.0, 0.95, 0.95 ], 0), # TLS 1.3 IMAP Direct TLS + PQC
    ([  4.0,  4.0, 3.0, 1.0, 1.0, 0.0, 1.00, 1.00 ], 0), # TLS 1.3 POP3 STLS + PQC
    ([  4.0,  4.0, 4.0, 1.0, 1.0, 0.0, 0.90, 1.00 ], 0), # TLS 1.3 POP3S Direct TLS + PQC
    ([  4.0,  4.0, 3.0, 1.0, 1.0, 0.0, 0.90, 0.95 ], 0), # TLS 1.3 SMTP + SecP256r1MLKEM768
]


def train_and_save_model():
    os.makedirs(MODEL_DIR, exist_ok=True)
    X = [sample[0] for sample in SYNTHETIC_DATASET]
    y = [sample[1] for sample in SYNTHETIC_DATASET]

    clf = RandomForestClassifier(n_estimators=20, max_depth=4, random_state=42)
    clf.fit(X, y)

    # Save joblib binary
    joblib.dump(clf, MODEL_JOBLIB_FILE)

    # Count class distribution
    class_counts = {0: 0, 1: 0, 2: 0, 3: 0}
    for label in y:
        class_counts[label] += 1

    class_names_map = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}

    metadata: Dict[str, Any] = {
        "model_version": "v1.0.0",
        "model_type": "RandomForestClassifier",
        "random_state": 42,
        "dataset_version": "synthetic-engineering-v1.0",
        "dataset_type": "Synthetic validation dataset for engineering testing only — not real-world generalization data",
        "evaluation_metrics_disclaimer": "Engineering self-check only — not generalization performance",
        "feature_names": FEATURE_NAMES,
        "classes": [class_names_map[c] for c in clf.classes_],
        "class_mapping": {str(c): class_names_map[c] for c in clf.classes_},
        "class_distribution": {class_names_map[k]: v for k, v in class_counts.items()},
        "feature_importances": dict(zip(FEATURE_NAMES, clf.feature_importances_.tolist())),
        "training_samples_count": len(X),
    }

    with open(MODEL_METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Model trained and saved successfully to {MODEL_DIR}")
    print(f"    Classes: {clf.classes_} -> {[class_names_map[c] for c in clf.classes_]}")
    print(f"    Samples: {len(X)} | Distribution: {metadata['class_distribution']}")


if __name__ == "__main__":
    train_and_save_model()

"""
Training pipeline for anomaly detection and intrusion classification.

Run:
    python -m ml.train

Produces:
    ml/artifacts/anomaly_detector.joblib
    ml/artifacts/intrusion_classifier.joblib
    ml/artifacts/metadata.json

Also registers both models in the MLModel table.
"""

from __future__ import annotations

import json
import os
import sys
import django

# --- Django bootstrap so we can run this as a standalone script -----------
if not os.environ.get("DJANGO_SETTINGS_MODULE"):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    django.setup()

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score, f1_score,
)
from sklearn.model_selection import train_test_split

from security.models import LogEntry, MLModel
from ml.features import logs_to_dataframe, build_feature_matrix

ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Supervised label heuristic
# ---------------------------------------------------------------------------
def pseudo_label(df):
    """
    Turn raw log rows into supervised labels for the classifier.

    We use a rule-based heuristic rather than human labels since we don't have
    ground truth. The label reflects "suspicious behavior" derived from
    event_type + port + hour.
    """
    labels = np.zeros(len(df), dtype=int)

    suspicious_events = {
        "login_failed", "port_scan", "malware_detected",
        "privilege_escalation", "data_transfer",
    }
    labels |= df["event_type"].isin(suspicious_events).astype(int).values

    # High, non-standard ports at odd hours are suspicious
    odd_hours = ((df["hour"] < 6) | (df["hour"] > 22)).astype(int).values
    labels |= (odd_hours & (df["port"] > 40000).values)

    return labels


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train():
    print("Loading logs from database...")
    logs = LogEntry.objects.all()
    print(f"  {logs.count()} log entries")

    df = logs_to_dataframe(logs)
    if df.empty:
        print("No logs to train on. Run `python manage.py seed_data` first.")
        sys.exit(1)

    X = build_feature_matrix(df)
    print(f"Feature matrix: {X.shape[0]} rows × {X.shape[1]} columns")

    # ------------------------------------------------------------------
    # 1. IsolationForest — unsupervised anomaly detection
    # ------------------------------------------------------------------
    print("\nTraining IsolationForest (anomaly detector)...")
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.1,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X)
    anomaly_flags = (iso.predict(X) == -1).astype(int)
    print(f"  Flagged anomalies: {anomaly_flags.sum()} / {len(anomaly_flags)}")

    # ------------------------------------------------------------------
    # 2. RandomForestClassifier — supervised intrusion classifier
    # ------------------------------------------------------------------
    print("\nBuilding pseudo-labels for classifier...")
    y = pseudo_label(df)
    print(f"  Positive class rate: {y.mean():.2%}")

    if y.sum() < 5:
        print("Not enough positive samples. Increase --logs in seed_data.")
        sys.exit(1)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y,
    )

    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, zero_division=0)

    print(f"\nClassifier accuracy: {acc:.3f}")
    print(f"Classifier F1:       {f1:.3f}")
    print(f"Confusion matrix:    {cm}")
    print("\nClassification report:\n" + report)

    # ------------------------------------------------------------------
    # 3. Save artifacts
    # ------------------------------------------------------------------
    print("Saving artifacts...")
    iso_path = ARTIFACT_DIR / "anomaly_detector.joblib"
    clf_path = ARTIFACT_DIR / "intrusion_classifier.joblib"

    joblib.dump(iso, iso_path)
    joblib.dump(clf, clf_path)

    metadata = {
        "n_samples": int(X.shape[0]),
        "n_features": int(X.shape[1]),
        "feature_names": list(X.columns),
        "anomaly_rate": float(anomaly_flags.mean()),
        "classifier": {
            "accuracy": float(acc),
            "f1": float(f1),
            "confusion_matrix": cm,
            "positive_rate": float(y.mean()),
        },
    }
    meta_path = ARTIFACT_DIR / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"  → {iso_path}")
    print(f"  → {clf_path}")
    print(f"  → {meta_path}")

    # ------------------------------------------------------------------
    # 4. Register in the database (idempotent)
    # ------------------------------------------------------------------
    print("\nRegistering models in the database...")
    MLModel.objects.update_or_create(
        name="anomaly_detector",
        defaults={
            "version": "1.0.0",
            "algorithm": "IsolationForest",
            "description": "Unsupervised anomaly detector for security logs.",
            "file_path": str(iso_path),
            "metrics": {"anomaly_rate": float(anomaly_flags.mean())},
            "is_active": True,
        },
    )
    MLModel.objects.update_or_create(
        name="intrusion_classifier",
        defaults={
            "version": "1.0.0",
            "algorithm": "RandomForestClassifier",
            "description": "Supervised classifier for suspicious log activity.",
            "file_path": str(clf_path),
            "metrics": {"accuracy": float(acc), "f1": float(f1)},
            "is_active": True,
        },
    )
    print("  Registered: anomaly_detector, intrusion_classifier")

    print("\nDone.")


if __name__ == "__main__":
    train()
"""
Inference helpers. Called by the API to score new LogEntry rows.
"""

from __future__ import annotations

import os
from pathlib import Path

import joblib
import pandas as pd

from ml.features import logs_to_dataframe, build_feature_matrix

ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"


class ModelRegistry:
    """Lazy loader so we don't hit disk on every request."""

    _cache: dict = {}

    @classmethod
    def get(cls, name: str):
        if name not in cls._cache:
            path = ARTIFACT_DIR / f"{name}.joblib"
            if not path.exists():
                raise FileNotFoundError(
                    f"Model artifact not found: {path}. "
                    f"Run `python -m ml.train` first."
                )
            cls._cache[name] = joblib.load(path)
        return cls._cache[name]

    @classmethod
    def clear(cls):
        cls._cache.clear()


def score_logs(logs) -> list[dict]:
    """
    Run both models on a list of LogEntry objects.
    Returns a list of dicts (one per log) with labels and scores.
    """
    df = logs_to_dataframe(logs)
    if df.empty:
        return []

    X = build_feature_matrix(df)

    iso = ModelRegistry.get("anomaly_detector")
    clf = ModelRegistry.get("intrusion_classifier")

    anomaly_flags = iso.predict(X)          # -1 or 1
    anomaly_scores = iso.decision_function(X)  # lower = more anomalous

    clf_labels = clf.predict(X)             # 0 or 1
    clf_probas = clf.predict_proba(X)[:, 1] if clf.classes_.size > 1 else [0.0] * len(X)

    results = []
    for i, log in enumerate(logs):
        is_anomaly = bool(anomaly_flags[i] == -1)
        is_suspicious = bool(clf_labels[i] == 1)
        results.append({
            "log_id": log.id,
            "is_anomaly": is_anomaly,
            "anomaly_score": float(anomaly_scores[i]),
            "is_suspicious": is_suspicious,
            "suspicion_probability": float(clf_probas[i]),
        })
    return results
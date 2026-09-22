"""
Feature engineering for LogEntry records.

Used by both the training pipeline (ml/train.py) and inference (ml/predict.py).
Keeping a single source of truth avoids train/serve skew.
"""

from __future__ import annotations

from typing import Iterable

import numpy as np
import pandas as pd

# Canonical list of event types we one-hot encode.
# Order matters — this list must not change without retraining the model.
EVENT_TYPES = [
    "login_failed", "login_success", "port_scan",
    "malware_detected", "firewall_block", "dns_query",
    "file_access", "privilege_escalation", "data_transfer",
]

# Canonical list of log sources we one-hot encode.
LOG_SOURCES = [
    "FIREWALL", "IDS", "ENDPOINT", "SERVER",
    "AUTH", "APPLICATION", "NETWORK", "OTHER",
]


def logs_to_dataframe(logs: Iterable) -> pd.DataFrame:
    """
    Convert an iterable of LogEntry (Django) objects into a DataFrame.
    Accepts any iterable, including QuerySets.
    """
    rows = []
    for log in logs:
        payload = log.raw_payload or {}
        rows.append({
            "source": log.source,
            "event_type": log.event_type,
            "hour": log.timestamp.hour if log.timestamp else 0,
            "day_of_week": log.timestamp.weekday() if log.timestamp else 0,
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "bytes": int(payload.get("bytes", 0) or 0),
            "port": int(payload.get("port", 0) or 0),
            "protocol": payload.get("protocol", "TCP"),
        })
    return pd.DataFrame(rows)


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """
    Produce a numeric feature matrix from the raw log DataFrame.
    """
    if df.empty:
        return pd.DataFrame(columns=_feature_columns())

    out = pd.DataFrame(index=df.index)

    # Numeric features
    out["hour"] = df["hour"].astype(int)
    out["day_of_week"] = df["day_of_week"].astype(int)
    out["bytes"] = df["bytes"].astype(float)
    out["log_bytes"] = np.log1p(out["bytes"])
    out["port"] = df["port"].astype(int)
    out["is_privileged_port"] = (out["port"] < 1024).astype(int)
    out["is_high_port"] = (out["port"] > 49152).astype(int)

    # One-hot: event_type
    for et in EVENT_TYPES:
        out[f"event_type_{et}"] = (df["event_type"] == et).astype(int)

    # One-hot: source
    for src in LOG_SOURCES:
        out[f"source_{src}"] = (df["source"] == src).astype(int)

    # Protocol
    for proto in ["TCP", "UDP", "ICMP", "HTTPS"]:
        out[f"proto_{proto}"] = (df["protocol"] == proto).astype(int)

    return out


def _feature_columns() -> list[str]:
    cols = [
        "hour", "day_of_week", "bytes", "log_bytes", "port",
        "is_privileged_port", "is_high_port",
    ]
    cols += [f"event_type_{et}" for et in EVENT_TYPES]
    cols += [f"source_{src}" for src in LOG_SOURCES]
    cols += [f"proto_{p}" for p in ["TCP", "UDP", "ICMP", "HTTPS"]]
    return cols
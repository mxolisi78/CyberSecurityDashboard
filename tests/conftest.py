"""
Pytest fixtures for the CyberSecurityDashboard test suite.
"""

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from security.models import (
    Asset, AssetType, AssetCriticality,
    Threat, ThreatCategory, Severity,
    Vulnerability,
    Incident, IncidentStatus,
    LogEntry, LogSource,
    MLModel,
    Prediction,
)

User = get_user_model()


# ---------------------------------------------------------------------------
# User fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def user(db):
    return User.objects.create_user(
        username="tester", password="testpass123"
    )


@pytest.fixture
def admin_user(db):
    return User.objects.create_superuser(
        username="admin", password="adminpass123", email="admin@example.com"
    )


# ---------------------------------------------------------------------------
# Domain model fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def asset(db):
    return Asset.objects.create(
        name="test-server-001",
        asset_type=AssetType.SERVER,
        criticality=AssetCriticality.HIGH,
        ip_address="10.0.0.1",
        hostname="test-server-001.local",
        owner="Alice",
    )


@pytest.fixture
def asset_factory(db):
    """Return a callable that creates additional Assets."""
    def make(**kwargs):
        defaults = {
            "asset_type": AssetType.WORKSTATION,
            "criticality": AssetCriticality.MEDIUM,
        }
        defaults.update(kwargs)
        if "name" not in defaults:
            import uuid
            defaults["name"] = f"asset-{uuid.uuid4().hex[:8]}"
        return Asset.objects.create(**defaults)
    return make


@pytest.fixture
def threat(db):
    return Threat.objects.create(
        name="TestMalware",
        category=ThreatCategory.MALWARE,
        severity=Severity.HIGH,
    )


@pytest.fixture
def vulnerability(db, asset):
    return Vulnerability.objects.create(
        cve_id="CVE-2024-99999",
        title="Test vulnerability",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        asset=asset,
    )


@pytest.fixture
def incident(db, asset, threat):
    return Incident.objects.create(
        title="Test incident",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        asset=asset,
        threat=threat,
    )


@pytest.fixture
def log_entry(db, asset):
    return LogEntry.objects.create(
        source=LogSource.FIREWALL,
        asset=asset,
        timestamp=timezone.now(),
        source_ip="192.168.1.10",
        destination_ip="10.0.0.1",
        event_type="port_scan",
        message="Port scan detected from 192.168.1.10",
        raw_payload={
            "bytes": 512, "port": 22, "protocol": "TCP", "user": "root",
        },
        is_processed=False,
    )


@pytest.fixture
def ml_model(db):
    return MLModel.objects.create(
        name="test-model",
        version="1.0.0",
        algorithm="RandomForestClassifier",
        file_path="ml/artifacts/test.joblib",
        metrics={"accuracy": 0.9},
        is_active=True,
    )


@pytest.fixture
def prediction(db, ml_model, log_entry):
    return Prediction.objects.create(
        model=ml_model,
        log_entry=log_entry,
        label="suspicious",
        score=0.87,
        is_anomaly=True,
    )


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------
@pytest.fixture
def api_client():
    from rest_framework.test import APIClient
    return APIClient()
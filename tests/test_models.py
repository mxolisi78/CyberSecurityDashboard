"""Tests for the security domain models."""

import pytest
from django.utils import timezone

from security.models import (
    Asset, Threat, Vulnerability, Incident, LogEntry, MLModel, Prediction,
    Severity, IncidentStatus,
)


pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------
class TestAsset:
    def test_str(self, asset):
        assert "test-server-001" in str(asset)
        assert "Server" in str(asset)

    def test_default_criticality_is_medium(self, asset_factory):
        a = asset_factory()
        assert a.criticality == "MEDIUM"

    def test_is_active_default_true(self, asset):
        assert asset.is_active is True

    def test_vulnerability_relationship(self, asset, vulnerability):
        assert asset.vulnerabilities.count() == 1
        assert asset.vulnerabilities.first() == vulnerability

    def test_incident_relationship(self, asset, incident):
        assert asset.incidents.count() == 1


# ---------------------------------------------------------------------------
# Threat
# ---------------------------------------------------------------------------
class TestThreat:
    def test_str(self, threat):
        assert str(threat) == "TestMalware"

    def test_default_category(self, db):
        t = Threat.objects.create(name="Generic")
        assert t.category == "OTHER"


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------
class TestVulnerability:
    def test_str(self, vulnerability):
        s = str(vulnerability)
        assert "CVE-2024-99999" in s
        assert "Test vulnerability" in s

    def test_default_unpatched(self, vulnerability):
        assert vulnerability.is_patched is False


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------
class TestIncident:
    def test_str_includes_severity(self, incident):
        assert "HIGH" in str(incident)

    def test_default_status_is_open(self, db, asset):
        i = Incident.objects.create(title="X", asset=asset)
        assert i.status == IncidentStatus.OPEN

    def test_can_be_resolved(self, incident):
        incident.status = IncidentStatus.RESOLVED
        incident.resolved_at = timezone.now()
        incident.save()
        incident.refresh_from_db()
        assert incident.resolved_at is not None


# ---------------------------------------------------------------------------
# LogEntry
# ---------------------------------------------------------------------------
class TestLogEntry:
    def test_str(self, log_entry):
        s = str(log_entry)
        assert "FIREWALL" in s
        assert "202" in s  # year prefix

    def test_default_unprocessed(self, log_entry):
        assert log_entry.is_processed is False

    def test_raw_payload_json(self, log_entry):
        assert log_entry.raw_payload["port"] == 22


# ---------------------------------------------------------------------------
# MLModel
# ---------------------------------------------------------------------------
class TestMLModel:
    def test_str_includes_version(self, ml_model):
        assert "test-model" in str(ml_model)
        assert "v1.0.0" in str(ml_model)

    def test_metrics_json(self, ml_model):
        assert ml_model.metrics["accuracy"] == 0.9


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------
class TestPrediction:
    def test_relationships(self, prediction, ml_model, log_entry):
        assert prediction.model == ml_model
        assert prediction.log_entry == log_entry

    def test_str(self, prediction):
        s = str(prediction)
        assert "test-model" in s
        assert "suspicious" in s
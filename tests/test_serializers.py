"""Tests for the DRF serializers."""

import pytest

from security.serializers import (
    AssetSerializer, ThreatSerializer, VulnerabilitySerializer,
    IncidentSerializer, LogEntrySerializer, MLModelSerializer,
    PredictionSerializer,
)


pytestmark = pytest.mark.django_db


class TestAssetSerializer:
    def test_exposes_computed_counts(self, asset, vulnerability, incident):
        data = AssetSerializer(asset).data
        assert data["vulnerability_count"] == 1
        assert data["incident_count"] == 1

    def test_read_only_fields(self, asset):
        data = AssetSerializer(asset).data
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data


class TestVulnerabilitySerializer:
    def test_includes_asset_name(self, vulnerability, asset):
        data = VulnerabilitySerializer(vulnerability).data
        assert data["asset_name"] == asset.name


class TestIncidentSerializer:
    def test_includes_related_names(self, incident, asset, threat):
        data = IncidentSerializer(incident).data
        assert data["asset_name"] == asset.name
        assert data["threat_name"] == threat.name


class TestLogEntrySerializer:
    def test_serializes_payload(self, log_entry):
        data = LogEntrySerializer(log_entry).data
        assert data["raw_payload"]["port"] == 22
        assert data["is_processed"] is False


class TestMLModelSerializer:
    def test_prediction_count(self, ml_model, prediction):
        data = MLModelSerializer(ml_model).data
        assert data["prediction_count"] == 1


class TestPredictionSerializer:
    def test_includes_model_name(self, prediction, ml_model):
        data = PredictionSerializer(prediction).data
        assert data["model_name"] == ml_model.name
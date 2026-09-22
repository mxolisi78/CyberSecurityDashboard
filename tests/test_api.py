"""Tests for the REST API endpoints."""

import pytest
from django.urls import reverse


pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Dashboard summary
# ---------------------------------------------------------------------------
class TestDashboardSummary:
    def test_summary_returns_all_sections(self, api_client):
        res = api_client.get("/api/dashboard/summary/")
        assert res.status_code == 200
        for key in [
            "assets", "threats", "vulnerabilities", "incidents",
            "logs", "ml_models", "predictions",
        ]:
            assert key in res.data

    def test_summary_counts(self, api_client, asset, incident, log_entry):
        res = api_client.get("/api/dashboard/summary/")
        assert res.data["assets"]["total"] == 1
        assert res.data["incidents"]["open"] == 1
        assert res.data["logs"]["unprocessed"] == 1


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------
class TestAssetAPI:
    def test_list(self, api_client, asset):
        res = api_client.get("/api/assets/")
        assert res.status_code == 200
        assert res.data["count"] == 1

    def test_detail(self, api_client, asset):
        res = api_client.get(f"/api/assets/{asset.id}/")
        assert res.status_code == 200
        assert res.data["name"] == asset.name

    def test_filter_by_criticality(self, api_client, asset, asset_factory):
        asset_factory(criticality="LOW")
        res = api_client.get("/api/assets/?criticality=HIGH")
        assert res.data["count"] == 1

    def test_search(self, api_client, asset):
        res = api_client.get("/api/assets/?search=test-server")
        assert res.data["count"] == 1


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
class TestIncidentAPI:
    def test_list_with_related_fields(self, api_client, incident, asset):
        res = api_client.get("/api/incidents/")
        assert res.status_code == 200
        assert res.data["results"][0]["asset_name"] == asset.name

    def test_filter_by_status(self, api_client, incident):
        res = api_client.get("/api/incidents/?status=OPEN")
        assert res.data["count"] == 1

    def test_filter_no_match(self, api_client, incident):
        res = api_client.get("/api/incidents/?status=CLOSED")
        assert res.data["count"] == 0


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------
class TestLogAPI:
    def test_list(self, api_client, log_entry):
        res = api_client.get("/api/logs/")
        assert res.data["count"] == 1

    def test_filter_unprocessed(self, api_client, log_entry):
        res = api_client.get("/api/logs/?is_processed=false")
        assert res.data["count"] == 1

    def test_filter_processed(self, api_client, log_entry):
        log_entry.is_processed = True
        log_entry.save()
        res = api_client.get("/api/logs/?is_processed=true")
        assert res.data["count"] == 1


# ---------------------------------------------------------------------------
# ML models
# ---------------------------------------------------------------------------
class TestMLModelAPI:
    def test_list(self, api_client, ml_model):
        res = api_client.get("/api/ml-models/")
        assert res.status_code == 200
        assert res.data["count"] == 1


# ---------------------------------------------------------------------------
# Predictions
# ---------------------------------------------------------------------------
class TestPredictionAPI:
    def test_filter_anomalies(self, api_client, prediction):
        res = api_client.get("/api/predictions/?is_anomaly=true")
        assert res.data["count"] == 1

    def test_filter_by_label(self, api_client, prediction):
        res = api_client.get("/api/predictions/?label=suspicious")
        assert res.data["count"] == 1
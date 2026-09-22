"""
DRF serializers for the security app.

Design notes
------------
- Read-only computed fields (e.g. counts) are exposed via SerializerMethodField.
- We use ModelSerializer to avoid duplicating field definitions.
- Related objects are exposed as IDs by default; nested read-only where useful.
"""

from rest_framework import serializers

from .models import (
    Asset,
    Threat,
    Vulnerability,
    Incident,
    LogEntry,
    MLModel,
    Prediction,
)


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------
class AssetSerializer(serializers.ModelSerializer):
    vulnerability_count = serializers.SerializerMethodField()
    incident_count = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = [
            "id", "name", "asset_type", "criticality",
            "ip_address", "hostname", "operating_system",
            "owner", "location", "description", "is_active",
            "vulnerability_count", "incident_count",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def get_vulnerability_count(self, obj):
        return obj.vulnerabilities.count()

    def get_incident_count(self, obj):
        return obj.incidents.count()


# ---------------------------------------------------------------------------
# Threat
# ---------------------------------------------------------------------------
class ThreatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Threat
        fields = [
            "id", "name", "category", "severity",
            "description", "indicators", "mitre_technique",
            "is_active", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------
class VulnerabilitySerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            "id", "cve_id", "title", "description", "severity",
            "cvss_score", "asset", "asset_name", "is_patched",
            "published_at", "discovered_at",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------
class IncidentSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    threat_name = serializers.CharField(source="threat.name", read_only=True)

    class Meta:
        model = Incident
        fields = [
            "id", "title", "description", "severity", "status",
            "asset", "asset_name", "threat", "threat_name",
            "detected_at", "resolved_at", "assigned_to",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


# ---------------------------------------------------------------------------
# LogEntry
# ---------------------------------------------------------------------------
class LogEntrySerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)

    class Meta:
        model = LogEntry
        fields = [
            "id", "source", "asset", "asset_name", "timestamp",
            "source_ip", "destination_ip", "event_type",
            "message", "raw_payload", "is_processed", "created_at",
        ]
        read_only_fields = ["id", "created_at"]


# ---------------------------------------------------------------------------
# MLModel
# ---------------------------------------------------------------------------
class MLModelSerializer(serializers.ModelSerializer):
    prediction_count = serializers.SerializerMethodField()

    class Meta:
        model = MLModel
        fields = [
            "id", "name", "version", "algorithm", "description",
            "file_path", "metrics", "is_active", "trained_at",
            "prediction_count", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def get_prediction_count(self, obj):
        return obj.predictions.count()


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------
class PredictionSerializer(serializers.ModelSerializer):
    model_name = serializers.CharField(source="model.name", read_only=True)

    class Meta:
        model = Prediction
        fields = [
            "id", "model", "model_name", "log_entry",
            "label", "score", "is_anomaly", "explanation", "created_at",
        ]
        read_only_fields = ["id", "created_at"]
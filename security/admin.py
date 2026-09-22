from django.contrib import admin

from .models import (
    Asset,
    Threat,
    Vulnerability,
    Incident,
    LogEntry,
    MLModel,
    Prediction,
)


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("name", "asset_type", "criticality", "ip_address", "is_active")
    list_filter = ("asset_type", "criticality", "is_active")
    search_fields = ("name", "hostname", "ip_address", "owner")


@admin.register(Threat)
class ThreatAdmin(admin.ModelAdmin):
    list_display = ("name", "category", "severity", "mitre_technique", "is_active")
    list_filter = ("category", "severity", "is_active")
    search_fields = ("name", "mitre_technique")


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "title", "severity", "cvss_score", "asset", "is_patched")
    list_filter = ("severity", "is_patched")
    search_fields = ("cve_id", "title")


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "status", "asset", "detected_at", "resolved_at")
    list_filter = ("severity", "status")
    search_fields = ("title", "description")
    date_hierarchy = "detected_at"


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ("source", "asset", "timestamp", "event_type", "is_processed")
    list_filter = ("source", "is_processed")
    search_fields = ("event_type", "message", "source_ip", "destination_ip")
    date_hierarchy = "timestamp"


@admin.register(MLModel)
class MLModelAdmin(admin.ModelAdmin):
    list_display = ("name", "version", "algorithm", "is_active", "trained_at")
    list_filter = ("is_active", "algorithm")
    search_fields = ("name", "algorithm")


@admin.register(Prediction)
class PredictionAdmin(admin.ModelAdmin):
    list_display = ("model", "log_entry", "label", "score", "is_anomaly", "created_at")
    list_filter = ("label", "is_anomaly", "model")
    search_fields = ("label",)
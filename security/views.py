"""
REST API views for the security app.

We use DRF ModelViewSets so each resource gets:
  GET    /api/<resource>/            list
  POST   /api/<resource>/            create
  GET    /api/<resource>/<id>/       retrieve
  PUT    /api/<resource>/<id>/       update
  PATCH  /api/<resource>/<id>/       partial update
  DELETE /api/<resource>/<id>/       destroy

Filtering is enabled via django-filter.
"""

from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import (
    Asset,
    Threat,
    Vulnerability,
    Incident,
    LogEntry,
    MLModel,
    Prediction,
)
from .serializers import (
    AssetSerializer,
    ThreatSerializer,
    VulnerabilitySerializer,
    IncidentSerializer,
    LogEntrySerializer,
    MLModelSerializer,
    PredictionSerializer,
)


# ---------------------------------------------------------------------------
# ViewSets
# ---------------------------------------------------------------------------
class AssetViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer
    filterset_fields = ["asset_type", "criticality", "is_active"]
    search_fields = ["name", "hostname", "ip_address", "owner"]
    ordering_fields = ["name", "criticality", "created_at"]


class ThreatViewSet(viewsets.ModelViewSet):
    queryset = Threat.objects.all()
    serializer_class = ThreatSerializer
    filterset_fields = ["category", "severity", "is_active"]
    search_fields = ["name", "mitre_technique"]
    ordering_fields = ["name", "severity", "created_at"]


class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.select_related("asset").all()
    serializer_class = VulnerabilitySerializer
    filterset_fields = ["severity", "is_patched", "asset"]
    search_fields = ["cve_id", "title"]
    ordering_fields = ["cvss_score", "discovered_at"]


class IncidentViewSet(viewsets.ModelViewSet):
    queryset = Incident.objects.select_related("asset", "threat").all()
    serializer_class = IncidentSerializer
    filterset_fields = ["severity", "status", "asset", "threat"]
    search_fields = ["title", "description", "assigned_to"]
    ordering_fields = ["detected_at", "severity"]


class LogEntryViewSet(viewsets.ModelViewSet):
    queryset = LogEntry.objects.select_related("asset").all()
    serializer_class = LogEntrySerializer
    filterset_fields = ["source", "is_processed", "asset"]
    search_fields = ["event_type", "message", "source_ip", "destination_ip"]
    ordering_fields = ["timestamp"]


class MLModelViewSet(viewsets.ModelViewSet):
    queryset = MLModel.objects.all()
    serializer_class = MLModelSerializer
    filterset_fields = ["is_active", "algorithm"]
    search_fields = ["name", "algorithm"]
    ordering_fields = ["created_at", "trained_at"]


class PredictionViewSet(viewsets.ModelViewSet):
    queryset = Prediction.objects.select_related("model", "log_entry").all()
    serializer_class = PredictionSerializer
    filterset_fields = ["label", "is_anomaly", "model"]
    search_fields = ["label"]
    ordering_fields = ["created_at", "score"]


# ---------------------------------------------------------------------------
# Dashboard stats (simple summary endpoint)
# ---------------------------------------------------------------------------
@api_view(["GET"])
def dashboard_summary(request):
    """
    Quick counts used by the dashboard home page.
    """
    return Response({
        "assets": {
            "total": Asset.objects.count(),
            "active": Asset.objects.filter(is_active=True).count(),
        },
        "threats": {
            "total": Threat.objects.count(),
            "active": Threat.objects.filter(is_active=True).count(),
        },
        "vulnerabilities": {
            "total": Vulnerability.objects.count(),
            "unpatched": Vulnerability.objects.filter(is_patched=False).count(),
            "critical": Vulnerability.objects.filter(severity="CRITICAL").count(),
        },
        "incidents": {
            "total": Incident.objects.count(),
            "open": Incident.objects.filter(status="OPEN").count(),
            "critical": Incident.objects.filter(severity="CRITICAL").count(),
        },
        "logs": {
            "total": LogEntry.objects.count(),
            "unprocessed": LogEntry.objects.filter(is_processed=False).count(),
        },
        "ml_models": {
            "total": MLModel.objects.count(),
            "active": MLModel.objects.filter(is_active=True).count(),
        },
        "predictions": {
            "total": Prediction.objects.count(),
            "anomalies": Prediction.objects.filter(is_anomaly=True).count(),
        },
    })

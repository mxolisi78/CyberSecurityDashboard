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

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.shortcuts import render

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

    # ------------------------------------------------------------------
    # POST /api/logs/{id}/predict/
    # ------------------------------------------------------------------
    @action(detail=True, methods=["post"])
    def predict(self, request, pk=None):
        """
        Score a single log entry with the ML pipeline and persist results
        as Prediction rows.
        """
        from ml.predict import score_logs
        from .models import MLModel, Prediction

        log = self.get_object()

        try:
            results = score_logs([log])
        except FileNotFoundError as exc:
            return Response(
                {"error": str(exc)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        if not results:
            return Response(
                {"error": "No features could be extracted from this log."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        r = results[0]

        anomaly_model = MLModel.objects.filter(
            name="anomaly_detector", is_active=True
        ).first()
        classifier_model = MLModel.objects.filter(
            name="intrusion_classifier", is_active=True
        ).first()

        created = []

        if anomaly_model:
            pred = Prediction.objects.create(
                model=anomaly_model,
                log_entry=log,
                label="anomaly" if r["is_anomaly"] else "normal",
                score=r["anomaly_score"],
                is_anomaly=r["is_anomaly"],
                explanation=f"Anomaly score: {r['anomaly_score']:.4f}",
            )
            created.append(PredictionSerializer(pred).data)

        if classifier_model:
            pred = Prediction.objects.create(
                model=classifier_model,
                log_entry=log,
                label="suspicious" if r["is_suspicious"] else "benign",
                score=r["suspicion_probability"],
                is_anomaly=r["is_suspicious"],
                explanation=(
                    f"Suspicion probability: {r['suspicion_probability']:.4f}"
                ),
            )
            created.append(PredictionSerializer(pred).data)

        # Mark the log as processed
        if not log.is_processed:
            log.is_processed = True
            log.save(update_fields=["is_processed"])

        return Response(
            {
                "log_id": log.id,
                "is_anomaly": r["is_anomaly"],
                "is_suspicious": r["is_suspicious"],
                "anomaly_score": r["anomaly_score"],
                "suspicion_probability": r["suspicion_probability"],
                "predictions": created,
            },
            status=status.HTTP_201_CREATED,
        )

    # ------------------------------------------------------------------
    # POST /api/logs/predict-batch/?limit=50
    # ------------------------------------------------------------------
    @action(detail=False, methods=["post"], url_path="predict-batch")
    def predict_batch(self, request):
        """
        Score up to `limit` unprocessed logs (default 50).
        """
        from ml.predict import score_logs
        from .models import MLModel, Prediction

        try:
            limit = int(request.query_params.get("limit", 50))
        except (TypeError, ValueError):
            limit = 50
        limit = max(1, min(limit, 500))

        logs = list(
            LogEntry.objects.filter(is_processed=False)
            .order_by("-timestamp")[:limit]
        )

        if not logs:
            return Response(
                {"message": "No unprocessed logs found.", "count": 0},
                status=status.HTTP_200_OK,
            )

        try:
            results = score_logs(logs)
        except FileNotFoundError as exc:
            return Response(
                {"error": str(exc)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        anomaly_model = MLModel.objects.filter(
            name="anomaly_detector", is_active=True
        ).first()
        classifier_model = MLModel.objects.filter(
            name="intrusion_classifier", is_active=True
        ).first()

        predictions_to_create = []
        processed_ids = []

        for log, r in zip(logs, results):
            if anomaly_model:
                predictions_to_create.append(Prediction(
                    model=anomaly_model,
                    log_entry=log,
                    label="anomaly" if r["is_anomaly"] else "normal",
                    score=r["anomaly_score"],
                    is_anomaly=r["is_anomaly"],
                    explanation=f"Anomaly score: {r['anomaly_score']:.4f}",
                ))
            if classifier_model:
                predictions_to_create.append(Prediction(
                    model=classifier_model,
                    log_entry=log,
                    label="suspicious" if r["is_suspicious"] else "benign",
                    score=r["suspicion_probability"],
                    is_anomaly=r["is_suspicious"],
                    explanation=(
                        f"Suspicion probability: "
                        f"{r['suspicion_probability']:.4f}"
                    ),
                ))
            processed_ids.append(log.id)

        Prediction.objects.bulk_create(predictions_to_create)
        LogEntry.objects.filter(id__in=processed_ids).update(is_processed=True)

        anomalies = sum(1 for r in results if r["is_anomaly"])
        suspicious = sum(1 for r in results if r["is_suspicious"])

        return Response({
            "processed": len(logs),
            "predictions_created": len(predictions_to_create),
            "anomalies_detected": anomalies,
            "suspicious_flagged": suspicious,
        }, status=status.HTTP_201_CREATED)


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

# ---------------------------------------------------------------------------
# Dashboard page views (server-rendered shells; data loaded via JS/API)
# ---------------------------------------------------------------------------
def dashboard_index(request):
    return render(request, "dashboard/index.html", {"active": "overview"})


def dashboard_logs(request):
    return render(request, "dashboard/logs.html", {"active": "logs"})


def dashboard_incidents(request):
    return render(request, "dashboard/incidents.html", {"active": "incidents"})
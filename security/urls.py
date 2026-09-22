from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AssetViewSet,
    ThreatViewSet,
    VulnerabilityViewSet,
    IncidentViewSet,
    LogEntryViewSet,
    MLModelViewSet,
    PredictionViewSet,
    dashboard_summary,
)

router = DefaultRouter()
router.register(r"assets", AssetViewSet, basename="asset")
router.register(r"threats", ThreatViewSet, basename="threat")
router.register(r"vulnerabilities", VulnerabilityViewSet, basename="vulnerability")
router.register(r"incidents", IncidentViewSet, basename="incident")
router.register(r"logs", LogEntryViewSet, basename="log")
router.register(r"ml-models", MLModelViewSet, basename="mlmodel")
router.register(r"predictions", PredictionViewSet, basename="prediction")

urlpatterns = [
    path("", include(router.urls)),
    path("dashboard/summary/", dashboard_summary, name="dashboard-summary"),
]
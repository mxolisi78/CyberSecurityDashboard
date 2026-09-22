from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path
from django.views.generic import TemplateView


def api_root(request):
    """Simple JSON root so / does not 404 during development."""
    return JsonResponse({
        "service": "CyberSecurityDashboard API",
        "version": "0.1.0",
        "endpoints": {
            "dashboard_ui": "/dashboard/",
            "api": "/api/",
            "dashboard_summary": "/api/dashboard/summary/",
            "assets": "/api/assets/",
            "threats": "/api/threats/",
            "vulnerabilities": "/api/vulnerabilities/",
            "incidents": "/api/incidents/",
            "logs": "/api/logs/",
            "ml_models": "/api/ml-models/",
            "predictions": "/api/predictions/",
            "admin": "/admin/",
        },
    })


urlpatterns = [
    path("", api_root, name="api-root"),
    path("admin/", admin.site.urls),
    path("api/", include("security.urls")),
    path("api-auth/", include("rest_framework.urls")),
    path("dashboard/", include("security.dashboard_urls")),
        path("robots.txt",
         TemplateView.as_view(template_name="robots.txt",
                              content_type="text/plain"),
         name="robots-txt"),
    path(".well-known/security.txt",
         TemplateView.as_view(template_name=".well-known/security.txt",
                              content_type="text/plain"),
         name="security-txt"),
]
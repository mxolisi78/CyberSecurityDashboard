from django.urls import path

from .views import dashboard_index, dashboard_logs, dashboard_incidents

urlpatterns = [
    path("", dashboard_index, name="dashboard-index"),
    path("logs/", dashboard_logs, name="dashboard-logs"),
    path("incidents/", dashboard_incidents, name="dashboard-incidents"),
]
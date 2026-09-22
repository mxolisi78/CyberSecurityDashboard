"""
Core domain models for the CyberSecurity Dashboard.

Design notes
------------
- All timestamps are timezone-aware (USE_TZ = True).
- Choice fields use TextChoices for readability and safety.
- ForeignKeys use on_delete=PROTECT where we never want silent data loss,
  and CASCADE where child records are meaningless without the parent.
- Indexes are added on fields we will filter/sort frequently.
"""

from django.db import models
from django.utils import timezone


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class Severity(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    CRITICAL = "CRITICAL", "Critical"


class AssetType(models.TextChoices):
    SERVER = "SERVER", "Server"
    WORKSTATION = "WORKSTATION", "Workstation"
    NETWORK_DEVICE = "NETWORK_DEVICE", "Network Device"
    DATABASE = "DATABASE", "Database"
    CLOUD = "CLOUD", "Cloud Resource"
    IOT = "IOT", "IoT Device"
    OTHER = "OTHER", "Other"


class AssetCriticality(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    MISSION_CRITICAL = "MISSION_CRITICAL", "Mission Critical"


class IncidentStatus(models.TextChoices):
    OPEN = "OPEN", "Open"
    INVESTIGATING = "INVESTIGATING", "Investigating"
    CONTAINED = "CONTAINED", "Contained"
    RESOLVED = "RESOLVED", "Resolved"
    CLOSED = "CLOSED", "Closed"
    FALSE_POSITIVE = "FALSE_POSITIVE", "False Positive"


class ThreatCategory(models.TextChoices):
    MALWARE = "MALWARE", "Malware"
    PHISHING = "PHISHING", "Phishing"
    RANSOMWARE = "RANSOMWARE", "Ransomware"
    DDOS = "DDOS", "DDoS"
    INSIDER = "INSIDER", "Insider Threat"
    APT = "APT", "Advanced Persistent Threat"
    VULNERABILITY_EXPLOIT = "VULN_EXPLOIT", "Vulnerability Exploit"
    OTHER = "OTHER", "Other"


class LogSource(models.TextChoices):
    FIREWALL = "FIREWALL", "Firewall"
    IDS = "IDS", "Intrusion Detection System"
    ENDPOINT = "ENDPOINT", "Endpoint"
    SERVER = "SERVER", "Server"
    AUTH = "AUTH", "Authentication"
    APPLICATION = "APPLICATION", "Application"
    NETWORK = "NETWORK", "Network"
    OTHER = "OTHER", "Other"


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------
class Asset(models.Model):
    """A system, device, or resource we are protecting."""

    name = models.CharField(max_length=255, unique=True)
    asset_type = models.CharField(
        max_length=32, choices=AssetType.choices, default=AssetType.OTHER
    )
    criticality = models.CharField(
        max_length=32, choices=AssetCriticality.choices, default=AssetCriticality.MEDIUM
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    operating_system = models.CharField(max_length=255, blank=True)
    owner = models.CharField(max_length=255, blank=True)
    location = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-criticality", "name"]
        indexes = [
            models.Index(fields=["asset_type"]),
            models.Index(fields=["criticality"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.get_asset_type_display()})"


# ---------------------------------------------------------------------------
# Threat
# ---------------------------------------------------------------------------
class Threat(models.Model):
    """A known threat: malware family, actor, technique, etc."""

    name = models.CharField(max_length=255, unique=True)
    category = models.CharField(
        max_length=32, choices=ThreatCategory.choices, default=ThreatCategory.OTHER
    )
    severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.MEDIUM
    )
    description = models.TextField(blank=True)
    indicators = models.TextField(
        blank=True, help_text="IOCs, signatures, or detection hints (free text)."
    )
    mitre_technique = models.CharField(max_length=64, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-severity", "name"]
        indexes = [
            models.Index(fields=["category"]),
            models.Index(fields=["severity"]),
        ]

    def __str__(self) -> str:
        return self.name


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------
class Vulnerability(models.Model):
    """A weakness (usually a CVE) that affects an asset."""

    cve_id = models.CharField(max_length=32, unique=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.MEDIUM
    )
    cvss_score = models.FloatField(null=True, blank=True)
    asset = models.ForeignKey(
        Asset,
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
    )
    is_patched = models.BooleanField(default=False)
    published_at = models.DateTimeField(null=True, blank=True)
    discovered_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-cvss_score", "-discovered_at"]
        indexes = [
            models.Index(fields=["severity"]),
            models.Index(fields=["is_patched"]),
        ]

    def __str__(self) -> str:
        return f"{self.cve_id} — {self.title}"


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------
class Incident(models.Model):
    """A security event that required response."""

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.MEDIUM
    )
    status = models.CharField(
        max_length=32, choices=IncidentStatus.choices, default=IncidentStatus.OPEN
    )
    asset = models.ForeignKey(
        Asset,
        on_delete=models.PROTECT,
        related_name="incidents",
        null=True,
        blank=True,
    )
    threat = models.ForeignKey(
        Threat,
        on_delete=models.SET_NULL,
        related_name="incidents",
        null=True,
        blank=True,
    )
    detected_at = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)
    assigned_to = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-detected_at"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["detected_at"]),
        ]

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}"


# ---------------------------------------------------------------------------
# LogEntry
# ---------------------------------------------------------------------------
class LogEntry(models.Model):
    """Raw security log / telemetry record."""

    source = models.CharField(
        max_length=32, choices=LogSource.choices, default=LogSource.OTHER
    )
    asset = models.ForeignKey(
        Asset,
        on_delete=models.SET_NULL,
        related_name="logs",
        null=True,
        blank=True,
    )
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    event_type = models.CharField(max_length=128, blank=True)
    message = models.TextField(blank=True)
    raw_payload = models.JSONField(null=True, blank=True)
    is_processed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["source"]),
            models.Index(fields=["is_processed"]),
        ]

    def __str__(self) -> str:
        return f"[{self.source}] {self.timestamp:%Y-%m-%d %H:%M:%S}"


# ---------------------------------------------------------------------------
# MLModel
# ---------------------------------------------------------------------------
class MLModel(models.Model):
    """Registry of trained machine-learning models."""

    name = models.CharField(max_length=255, unique=True)
    version = models.CharField(max_length=32, default="1.0.0")
    algorithm = models.CharField(max_length=128, blank=True)
    description = models.TextField(blank=True)
    file_path = models.CharField(
        max_length=512, help_text="Path to the .joblib/.pkl artifact on disk."
    )
    metrics = models.JSONField(
        null=True, blank=True, help_text="Stored evaluation metrics (accuracy, F1, etc.)."
    )
    is_active = models.BooleanField(default=True)
    trained_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.name} v{self.version}"


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------
class Prediction(models.Model):
    """Result of running an ML model on a log entry."""

    model = models.ForeignKey(
        MLModel,
        on_delete=models.PROTECT,
        related_name="predictions",
    )
    log_entry = models.ForeignKey(
        LogEntry,
        on_delete=models.CASCADE,
        related_name="predictions",
    )
    label = models.CharField(max_length=128)
    score = models.FloatField(
        null=True, blank=True, help_text="Confidence or anomaly score."
    )
    is_anomaly = models.BooleanField(default=False)
    explanation = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["label"]),
            models.Index(fields=["is_anomaly"]),
        ]

    def __str__(self) -> str:
        return f"{self.model.name} → {self.label} ({self.score})"

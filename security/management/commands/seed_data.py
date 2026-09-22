"""
Seed the database with realistic cybersecurity demo data.

Usage:
    python manage.py seed_data --reset
    python manage.py seed_data --assets 50 --threats 20 --logs 500
"""

import random
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from faker import Faker

from security.models import (
    Asset, AssetType, AssetCriticality,
    Threat, ThreatCategory, Severity,
    Vulnerability,
    Incident, IncidentStatus,
    LogEntry, LogSource,
    MLModel,
    Prediction,
)


class Command(BaseCommand):
    help = "Seed the database with demo cybersecurity data."

    def add_arguments(self, parser):
        parser.add_argument("--assets", type=int, default=30)
        parser.add_argument("--threats", type=int, default=15)
        parser.add_argument("--logs", type=int, default=300)
        parser.add_argument("--incidents", type=int, default=25)
        parser.add_argument("--reset", action="store_true",
                            help="Delete all existing seeded data first.")

    @transaction.atomic
    def handle(self, *args, **options):
        fake = Faker()
        Faker.seed(42)
        random.seed(42)

        if options["reset"]:
            self.stdout.write(self.style.WARNING("Resetting existing data..."))
            Prediction.objects.all().delete()
            LogEntry.objects.all().delete()
            Incident.objects.all().delete()
            Vulnerability.objects.all().delete()
            Threat.objects.all().delete()
            Asset.objects.all().delete()
            MLModel.objects.all().delete()

        # ---------------------------------------------------------------
        # Assets
        # ---------------------------------------------------------------
        self.stdout.write("Seeding assets...")
        asset_types = [c[0] for c in AssetType.choices]
        criticalities = [c[0] for c in AssetCriticality.choices]

        assets = []
        for i in range(options["assets"]):
            assets.append(Asset(
                name=f"{fake.company().split()[0].lower()}-{fake.word()}-{i:03d}",
                asset_type=random.choice(asset_types),
                criticality=random.choice(criticalities),
                ip_address=fake.ipv4(),
                hostname=fake.hostname(),
                operating_system=random.choice([
                    "Ubuntu 22.04", "Windows Server 2019", "Windows 11",
                    "CentOS 7", "Debian 12", "macOS 14",
                ]),
                owner=fake.name(),
                location=random.choice([
                    "AWS us-east-1", "AWS eu-west-1", "Azure East US",
                    "On-prem DC1", "On-prem DC2", "GCP us-central1",
                ]),
                description=fake.sentence(nb_words=12),
                is_active=random.random() > 0.1,
            ))
        Asset.objects.bulk_create(assets)
        assets = list(Asset.objects.all())

        # ---------------------------------------------------------------
        # Threats
        # ---------------------------------------------------------------
        self.stdout.write("Seeding threats...")
        threat_names = [
            "Emotet", "TrickBot", "Ryuk", "LockBit", "REvil",
            "Cobalt Strike", "Mimikatz", "SQL Injection Campaign",
            "Credential Stuffing Botnet", "Phishing Kit Alpha",
            "Log4Shell Exploitation", "ProxyShell Exploit",
            "DDoS Mirai Variant", "Insider Data Exfiltration",
            "APT29 Spear Phishing",
        ]
        threat_categories = [c[0] for c in ThreatCategory.choices]

        threats = []
        for i in range(min(options["threats"], len(threat_names))):
            threats.append(Threat(
                name=threat_names[i],
                category=random.choice(threat_categories),
                severity=random.choice([c[0] for c in Severity.choices]),
                description=fake.paragraph(nb_sentences=3),
                indicators=fake.sentence(nb_words=15),
                mitre_technique=f"T{random.randint(1000, 1599)}",
                is_active=random.random() > 0.15,
            ))
        Threat.objects.bulk_create(threats)
        threats = list(Threat.objects.all())

        # ---------------------------------------------------------------
        # Vulnerabilities
        # ---------------------------------------------------------------
        self.stdout.write("Seeding vulnerabilities...")
        vulns = []
        for i in range(options["assets"] * 2):
            asset = random.choice(assets)
            year = random.choice([2022, 2023, 2024, 2025])
            cve_num = random.randint(1000, 99999)
            vulns.append(Vulnerability(
                cve_id=f"CVE-{year}-{cve_num}",
                title=fake.sentence(nb_words=6),
                description=fake.paragraph(nb_sentences=2),
                severity=random.choice([c[0] for c in Severity.choices]),
                cvss_score=round(random.uniform(1.0, 10.0), 1),
                asset=asset,
                is_patched=random.random() > 0.6,
                published_at=timezone.now() - timedelta(days=random.randint(30, 900)),
            ))
        Vulnerability.objects.bulk_create(vulns)

        # ---------------------------------------------------------------
        # Incidents
        # ---------------------------------------------------------------
        self.stdout.write("Seeding incidents...")
        incidents = []
        for i in range(options["incidents"]):
            detected = timezone.now() - timedelta(days=random.randint(0, 90))
            status = random.choice([c[0] for c in IncidentStatus.choices])
            resolved = (
                detected + timedelta(hours=random.randint(1, 72))
                if status in ("RESOLVED", "CLOSED") else None
            )
            incidents.append(Incident(
                title=f"{random.choice(threat_names)} on {random.choice(assets).name}",
                description=fake.paragraph(nb_sentences=3),
                severity=random.choice([c[0] for c in Severity.choices]),
                status=status,
                asset=random.choice(assets),
                threat=random.choice(threats) if threats else None,
                detected_at=detected,
                resolved_at=resolved,
                assigned_to=fake.name(),
            ))
        Incident.objects.bulk_create(incidents)

        # ---------------------------------------------------------------
        # Log Entries
        # ---------------------------------------------------------------
        self.stdout.write("Seeding log entries...")
        sources = [c[0] for c in LogSource.choices]
        event_types = [
            "login_failed", "login_success", "port_scan",
            "malware_detected", "firewall_block", "dns_query",
            "file_access", "privilege_escalation", "data_transfer",
        ]
        logs = []
        for i in range(options["logs"]):
            logs.append(LogEntry(
                source=random.choice(sources),
                asset=random.choice(assets),
                timestamp=timezone.now() - timedelta(
                    minutes=random.randint(0, 60 * 24 * 30)
                ),
                source_ip=fake.ipv4(),
                destination_ip=fake.ipv4(),
                event_type=random.choice(event_types),
                message=fake.sentence(nb_words=12),
                raw_payload={
                    "user": fake.user_name(),
                    "bytes": random.randint(64, 10_000_000),
                    "protocol": random.choice(["TCP", "UDP", "ICMP", "HTTPS"]),
                    "port": random.randint(1, 65535),
                },
                is_processed=random.random() > 0.5,
            ))
        LogEntry.objects.bulk_create(logs)
        logs = list(LogEntry.objects.all())

        # ---------------------------------------------------------------
        # ML Models + Predictions
        # ---------------------------------------------------------------
        self.stdout.write("Seeding ML models and predictions...")
        ml_models = []
        for name, algo in [
            ("anomaly-detector", "IsolationForest"),
            ("intrusion-classifier", "RandomForest"),
            ("malware-detector", "GradientBoosting"),
        ]:
            ml_models.append(MLModel(
                name=name,
                version="1.0.0",
                algorithm=algo,
                description=fake.sentence(),
                file_path=f"ml/artifacts/{name}.joblib",
                metrics={"accuracy": round(random.uniform(0.85, 0.99), 3),
                         "f1": round(random.uniform(0.80, 0.98), 3)},
                is_active=True,
                trained_at=timezone.now() - timedelta(days=random.randint(1, 60)),
            ))
        MLModel.objects.bulk_create(ml_models)
        ml_models = list(MLModel.objects.all())

        predictions = []
        for log in random.sample(logs, k=min(150, len(logs))):
            predictions.append(Prediction(
                model=random.choice(ml_models),
                log_entry=log,
                label=random.choice(["benign", "suspicious", "malicious"]),
                score=round(random.uniform(0.0, 1.0), 3),
                is_anomaly=random.random() < 0.2,
                explanation=fake.sentence(nb_words=10),
            ))
        Prediction.objects.bulk_create(predictions)

        # ---------------------------------------------------------------
        # Summary
        # ---------------------------------------------------------------
        self.stdout.write(self.style.SUCCESS(
            f"\nSeeded:\n"
            f"  Assets:          {Asset.objects.count()}\n"
            f"  Threats:         {Threat.objects.count()}\n"
            f"  Vulnerabilities: {Vulnerability.objects.count()}\n"
            f"  Incidents:       {Incident.objects.count()}\n"
            f"  Log entries:     {LogEntry.objects.count()}\n"
            f"  ML models:       {MLModel.objects.count()}\n"
            f"  Predictions:     {Prediction.objects.count()}\n"
        ))
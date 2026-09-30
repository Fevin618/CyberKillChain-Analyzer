from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis import analyze_pending, ingest_event
from app.database import SessionLocal
from app.models import Event
from app.schemas import EventCreate


BASE_TIME = datetime(2026, 9, 30, 10, 0, tzinfo=timezone.utc)


def _event(offset: int, event_type: str, description: str, **fields) -> EventCreate:
    return EventCreate(timestamp=BASE_TIME + timedelta(minutes=offset), event_type=event_type, description=description, **fields)


SAMPLE_EVENTS = [
    _event(0, "phishing_attachment", "Suspicious invoice attachment delivered to user", user="j.morgan", hostname="FIN-WS-014", source_ip="198.51.100.24", filename="invoice_q3.xlsm"),
    _event(1, "failed_login", "Failed authentication attempt", user="j.morgan", hostname="FIN-WS-014", source_ip="198.51.100.24", destination_ip="10.20.4.14"),
    _event(2, "failed_login", "Failed authentication attempt", user="j.morgan", hostname="FIN-WS-014", source_ip="198.51.100.24", destination_ip="10.20.4.14"),
    _event(3, "failed_login", "Failed authentication attempt", user="j.morgan", hostname="FIN-WS-014", source_ip="198.51.100.24", destination_ip="10.20.4.14"),
    _event(4, "successful_login", "Successful login after multiple failures", user="j.morgan", hostname="FIN-WS-014", source_ip="198.51.100.24", destination_ip="10.20.4.14"),
    _event(6, "powershell", "Encoded PowerShell command executed: powershell -enc [redacted]", user="j.morgan", hostname="FIN-WS-014", source_ip="10.20.4.14", process="powershell.exe"),
    _event(8, "file_download", "Executable downloaded from suspicious infrastructure", user="j.morgan", hostname="FIN-WS-014", source_ip="10.20.4.14", destination_ip="203.0.113.44", filename="update-check.exe"),
    _event(10, "malware_execution", "Downloaded executable launched by user process", user="j.morgan", hostname="FIN-WS-014", source_ip="10.20.4.14", filename="update-check.exe"),
    _event(12, "c2_traffic", "Periodic HTTPS beacon to untrusted external host", user="j.morgan", hostname="FIN-WS-014", source_ip="10.20.4.14", destination_ip="203.0.113.44", domain="cdn-sync.example"),
    _event(15, "data_staging", "Sensitive documents archived in temporary staging directory", user="j.morgan", hostname="FIN-WS-014", filename="q3-finance.zip"),
    _event(18, "data_transfer", "Large outbound transfer to external server; 860 MB", user="j.morgan", hostname="FIN-WS-014", source_ip="10.20.4.14", destination_ip="203.0.113.44", filename="q3-finance.zip"),
    _event(120, "failed_login", "Failed authentication attempt", user="svc-backup", hostname="APP-021", source_ip="198.51.100.88", destination_ip="10.20.8.21"),
    _event(121, "failed_login", "Failed authentication attempt", user="svc-backup", hostname="APP-021", source_ip="198.51.100.88", destination_ip="10.20.8.21"),
    _event(122, "failed_login", "Failed authentication attempt", user="svc-backup", hostname="APP-021", source_ip="198.51.100.88", destination_ip="10.20.8.21"),
    _event(123, "successful_login", "Successful login after repeated failures", user="svc-backup", hostname="APP-021", source_ip="198.51.100.88", destination_ip="10.20.8.21"),
    _event(127, "remote_access", "Remote service session opened from unusual source", user="svc-backup", hostname="APP-021", source_ip="198.51.100.88", destination_ip="10.20.8.21"),
    _event(130, "credential_dumping", "Credential dumping behavior detected by endpoint telemetry", user="svc-backup", hostname="APP-021", source_ip="10.20.8.21"),
    _event(260, "network_scan", "Internal network service scan from compromised workstation", user="a.chen", hostname="ENG-WS-008", source_ip="10.30.2.8", destination_ip="10.30.2.0"),
    _event(262, "powershell", "Suspicious PowerShell download behavior observed", user="a.chen", hostname="ENG-WS-008", source_ip="10.30.2.8", process="powershell.exe"),
    _event(264, "file_download", "Executable tool downloaded from external server", user="a.chen", hostname="ENG-WS-008", source_ip="10.30.2.8", destination_ip="192.0.2.77", filename="support-tool.exe"),
    _event(266, "malware_execution", "Unrecognized binary executed from temporary folder", user="a.chen", hostname="ENG-WS-008", filename="support-tool.exe"),
    _event(268, "dns_request", "Suspicious periodic beacon DNS request after malware execution", user="a.chen", hostname="ENG-WS-008", source_ip="10.30.2.8", domain="x9-sync.example"),
    _event(430, "benign", "Scheduled inventory task completed", user="it-ops", hostname="MGMT-001", source_ip="10.40.1.12", process="Get-Process"),
    _event(431, "powershell", "Routine administration: Get-Process; no encoded command or network retrieval", user="it-ops", hostname="MGMT-001", source_ip="10.40.1.12", process="powershell.exe"),
]


def seed_database() -> None:
    with SessionLocal() as db:
        if db.scalar(select(func.count(Event.id))) > 0:
            return
        for event in SAMPLE_EVENTS:
            ingest_event(db, event)
        analyze_pending(db)
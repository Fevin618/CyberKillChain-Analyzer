import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.analysis import _components, _risk, analyze_pending, classify_event, incident_report, ingest_event
from app.database import Base, get_db
from app.main import app
from app.models import Event, Incident
from app.parsers import MAX_UPLOAD_BYTES, parse_upload
from app.schemas import EventCreate
from app.seed import SAMPLE_EVENTS


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    Base.metadata.drop_all(engine)
    engine.dispose()


def make_event(offset: int, kind: str, description: str, **extra) -> EventCreate:
    return EventCreate(timestamp=datetime(2026, 9, 30, 10, tzinfo=timezone.utc) + timedelta(minutes=offset), event_type=kind, description=description, user="analyst-target", hostname="WS-100", source_ip="198.51.100.9", **extra)


def test_csv_parser_accepts_valid_rows_and_reports_bad_row():
    csv_data = b"timestamp,event_type,source_ip,description\n2026-09-30T10:00:00Z,failed_login,203.0.113.1,bad password\nnot-a-date,powershell,10.0.0.2,command\n"
    events, errors = parse_upload("events.csv", csv_data)
    assert len(events) == 1
    assert events[0].event_type == "failed_login"
    assert len(errors) == 1


def test_json_parser_accepts_events_array():
    payload = [{"timestamp": "2026-09-30T10:00:00Z", "event_type": "network_scan"}]
    events, errors = parse_upload("events.json", json.dumps({"events": payload}).encode())
    assert len(events) == 1 and not errors


def test_txt_parser_preserves_unstructured_log_line():
    events, errors = parse_upload("events.txt", b"Sep 30 10:00:00 host process alert observed\n")
    assert not errors
    assert events[0].event_type == "unclassified_log"
    assert "alert observed" in events[0].description


def test_upload_size_limit_is_enforced():
    with pytest.raises(ValueError, match="5 MiB"):
        parse_upload("events.txt", b"x" * (MAX_UPLOAD_BYTES + 1))


def test_powerShell_encoded_command_maps_technique_and_high_confidence():
    result = classify_event(make_event(0, "powershell", "powershell -enc [redacted]"))
    assert result["technique"] == "T1059.001"
    assert result["stage"] == "Exploitation"
    assert result["severity"] == "High"
    assert result["confidence"] >= 0.9


def test_routine_powershell_has_low_false_positive_risk():
    result = classify_event(make_event(0, "powershell", "Get-Process"))
    assert result["severity"] == "Low"
    assert result["false_positive_likelihood"] > 0.7


def test_unknown_event_is_kept_as_contextual_evidence():
    result = classify_event(make_event(0, "custom_sensor_event", "routine observation"))
    assert result["stage"] == ""
    assert result["technique"] is None


def test_events_correlate_by_user_and_host_within_24_hours():
    events = [Event(timestamp=make_event(i, "failed_login", "failure").timestamp, user="u", hostname="h") for i in (0, 5)]
    assert len(_components(events)) == 1
    events[1].timestamp += timedelta(days=2)
    assert len(_components(events)) == 2


def test_generic_shell_process_does_not_join_distinct_hosts():
    first = Event(timestamp=make_event(0, "powershell", "routine").timestamp, hostname="HOST-A", process="powershell.exe")
    second = Event(timestamp=make_event(1, "powershell", "routine").timestamp, hostname="HOST-B", process="powershell.exe")
    assert len(_components([first, second])) == 2


def test_seeded_acceptance_sequence_creates_phishing_to_exfiltration_case(db):
    for event in SAMPLE_EVENTS:
        ingest_event(db, event)
    incidents = analyze_pending(db)
    primary = next(item for item in incidents if any(event.event_type == "failed_login" and event.user == "j.morgan" for event in item.events))
    types = [event.event_type for event in sorted(primary.events, key=lambda item: item.timestamp)]
    assert types.index("failed_login") < types.index("successful_login") < types.index("powershell") < types.index("file_download") < types.index("c2_traffic") < types.index("data_transfer")
    assert primary.risk_score >= 76
    assert {event.kill_chain_stage for event in primary.events} >= {"Delivery", "Exploitation", "Installation", "Command & Control", "Actions on Objectives"}
    assert any(alert.rule_id == "KC-002" for alert in primary.alerts)
    assert any(alert.rule_id == "KC-005" for alert in primary.alerts)


def test_attack_sequence_creates_one_correlated_incident_and_rules(db):
    kinds = [(0, "failed_login", "failed"), (1, "failed_login", "failed"), (2, "failed_login", "failed"), (3, "successful_login", "login success"), (4, "powershell", "powershell -enc [redacted]"), (6, "file_download", "executable downloaded"), (8, "c2_traffic", "periodic beacon"), (10, "data_transfer", "large outbound transfer")]
    for minute, kind, description in kinds:
        ingest_event(db, make_event(minute, kind, description, destination_ip="203.0.113.55"))
    incidents = analyze_pending(db)
    assert len(incidents) == 1
    assert len(incidents[0].events) == len(kinds)
    assert incidents[0].risk_score > 50
    assert {event.kill_chain_stage for event in incidents[0].events} >= {"Exploitation", "Installation", "Command & Control", "Actions on Objectives"}


def test_benign_event_does_not_create_incident(db):
    ingest_event(db, make_event(0, "powershell", "Routine administration: Get-Process"))
    assert analyze_pending(db) == []
    assert db.query(Incident).count() == 0


def test_risk_score_is_bounded_and_explained():
    event = Event(severity="Critical", confidence=0.9, kill_chain_stage="Delivery", mitre_id="T1566.001")
    score, factors = _risk([event] * 8, [{"severity": "Critical"}] * 6, 3)
    assert 0 <= score <= 100
    assert factors and all(item["points"] > 0 for item in factors)


def test_report_contains_timeline_stage_and_attack_mapping(db):
    ingest_event(db, make_event(0, "phishing_attachment", "malicious attachment delivered"))
    ingest_event(db, make_event(1, "powershell", "powershell -enc [redacted]"))
    incident = analyze_pending(db)[0]
    report = incident_report(incident)
    assert report["kill_chain"]["progress"] == "2/7"
    assert len(report["timeline"]) == 2
    assert any(tech["id"] == "T1059.001" for tech in report["techniques"])
    assert report["investigation_steps"]


def test_later_event_batch_extends_existing_incident_and_persists_factors(db):
    for minute in range(5):
        ingest_event(db, make_event(minute, "failed_login", "repeated failed authentication"))
    original = analyze_pending(db)[0]
    for minute, kind, description in [(6, "successful_login", "login success"), (7, "powershell", "powershell -enc [redacted]"), (8, "file_download", "executable downloaded"), (9, "data_transfer", "large outbound transfer")]:
        ingest_event(db, make_event(minute, kind, description, destination_ip="203.0.113.55"))
    updated = analyze_pending(db)[0]
    assert updated.id == original.id
    assert db.query(Incident).count() == 1
    assert len(updated.events) == 9
    report = incident_report(updated)
    assert report["risk_factors"]
    assert any(item["value"] == "203.0.113.55" for item in report["indicators"])


def test_api_accepts_manual_event_and_returns_real_database_rows(db):
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        response = client.post("/api/events", json={"timestamp": "2026-09-30T10:00:00Z", "event_type": "network_scan", "description": "service discovery", "hostname": "WS-API"})
        assert response.status_code == 200
        assert response.json()["kill_chain_stage"] == "Reconnaissance"
        assert response.json()["mitre_tactic"] == "Discovery"
        assert client.get("/api/events").json()[0]["hostname"] == "WS-API"
        assert client.get("/api/statistics").json()["high_risk_events"] == 0
    finally:
        app.dependency_overrides.clear()
from datetime import timedelta
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.knowledge import CONTAINMENT, EVENT_MAP, INVESTIGATION, STAGES, TECHNIQUES
from app.models import Alert, Event, Host, Incident, Indicator, MitreTechnique, RelationshipRecord, User
from app.schemas import EventCreate


SEVERITY_WEIGHT = {"Low": 12, "Medium": 32, "High": 58, "Critical": 82}
BASE_SEVERITY = {
    "failed_login": "Low", "successful_login": "Medium", "powershell": "Medium",
    "command_shell": "Low", "file_download": "Medium", "malware_execution": "High",
    "persistence": "High", "scheduled_task": "High", "credential_dumping": "Critical",
    "c2_traffic": "High", "dns_request": "Low", "data_staging": "Medium",
    "data_transfer": "High", "network_scan": "Low", "phishing_attachment": "Medium",
    "phishing_link": "Medium", "benign": "Low", "unclassified_log": "Low",
    "privilege_escalation": "High", "security_tool_disabled": "Critical",
    "file_modification": "Medium", "process_creation": "Low",
}


def classify_event(event: Event | EventCreate) -> dict:
    kind = event.event_type.lower().replace(" ", "_")
    desc = event.description.lower()
    stage, technique, confidence = EVENT_MAP.get(kind, ("", None, 0.15))
    severity = BASE_SEVERITY.get(kind, "Low")
    explanation = f"Event type '{kind}' maps to {stage or 'no specific'} activity; the description did not independently confirm a technique." if stage else "No specific attack behavior was recognized; retained as contextual evidence."
    if kind == "powershell":
        suspicious = any(pattern in desc for pattern in ("-enc", "-encodedcommand", "frombase64string", "downloadstring", "iex ", "invoke-expression"))
        if suspicious:
            severity, confidence = "High", 0.92
            explanation = "PowerShell contains an encoded or download-and-execute indicator, consistent with obfuscated command execution."
        else:
            severity, confidence = "Low", 0.24
            explanation = "PowerShell activity is present without an encoded or download-and-execute indicator; routine administrative use remains plausible."
    elif kind == "failed_login":
        explanation = "A failed authentication attempt is contextual evidence; repeated attempts or a subsequent success are required for a stronger conclusion."
    elif kind == "successful_login":
        explanation = "A successful login used a valid account. Suspicion increases when it follows failures from the same source or is otherwise anomalous."
    elif kind == "data_transfer":
        if any(word in desc for word in ("large", "bulk", "exfil", "unusual")):
            confidence = 0.84
            explanation = "A large or explicitly unusual outbound transfer can indicate data exfiltration; confirm destination, volume, and business context."
        else:
            severity, confidence = "Low", 0.25
            explanation = "Outbound transfer is recorded without volume or suspiciousness evidence."
    elif kind == "dns_request" and any(word in desc for word in ("suspicious", "beacon", "periodic", "dga", "malware")):
        severity, confidence = "High", 0.86
        explanation = "DNS activity is described as suspicious or beacon-like and is consistent with possible DNS command and control."
    fp = 1.0 - confidence
    return {"stage": stage, "technique": technique, "confidence": confidence, "severity": severity, "explanation": explanation, "false_positive_likelihood": fp}


def _event_record(db: Session, data: EventCreate) -> Event:
    result = classify_event(data)
    event = Event(**data.model_dump(), kill_chain_stage=result["stage"], mitre_id=result["technique"], severity=result["severity"], confidence=result["confidence"], false_positive_likelihood=result["false_positive_likelihood"], explanation=result["explanation"])
    db.add(event)
    if data.user and not db.scalar(select(User.id).where(User.username == data.user)):
        db.add(User(username=data.user))
    if data.hostname and not db.scalar(select(Host.id).where(Host.hostname == data.hostname)):
        criticality = 2 if any(term in data.hostname.lower() for term in ("dc", "domain", "finance", "prod")) else 1
        db.add(Host(hostname=data.hostname, criticality=criticality))
    return event


def ingest_event(db: Session, data: EventCreate) -> Event:
    for technique_id, (name, tactic, description, severity) in TECHNIQUES.items():
        db.merge(MitreTechnique(id=technique_id, name=name, tactic=tactic, description=description, severity=severity))
    event = _event_record(db, data)
    db.commit()
    db.refresh(event)
    return event


def _correlates(left: Event, right: Event) -> bool:
    if abs((right.timestamp - left.timestamp).total_seconds()) > 24 * 3600:
        return False
    fields = ("user", "hostname", "source_ip", "destination_ip", "filename", "session_id")
    if any(getattr(left, field) and getattr(left, field) == getattr(right, field) for field in fields):
        return True
    generic_processes = {"powershell", "powershell.exe", "cmd", "cmd.exe", "bash", "sh", "python", "python.exe"}
    process = (left.process or "").strip().lower()
    return bool(process and process not in generic_processes and process == (right.process or "").strip().lower())


def _components(events: list[Event]) -> list[list[Event]]:
    remaining = set(range(len(events)))
    components = []
    while remaining:
        stack = [remaining.pop()]
        component = []
        while stack:
            index = stack.pop()
            component.append(events[index])
            neighbors = [other for other in remaining if _correlates(events[index], events[other])]
            remaining.difference_update(neighbors)
            stack.extend(neighbors)
        components.append(sorted(component, key=lambda event: event.timestamp))
    return components


def _rule_alerts(events: list[Event]) -> list[dict]:
    alerts = []
    failures = [e for e in events if e.event_type == "failed_login"]
    successes = [e for e in events if e.event_type == "successful_login"]
    for success in successes:
        related = [failure for failure in failures if failure.source_ip == success.source_ip and failure.user == success.user and timedelta(0) <= success.timestamp - failure.timestamp <= timedelta(minutes=10)]
        if len(related) >= 3:
            alerts.append({"rule_id": "KC-002", "title": "Possible account compromise after repeated failures", "severity": "High", "confidence": 0.92, "evidence": f"{len(related)} failed logins from {success.source_ip} against {success.user} preceded a successful login within 10 minutes."})
    for event in events:
        desc = event.description.lower()
        if event.event_type == "powershell" and any(token in desc for token in ("-enc", "-encodedcommand", "frombase64string")):
            alerts.append({"rule_id": "KC-003", "title": "Encoded PowerShell execution", "severity": "High", "confidence": 0.92, "evidence": event.explanation})
        if event.event_type == "failed_login":
            same_ip = [e for e in failures if e.source_ip == event.source_ip and abs((e.timestamp - event.timestamp).total_seconds()) <= 300]
            if len(same_ip) >= 5:
                alerts.append({"rule_id": "KC-001", "title": "Possible brute-force authentication", "severity": "Medium", "confidence": 0.86, "evidence": f"{len(same_ip)} failed authentication events from {event.source_ip} occurred within five minutes."})
                break
    for event in events:
        if event.event_type == "file_download" and any(other.event_type == "powershell" and timedelta(0) <= event.timestamp - other.timestamp <= timedelta(minutes=15) for other in events):
            alerts.append({"rule_id": "KC-004", "title": "Download after PowerShell execution", "severity": "High", "confidence": 0.82, "evidence": "An executable download followed PowerShell execution within 15 minutes."})
            break
    for event in events:
        if event.event_type == "data_transfer" and any(other.event_type in ("powershell", "malware_execution", "c2_traffic") and timedelta(0) <= event.timestamp - other.timestamp <= timedelta(hours=8) for other in events) and any(word in event.description.lower() for word in ("large", "bulk", "exfil", "unusual")):
            alerts.append({"rule_id": "KC-005", "title": "Possible data exfiltration after suspicious execution", "severity": "Critical", "confidence": 0.91, "evidence": "A large or unusual outbound transfer followed suspicious execution or command-and-control activity."})
            break
    for event in events:
        if event.event_type == "dns_request" and any(other.event_type in ("malware_execution", "file_download") and timedelta(0) <= event.timestamp - other.timestamp <= timedelta(hours=8) for other in events) and any(word in event.description.lower() for word in ("suspicious", "beacon", "periodic", "malware")):
            alerts.append({"rule_id": "KC-006", "title": "Possible DNS command and control", "severity": "High", "confidence": 0.87, "evidence": "Suspicious DNS communication followed malware execution or tool download."})
            break
    return alerts


def _risk(events: list[Event], alerts: list[dict], host_criticality: int) -> tuple[int, list[dict]]:
    factors = []
    base = max((SEVERITY_WEIGHT.get(event.severity, 10) for event in events), default=0)
    if base:
        factors.append({"label": "Highest event severity", "points": min(base, 30)})
    stages = {e.kill_chain_stage for e in events if e.kill_chain_stage}
    progression = min(28, max(0, len(stages) - 1) * 5)
    if progression:
        factors.append({"label": f"Kill Chain progression ({len(stages)} stages)", "points": progression})
    count_points = min(12, max(0, len(events) - 1) * 2)
    if count_points:
        factors.append({"label": f"Related events ({len(events)})", "points": count_points})
    technique_points = min(15, len({e.mitre_id for e in events if e.mitre_id}) * 2)
    if technique_points:
        factors.append({"label": "Distinct ATT&CK techniques", "points": technique_points})
    technique_ids = {event.mitre_id for event in events if event.mitre_id in TECHNIQUES}
    technique_severity = min(15, round(sum(TECHNIQUES[item][3] for item in technique_ids) / max(1, len(technique_ids)) / 10))
    if technique_severity:
        factors.append({"label": "ATT&CK technique severity", "points": technique_severity})
    alert_points = min(20, sum(8 if a["severity"] == "Critical" else 5 if a["severity"] == "High" else 3 for a in alerts))
    if alert_points:
        factors.append({"label": "Correlated detection rules", "points": alert_points})
    asset_points = min(10, max(0, host_criticality - 1) * 5)
    if asset_points:
        factors.append({"label": "Asset criticality", "points": asset_points})
    confidence = sum(event.confidence for event in events) / max(1, len(events))
    score = round(min(100, sum(item["points"] for item in factors)) * (0.65 + 0.35 * confidence))
    return score, factors


def analyze_pending(db: Session) -> list[Incident]:
    pending_ids = set(db.scalars(select(Event.id).where(Event.incident_id.is_(None))))
    if not pending_ids:
        return []
    events = list(db.scalars(select(Event).order_by(Event.timestamp)))
    for technique_id, (name, tactic, description, severity) in TECHNIQUES.items():
        db.merge(MitreTechnique(id=technique_id, name=name, tactic=tactic, description=description, severity=severity))
    db.flush()
    incidents = []
    for group in _components(events):
        if not any(event.id in pending_ids for event in group):
            continue
        alerts = _rule_alerts(group)
        suspicious = any(e.severity in ("Medium", "High", "Critical") for e in group) or alerts
        if not suspicious:
            continue
        hosts = {event.hostname for event in group if event.hostname}
        criticality = max((db.scalar(select(Host.criticality).where(Host.hostname == hostname)) or 1 for hostname in hosts), default=1)
        score, factors = _risk(group, alerts, criticality)
        severity = "Critical" if score >= 76 else "High" if score >= 51 else "Medium" if score >= 26 else "Low"
        stages = {e.kill_chain_stage for e in group if e.kill_chain_stage}
        title = "Correlated multi-stage activity" if len(stages) >= 3 else (alerts[0]["title"] if alerts else "Suspicious activity requiring review")
        summary = f"{len(group)} related events across {len(stages)} Kill Chain stage(s); {len(alerts)} detection rule(s) matched. Risk score {score}/100."
        existing_ids = sorted({event.incident_id for event in group if event.incident_id is not None})
        if existing_ids:
            incident = db.get(Incident, existing_ids[0])
            for old_id in existing_ids:
                db.query(Alert).filter(Alert.incident_id == old_id).delete(synchronize_session=False)
                db.query(Indicator).filter(Indicator.incident_id == old_id).delete(synchronize_session=False)
                db.query(RelationshipRecord).filter(RelationshipRecord.incident_id == old_id).delete(synchronize_session=False)
                if old_id != incident.id:
                    db.query(Event).filter(Event.incident_id == old_id).update({Event.incident_id: incident.id}, synchronize_session=False)
                    old_incident = db.get(Incident, old_id)
                    if old_incident:
                        db.delete(old_incident)
            incident.title = title
            incident.severity = severity
            incident.risk_score = score
            incident.confidence = round(sum(e.confidence for e in group) / len(group), 2)
            incident.first_seen = group[0].timestamp
            incident.last_seen = group[-1].timestamp
            incident.summary = summary
        else:
            incident = Incident(title=title, severity=severity, risk_score=score, confidence=round(sum(e.confidence for e in group) / len(group), 2), first_seen=group[0].timestamp, last_seen=group[-1].timestamp, summary=summary)
            db.add(incident)
        db.flush()
        incident.risk_factors_json = json.dumps(factors)
        for event in group:
            event.incident_id = incident.id
        for alert in alerts:
            db.add(Alert(incident_id=incident.id, **alert))
        for left, right in zip(group, group[1:]):
            db.add(RelationshipRecord(incident_id=incident.id, source_event_id=left.id, target_event_id=right.id, relation="temporal_and_entity_correlation"))
        _store_indicators(db, incident.id, group)
        incidents.append(incident)
    db.commit()
    return incidents


def _store_indicators(db: Session, incident_id: int, events: list[Event]) -> None:
    seen = set()
    for event in events:
        values = [("ip", event.source_ip), ("ip", event.destination_ip), ("user", event.user), ("hostname", event.hostname), ("domain", event.domain), ("url", event.url), ("filename", event.filename), ("sha256", event.sha256)]
        for kind, value in values:
            if value and (kind, value) not in seen:
                db.add(Indicator(incident_id=incident_id, kind=kind, value=value))
                seen.add((kind, value))


def incident_report(incident: Incident) -> dict:
    events = sorted(incident.events, key=lambda event: event.timestamp)
    stages = [stage for stage in STAGES if any(event.kill_chain_stage == stage for event in events)]
    techniques = {}
    for event in events:
        if event.mitre_id:
            item = TECHNIQUES.get(event.mitre_id)
            techniques[event.mitre_id] = {"id": event.mitre_id, "name": item[0] if item else "Unknown", "tactic": item[1] if item else "Unknown", "confidence": event.confidence, "evidence": event.explanation}
    return {
        "incident_id": incident.id, "title": incident.title, "severity": incident.severity,
        "risk_score": incident.risk_score, "confidence": incident.confidence, "summary": incident.summary,
        "executive_summary": f"{incident.title}. {incident.summary}",
        "first_seen": incident.first_seen.isoformat(), "last_seen": incident.last_seen.isoformat(),
        "duration_seconds": max(0, (events[-1].timestamp - events[0].timestamp).total_seconds()) if events else 0,
        "affected_hosts": sorted({event.hostname for event in events if event.hostname}),
        "affected_users": sorted({event.user for event in events if event.user}),
        "source_ips": sorted({event.source_ip for event in events if event.source_ip}),
        "destination_ips": sorted({event.destination_ip for event in events if event.destination_ip}),
        "kill_chain": {"stages": stages, "progress": f"{len(stages)}/7"},
        "techniques": list(techniques.values()),
        "indicators": [{"kind": item.kind, "value": item.value} for item in incident.indicators],
        "timeline": [{"timestamp": event.timestamp.isoformat(), "event_type": event.event_type, "hostname": event.hostname, "user": event.user, "stage": event.kill_chain_stage, "severity": event.severity, "evidence": event.explanation} for event in events],
        "risk_factors": json.loads(incident.risk_factors_json or "[]"),
        "investigation_steps": INVESTIGATION, "containment_actions": CONTAINMENT,
    }

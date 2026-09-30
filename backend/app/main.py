from contextlib import asynccontextmanager
from io import BytesIO

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis import analyze_pending, incident_report, ingest_event
from app.database import get_db, initialize_database
from app.knowledge import STAGES, TECHNIQUES
from app.models import Alert, Event, Host, Incident, Indicator, MitreTechnique, RelationshipRecord, User
from app.parsers import MAX_UPLOAD_BYTES, parse_upload
from app.schemas import EventCreate, EventRead
from app.seed import seed_database


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    seed_database()
    yield


app = FastAPI(title="Kill Chain-Based Incident Analyzer", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/events", response_model=EventRead)
def create_event(payload: EventCreate, db: Session = Depends(get_db)):
    return ingest_event(db, payload)


@app.post("/api/events/upload")
async def upload_events(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Upload exceeds the 5 MiB limit")
    try:
        records, errors = parse_upload(file.filename or "", content)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    added = [ingest_event(db, record) for record in records]
    incidents = analyze_pending(db)
    return {"accepted": len(added), "rejected": len(errors), "errors": errors, "incidents_created": len(incidents)}


@app.get("/api/events", response_model=list[EventRead])
def list_events(limit: int = 500, db: Session = Depends(get_db)):
    return list(db.scalars(select(Event).order_by(Event.timestamp.desc()).limit(min(max(limit, 1), 2000))))


@app.post("/api/analyze")
def analyze(db: Session = Depends(get_db)):
    created = analyze_pending(db)
    return {"incidents_created": len(created), "incident_ids": [item.id for item in created]}


def _incident_or_404(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


@app.get("/api/incidents")
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.scalars(select(Incident).order_by(Incident.first_seen.desc())).all()
    return [{**incident_report(item), "alert_count": len(item.alerts), "event_count": len(item.events)} for item in incidents]


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: int, db: Session = Depends(get_db)):
    incident = _incident_or_404(db, incident_id)
    report = incident_report(incident)
    report["alerts"] = [{"rule_id": alert.rule_id, "title": alert.title, "severity": alert.severity, "confidence": alert.confidence, "evidence": alert.evidence} for alert in incident.alerts]
    report["events"] = [EventRead.model_validate(event).model_dump(mode="json") for event in sorted(incident.events, key=lambda item: item.timestamp)]
    report["indicators"] = [{"kind": item.kind, "value": item.value} for item in db.scalars(select(Indicator).where(Indicator.incident_id == incident_id))]
    return report


@app.get("/api/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: int, db: Session = Depends(get_db)):
    return _incident_or_404(db, incident_id) and incident_report(db.get(Incident, incident_id))["timeline"]


@app.get("/api/incidents/{incident_id}/attack-graph")
def incident_graph(incident_id: int, db: Session = Depends(get_db)):
    incident = _incident_or_404(db, incident_id)
    nodes = [{"id": f"event-{e.id}", "event_id": e.id, "label": e.event_type.replace("_", " ").title(), "entity": e.hostname or e.user or e.source_ip or "Event", "timestamp": e.timestamp.isoformat(), "severity": e.severity, "technique": e.mitre_id, "stage": e.kill_chain_stage, "evidence": e.explanation} for e in sorted(incident.events, key=lambda item: item.timestamp)]
    edges = [{"source": f"event-{r.source_event_id}", "target": f"event-{r.target_event_id}", "label": r.relation.replace("_", " ")} for r in db.scalars(select(RelationshipRecord).where(RelationshipRecord.incident_id == incident_id))]
    return {"nodes": nodes, "edges": edges}


@app.get("/api/mitre/techniques")
def techniques(db: Session = Depends(get_db)):
    rows = db.scalars(select(MitreTechnique).order_by(MitreTechnique.id)).all()
    if not rows:
        return [{"id": key, "name": value[0], "tactic": value[1], "description": value[2], "severity": value[3]} for key, value in TECHNIQUES.items()]
    return [{"id": row.id, "name": row.name, "tactic": row.tactic, "description": row.description, "severity": row.severity} for row in rows]


@app.get("/api/statistics")
def statistics(db: Session = Depends(get_db)):
    incidents = list(db.scalars(select(Incident)))
    events = list(db.scalars(select(Event)))
    severity = {name: sum(incident.severity == name for incident in incidents) for name in ("Critical", "High", "Medium", "Low")}
    ips, hosts, techs, days, stages = {}, {}, {}, {}, set()
    for event in events:
        if event.source_ip:
            ips[event.source_ip] = ips.get(event.source_ip, 0) + 1
        if event.hostname:
            hosts[event.hostname] = hosts.get(event.hostname, 0) + 1
        if event.mitre_id:
            techs[event.mitre_id] = techs.get(event.mitre_id, 0) + 1
        hour = event.timestamp.strftime("%Y-%m-%d %H:00")
        days[hour] = days.get(hour, 0) + 1
        if event.kill_chain_stage:
            stages.add(event.kill_chain_stage)
    return {
        "total_incidents": len(incidents), "critical_incidents": severity["Critical"],
        "high_risk_events": sum(event.severity in ("High", "Critical") for event in events),
        "hosts_affected": len({e.hostname for e in events if e.incident_id and e.hostname}),
        "users_affected": len({e.user for e in events if e.incident_id and e.user}),
        "techniques_detected": len(techs), "stages_detected": len(stages),
        "severity_distribution": severity,
        "events_over_time": [{"time": key, "count": value} for key, value in sorted(days.items())],
        "top_ips": sorted([{"name": k, "count": v} for k, v in ips.items()], key=lambda x: x["count"], reverse=True)[:8],
        "top_hosts": sorted([{"name": k, "count": v} for k, v in hosts.items()], key=lambda x: x["count"], reverse=True)[:8],
        "technique_distribution": [{"id": key, "name": TECHNIQUES.get(key, (key,))[0], "count": value} for key, value in sorted(techs.items(), key=lambda x: x[1], reverse=True)[:10]],
        "kill_chain": [{"stage": stage, "detected": stage in stages} for stage in STAGES],
    }


@app.get("/api/reports/{incident_id}")
def get_report(incident_id: int, db: Session = Depends(get_db)):
    return incident_report(_incident_or_404(db, incident_id))


@app.post("/api/reports/{incident_id}/generate")
def generate_report(incident_id: int, format: str = "json", db: Session = Depends(get_db)):
    data = incident_report(_incident_or_404(db, incident_id))
    if format.lower() == "json":
        return data
    if format.lower() != "pdf":
        raise HTTPException(400, "format must be json or pdf")
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 48
    lines = ["Incident Investigation Report", f"Incident #{incident_id}: {data['title']}", f"Severity: {data['severity']} | Risk: {data['risk_score']}/100", "", "Executive Summary", data["executive_summary"], "", "Kill Chain: " + " -> ".join(data["kill_chain"]["stages"]), "", "ATT&CK Mapping"]
    lines.extend(f"{item['id']} | {item['name']} | {item['tactic']} | confidence {item['confidence']:.0%}" for item in data["techniques"])
    lines.extend(["", "Risk Factors"])
    lines.extend(f"+{item['points']} | {item['label']}" for item in data["risk_factors"])
    lines.extend(["", "Indicators"])
    lines.extend(f"{item['kind']} | {item['value']}" for item in data["indicators"])
    lines.extend(["", "Timeline"])
    lines.extend(f"{item['timestamp']} | {item['event_type']} | {item['evidence']}" for item in data["timeline"])
    lines.extend(["", "Recommended Investigation"] + ["- " + item for item in data["investigation_steps"]] + ["", "Containment Actions"] + ["- " + item for item in data["containment_actions"]])
    for line in lines:
        words = line.split()
        current = ""
        for word in words:
            if len(current) + len(word) > 95:
                pdf.drawString(40, y, current)
                y -= 14
                current = ""
            current += word + " "
        pdf.drawString(40, y, current)
        y -= 16
        if y < 48:
            pdf.showPage()
            y = height - 48
    pdf.save()
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}-report.pdf"'})

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.knowledge import TECHNIQUES


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(160), unique=True, index=True)


class Host(Base):
    __tablename__ = "hosts"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    criticality: Mapped[int] = mapped_column(Integer, default=1)


class KillChainStage(Base):
    __tablename__ = "kill_chain_stages"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    position: Mapped[int] = mapped_column(Integer)


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    tactic: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[int] = mapped_column(Integer, default=50)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), default="Low")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(30), default="Open")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    summary: Mapped[str] = mapped_column(Text, default="")
    risk_factors_json: Mapped[str] = mapped_column(Text, default="[]")
    events: Mapped[list["Event"]] = relationship(back_populates="incident")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")
    indicators: Mapped[list["Indicator"]] = relationship(back_populates="incident")


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="Low")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    false_positive_likelihood: Mapped[float] = mapped_column(Float, default=0.0)
    kill_chain_stage: Mapped[str] = mapped_column(String(80), default="")
    mitre_id: Mapped[str | None] = mapped_column(ForeignKey("mitre_techniques.id"), nullable=True)
    explanation: Mapped[str] = mapped_column(Text, default="")
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    incident: Mapped[Incident | None] = relationship(back_populates="events")

    @property
    def mitre_tactic(self) -> str | None:
        technique = TECHNIQUES.get(self.mitre_id or "")
        return technique[1] if technique else None


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    incident: Mapped[Incident] = relationship(back_populates="alerts")


class Indicator(Base):
    __tablename__ = "indicators"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    kind: Mapped[str] = mapped_column(String(30))
    value: Mapped[str] = mapped_column(String(512))
    incident: Mapped[Incident] = relationship(back_populates="indicators")


class RelationshipRecord(Base):
    __tablename__ = "relationships"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    source_event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    target_event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    relation: Mapped[str] = mapped_column(String(100))
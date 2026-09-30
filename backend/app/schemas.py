from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class EventCreate(BaseModel):
    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=80)
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    hostname: str | None = None
    description: str = Field(default="", max_length=8000)
    process: str | None = None
    filename: str | None = None
    domain: str | None = None
    url: str | None = None
    session_id: str | None = None
    sha256: str | None = None


class EventRead(EventCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    severity: str
    confidence: float
    false_positive_likelihood: float
    kill_chain_stage: str
    mitre_id: str | None
    mitre_tactic: str | None
    explanation: str
    incident_id: int | None

import csv
import io
import json
from datetime import datetime
from typing import Any

from app.schemas import EventCreate

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
REQUIRED = {"timestamp", "event_type"}


def _convert(record: dict[str, Any]) -> EventCreate:
    aliases = {"time": "timestamp", "type": "event_type", "host": "hostname", "src_ip": "source_ip", "dst_ip": "destination_ip"}
    normalized = {aliases.get(str(key).strip().lower(), str(key).strip().lower()): value for key, value in record.items()}
    missing = REQUIRED - normalized.keys()
    if missing:
        raise ValueError("missing required fields: " + ", ".join(sorted(missing)))
    raw_time = normalized["timestamp"]
    if isinstance(raw_time, str):
        normalized["timestamp"] = datetime.fromisoformat(raw_time.strip().replace("Z", "+00:00"))
    normalized["event_type"] = str(normalized["event_type"]).strip().lower().replace(" ", "_")
    allowed = set(EventCreate.model_fields)
    return EventCreate.model_validate({key: value for key, value in normalized.items() if key in allowed})


def parse_upload(filename: str, content: bytes) -> tuple[list[EventCreate], list[str]]:
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("Upload exceeds the 5 MiB limit")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Upload must be UTF-8 text") from exc
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if suffix == "json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc.msg}") from exc
        records = payload if isinstance(payload, list) else payload.get("events", [payload]) if isinstance(payload, dict) else None
        if not isinstance(records, list):
            raise ValueError("JSON must contain an event object or an events array")
    elif suffix == "csv":
        records = list(csv.DictReader(io.StringIO(text)))
    elif suffix == "txt":
        records = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # A plain line is kept as evidence instead of being silently discarded.
                records.append({"timestamp": datetime.now().isoformat(), "event_type": "unclassified_log", "description": line[:8000], "_line": line_number})
    else:
        raise ValueError("Supported upload types are CSV, JSON, and TXT")
    parsed, errors = [], []
    for index, record in enumerate(records, 1):
        try:
            parsed.append(_convert(record))
        except Exception as exc:
            errors.append(f"Record {index}: {str(exc)[:240]}")
    return parsed, errors
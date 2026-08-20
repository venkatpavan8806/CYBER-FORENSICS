"""Event log / shadow-copy-deletion extractor.

Looks for two things in Windows event log data:

  1. Execution evidence of shadow-copy / backup-catalog / recovery-tampering
     commands (`vssadmin delete shadows`, `wmic shadowcopy delete`,
     `wbadmin delete catalog`, `bcdedit ... recoveryenabled no`) - these show
     up in process-creation auditing (Security 4688) or Sysmon (Event ID 1)
     as a command-line string.
  2. Event ID 1102 ("The audit log was cleared") - anti-forensics evidence,
     see Rule 5 in correlation/rules.py.

Supports two input formats that normalize to the same Event objects:

  - Real `.evtx` files, parsed with `python-evtx` (Mode A, and any real
    Mode B eventlogs/ folder).
  - "Mocked event record" JSON files - a plain list of objects shaped like
    {"timestamp": ISO8601, "event_id": int, "provider": str, "description": str}.
    `python-evtx` has no write support, and hand-rolling a binary EVTX/BinXML
    writer is exactly the kind of low-level-format reinvention Section 2 of
    the project spec tells us to avoid - the project spec itself sanctions
    this "mocked event-record structure" as the fallback for synthetic test
    data (Section 6), which is what simulate/synthetic_incident.py uses.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from ransomtrace.models import Event, SourceExtractor

_EVTX_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

SHADOW_COPY_DELETION_PATTERNS = [
    re.compile(r"(?i)vssadmin(\.exe)?\s+delete\s+shadows"),
    re.compile(r"(?i)wmic(\.exe)?\s+shadowcopy\s+delete"),
    re.compile(r"(?i)wbadmin(\.exe)?\s+delete\s+catalog"),
    re.compile(r"(?i)bcdedit(\.exe)?\s*/set\s*\{default\}\s*recoveryenabled\s*no"),
]

AUDIT_LOG_CLEARED_EVENT_ID = 1102


def _classify(
    timestamp: datetime, event_id: int | None, searchable_text: str, raw_evidence: dict
) -> Event | None:
    if event_id == AUDIT_LOG_CLEARED_EVENT_ID:
        return Event(
            timestamp=timestamp,
            source_extractor=SourceExtractor.EVENTLOG_VSS,
            event_type="audit_log_cleared",
            description="Event ID 1102: The audit log was cleared",
            raw_evidence=raw_evidence,
        )

    for pattern in SHADOW_COPY_DELETION_PATTERNS:
        if pattern.search(searchable_text):
            return Event(
                timestamp=timestamp,
                source_extractor=SourceExtractor.EVENTLOG_VSS,
                event_type="shadow_copy_deletion_command",
                description=f"Shadow-copy/recovery-tampering command evidence: {searchable_text.strip()}",
                raw_evidence=raw_evidence,
            )

    return None


def _parse_evtx_file(path: Path) -> list[Event]:
    import Evtx.Evtx as evtx

    events: list[Event] = []
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            xml_str = record.xml()
            try:
                root = ET.fromstring(xml_str)
            except ET.ParseError:
                continue

            system = root.find(f"{_EVTX_NS}System")
            if system is None:
                continue

            event_id_el = system.find(f"{_EVTX_NS}EventID")
            time_el = system.find(f"{_EVTX_NS}TimeCreated")
            provider_el = system.find(f"{_EVTX_NS}Provider")

            if time_el is None or "SystemTime" not in time_el.attrib:
                continue
            timestamp = datetime.fromisoformat(
                time_el.attrib["SystemTime"].replace("Z", "+00:00")
            )
            event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else None
            provider = provider_el.attrib.get("Name", "") if provider_el is not None else ""

            event_data = root.find(f"{_EVTX_NS}EventData")
            data_texts = []
            if event_data is not None:
                for data_el in event_data:
                    if data_el.text:
                        data_texts.append(data_el.text)
            searchable_text = " ".join(data_texts)

            finding = _classify(
                timestamp,
                event_id,
                searchable_text,
                raw_evidence={
                    "source_file": str(path),
                    "event_id": event_id,
                    "provider": provider,
                    "data": data_texts,
                },
            )
            if finding is not None:
                events.append(finding)

    return events


def _parse_mocked_json_file(path: Path) -> list[Event]:
    records = json.loads(path.read_text(encoding="utf-8"))
    events: list[Event] = []
    for record in records:
        timestamp = datetime.fromisoformat(record["timestamp"])
        event_id = record.get("event_id")
        searchable_text = " ".join(
            str(record.get(field, ""))
            for field in ("description", "command_line", "provider")
        )
        finding = _classify(
            timestamp,
            event_id,
            searchable_text,
            raw_evidence={"source_file": str(path), **record},
        )
        if finding is not None:
            events.append(finding)
    return events


def extract_eventlog_events(path: str | Path) -> list[Event]:
    """Parse one event-log source file (real .evtx or mocked .json) into Events."""
    path = Path(path)
    if path.suffix.lower() == ".evtx":
        return _parse_evtx_file(path)
    if path.suffix.lower() == ".json":
        return _parse_mocked_json_file(path)
    raise ValueError(f"Unsupported event log file type: {path}")

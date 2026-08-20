"""Shared data model used across ingest, extractors, correlation, validation, and report.

Every extractor (filesystem / registry / eventlog_vss), regardless of whether its
source data came from Mode A (disk image) or Mode B (pre-extracted folder), must
normalize what it finds into `Event` objects. The correlation engine only ever
operates on `Event` objects, never on extractor-specific raw structures - that
normalization boundary is what lets the same rules.py work against both ingestion
modes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SourceExtractor(str, Enum):
    FILESYSTEM = "filesystem"
    REGISTRY = "registry"
    EVENTLOG_VSS = "eventlog_vss"


class ValidationStatus(str, Enum):
    UNREVIEWED = "Unreviewed"
    CONFIRMED = "Confirmed"
    FALSE_POSITIVE = "False Positive"
    UNCERTAIN = "Uncertain"


@dataclass
class Event:
    """A single normalized, timestamped observation extracted from raw evidence.

    `raw_evidence` keeps the original, extractor-specific detail (a dict) so a
    Finding can always be traced back to exactly what was observed on disk -
    this is what makes findings explainable instead of an opaque score.
    """

    timestamp: datetime
    source_extractor: SourceExtractor
    event_type: str
    description: str
    raw_evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_extractor": self.source_extractor.value,
            "event_type": self.event_type,
            "description": self.description,
            "raw_evidence": self.raw_evidence,
        }


@dataclass
class Finding:
    """A correlation-engine output: a rule fired, producing an interpreted claim
    tied to one or more MITRE ATT&CK technique IDs and the Events that support it.
    """

    finding_id: str
    rule_id: str
    title: str
    mitre_techniques: list[str]
    confidence: str  # "Low" | "Medium" | "High"
    description: str
    evidence: list[Event]
    window_start: datetime
    window_end: datetime
    validation_status: ValidationStatus = ValidationStatus.UNREVIEWED
    analyst_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "mitre_techniques": self.mitre_techniques,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "validation_status": self.validation_status.value,
            "analyst_note": self.analyst_note,
        }

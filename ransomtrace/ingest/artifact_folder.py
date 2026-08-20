"""Mode B ingestion: read a pre-extracted artifact folder.

Expected layout (all three subdirectories/files are optional - whatever is
present gets analyzed, whatever is missing is silently skipped rather than
treated as an error, since a real analyst may only have partial artifacts):

    <folder>/
      registry/        hive files (SYSTEM, SOFTWARE, NTUSER.DAT, ...)
      eventlogs/        .evtx files and/or mocked-event-record .json files
      filelist.csv      OR
      files/            a real directory tree representing filesystem state

This is what makes the project testable without a full disk image or a
Windows VM - see simulate/synthetic_incident.py, which generates exactly this
folder shape.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from ransomtrace.extractors.eventlog_vss import extract_eventlog_events
from ransomtrace.extractors.filesystem import (
    ENTROPY_SAMPLE_BYTES,
    FileRecord,
    extract_filesystem_events,
)
from ransomtrace.extractors.registry import extract_registry_events
from ransomtrace.models import Event


def _read_filelist_csv(csv_path: Path) -> list[FileRecord]:
    records: list[FileRecord] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            records.append(
                FileRecord(
                    path=row["path"],
                    extension=row.get("extension", "").lstrip(".").lower(),
                    mtime=datetime.fromisoformat(row["mtime"]),
                    size=int(row.get("size") or 0),
                )
            )
    return records


def _walk_files_directory(files_dir: Path) -> list[FileRecord]:
    records: list[FileRecord] = []
    for path in files_dir.rglob("*"):
        if not path.is_file():
            continue
        stat = path.stat()
        records.append(
            FileRecord(
                path=str(path.relative_to(files_dir)),
                extension=path.suffix.lstrip(".").lower(),
                mtime=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                size=stat.st_size,
            )
        )
    return records


def _make_sample_reader(files_dir: Path):
    def _read_sample(rel_path: str) -> bytes | None:
        try:
            with (files_dir / rel_path).open("rb") as f:
                return f.read(ENTROPY_SAMPLE_BYTES)
        except OSError:
            return None

    return _read_sample


def _collect_filesystem_events(root: Path) -> list[Event]:
    filelist_csv = root / "filelist.csv"
    files_dir = root / "files"

    if filelist_csv.exists():
        # filelist.csv describes filesystem state without guaranteeing real
        # file content is available, so no entropy sampling here.
        records = _read_filelist_csv(filelist_csv)
        return extract_filesystem_events(records)
    elif files_dir.is_dir():
        records = _walk_files_directory(files_dir)
        return extract_filesystem_events(records, read_sample=_make_sample_reader(files_dir))
    else:
        return extract_filesystem_events([])


def _collect_registry_events(root: Path) -> list[Event]:
    registry_dir = root / "registry"
    if not registry_dir.is_dir():
        return []

    events: list[Event] = []
    for hive_path in sorted(registry_dir.iterdir()):
        if hive_path.is_file():
            events.extend(extract_registry_events(hive_path))
    return events


def _collect_eventlog_events(root: Path) -> list[Event]:
    eventlogs_dir = root / "eventlogs"
    if not eventlogs_dir.is_dir():
        return []

    events: list[Event] = []
    for log_path in sorted(eventlogs_dir.iterdir()):
        if log_path.is_file() and log_path.suffix.lower() in (".evtx", ".json"):
            events.extend(extract_eventlog_events(log_path))
    return events


def ingest_artifact_folder(folder: str | Path) -> list[Event]:
    """Read a Mode B artifact folder and return normalized Events from every
    extractor that found applicable input."""
    root = Path(folder)
    if not root.is_dir():
        raise FileNotFoundError(f"Artifact folder not found: {root}")

    events: list[Event] = []
    events.extend(_collect_filesystem_events(root))
    events.extend(_collect_registry_events(root))
    events.extend(_collect_eventlog_events(root))
    return events

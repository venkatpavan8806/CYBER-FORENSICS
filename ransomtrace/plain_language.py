"""Turns raw evidence (ISO timestamps, registry paths, SIDs, command lines)
into plain sentences a non-technical reader can follow. Pure functions - no
UI imports - so the dashboard and the HTML report share one wording.
"""
from __future__ import annotations

import ntpath
from collections import Counter
from datetime import datetime, timezone

from ransomtrace.extractors.eventlog_vss import SHADOW_COPY_DELETION_PATTERNS
from ransomtrace.extractors.filesystem import HIGH_ENTROPY_THRESHOLD
from ransomtrace.models import Event

PLAIN_EVENT_TYPE = {
    "file_extension_change": "Files with an unfamiliar extension",
    "ransom_note_file": "Ransom-note-style file",
    "run_key_persistence": "Auto-start entry added",
    "suspicious_service_created": "Suspicious background service",
    "suspicious_binary_execution": "Backup-tampering tool was run",
    "shadow_copy_deletion_command": "Backup deletion command",
    "audit_log_cleared": "Security log cleared",
}


def friendly_time(dt: datetime) -> str:
    """'11 Oct 2026, 09:32:23 UTC' instead of '2026-10-11T09:32:23.621424+00:00'."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")


def _name(path: object) -> str:
    text = str(path).replace("/", "\\").strip('"')
    return ntpath.basename(text) or text


def _folder(path: object) -> str:
    text = str(path).replace("/", "\\").strip('"')
    return ntpath.dirname(text) or text


def _command_text(event: Event) -> str:
    raw = event.raw_evidence
    command = raw.get("command_line")
    if command:
        return str(command)
    data = raw.get("data")
    text = " ".join(str(d) for d in data) if data else event.description
    for pattern in SHADOW_COPY_DELETION_PATTERNS:
        match = pattern.search(text)
        if match:
            return text[match.start(): match.start() + 90].strip()
    return text[:90]


def _looks_encrypted(event: Event) -> bool | None:
    entropy = event.raw_evidence.get("entropy_bits_per_byte")
    if entropy is None:
        return None
    return entropy >= HIGH_ENTROPY_THRESHOLD


def plain_event(event: Event) -> str:
    raw, etype = event.raw_evidence, event.event_type

    if etype == "file_extension_change":
        text = f"The file '{_name(raw.get('path', ''))}' now ends in an unfamiliar type (.{raw.get('extension', '?')})"
        encrypted = _looks_encrypted(event)
        if encrypted is True:
            text += ", and its contents look scrambled, as if encrypted"
        elif encrypted is False:
            text += " (its contents look normal)"
        return text + "."
    if etype == "ransom_note_file":
        return (f"A file named '{_name(raw.get('path', ''))}' was found - ransomware leaves "
                "notes like this to tell victims how to pay.")
    if etype == "run_key_persistence":
        target = raw.get("value_data", "")
        return (f"'{raw.get('value_name', '?')}' is set to start automatically whenever Windows starts "
                f"(it runs {_name(target)} from {_folder(target)}).")
    if etype == "suspicious_service_created":
        image = raw.get("image_path", "")
        return (f"A background service called '{raw.get('service_name', '?')}' was added to Windows. "
                f"It runs {_name(image)} from an unusual folder ({_folder(image)}).")
    if etype == "suspicious_binary_execution":
        return (f"Windows' activity log shows that '{_name(raw.get('executable', ''))}' was run on this "
                "computer. This is a tool attackers use to delete backups.")
    if etype == "shadow_copy_deletion_command":
        return f"A command that deletes Windows' backups was run: {_command_text(event)}"
    if etype == "audit_log_cleared":
        return "The Windows security log was erased, which hides what happened on the computer."
    return event.description


def summarize_events(events: list[Event]) -> list[str]:
    """One plain sentence per kind of evidence (many similar items collapse
    into a single line, e.g. '40 files were renamed...')."""
    by_type: dict[str, list[Event]] = {}
    for event in events:
        by_type.setdefault(event.event_type, []).append(event)

    lines: list[str] = []
    for etype, group in by_type.items():
        if len(group) == 1:
            lines.append(plain_event(group[0]))
        elif etype == "file_extension_change":
            exts = Counter(e.raw_evidence.get("extension", "?") for e in group)
            kinds = ", ".join(f".{x}" for x in exts)
            example = _name(group[0].raw_evidence.get("path", ""))
            line = f"{len(group)} files were renamed to an unfamiliar type ({kinds}), for example '{example}'."
            flags = [_looks_encrypted(e) for e in group if _looks_encrypted(e) is not None]
            if flags and sum(flags) / len(flags) > 0.5:
                line += " Their contents look scrambled, as if encrypted."
            lines.append(line)
        else:
            lines.append(f"{len(group)} items of this kind: {PLAIN_EVENT_TYPE.get(etype, etype).lower()}.")
    return lines

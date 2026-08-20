import json
from datetime import datetime, timezone

from ransomtrace.extractors.eventlog_vss import extract_eventlog_events
from ransomtrace.models import SourceExtractor


def _write_mocked_events(tmp_path, records):
    path = tmp_path / "events.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    return path


def test_vssadmin_delete_shadows_detected(tmp_path):
    now = datetime.now(timezone.utc).isoformat()
    path = _write_mocked_events(
        tmp_path,
        [
            {
                "timestamp": now,
                "event_id": 4688,
                "provider": "Microsoft-Windows-Security-Auditing",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
            }
        ],
    )
    events = extract_eventlog_events(path)
    assert len(events) == 1
    assert events[0].event_type == "shadow_copy_deletion_command"
    assert events[0].source_extractor == SourceExtractor.EVENTLOG_VSS


def test_all_documented_shadow_copy_commands_are_detected(tmp_path):
    now = datetime.now(timezone.utc).isoformat()
    commands = [
        "vssadmin delete shadows /all",
        "wmic shadowcopy delete",
        "wbadmin delete catalog -quiet",
        "bcdedit /set {default} recoveryenabled no",
    ]
    for cmd in commands:
        path = _write_mocked_events(
            tmp_path, [{"timestamp": now, "event_id": 1, "command_line": cmd}]
        )
        events = extract_eventlog_events(path)
        assert any(e.event_type == "shadow_copy_deletion_command" for e in events), cmd


def test_audit_log_cleared_detected(tmp_path):
    now = datetime.now(timezone.utc).isoformat()
    path = _write_mocked_events(
        tmp_path, [{"timestamp": now, "event_id": 1102, "provider": "Eventlog"}]
    )
    events = extract_eventlog_events(path)
    assert len(events) == 1
    assert events[0].event_type == "audit_log_cleared"


def test_unrelated_event_produces_no_event(tmp_path):
    now = datetime.now(timezone.utc).isoformat()
    path = _write_mocked_events(
        tmp_path,
        [{"timestamp": now, "event_id": 4624, "description": "An account was successfully logged on"}],
    )
    events = extract_eventlog_events(path)
    assert events == []

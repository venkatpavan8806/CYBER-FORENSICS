from datetime import datetime, timezone

from ransomtrace.extractors.filesystem import FileRecord, extract_filesystem_events
from ransomtrace.models import SourceExtractor


def _record(path: str, extension: str, minute: int = 0) -> FileRecord:
    return FileRecord(
        path=path,
        extension=extension,
        mtime=datetime(2026, 1, 1, 12, minute, 0, tzinfo=timezone.utc),
        size=1024,
    )


def test_common_extension_produces_no_event():
    events = extract_filesystem_events([_record("a.txt", "txt")])
    assert events == []


def test_unusual_extension_produces_extension_change_event():
    events = extract_filesystem_events([_record("a.locked_demo", "locked_demo")])
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "file_extension_change"
    assert event.source_extractor == SourceExtractor.FILESYSTEM
    assert event.raw_evidence["extension"] == "locked_demo"


def test_ransom_note_filenames_are_detected():
    candidates = [
        "README_RESTORE_FILES.txt",
        "DECRYPT_INSTRUCTIONS.html",
        "HOW_TO_DECRYPT.hta",
        "RECOVERY_INFO.txt",
    ]
    for name in candidates:
        events = extract_filesystem_events([_record(name, name.rsplit(".", 1)[-1])])
        types = {e.event_type for e in events}
        assert "ransom_note_file" in types, f"{name} was not detected as a ransom note"


def test_normal_filename_is_not_flagged_as_ransom_note():
    events = extract_filesystem_events([_record("quarterly_report.txt", "txt")])
    assert events == []


def test_file_with_no_extension_is_ignored():
    events = extract_filesystem_events([_record("Makefile", "")])
    assert events == []

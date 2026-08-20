import os
from datetime import datetime, timezone

from ransomtrace.extractors.filesystem import (
    FileRecord,
    extract_filesystem_events,
    shannon_entropy,
)
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


def test_shannon_entropy_of_empty_bytes_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_shannon_entropy_of_repeated_byte_is_zero():
    assert shannon_entropy(b"a" * 1000) == 0.0


def test_shannon_entropy_of_random_bytes_is_high():
    assert shannon_entropy(os.urandom(4096)) > 7.5


def test_extension_change_without_read_sample_has_no_entropy_field():
    events = extract_filesystem_events([_record("a.locked_demo", "locked_demo")])
    assert "entropy_bits_per_byte" not in events[0].raw_evidence


def test_extension_change_with_high_entropy_sample_is_annotated():
    events = extract_filesystem_events(
        [_record("a.locked_demo", "locked_demo")],
        read_sample=lambda path: os.urandom(8192),
    )
    assert events[0].raw_evidence["entropy_bits_per_byte"] > 7.5
    assert "high-entropy" in events[0].description


def test_extension_change_with_low_entropy_sample_is_not_annotated_as_high_entropy():
    events = extract_filesystem_events(
        [_record("a.locked_demo", "locked_demo")],
        read_sample=lambda path: b"a" * 8192,
    )
    assert events[0].raw_evidence["entropy_bits_per_byte"] < 7.5
    assert "high-entropy" not in events[0].description


def test_read_sample_returning_none_does_not_crash():
    events = extract_filesystem_events(
        [_record("a.locked_demo", "locked_demo")],
        read_sample=lambda path: None,
    )
    assert "entropy_bits_per_byte" not in events[0].raw_evidence

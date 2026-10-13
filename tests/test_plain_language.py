from datetime import datetime, timezone

from ransomtrace.models import Event, SourceExtractor
from ransomtrace.plain_language import friendly_time, plain_event, summarize_events

T = datetime(2026, 10, 11, 9, 32, 23, 621424, tzinfo=timezone.utc)


def _ev(extractor, etype, **raw):
    return Event(timestamp=T, source_extractor=extractor, event_type=etype, description="RAW", raw_evidence=raw)


def test_friendly_time_has_no_iso_noise():
    assert friendly_time(T) == "11 Oct 2026, 09:32:23 UTC"


def test_bam_evidence_becomes_plain_sentence_without_sid():
    e = _ev(SourceExtractor.REGISTRY, "suspicious_binary_execution",
            executable=r"C:\Windows\System32\vssadmin.exe",
            user_sid="S-1-5-21-1111111111-2222222222-3333333333-1001")
    text = plain_event(e)
    assert "vssadmin.exe" in text and "delete backups" in text
    assert "S-1-5-21" not in text and "BAM" not in text


def test_encrypted_looking_file_is_explained():
    e = _ev(SourceExtractor.FILESYSTEM, "file_extension_change", path="invoice_0.locked_demo",
            extension="locked_demo", entropy_bits_per_byte=7.98)
    assert "scrambled" in plain_event(e) and "'invoice_0.locked_demo'" in plain_event(e)


def test_many_files_collapse_into_one_line():
    events = [_ev(SourceExtractor.FILESYSTEM, "file_extension_change", path=f"f{i}.locked_demo",
                  extension="locked_demo", entropy_bits_per_byte=7.9) for i in range(40)]
    lines = summarize_events(events)
    assert len(lines) == 1 and lines[0].startswith("40 files were renamed") and "scrambled" in lines[0]


def test_persistence_and_service_and_command_and_log_cleared():
    assert "start automatically" in plain_event(
        _ev(SourceExtractor.REGISTRY, "run_key_persistence", value_name="SecurityUpdate",
            value_data=r"C:\Users\Public\evil.exe"))
    assert "unusual folder" in plain_event(
        _ev(SourceExtractor.REGISTRY, "suspicious_service_created", service_name="Svc",
            image_path=r"C:\Users\Public\svc.exe"))
    assert "vssadmin.exe delete shadows" in plain_event(
        _ev(SourceExtractor.EVENTLOG_VSS, "shadow_copy_deletion_command",
            command_line="vssadmin.exe delete shadows /all /quiet"))
    assert "erased" in plain_event(_ev(SourceExtractor.EVENTLOG_VSS, "audit_log_cleared"))


def test_unknown_event_type_falls_back_to_description():
    assert plain_event(_ev(SourceExtractor.REGISTRY, "something_new")) == "RAW"

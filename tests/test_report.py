import hashlib
from datetime import datetime, timezone

from ransomtrace.models import Event, Finding, SourceExtractor, ValidationStatus
from ransomtrace.report.generate import generate_report, hash_input


def _finding() -> Finding:
    now = datetime.now(timezone.utc)
    event = Event(
        timestamp=now,
        source_extractor=SourceExtractor.FILESYSTEM,
        event_type="file_extension_change",
        description="Test file changed to .locked_demo",
        raw_evidence={"path": "invoice_0001.locked_demo"},
    )
    return Finding(
        finding_id="R1-abc123",
        rule_id="R1",
        title="Mass extension-change burst: .locked_demo (40 files)",
        mitre_techniques=["T1486"],
        confidence="Medium",
        description="40 files changed to .locked_demo within 10 minutes.",
        evidence=[event],
        window_start=now,
        window_end=now,
        validation_status=ValidationStatus.CONFIRMED,
        analyst_note="Reviewed - matches expected synthetic burst pattern.",
    )


def test_hash_input_for_single_file(tmp_path):
    file_path = tmp_path / "image.raw"
    file_path.write_bytes(b"synthetic disk image bytes")
    expected = hashlib.sha256(b"synthetic disk image bytes").hexdigest()
    assert hash_input(file_path) == expected


def test_hash_input_for_directory_changes_when_content_changes(tmp_path):
    folder = tmp_path / "artifacts"
    folder.mkdir()
    (folder / "a.txt").write_text("hello")
    hash_before = hash_input(folder)

    (folder / "a.txt").write_text("hello world")
    hash_after = hash_input(folder)

    assert hash_before != hash_after


def test_hash_input_for_directory_is_stable_for_same_content(tmp_path):
    folder = tmp_path / "artifacts"
    folder.mkdir()
    (folder / "a.txt").write_text("hello")
    (folder / "b.txt").write_text("world")
    assert hash_input(folder) == hash_input(folder)


def test_generate_report_produces_html_with_finding_content(tmp_path):
    findings = [_finding()]
    input_dir = tmp_path / "artifacts"
    input_dir.mkdir()
    (input_dir / "marker.txt").write_text("x")

    output_path = generate_report(
        findings, input_path=input_dir, output_path=tmp_path / "report.html", mode="b"
    )

    html = output_path.read_text(encoding="utf-8")
    assert "Mass extension-change burst" in html
    assert "T1486" in html
    assert "Confirmed" in html
    assert "Reviewed - matches expected synthetic burst pattern." in html
    assert hash_input(input_dir) in html


def test_generate_report_with_no_findings_shows_empty_state(tmp_path):
    input_dir = tmp_path / "artifacts"
    input_dir.mkdir()
    output_path = generate_report([], input_path=input_dir, output_path=tmp_path / "report.html", mode="b")
    html = output_path.read_text(encoding="utf-8")
    assert "No findings were produced" in html

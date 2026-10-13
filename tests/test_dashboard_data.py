from datetime import datetime, timedelta, timezone

from ransomtrace.models import Event, Finding, SourceExtractor, ValidationStatus
from ransomtrace.validation import dashboard_data as dd

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _event(extractor, etype, seconds=0):
    return Event(
        timestamp=T0 + timedelta(seconds=seconds), source_extractor=extractor,
        event_type=etype, description=etype, raw_evidence={},
    )


def _finding(fid, rule, conf, techniques, evidence, status=ValidationStatus.UNREVIEWED):
    return Finding(
        finding_id=fid, rule_id=rule, title=f"title {fid}", mitre_techniques=techniques,
        confidence=conf, description="d", evidence=evidence,
        window_start=T0, window_end=T0 + timedelta(seconds=90), validation_status=status,
    )


def _sample():
    fs = [_event(SourceExtractor.FILESYSTEM, "file_extension_change", i) for i in range(5)]
    reg = [_event(SourceExtractor.REGISTRY, "run_key_persistence", 10)]
    log = [_event(SourceExtractor.EVENTLOG_VSS, "shadow_copy_deletion_command", 20)]
    findings = [
        _finding("R1-a", "R1", "Medium", ["T1486"], fs),
        _finding("R4-a", "R4", "High", ["T1486", "T1490"], fs + reg + log, ValidationStatus.CONFIRMED),
        _finding("R2-a", "R2", "High", ["T1490"], log),
    ]
    return findings, fs + reg + log


def test_ordered_findings_puts_correlated_first_then_confidence():
    findings, _ = _sample()
    assert [f.finding_id for f in dd.ordered_findings(findings)] == ["R4-a", "R2-a", "R1-a"]


def test_risk_level():
    findings, _ = _sample()
    assert dd.risk_level([]) == "none"
    assert dd.risk_level(findings) == "high"
    assert dd.risk_level([findings[0]]) == "medium"


def test_graph_data_has_five_categories_with_counts():
    findings, events = _sample()
    data = dd.build_graph_data(findings, events, "case", "sub")
    cats = {c["id"]: c for c in data["categories"]}
    assert list(cats) == ["findings", "filesystem", "registry", "eventlog_vss", "mitre"]
    assert cats["findings"]["count"] == 3
    assert cats["filesystem"]["count"] == 5
    assert cats["registry"]["count"] == 1
    assert cats["mitre"]["count"] == 2
    assert data["case"]["risk"] == "high" and data["case"]["findings"] == 3


def test_finding_items_carry_status_and_confidence_tone():
    findings, events = _sample()
    items = dd.build_graph_data(findings, events, "c", "s")["categories"][0]["items"]
    assert items[0]["id"] == "R4-a" and items[0]["status"] == "confirmed" and items[0]["tone"] == "high"


def test_mitre_items_sorted_by_number_of_findings():
    findings, events = _sample()
    mitre = dd.build_graph_data(findings, events, "c", "s")["categories"][4]["items"]
    assert mitre[0]["id"] in {"T1486", "T1490"} and mitre[0]["badge"] == "2 findings"


def test_evidence_group_items_use_plain_names():
    findings, events = _sample()
    fs_items = dd.build_graph_data(findings, events, "c", "s")["categories"][1]["items"]
    assert fs_items[0]["label"] == "Files with an unfamiliar extension"
    assert fs_items[0]["id"] == "filesystem:file_extension_change"


def test_default_selection():
    findings, _ = _sample()
    assert dd.default_selection(findings) == {"category": "findings", "item": "R4-a"}
    assert dd.default_selection([]) == {"category": "findings", "item": None}


def test_evidence_buckets_conserve_event_count():
    _, events = _sample()
    buckets = dd.evidence_buckets(events, buckets=10)
    assert len(buckets) == 10 and sum(buckets) == len(events)
    assert sum(dd.evidence_buckets([], 10)) == 0


def test_format_duration():
    assert dd.format_duration(timedelta(0)) == "instant"
    assert dd.format_duration(timedelta(seconds=42)) == "42s"
    assert dd.format_duration(timedelta(seconds=78)) == "1m 18s"
    assert dd.format_duration(timedelta(hours=2, minutes=5)) == "2h 05m"


def test_html_fragments_escape_text():
    html = dd.tiles_html([("doc", "<b>1</b>", "x & y")])
    assert "&lt;b&gt;" in html and "x &amp; y" in html
    assert "<svg" in dd.score_card_html("L", "V", "S", "high", [1, 2, 3])

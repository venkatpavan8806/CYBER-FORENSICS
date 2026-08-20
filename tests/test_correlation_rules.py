import platform
from datetime import datetime, timedelta, timezone

import pytest

from ransomtrace.correlation import rules
from ransomtrace.correlation.engine import run_correlation
from ransomtrace.ingest.artifact_folder import ingest_artifact_folder
from ransomtrace.models import Event, SourceExtractor
from ransomtrace.simulate.synthetic_incident import generate_synthetic_incident

BASE_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _fs_event(index: int, extension: str = "locked_demo") -> Event:
    # 5-second spacing keeps even a large burst well inside BURST_WINDOW_MINUTES.
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=index * 5),
        source_extractor=SourceExtractor.FILESYSTEM,
        event_type="file_extension_change",
        description="test",
        raw_evidence={"path": f"f{index}.{extension}", "extension": extension},
    )


def _vss_event(minute_offset: int) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(minutes=minute_offset),
        source_extractor=SourceExtractor.EVENTLOG_VSS,
        event_type="shadow_copy_deletion_command",
        description="vssadmin delete shadows /all",
        raw_evidence={},
    )


def _registry_event(minute_offset: int) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(minutes=minute_offset),
        source_extractor=SourceExtractor.REGISTRY,
        event_type="run_key_persistence",
        description="test run key",
        raw_evidence={},
    )


# --- Rule 1: burst detection + confidence scaling ---------------------------

def test_burst_below_threshold_produces_no_finding():
    events = [_fs_event(i) for i in range(rules.BURST_MIN_FILES - 1)]
    findings = rules.rule_mass_rename_burst(events)
    assert findings == []


def test_burst_at_threshold_produces_low_confidence_finding():
    events = [_fs_event(i) for i in range(rules.BURST_MIN_FILES)]
    findings = rules.rule_mass_rename_burst(events)
    assert len(findings) == 1
    assert findings[0].confidence == "Low"
    assert "T1486" in findings[0].mitre_techniques


def test_larger_burst_produces_higher_confidence():
    events = [_fs_event(i) for i in range(rules.BURST_MIN_FILES * 3)]
    findings = rules.rule_mass_rename_burst(events)
    assert len(findings) == 1
    assert findings[0].confidence == "High"


def test_high_entropy_evidence_bumps_confidence_one_level():
    # BURST_MIN_FILES exactly -> base confidence is Low; high-entropy samples
    # should bump it to Medium.
    events = [_fs_event(i) for i in range(rules.BURST_MIN_FILES)]
    for e in events:
        e.raw_evidence["entropy_bits_per_byte"] = 7.9

    findings = rules.rule_mass_rename_burst(events)
    assert len(findings) == 1
    assert findings[0].confidence == "Medium"


def test_high_entropy_bump_is_capped_at_high():
    events = [_fs_event(i) for i in range(rules.BURST_MIN_FILES * 3)]  # base = High
    for e in events:
        e.raw_evidence["entropy_bits_per_byte"] = 7.9

    findings = rules.rule_mass_rename_burst(events)
    assert findings[0].confidence == "High"


def test_low_entropy_evidence_does_not_bump_confidence():
    events = [_fs_event(i) for i in range(rules.BURST_MIN_FILES)]
    for e in events:
        e.raw_evidence["entropy_bits_per_byte"] = 1.0

    findings = rules.rule_mass_rename_burst(events)
    assert findings[0].confidence == "Low"


def test_files_outside_window_are_not_merged_into_one_burst():
    near = [_fs_event(i) for i in range(rules.BURST_MIN_FILES)]
    far = [_fs_event(i) for i in range(1000, 1000 + rules.BURST_MIN_FILES)]
    findings = rules.rule_mass_rename_burst(near + far)
    assert len(findings) == 2


# --- Rule 2 / Rule 3 / Rule 5 basics -----------------------------------------

def test_shadow_copy_deletion_rule_produces_high_confidence_finding():
    findings = rules.rule_shadow_copy_deletion([_vss_event(0)])
    assert len(findings) == 1
    assert findings[0].mitre_techniques == ["T1490"]
    assert findings[0].confidence == "High"


def test_persistence_registry_rule_tags_run_key():
    findings = rules.rule_persistence_registry([_registry_event(0)])
    assert len(findings) == 1
    assert "T1112" in findings[0].mitre_techniques
    assert "T1547.001" in findings[0].mitre_techniques


def test_anti_forensics_rule_flags_log_clearing():
    event = Event(
        timestamp=BASE_TIME,
        source_extractor=SourceExtractor.EVENTLOG_VSS,
        event_type="audit_log_cleared",
        description="test",
        raw_evidence={},
    )
    findings = rules.rule_anti_forensics_signal([event])
    assert len(findings) == 1
    assert findings[0].mitre_techniques == ["T1070.001"]
    assert "incomplete" in findings[0].description.lower()


# --- Rule 4: cross-artifact correlation --------------------------------------

def test_correlated_sequence_requires_all_three_categories():
    burst = rules.rule_mass_rename_burst([_fs_event(i) for i in range(rules.BURST_MIN_FILES)])
    vss = rules.rule_shadow_copy_deletion([_vss_event(2)])
    registry = rules.rule_persistence_registry([_registry_event(3)])

    # burst + vss only -> no R4 finding
    assert rules.rule_correlated_execution_sequence(burst, vss, []) == []
    # burst + registry only -> no R4 finding
    assert rules.rule_correlated_execution_sequence(burst, [], registry) == []
    # all three, within window -> R4 finding
    merged = rules.rule_correlated_execution_sequence(burst, vss, registry)
    assert len(merged) == 1
    assert merged[0].rule_id == "R4"
    assert merged[0].confidence == "High"
    assert set(merged[0].mitre_techniques) >= {"T1486", "T1490", "T1112"}


def test_correlated_sequence_ignores_events_outside_correlation_window():
    burst = rules.rule_mass_rename_burst([_fs_event(i) for i in range(rules.BURST_MIN_FILES)])
    far_offset = rules.CORRELATION_WINDOW_MINUTES + 120
    vss = rules.rule_shadow_copy_deletion([_vss_event(far_offset)])
    registry = rules.rule_persistence_registry([_registry_event(far_offset)])
    assert rules.rule_correlated_execution_sequence(burst, vss, registry) == []


# --- End-to-end: synthetic incident fixture ----------------------------------

@pytest.mark.skipif(
    platform.system() != "Windows",
    reason="the synthetic incident's registry artifact requires the Windows hive writer",
)
def test_synthetic_incident_produces_ransomware_execution_sequence(tmp_path):
    incident_dir = generate_synthetic_incident(tmp_path / "incident")
    events = ingest_artifact_folder(incident_dir)
    findings = run_correlation(events)

    r4_findings = [f for f in findings if f.rule_id == "R4"]
    assert len(r4_findings) == 1, "expected exactly one correlated Ransomware Execution Sequence finding"

    finding = r4_findings[0]
    assert finding.confidence == "High"
    assert set(finding.mitre_techniques) >= {"T1486", "T1490", "T1112"}
    assert len(finding.evidence) > rules.BURST_MIN_FILES

    # sanity: the underlying per-rule findings are also present, not swallowed
    assert any(f.rule_id == "R1" for f in findings)
    assert any(f.rule_id == "R2" for f in findings)
    assert any(f.rule_id == "R3" for f in findings)

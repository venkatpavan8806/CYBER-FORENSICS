import platform
from datetime import datetime, timezone

import pytest

from ransomtrace.extractors.registry import extract_registry_events
from ransomtrace.models import SourceExtractor
from ransomtrace.simulate.hive_writer import REG_BINARY, REG_SZ, SyntheticHiveBuilder, filetime_bytes

pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="synthetic hive fixtures are generated via the Windows Registry API",
)


@pytest.fixture()
def synthetic_hive(tmp_path):
    hive_path = tmp_path / "test_system_software.hiv"
    now = datetime.now(timezone.utc)
    with SyntheticHiveBuilder(hive_path) as hive:
        hive.set_value(
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "SecurityUpdate",
            REG_SZ,
            r"C:\Users\Public\evil.exe",
        )
        hive.set_value(
            r"Services\NotARealSvc",
            "ImagePath",
            REG_SZ,
            r"C:\Users\Public\svc.exe",
        )
        hive.set_value(
            r"Services\NotARealSvc",  # legitimate-looking sibling, standard path
            "Start",
            REG_SZ,
            "2",
        )
        hive.set_value(
            r"Services\LegitSvc",
            "ImagePath",
            REG_SZ,
            r"C:\Windows\System32\legit.exe",
        )
        hive.set_value(
            r"Services\bam\State\UserSettings\S-1-5-21-1-2-3-1001",
            r"C:\Windows\System32\vssadmin.exe",
            REG_BINARY,
            filetime_bytes(now),
        )
    return hive_path


def test_run_key_persistence_detected(synthetic_hive):
    events = extract_registry_events(synthetic_hive)
    run_events = [e for e in events if e.event_type == "run_key_persistence"]
    assert len(run_events) == 1
    assert run_events[0].source_extractor == SourceExtractor.REGISTRY
    assert run_events[0].raw_evidence["value_name"] == "SecurityUpdate"


def test_suspicious_service_detected_but_standard_path_service_is_not(synthetic_hive):
    events = extract_registry_events(synthetic_hive)
    service_events = [e for e in events if e.event_type == "suspicious_service_created"]
    assert len(service_events) == 1
    assert service_events[0].raw_evidence["service_name"] == "NotARealSvc"


def test_bam_execution_evidence_detected(synthetic_hive):
    events = extract_registry_events(synthetic_hive)
    bam_events = [e for e in events if e.event_type == "suspicious_binary_execution"]
    assert len(bam_events) == 1
    assert "vssadmin.exe" in bam_events[0].raw_evidence["executable"]


def test_missing_hive_keys_do_not_raise(tmp_path):
    empty_hive_path = tmp_path / "empty.hiv"
    with SyntheticHiveBuilder(empty_hive_path) as hive:
        hive.set_value(r"SomeUnrelatedKey", "Foo", REG_SZ, "bar")
    events = extract_registry_events(empty_hive_path)
    assert events == []

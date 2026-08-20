import platform

import pytest

from ransomtrace.correlation.engine import run_correlation
from ransomtrace.ingest.disk_image import ingest_disk_image
from ransomtrace.simulate.synthetic_disk_image import generate_synthetic_disk_image

pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="the synthetic disk image's registry artifact requires the Windows hive writer",
)


def test_synthetic_disk_image_mode_a_produces_ransomware_execution_sequence(tmp_path):
    image_path = generate_synthetic_disk_image(tmp_path / "incident.raw")
    assert image_path.exists()
    assert image_path.stat().st_size > 0

    events = ingest_disk_image(image_path)
    assert events, "Mode A ingestion found no events at all"

    findings = run_correlation(events)
    r4_findings = [f for f in findings if f.rule_id == "R4"]
    assert len(r4_findings) == 1, "expected the correlated Ransomware Execution Sequence finding via Mode A"
    assert r4_findings[0].confidence == "High"

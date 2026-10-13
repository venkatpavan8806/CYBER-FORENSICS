"""End-to-end test of the Streamlit app itself, using Streamlit's official
AppTest harness (programmatic widget interaction - much higher fidelity for
custom-styled widgets like st.radio than coordinate-based browser clicks).
Complements tests/test_web_review.py, which covers the pure decision-merging
logic in isolation.
"""
import platform
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from ransomtrace.simulate.synthetic_incident import generate_synthetic_incident

pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="the synthetic incident's registry artifact requires the Windows hive writer",
)

APP_PATH = Path(__file__).resolve().parent.parent / "ransomtrace" / "validation" / "web_review.py"


def test_analyze_and_confirm_finding_flows_into_report(tmp_path):
    incident_dir = generate_synthetic_incident(tmp_path / "incident")

    at = AppTest.from_file(str(APP_PATH), default_timeout=30)
    at.run()
    assert not at.exception

    path_input = next(w for w in at.text_input if w.label == "Or paste a path here")
    path_input.set_value(str(incident_dir))
    check_button = next(w for w in at.button if w.label == "Check for ransomware")
    check_button.click().run()
    assert not at.exception
    assert any("High risk" in m.value for m in at.markdown)

    # Confirm the first finding (plain-language options shown to the user).
    at.radio[0].set_value("Yes, this is real")
    report_path_input = next(w for w in at.text_input if w.label == "Save report as")
    report_path = tmp_path / "report.html"
    report_path_input.set_value(str(report_path))
    save_button = next(w for w in at.button if w.label == "Save report")
    save_button.click().run()
    assert not at.exception

    assert report_path.exists()
    html = report_path.read_text(encoding="utf-8")
    assert 'badge badge-status-confirmed">Confirmed' in html


def test_sample_incident_button_runs_end_to_end(tmp_path):
    at = AppTest.from_file(str(APP_PATH), default_timeout=30)
    at.run()
    assert not at.exception

    sample_button = next(w for w in at.button if w.label == "Try a sample incident")
    sample_button.click().run()
    assert not at.exception
    assert any("High risk" in m.value for m in at.markdown)

"""Streamlit web review UI (SHOULD-HAVE, Section 8 #10) - an alternative to
validation/cli_review.py for analysts who'd rather click through findings in
a browser than a terminal. Same guarantee either way: every finding needs an
explicit analyst decision before the report treats it as Confirmed.

Run with:

    streamlit run ransomtrace/validation/web_review.py

`apply_review_decisions` is a plain function, deliberately kept independent
of `streamlit` so it's unit-testable without a Streamlit runtime (see
tests/test_web_review.py); only `_run_app` below it touches `st`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ransomtrace.models import Finding, ValidationStatus

_STATUS_LABELS = {
    "Unreviewed": ValidationStatus.UNREVIEWED,
    "Confirmed": ValidationStatus.CONFIRMED,
    "False Positive": ValidationStatus.FALSE_POSITIVE,
    "Uncertain": ValidationStatus.UNCERTAIN,
}


def apply_review_decisions(findings: list[Finding], decisions: dict[str, dict]) -> list[Finding]:
    """Apply {finding_id: {"status": "Confirmed", "note": "..."}} decisions
    onto findings in place, and return them. Decisions for unknown
    finding_ids are ignored, so a partially-built decision dict never errors."""
    by_id = {f.finding_id: f for f in findings}
    for finding_id, decision in decisions.items():
        finding = by_id.get(finding_id)
        if finding is None:
            continue
        status_label = decision.get("status", "Unreviewed")
        finding.validation_status = _STATUS_LABELS.get(status_label, ValidationStatus.UNREVIEWED)
        finding.analyst_note = decision.get("note", "")
    return findings


def _run_app() -> None:  # pragma: no cover - exercised via `streamlit run`, not pytest
    import streamlit as st

    from ransomtrace.correlation.engine import run_correlation
    from ransomtrace.ingest.artifact_folder import ingest_artifact_folder
    from ransomtrace.ingest.disk_image import ingest_disk_image
    from ransomtrace.report.generate import generate_report

    st.set_page_config(page_title="RansomTrace Review", layout="wide")
    st.title("RansomTrace \u2014 Finding Review")
    st.caption(
        "Local, offline ransomware artifact review. Every finding needs your "
        "decision before the report treats it as confirmed."
    )

    if "rt_findings" not in st.session_state:
        st.session_state.rt_findings = None
        st.session_state.rt_input_path = None
        st.session_state.rt_mode = None
        st.session_state.rt_processing_started_at = None

    with st.sidebar:
        st.header("Run analysis")
        mode = st.radio(
            "Ingestion mode", ["b", "a"],
            format_func=lambda m: "Mode B \u2014 artifact folder" if m == "b" else "Mode A \u2014 disk image",
        )
        path = st.text_input("Path", placeholder=r"C:\path\to\artifact_folder_or_image")
        if st.button("Analyze", type="primary", disabled=not path):
            started_at = datetime.now(timezone.utc)
            with st.spinner("Extracting and correlating..."):
                events = ingest_disk_image(path) if mode == "a" else ingest_artifact_folder(path)
                st.session_state.rt_findings = run_correlation(events)
                st.session_state.rt_input_path = path
                st.session_state.rt_mode = mode
                st.session_state.rt_processing_started_at = started_at
            st.success(
                f"{len(st.session_state.rt_findings)} finding(s) produced from "
                f"{len(events)} event(s)."
            )

    findings = st.session_state.rt_findings
    if not findings:
        st.info("Run an analysis from the sidebar to review findings here.")
        return

    decisions: dict[str, dict] = {}
    status_options = list(_STATUS_LABELS.keys())
    for finding in findings:
        with st.expander(f"[{finding.confidence}] {finding.title}", expanded=False):
            st.markdown(f"**Rule:** {finding.rule_id}  **MITRE:** {', '.join(finding.mitre_techniques)}")
            st.markdown(f"**Window:** {finding.window_start.isoformat()} \u2013 {finding.window_end.isoformat()}")
            st.write(finding.description)
            st.markdown(f"**{len(finding.evidence)} supporting event(s):**")
            for event in finding.evidence[:10]:
                st.code(f"[{event.source_extractor.value}] {event.timestamp.isoformat()} - {event.description}")
            if len(finding.evidence) > 10:
                st.caption(f"... and {len(finding.evidence) - 10} more")

            status = st.radio(
                "Validation status", status_options,
                index=status_options.index(finding.validation_status.value),
                key=f"status_{finding.finding_id}", horizontal=True,
            )
            note = st.text_area(
                "Analyst note", value=finding.analyst_note, key=f"note_{finding.finding_id}"
            )
            decisions[finding.finding_id] = {"status": status, "note": note}

    apply_review_decisions(findings, decisions)

    st.divider()
    output_path = st.text_input("Report output path", value="report.html")
    if st.button("Generate report"):
        report_path = generate_report(
            findings,
            input_path=st.session_state.rt_input_path,
            output_path=output_path,
            mode=st.session_state.rt_mode,
            processing_started_at=st.session_state.rt_processing_started_at,
        )
        st.success(f"Report written to {report_path}")
        with open(report_path, "rb") as f:
            st.download_button(
                "Download report", f, file_name=Path(report_path).name, mime="text/html"
            )


if __name__ == "__main__":  # pragma: no cover
    _run_app()

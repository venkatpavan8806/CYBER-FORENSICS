"""Streamlit web review UI (SHOULD-HAVE, Section 8 #10) - a no-terminal,
plain-language front end for RansomTrace, aimed at someone with zero
forensics or coding background. Same guarantee as the CLI flow either way:
every finding needs an explicit human decision before the report treats it
as confirmed.

Run with:

    streamlit run ransomtrace/validation/web_review.py

...or just double-click "Run RansomTrace.bat" in the project root, which
does that for you - no command line needed at all.

`apply_review_decisions` is a plain function, deliberately kept independent
of `streamlit` so it's unit-testable without a Streamlit runtime (see
tests/test_web_review.py); only `_run_app` below it touches `st`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ransomtrace.models import Finding, ValidationStatus

# Internal status keys never change (the report template renders these
# exact strings) - only the on-screen button wording is friendlier.
_STATUS_LABELS = {
    "Unreviewed": ValidationStatus.UNREVIEWED,
    "Confirmed": ValidationStatus.CONFIRMED,
    "False Positive": ValidationStatus.FALSE_POSITIVE,
    "Uncertain": ValidationStatus.UNCERTAIN,
}

# What each internal status is called on screen, for someone who has never
# heard the term "false positive" before.
_STATUS_DISPLAY = {
    "Unreviewed": "Not reviewed yet",
    "Confirmed": "Yes, this is real",
    "False Positive": "No, false alarm",
    "Uncertain": "Not sure",
}
_DISPLAY_TO_STATUS = {v: k for k, v in _STATUS_DISPLAY.items()}

# One plain-English sentence per rule, shown before any technical detail.
_RULE_PLAIN_LANGUAGE = {
    "R1": "A large number of files were suddenly changed to an unfamiliar "
          "file type in a very short time - the classic sign of ransomware "
          "encrypting files.",
    "R2": "A command was found that deletes Windows' built-in backups - "
          "attackers do this so the files can't just be restored for free.",
    "R3": "Something added itself to Windows so it runs automatically every "
          "time the computer starts - a common way malware stays installed.",
    "R4": "This is the important one: file encryption, backup deletion, and "
          "a program installing itself all happened within the same short "
          "window of time. That combination is the signature of an actual "
          "ransomware attack, not a coincidence.",
    "R5": "The security log was cleared around the time of the incident - "
          "some evidence may be missing or hidden as a result.",
}

_CONFIDENCE_PLAIN_LANGUAGE = {
    "High": "The tool is very confident about this.",
    "Medium": "The tool found a match, but it's less certain - worth a closer look.",
    "Low": "This might be worth reviewing, but could also be nothing.",
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


def _pick_path(pick_folder: bool) -> str | None:  # pragma: no cover - opens a real OS dialog
    """Open a native OS file/folder picker on the machine running the app.
    Works because this is a local app: the browser and the Streamlit server
    are the same computer, so a dialog opened server-side appears on screen
    exactly where the user is sitting."""
    import tkinter as tk
    from tkinter import filedialog

    root = tk.Tk()
    root.withdraw()
    root.wm_attributes("-topmost", 1)
    try:
        if pick_folder:
            path = filedialog.askdirectory(master=root, title="Choose the evidence folder")
        else:
            path = filedialog.askopenfilename(master=root, title="Choose the disk image file")
    finally:
        root.destroy()
    return path or None


def _run_app() -> None:  # pragma: no cover - exercised via `streamlit run`, not pytest
    import streamlit as st

    from ransomtrace.correlation.engine import run_correlation
    from ransomtrace.ingest.artifact_folder import ingest_artifact_folder
    from ransomtrace.ingest.disk_image import ingest_disk_image
    from ransomtrace.report.generate import generate_report

    st.set_page_config(page_title="RansomTrace", layout="wide")
    st.title("RansomTrace")
    st.caption(
        "Checks a computer's files for signs of a ransomware attack. Runs entirely on "
        "this machine - nothing is uploaded anywhere. No technical knowledge required."
    )

    if "rt_findings" not in st.session_state:
        st.session_state.rt_findings = None
        st.session_state.rt_input_path = None
        st.session_state.rt_mode = None
        st.session_state.rt_processing_started_at = None
        st.session_state.rt_path_input = ""

    def _run_analysis(path: str, mode: str) -> None:
        started_at = datetime.now(timezone.utc)
        with st.spinner("Checking for ransomware evidence - this can take a moment..."):
            events = ingest_disk_image(path) if mode == "a" else ingest_artifact_folder(path)
            st.session_state.rt_findings = run_correlation(events)
            st.session_state.rt_input_path = path
            st.session_state.rt_mode = mode
            st.session_state.rt_processing_started_at = started_at

    with st.sidebar:
        st.header("1. What do you want to check?")
        st.caption("Pick a folder of evidence, or a single disk image file.")

        if st.button("Choose a folder..."):
            picked = _pick_path(pick_folder=True)
            if picked:
                st.session_state.rt_path_input = picked
        if st.button("Choose a disk image file..."):
            picked = _pick_path(pick_folder=False)
            if picked:
                st.session_state.rt_path_input = picked

        path = st.text_input(
            "Or paste a path here", value=st.session_state.rt_path_input,
            placeholder=r"C:\path\to\folder_or_image",
        )
        st.session_state.rt_path_input = path

        if path:
            detected_mode = "a" if Path(path).is_file() else "b"
            st.caption(
                "Detected: a single disk image file." if detected_mode == "a"
                else "Detected: a folder of evidence files."
            )
        else:
            detected_mode = "b"

        if st.button("Check for ransomware", type="primary", disabled=not path):
            _run_analysis(path, detected_mode)

        st.divider()
        st.header("Don't have evidence handy?")
        st.caption("Generate a safe, made-up example incident and check that instead.")
        if st.button("Try a sample incident"):
            import tempfile

            from ransomtrace.simulate.synthetic_incident import generate_synthetic_incident

            tmp_dir = Path(tempfile.mkdtemp(prefix="ransomtrace_sample_"))
            sample_path = generate_synthetic_incident(tmp_dir / "sample_incident")
            st.session_state.rt_path_input = str(sample_path)
            _run_analysis(str(sample_path), "b")

    findings = st.session_state.rt_findings
    if not findings:
        st.info(
            "Choose a folder or disk image on the left, or try a sample incident, "
            "then click **Check for ransomware**."
        )
        return

    st.success(f"Done - {len(findings)} thing(s) found to review.")

    high_risk = any(f.rule_id == "R4" for f in findings) or any(
        f.confidence == "High" for f in findings
    )
    if high_risk:
        st.error(
            "**This looks like it could be ransomware.** One or more strong warning "
            "signs were found below - review each one and confirm what you see."
        )
    elif findings:
        st.warning(
            "Some suspicious activity was found, but nothing overwhelming yet. "
            "Review each item below."
        )

    with st.expander("What do these terms mean?"):
        st.markdown(
            "- **Confidence** - how sure the tool is about a given finding "
            "(High / Medium / Low).\n"
            "- **MITRE ATT&CK code** (e.g. T1486) - an industry-standard ID for a "
            "type of attacker behavior, used by security teams everywhere.\n"
            "- **SHA-256 hash** - a fingerprint of the evidence, included in the "
            "final report so anyone can verify it wasn't changed afterward."
        )

    decisions: dict[str, dict] = {}
    display_options = list(_STATUS_DISPLAY.values())
    for finding in findings:
        headline = _RULE_PLAIN_LANGUAGE.get(finding.rule_id, finding.description)
        confidence_note = _CONFIDENCE_PLAIN_LANGUAGE.get(finding.confidence, "")
        with st.container(border=True):
            st.subheader(finding.title)
            st.write(headline)
            st.caption(f"{finding.confidence} confidence. {confidence_note}")

            current_display = _STATUS_DISPLAY[finding.validation_status.value]
            display_status = st.radio(
                "Does this match what you're seeing on the computer?",
                display_options,
                index=display_options.index(current_display),
                key=f"status_{finding.finding_id}", horizontal=True,
            )
            note = st.text_area(
                "Notes (optional)", value=finding.analyst_note, key=f"note_{finding.finding_id}"
            )
            decisions[finding.finding_id] = {
                "status": _DISPLAY_TO_STATUS[display_status], "note": note,
            }

            with st.expander("Technical details"):
                st.markdown(
                    f"**Rule:** {finding.rule_id}  **MITRE ATT&CK:** "
                    f"{', '.join(finding.mitre_techniques)}"
                )
                st.markdown(
                    f"**Time window:** {finding.window_start.isoformat()} "
                    f"to {finding.window_end.isoformat()}"
                )
                st.write(finding.description)
                st.markdown(f"**{len(finding.evidence)} supporting event(s):**")
                for event in finding.evidence[:10]:
                    st.code(f"[{event.source_extractor.value}] {event.timestamp.isoformat()} - {event.description}")
                if len(finding.evidence) > 10:
                    st.caption(f"... and {len(finding.evidence) - 10} more")

    apply_review_decisions(findings, decisions)

    st.divider()
    st.header("2. Save your results")
    st.caption("This creates a report you can save, print, or share with someone else.")
    output_path = st.text_input("Save report as", value="RansomTrace_Report.html")
    if st.button("Save report", type="primary"):
        report_path = generate_report(
            findings,
            input_path=st.session_state.rt_input_path,
            output_path=output_path,
            mode=st.session_state.rt_mode,
            processing_started_at=st.session_state.rt_processing_started_at,
        )
        st.success(f"Report saved to {report_path}")
        with open(report_path, "rb") as f:
            st.download_button(
                "Download report", f, file_name=Path(report_path).name, mime="text/html"
            )


if __name__ == "__main__":  # pragma: no cover
    _run_app()

"""RansomTrace dashboard UI (Streamlit) - a no-terminal, plain-language front
end for someone with zero forensics or coding background. Same guarantee as
the CLI flow: every finding needs an explicit human decision before the
report treats it as confirmed.

Layout: a node graph on the left (case -> evidence categories -> a fan of
findings / evidence / MITRE techniques; click anything to inspect it) and a
detail panel on the right with the plain-English analysis and the review
buttons.

Run with:

    streamlit run ransomtrace/validation/web_review.py

...or double-click "Run RansomTrace.bat" in the project root.

`apply_review_decisions` is a plain function, independent of `streamlit`, so
it is unit-testable (see tests/test_web_review.py). Data shaping for the
graph/panel lives in dashboard_data.py for the same reason.
"""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
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

_STATUS_DISPLAY = {
    "Unreviewed": "Not reviewed yet",
    "Confirmed": "Yes, this is real",
    "False Positive": "No, false alarm",
    "Uncertain": "Not sure",
}
_DISPLAY_TO_STATUS = {v: k for k, v in _STATUS_DISPLAY.items()}
_STATUS_CHIP_TONE = {
    "Unreviewed": "none", "Confirmed": "low", "False Positive": "none", "Uncertain": "medium",
}

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

_GRAPH_DIR = Path(__file__).parent / "graph_component"

_CSS = """
<style>
header[data-testid="stHeader"], footer, #MainMenu, [data-testid="stToolbar"],
[data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"],
[data-testid="collapsedControl"] { display: none !important; }
.stApp {
  background:
    radial-gradient(900px 600px at 28% 48%, rgba(30,110,110,.30) 0%, rgba(8,34,40,.0) 70%),
    radial-gradient(1100px 800px at 85% 10%, rgba(40,90,120,.18) 0%, rgba(0,0,0,0) 60%),
    linear-gradient(180deg, #071318 0%, #050d11 100%);
  background-size: 135% 135%, 135% 135%, 100% 100%;
  animation: rt-drift 26s ease-in-out infinite alternate;
}
@keyframes rt-drift {
  0%   { background-position: 0% 0%, 100% 0%, 0 0; }
  100% { background-position: 100% 100%, 0% 70%, 0 0; }
}
@keyframes rt-rise { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: none; } }
@keyframes rt-grow { from { transform: scaleY(0); } to { transform: scaleY(1); } }
@keyframes rt-sheen { 0% { left: -60%; } 55%, 100% { left: 135%; } }
@keyframes rt-blink { 0%, 100% { box-shadow: 0 0 4px #ef4a5f; } 50% { box-shadow: 0 0 15px #ef4a5f; } }
@keyframes rt-glow { 0%, 100% { box-shadow: 0 0 0 rgba(241,217,160,0); } 50% { box-shadow: 0 0 18px rgba(241,217,160,.28); } }
.block-container { padding: 1rem 1.6rem 1.2rem !important; max-width: 100% !important; }
[data-testid="stVerticalBlock"] { gap: 0.7rem; }

/* top bar */
.rt-brand { display: flex; align-items: center; gap: 12px; }
.rt-brand-logo { width: 38px; height: 38px; border-radius: 11px; display: grid; place-items: center;
  border: 1px solid rgba(255,255,255,.18); background: rgba(255,255,255,.05); color: #f1d9a0; }
.rt-brand-name { font-weight: 700; font-size: 15px; line-height: 1.1; color: #fff; }
.rt-brand-sub { font-size: 10.5px; color: #94a1b8; letter-spacing: .04em; }
.rt-pill { display: inline-flex; align-items: center; gap: 8px; padding: 9px 18px; border-radius: 999px;
  font-size: 13px; border: 1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.06); color: #cfd8dc;
  white-space: nowrap; }
.rt-pill i { width: 8px; height: 8px; border-radius: 50%; display: inline-block; background: #94a1b8; }
.rt-pill.tone-high { color: #ffb3bd; border-color: rgba(239,74,95,.55); background: rgba(239,74,95,.12); }
.rt-pill.tone-high i { background: #ef4a5f; box-shadow: 0 0 10px #ef4a5f; }
.rt-pill.tone-medium { color: #ffd9a0; border-color: rgba(242,169,59,.5); background: rgba(242,169,59,.10); }
.rt-pill.tone-medium i { background: #f2a93b; }
.rt-pill.tone-low { color: #bfe8c2; border-color: rgba(111,191,115,.5); background: rgba(111,191,115,.10); }
.rt-pill.tone-low i { background: #6fbf73; }

/* buttons + popovers */
.stButton > button, [data-testid="stPopover"] > div > button, [data-testid="stPopoverButton"] {
  background: rgba(255,255,255,.05); border: 1px solid rgba(255,255,255,.22); color: #eaf0f2;
  border-radius: 11px; font-weight: 500; }
.stButton > button:hover, [data-testid="stPopoverButton"]:hover { border-color: #f1d9a0; color: #fff; }
.stButton > button[kind="primary"] { background: linear-gradient(135deg, #f1d9a0, #c9a45a); color: #1a1405;
  border: none; font-weight: 600; }

/* detail panel */
.st-key-rt_detail {
  background: linear-gradient(165deg, rgba(255,255,255,.075), rgba(255,255,255,.025));
  border: 1px solid rgba(255,255,255,.10); border-radius: 22px; padding: 1.25rem 1.3rem;
  box-shadow: 0 24px 70px rgba(0,0,0,.5); backdrop-filter: blur(16px);
}
.rt-eyebrow { display: flex; align-items: center; gap: 9px; color: #cfd8dc; font-size: 14px; }
.rt-eyebrow svg { color: #f1d9a0; }
.rt-title { font-size: 25px; line-height: 1.2; font-weight: 500; color: #fff; margin: 10px 0 4px; }
.rt-subtitle { color: #94a1b8; font-size: 13px; margin-bottom: 4px; }
.rt-statusrow { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin: 10px 0 14px;
  padding: 11px 14px; border-radius: 14px; border: 1px solid rgba(255,255,255,.08); background: rgba(255,255,255,.035);
  font-size: 12.5px; color: #94a1b8; }
.rt-chip { display: inline-block; padding: 2px 10px; border-radius: 6px; font-size: 11.5px; font-weight: 600;
  border: 1px solid rgba(148,161,184,.5); color: #cfd8dc; background: rgba(148,161,184,.10); }
.rt-chip.tone-high { color: #ff9aa8; border-color: rgba(239,74,95,.6); background: rgba(239,74,95,.14); }
.rt-chip.tone-medium { color: #ffcd88; border-color: rgba(242,169,59,.6); background: rgba(242,169,59,.14); }
.rt-chip.tone-low { color: #9fe0a4; border-color: rgba(111,191,115,.6); background: rgba(111,191,115,.14); }
.rt-chip.tone-info { color: #9db8ff; border-color: rgba(91,140,255,.6); background: rgba(91,140,255,.14); }
.rt-score { border-radius: 16px; padding: 14px 16px; margin: 6px 0 12px; border: 1px solid rgba(255,255,255,.08); }
.rt-score.tone-high { background: linear-gradient(135deg, rgba(239,74,95,.30), rgba(60,20,30,.45)); }
.rt-score.tone-medium { background: linear-gradient(135deg, rgba(242,169,59,.28), rgba(60,40,15,.45)); }
.rt-score.tone-low { background: linear-gradient(135deg, rgba(111,191,115,.26), rgba(20,50,30,.45)); }
.rt-score.tone-info { background: linear-gradient(135deg, rgba(91,140,255,.28), rgba(20,30,60,.45)); }
.rt-score.tone-none { background: linear-gradient(135deg, rgba(148,161,184,.2), rgba(25,30,40,.45)); }
.rt-score-top { display: flex; justify-content: space-between; align-items: center; color: #e8eef0; font-size: 14px; }
.rt-score-body { display: flex; justify-content: space-between; align-items: flex-end; gap: 12px; margin-top: 4px; }
.rt-score-value { font-size: 40px; font-weight: 300; color: #fff; line-height: 1.1; letter-spacing: .01em; }
.rt-score-sub { font-size: 11.5px; color: #cfd8dc; opacity: .8; }
.rt-tiles { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 14px; }
.rt-tile { display: flex; align-items: center; gap: 12px; padding: 14px; border-radius: 14px;
  border: 1px solid rgba(255,255,255,.08); background: rgba(255,255,255,.04); }
.rt-tile-ico { color: #94a1b8; display: grid; place-items: center; }
.rt-tile-num { font-size: 24px; font-weight: 400; color: #fff; line-height: 1.1; }
.rt-tile-lbl { font-size: 11.5px; color: #94a1b8; }
.rt-section { display: flex; align-items: center; gap: 8px; color: #e8eef0; font-weight: 600; font-size: 14.5px; margin: 6px 0 8px; }
.rt-section svg { color: #f1d9a0; }
.rt-body { color: #cfd8dc; font-size: 13.5px; line-height: 1.6; }
.rt-body .rt-note { color: #94a1b8; font-size: 12px; margin-top: 6px; }
.rt-links { display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0 10px; }
.rt-hero { text-align: left; }
.rt-hero h2 { font-size: 26px; font-weight: 500; color: #fff; margin: 8px 0 8px; }
.rt-hero .rt-body { margin-bottom: 14px; }
[data-testid="stRadio"] { margin-top: .55rem; }
.rt-brand-logo { animation: rt-glow 4s ease-in-out infinite; }
.rt-pill.tone-high i { animation: rt-blink 1.8s ease-in-out infinite; }
.rt-eyebrow, .rt-title, .rt-subtitle, .rt-statusrow, .rt-score, .rt-tile, .rt-section, .rt-body, .rt-links, .rt-hero h2 {
  animation: rt-rise .6s cubic-bezier(.2,.7,.2,1) both; }
.rt-title { animation-delay: .04s; } .rt-subtitle { animation-delay: .08s; } .rt-statusrow { animation-delay: .12s; }
.rt-score { animation-delay: .16s; position: relative; overflow: hidden; }
.rt-score::after { content: ""; position: absolute; top: 0; left: -60%; width: 40%; height: 100%; pointer-events: none;
  background: linear-gradient(100deg, transparent, rgba(255,255,255,.09), transparent); animation: rt-sheen 5.5s ease-in-out infinite; }
.rt-tile:nth-child(1) { animation-delay: .22s; } .rt-tile:nth-child(2) { animation-delay: .28s; }
.rt-tile:nth-child(3) { animation-delay: .34s; } .rt-tile:nth-child(4) { animation-delay: .40s; }
.rt-section { animation-delay: .44s; } .rt-body { animation-delay: .5s; } .rt-links { animation-delay: .56s; }
.rt-spark rect { transform-box: fill-box; transform-origin: 50% 100%; animation: rt-grow .75s cubic-bezier(.2,.7,.2,1) both; }
.stButton > button, [data-testid="stPopoverButton"] { transition: border-color .25s, box-shadow .25s, transform .25s; }
.stButton > button:hover, [data-testid="stPopoverButton"]:hover { box-shadow: 0 0 18px rgba(241,217,160,.22); transform: translateY(-1px); }
@media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
[data-testid="stExpander"] { border: 1px solid rgba(255,255,255,.10); border-radius: 12px; background: rgba(255,255,255,.03); }
[data-testid="stTextArea"] textarea, [data-testid="stTextInput"] input { background: rgba(0,0,0,.28); border-color: rgba(255,255,255,.14); }
</style>
"""

_BRAND_HTML = (
    '<div class="rt-brand"><div class="rt-brand-logo"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" '
    'stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/>'
    '<path d="M12 8.5v5M9.5 11h5"/></svg></div><div><div class="rt-brand-name">RansomTrace</div>'
    '<div class="rt-brand-sub">Ransomware Evidence Platform</div></div></div>'
)

_ICON_ALERT = ('<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.6" '
               'stroke-linejoin="round" stroke-linecap="round"><path d="M12 3l9.5 17h-19z"/><path d="M12 10v4.5M12 17.5v.01"/></svg>')
_ICON_BRAIN = ('<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" '
               'stroke-linecap="round"><path d="M12 3v3M12 18v3M4.5 7.5l2.1 1.5M17.4 15l2.1 1.5M4.5 16.5L6.6 15M17.4 9l2.1-1.5"/>'
               '<circle cx="12" cy="12" r="3.2"/></svg>')


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


def _md(text: str) -> str:
    return text.replace("\\", "\\\\").replace("_", "\\_").replace("*", "\\*").replace("`", "\\`")


def _render_evidence(st, events, key: str) -> None:  # pragma: no cover
    from ransomtrace import plain_language as pl

    st.markdown("**What was found**")
    for line in pl.summarize_events(events):
        st.markdown(f"- {_md(line)}")
    if st.checkbox("Show each item", key=f"items_{key}"):
        for event in events[:25]:
            st.markdown(f"- *{pl.friendly_time(event.timestamp)}* \u2014 {_md(pl.plain_event(event))}")
        if len(events) > 25:
            st.caption(f"... and {len(events) - 25} more")
    if st.checkbox("Show raw technical text", key=f"raw_{key}"):
        for event in events[:10]:
            st.code(f"[{event.source_extractor.value}] {event.timestamp.isoformat()} - {event.description}")
        if len(events) > 10:
            st.caption(f"... and {len(events) - 10} more")


def _short(text: str, limit: int = 40) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _pill_html(findings: list[Finding] | None) -> str:
    from ransomtrace.validation import dashboard_data as dd

    if findings is None:
        return '<span class="rt-pill"><i></i>No analysis yet \u2014 start a new one</span>'
    if not findings:
        return '<span class="rt-pill tone-low"><i></i>No ransomware evidence found</span>'
    risk = dd.risk_level(findings)
    text = {
        "high": "High risk \u2014 this looks like ransomware",
        "medium": "Suspicious activity found \u2014 review below",
        "low": "Low-risk items to review",
    }[risk]
    return f'<span class="rt-pill tone-{risk}"><i></i>{escape(text)}</span>'


def _run_app() -> None:  # pragma: no cover - exercised via `streamlit run` / AppTest
    import tempfile

    import streamlit as st
    import streamlit.components.v1 as components

    from ransomtrace.correlation.engine import run_correlation
    from ransomtrace.correlation.mitre_map import technique_name
    from ransomtrace.ingest.artifact_folder import ingest_artifact_folder
    from ransomtrace.ingest.disk_image import ingest_disk_image
    from ransomtrace.report.generate import generate_report
    from ransomtrace.simulate.synthetic_incident import generate_synthetic_incident
    from ransomtrace.validation import dashboard_data as dd

    st.set_page_config(page_title="RansomTrace", layout="wide", initial_sidebar_state="collapsed")
    st.markdown(_CSS, unsafe_allow_html=True)
    graph = components.declare_component("ransomtrace_graph", path=str(_GRAPH_DIR))

    defaults = {
        "rt_findings": None, "rt_events": [], "rt_input_path": None, "rt_mode": None,
        "rt_processing_started_at": None, "rt_path_input": "", "rt_decisions": {},
        "rt_sel": None, "rt_run_id": 0, "rt_case_name": "No case loaded", "rt_case_sub": "Choose evidence to begin",
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)

    def _run_analysis(path: str, mode: str, case_name: str, case_sub: str) -> None:
        started_at = datetime.now(timezone.utc)
        with st.spinner("Checking for ransomware evidence - this can take a moment..."):
            events = ingest_disk_image(path) if mode == "a" else ingest_artifact_folder(path)
            st.session_state.rt_events = events
            st.session_state.rt_findings = run_correlation(events)
        st.session_state.rt_input_path = path
        st.session_state.rt_mode = mode
        st.session_state.rt_processing_started_at = started_at
        st.session_state.rt_decisions = {}
        st.session_state.rt_sel = None
        st.session_state.rt_run_id += 1
        st.session_state.rt_case_name = case_name
        st.session_state.rt_case_sub = case_sub

    def _run_sample() -> None:
        tmp_dir = Path(tempfile.mkdtemp(prefix="ransomtrace_sample_"))
        sample_path = generate_synthetic_incident(tmp_dir / "sample_incident")
        _run_analysis(str(sample_path), "b", "Sample incident", "Built-in example")

    # ---- top bar ----------------------------------------------------------
    c_brand, c_pill, c_new, c_exp = st.columns([2.2, 3.4, 1.3, 1.3], vertical_alignment="center")

    with c_new:
        with st.popover("+ New analysis", width="stretch"):
            st.markdown("**What do you want to check?**")
            st.caption("Pick a folder of evidence, or a single disk image file.")
            if st.button("Choose a folder...", key="btn_pick_folder"):
                picked = _pick_path(pick_folder=True)
                if picked:
                    st.session_state.rt_path_input = picked
            if st.button("Choose a disk image file...", key="btn_pick_file"):
                picked = _pick_path(pick_folder=False)
                if picked:
                    st.session_state.rt_path_input = picked
            path = st.text_input(
                "Or paste a path here", value=st.session_state.rt_path_input,
                placeholder=r"C:\path\to\folder_or_image",
            )
            st.session_state.rt_path_input = path
            detected_mode = "a" if path and Path(path).is_file() else "b"
            if path:
                st.caption(
                    "Detected: a single disk image file." if detected_mode == "a"
                    else "Detected: a folder of evidence files."
                )
            if st.button("Check for ransomware", type="primary", disabled=not path, key="btn_check"):
                _run_analysis(
                    path, detected_mode, Path(path).name or path,
                    "Disk image" if detected_mode == "a" else "Evidence folder",
                )
            st.divider()
            st.caption("Don't have evidence handy? Generate a safe, made-up example incident.")
            if st.button("Try a sample incident", key="btn_sample_pop"):
                _run_sample()

    findings = st.session_state.rt_findings
    events = st.session_state.rt_events

    with c_exp:
        with st.popover("Export report", width="stretch"):
            if not findings:
                st.caption("Run an analysis first - then you can save a report here.")
            else:
                st.caption("Creates a report you can save, print, or share with someone else.")
                output_path = st.text_input("Save report as", value="RansomTrace_Report.html")
                if st.button("Save report", type="primary", key="btn_save_report"):
                    # Pull the latest choice straight from the review widgets, since
                    # the detail panel (which normally records it) renders later.
                    for f in findings:
                        shown = st.session_state.get(f"status_{f.finding_id}")
                        if shown in _DISPLAY_TO_STATUS:
                            prior = st.session_state.rt_decisions.get(f.finding_id, {})
                            st.session_state.rt_decisions[f.finding_id] = {
                                "status": _DISPLAY_TO_STATUS[shown],
                                "note": st.session_state.get(f"note_{f.finding_id}", prior.get("note", "")),
                            }
                    apply_review_decisions(findings, st.session_state.rt_decisions)
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

    with c_brand:
        st.markdown(_BRAND_HTML, unsafe_allow_html=True)
    with c_pill:
        st.markdown(
            f'<div style="text-align:center">{_pill_html(st.session_state.rt_findings)}</div>',
            unsafe_allow_html=True,
        )

    # ---- dashboard --------------------------------------------------------
    findings = st.session_state.rt_findings
    events = st.session_state.rt_events
    decisions = st.session_state.rt_decisions
    left, right = st.columns([1.7, 1], gap="medium")

    sel = st.session_state.rt_sel or (dd.default_selection(findings) if findings else {})
    by_id = {f.finding_id: f for f in (findings or [])}

    with right:
        with st.container(key="rt_detail"):
            if findings is None:
                st.markdown(
                    '<div class="rt-hero"><div class="rt-eyebrow">' + _ICON_BRAIN + ' Welcome</div>'
                    '<h2>Check a computer for ransomware</h2><div class="rt-body">'
                    'RansomTrace looks through a computer\'s files, settings, and logs for the footprints '
                    'ransomware leaves behind, then explains what it found in plain English. '
                    'Everything runs on this machine - nothing is uploaded anywhere.'
                    '<div class="rt-note">Use <b>+ New analysis</b> above to pick a folder or disk image, '
                    'or try the built-in example to see how it works.</div></div></div>',
                    unsafe_allow_html=True,
                )
                if st.button("Try a sample incident", type="primary", key="btn_sample_hero"):
                    _run_sample()
                    st.rerun()
            elif not findings:
                st.markdown(
                    '<div class="rt-hero"><div class="rt-eyebrow">' + _ICON_BRAIN + ' Result</div>'
                    '<h2>Nothing suspicious found</h2><div class="rt-body">The checks did not find signs of '
                    'a ransomware attack in this evidence. That is not a guarantee - the tool only detects '
                    'the patterns it has rules for - but nothing alarming turned up.</div></div>',
                    unsafe_allow_html=True,
                )
            else:
                _render_detail(st, dd, technique_name, findings, events, by_id, sel, decisions)

    apply_review_decisions(findings or [], decisions)

    with left:
        data = dd.build_graph_data(
            findings or [], events or [],
            st.session_state.rt_case_name, st.session_state.rt_case_sub,
        )
        value = graph(
            data=data, selected=sel, default=None, key=f"rt_graph_{st.session_state.rt_run_id}",
        )
        if findings and value and value != st.session_state.rt_sel:
            st.session_state.rt_sel = value
            st.rerun()


def _render_detail(st, dd, technique_name, findings, events, by_id, sel, decisions) -> None:  # pragma: no cover
    cat, item = sel.get("category"), sel.get("item")
    grouped = dd.group_events(events)
    index = dd.technique_index(findings)

    if cat == "mitre" and item in index:
        fs = index[item]
        top = min(("High", "Medium", "Low").index(f.confidence) for f in fs)
        tone = ("high", "medium", "low")[top]
        all_events = [e for f in fs for e in f.evidence]
        st.markdown(
            f'<div class="rt-eyebrow">{_ICON_ALERT} MITRE ATT&amp;CK technique</div>'
            f'<div class="rt-title">{escape(item)} \u2014 {escape(technique_name(item))}</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            dd.score_card_html("Findings using it", str(len(fs)), "across this case", tone,
                               dd.evidence_buckets(all_events), chip=("Used in " + str(len(fs)))),
            unsafe_allow_html=True,
        )
        st.markdown(
            dd.tiles_html([
                ("doc", len(all_events), "Evidence events"),
                ("shield", len(fs), "Findings"),
                ("check", ("High", "Medium", "Low")[top], "Top confidence"),
                ("clock", dd.format_duration(max(f.window_end for f in fs) - min(f.window_start for f in fs)), "Time span"),
            ]),
            unsafe_allow_html=True,
        )
        st.markdown(
            f'<div class="rt-section">{_ICON_BRAIN} Analysis</div><div class="rt-body">'
            f'{escape(dd.PLAIN_MITRE_EXPLAIN.get(item, "A recognised attacker technique from the MITRE ATT&CK catalogue."))}'
            '<div class="rt-note">MITRE ATT&amp;CK is an industry-standard catalogue of attacker behaviour, '
            'used by security teams everywhere.</div></div><div class="rt-links">'
            + "".join(f'<span class="rt-chip tone-{dd._TONE.get(f.confidence, "info")}">{escape(_short(f.title))}</span>' for f in fs)
            + '</div>',
            unsafe_allow_html=True,
        )
        return

    if cat in dd.EXTRACTOR_IDS and item and ":" in item:
        ext, etype = item.split(":", 1)
        evs = grouped.get(ext, {}).get(etype, [])
        if evs:
            feeds = [f for f in findings if any(e.event_type == etype for e in f.evidence)]
            span = max(e.timestamp for e in evs) - min(e.timestamp for e in evs)
            source = {"filesystem": "Files", "registry": "Registry", "eventlog_vss": "Event logs"}[ext]
            st.markdown(
                f'<div class="rt-eyebrow">{_ICON_ALERT} {source} evidence</div>'
                f'<div class="rt-title">{escape(dd.PLAIN_EVENT_TYPE.get(etype, etype))}</div>',
                unsafe_allow_html=True,
            )
            st.markdown(
                dd.score_card_html("Flagged items", str(len(evs)), "timeline of when they appeared", "info",
                                   dd.evidence_buckets(evs), chip=source),
                unsafe_allow_html=True,
            )
            st.markdown(
                dd.tiles_html([
                    ("doc", len(evs), "Flagged items"),
                    ("clock", dd.format_duration(span), "Time span"),
                    ("shield", len(feeds), "Findings it feeds"),
                    ("check", source, "Evidence source"),
                ]),
                unsafe_allow_html=True,
            )
            st.markdown(
                f'<div class="rt-section">{_ICON_BRAIN} Analysis</div><div class="rt-body">'
                f'{escape(dd.PLAIN_EVENT_EXPLAIN.get(etype, ""))}</div>'
                + ('<div class="rt-section">Feeds these findings</div><div class="rt-links">'
                   + "".join(f'<span class="rt-chip tone-{dd._TONE.get(f.confidence, "info")}">{escape(_short(f.title))}</span>' for f in feeds)
                   + '</div>' if feeds else ''),
                unsafe_allow_html=True,
            )
            with st.expander("Explore details"):
                _render_evidence(st, evs, item)
            return

    finding = by_id.get(item) or by_id[dd.default_selection(findings)["item"]]
    tone = dd._TONE.get(finding.confidence, "info")
    dec = decisions.get(finding.finding_id, {"status": "Unreviewed", "note": ""})
    st.markdown(
        f'<div class="rt-eyebrow">{_ICON_ALERT} Ransomware finding</div>'
        f'<div class="rt-title">{escape(finding.title)}</div>'
        f'<div class="rt-subtitle">Rule {escape(finding.rule_id)} \u00b7 '
        + " ".join(f'<span class="rt-chip tone-info">{escape(t)}</span>' for t in finding.mitre_techniques)
        + '</div>'
        f'<div class="rt-statusrow"><span class="rt-chip tone-{_STATUS_CHIP_TONE[dec["status"]]}">'
        f'{escape(_STATUS_DISPLAY[dec["status"]])}</span>'
        f'<span>{escape(finding.window_start.strftime("%d %b %Y, %H:%M:%S"))} UTC</span></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        dd.score_card_html("Confidence", finding.confidence.upper(),
                           f"{len(finding.evidence)} evidence events over time", tone,
                           dd.evidence_buckets(finding.evidence), chip=finding.rule_id),
        unsafe_allow_html=True,
    )
    st.markdown(
        dd.tiles_html([
            ("doc", len(finding.evidence), "Evidence events"),
            ("shield", len(finding.mitre_techniques), "MITRE techniques"),
            ("clock", dd.format_duration(finding.window_end - finding.window_start), "Time window"),
            ("check", finding.rule_id, "Detected by rule"),
        ]),
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<div class="rt-section">{_ICON_BRAIN} Analysis</div><div class="rt-body">'
        f'{escape(_RULE_PLAIN_LANGUAGE.get(finding.rule_id, finding.description))}'
        f'<div class="rt-note">{escape(finding.confidence)} confidence. '
        f'{escape(_CONFIDENCE_PLAIN_LANGUAGE.get(finding.confidence, ""))}</div></div>',
        unsafe_allow_html=True,
    )

    display_options = list(_STATUS_DISPLAY.values())
    choice = st.radio(
        "Does this match what you're seeing on the computer?", display_options,
        index=display_options.index(_STATUS_DISPLAY[dec["status"]]),
        key=f"status_{finding.finding_id}", horizontal=True,
    )
    note = st.text_area("Notes (optional)", value=dec["note"], key=f"note_{finding.finding_id}")
    decisions[finding.finding_id] = {"status": _DISPLAY_TO_STATUS[choice], "note": note}

    with st.expander("Explore details"):
        from ransomtrace import plain_language as pl

        start, end = pl.friendly_time(finding.window_start), pl.friendly_time(finding.window_end)
        st.markdown(f"**When:** {start}" if start == end else f"**When:** {start} to {end}")
        _render_evidence(st, finding.evidence, finding.finding_id)


if __name__ == "__main__":  # pragma: no cover
    _run_app()

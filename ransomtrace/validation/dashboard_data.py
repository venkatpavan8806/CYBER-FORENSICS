"""Pure-Python data shaping for the dashboard UI (no streamlit imports, so it
is unit-testable). Turns findings + extracted events into:

  - the node-graph payload drawn by graph_component/index.html
    (case orb -> category cards -> a fan of items), and
  - the small HTML fragments (score card, stat tiles, sparkline) used by the
    right-hand detail panel in web_review.py.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from html import escape

from ransomtrace.correlation.mitre_map import technique_name
from ransomtrace.models import Event, Finding, ValidationStatus
from ransomtrace.plain_language import PLAIN_EVENT_TYPE  # noqa: F401  (re-exported)

PLAIN_EVENT_EXPLAIN = {
    "file_extension_change": "Files whose names end in an unfamiliar extension. When many appear "
        "at once it usually means something renamed them after locking (encrypting) their contents.",
    "ransom_note_file": "A file named like the 'how to pay us' notes that ransomware leaves behind.",
    "run_key_persistence": "A program was set to start automatically every time Windows starts.",
    "suspicious_service_created": "A new background service was installed that runs from an unusual folder.",
    "suspicious_binary_execution": "Windows recorded that a tool commonly used to delete backups was run.",
    "shadow_copy_deletion_command": "Windows' built-in restore points and backups were deleted by command.",
    "audit_log_cleared": "The Windows security log was erased, which hides what happened.",
}

PLAIN_MITRE_EXPLAIN = {
    "T1486": "Attackers lock files with encryption so victims lose access to them.",
    "T1490": "Attackers delete backups so the victim cannot recover without paying.",
    "T1112": "Attackers change Windows registry settings to alter how the system behaves.",
    "T1547.001": "Attackers make a program start automatically at login via the registry.",
    "T1543.003": "Attackers install a Windows service so their program keeps running.",
    "T1070.001": "Attackers erase event logs to cover their tracks.",
}

CATEGORY_DEFS = [
    ("findings", "Findings", "alert"),
    ("filesystem", "File evidence", "folder"),
    ("registry", "Registry evidence", "registry"),
    ("eventlog_vss", "Event-log evidence", "log"),
    ("mitre", "MITRE techniques", "shield"),
]
EXTRACTOR_IDS = ("filesystem", "registry", "eventlog_vss")

_CONF_RANK = {"High": 0, "Medium": 1, "Low": 2}
_TONE = {"High": "high", "Medium": "medium", "Low": "low"}
_STATUS_KEY = {
    ValidationStatus.CONFIRMED: "confirmed",
    ValidationStatus.FALSE_POSITIVE: "false_positive",
    ValidationStatus.UNCERTAIN: "uncertain",
    ValidationStatus.UNREVIEWED: "unreviewed",
}


def ordered_findings(findings: list[Finding]) -> list[Finding]:
    """Correlated R4 first, then by confidence, then chronologically."""
    return sorted(
        findings,
        key=lambda f: (f.rule_id != "R4", _CONF_RANK.get(f.confidence, 3), f.window_start),
    )


def risk_level(findings: list[Finding]) -> str:
    if not findings:
        return "none"
    if any(f.rule_id == "R4" or f.confidence == "High" for f in findings):
        return "high"
    if any(f.confidence == "Medium" for f in findings):
        return "medium"
    return "low"


def group_events(events: list[Event]) -> dict[str, dict[str, list[Event]]]:
    grouped: dict[str, dict[str, list[Event]]] = {k: defaultdict(list) for k in EXTRACTOR_IDS}
    for event in events:
        grouped[event.source_extractor.value][event.event_type].append(event)
    return grouped


def technique_index(findings: list[Finding]) -> dict[str, list[Finding]]:
    index: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for tid in finding.mitre_techniques:
            index[tid].append(finding)
    return index


def _short_mitre(f: Finding) -> str:
    first = f.mitre_techniques[0] if f.mitre_techniques else ""
    extra = len(f.mitre_techniques) - 1
    return f"{first} +{extra}" if extra > 0 else first


def build_graph_data(
    findings: list[Finding], events: list[Event], case_name: str, case_sub: str
) -> dict:
    grouped = group_events(events)
    index = technique_index(findings)

    finding_items = [
        {
            "id": f.finding_id,
            "label": f.title,
            "sub": f"{f.rule_id} · {_short_mitre(f)}",
            "badge": f.confidence,
            "tone": _TONE.get(f.confidence, "info"),
            "status": _STATUS_KEY[f.validation_status],
        }
        for f in ordered_findings(findings)
    ]

    categories = []
    for cat_id, label, icon in CATEGORY_DEFS:
        if cat_id == "findings":
            items, count = finding_items, len(finding_items)
        elif cat_id == "mitre":
            items = []
            for tid, fs in sorted(index.items(), key=lambda kv: (-len(kv[1]), kv[0])):
                top = min((_CONF_RANK.get(f.confidence, 3) for f in fs), default=3)
                tone = {0: "high", 1: "medium", 2: "low"}.get(top, "info")
                items.append({
                    "id": tid, "label": tid, "sub": technique_name(tid),
                    "badge": f"{len(fs)} finding{'s' if len(fs) != 1 else ''}",
                    "tone": tone, "status": "none",
                })
            count = len(items)
        else:
            items = []
            for etype, evs in sorted(grouped[cat_id].items(), key=lambda kv: -len(kv[1])):
                items.append({
                    "id": f"{cat_id}:{etype}",
                    "label": PLAIN_EVENT_TYPE.get(etype, etype),
                    "sub": f"{len(evs)} flagged",
                    "badge": f"×{len(evs)}", "tone": "info", "status": "none",
                })
            count = sum(len(v) for v in grouped[cat_id].values())
        categories.append({"id": cat_id, "label": label, "icon": icon, "count": count, "items": items})

    return {
        "case": {
            "name": case_name, "sub": case_sub,
            "risk": risk_level(findings), "findings": len(findings),
        },
        "categories": categories,
    }


def default_selection(findings: list[Finding]) -> dict:
    ordered = ordered_findings(findings)
    return {"category": "findings", "item": ordered[0].finding_id if ordered else None}


def evidence_buckets(events: list[Event], buckets: int = 28) -> list[int]:
    if not events:
        return [0] * buckets
    stamps = sorted(e.timestamp.timestamp() for e in events)
    lo, hi = stamps[0], stamps[-1]
    if hi - lo < 1e-6:
        out = [0] * buckets
        out[buckets // 2] = len(stamps)
        return out
    out = [0] * buckets
    for s in stamps:
        out[min(buckets - 1, int((s - lo) / (hi - lo) * buckets))] += 1
    return out


def format_duration(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds <= 0:
        return "instant"
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


# --- HTML fragments for the detail panel -------------------------------------

_TONE_COLOR = {
    "high": "#ef4a5f", "medium": "#f2a93b", "low": "#6fbf73", "info": "#5b8cff", "none": "#94a1b8",
}

_ICON_CHECK = (
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
    'stroke-width="1.6"><circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.6 2.6L16 9.5"/></svg>'
)
_ICON_DOC = (
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
    'stroke-width="1.6"><path d="M7 3h7l4 4v14H7z"/><path d="M14 3v4h4M10 12h5M10 16h5"/></svg>'
)
_ICON_CLOCK = (
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
    'stroke-width="1.6"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>'
)
_ICON_SHIELD = (
    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
    'stroke-width="1.6"><path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/></svg>'
)
TILE_ICONS = {"check": _ICON_CHECK, "doc": _ICON_DOC, "clock": _ICON_CLOCK, "shield": _ICON_SHIELD}


def sparkline_svg(buckets: list[int], tone: str) -> str:
    color = _TONE_COLOR.get(tone, _TONE_COLOR["info"])
    width, height, n = 170, 38, len(buckets)
    peak = max(buckets) or 1
    bar_w = width / n
    bars = []
    for i, v in enumerate(buckets):
        h = 2 if v == 0 else max(4, v / peak * (height - 2))
        opacity = 0.25 if v == 0 else 0.55 + 0.45 * (v / peak)
        bars.append(
            f'<rect x="{i * bar_w + 0.6:.1f}" y="{height - h:.1f}" width="{bar_w - 1.4:.1f}" '
            f'height="{h:.1f}" rx="1" fill="{color}" opacity="{opacity:.2f}" style="animation-delay:{i * 22}ms"/>'
        )
    return f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}">{"".join(bars)}</svg>'


def score_card_html(label: str, value: str, sub: str, tone: str, buckets: list[int], chip: str = "") -> str:
    chip_html = f'<span class="rt-chip tone-{tone}">{escape(chip)}</span>' if chip else ""
    return (
        f'<div class="rt-score tone-{tone}">'
        f'<div class="rt-score-top"><span class="rt-score-label">{escape(label)}</span>{chip_html}</div>'
        f'<div class="rt-score-body"><div><div class="rt-score-value">{escape(value)}</div>'
        f'<div class="rt-score-sub">{escape(sub)}</div></div>'
        f'<div class="rt-spark">{sparkline_svg(buckets, tone)}</div></div></div>'
    )


def tiles_html(tiles: list[tuple[str, str, str]]) -> str:
    """tiles: (icon key, number/text, label)."""
    cells = "".join(
        f'<div class="rt-tile"><div class="rt-tile-ico">{TILE_ICONS[icon]}</div>'
        f'<div><div class="rt-tile-num">{escape(str(num))}</div>'
        f'<div class="rt-tile-lbl">{escape(label)}</div></div></div>'
        for icon, num, label in tiles
    )
    return f'<div class="rt-tiles">{cells}</div>'

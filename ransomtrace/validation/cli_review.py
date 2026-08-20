"""Terminal-based human-in-the-loop validation flow (MUST-HAVE, Section 8 #6).

RansomTrace never presents a finding as fact without an analyst having looked
at it - every Finding starts as ValidationStatus.UNREVIEWED and this flow asks
a human to mark each one Confirmed / False Positive / Uncertain before it goes
into the report. `input_func` is injectable so this is unit-testable without a
real terminal (see tests/test_validation.py).
"""
from __future__ import annotations

from collections.abc import Callable

from ransomtrace.models import Finding, ValidationStatus

_PROMPT = "  [c]onfirm / [f]alse positive / [u]ncertain / [s]kip (leave unreviewed) > "

_CHOICE_MAP = {
    "c": ValidationStatus.CONFIRMED,
    "confirm": ValidationStatus.CONFIRMED,
    "f": ValidationStatus.FALSE_POSITIVE,
    "false positive": ValidationStatus.FALSE_POSITIVE,
    "u": ValidationStatus.UNCERTAIN,
    "uncertain": ValidationStatus.UNCERTAIN,
}


def _print_finding(finding: Finding, index: int, total: int, printer: Callable[[str], None]) -> None:
    printer(f"\n[{index}/{total}] {finding.title}")
    printer(f"  Rule: {finding.rule_id}   Confidence: {finding.confidence}   "
            f"MITRE: {', '.join(finding.mitre_techniques)}")
    printer(f"  Window: {finding.window_start.isoformat()} to {finding.window_end.isoformat()}")
    printer(f"  {finding.description}")
    printer(f"  Evidence ({len(finding.evidence)} event(s)):")
    for event in finding.evidence[:5]:
        printer(f"    - [{event.source_extractor.value}] {event.description}")
    if len(finding.evidence) > 5:
        printer(f"    ... and {len(finding.evidence) - 5} more")


def review_findings_cli(
    findings: list[Finding],
    input_func: Callable[[str], str] = input,
    printer: Callable[[str], None] = print,
) -> list[Finding]:
    """Walk the analyst through each finding and record Confirmed / False
    Positive / Uncertain / (left) Unreviewed. Mutates and returns `findings`."""
    printer(f"RansomTrace validation: {len(findings)} finding(s) to review.\n")

    for i, finding in enumerate(findings, start=1):
        _print_finding(finding, i, len(findings), printer)
        while True:
            raw = input_func(_PROMPT).strip().lower()
            if raw in ("s", "skip", ""):
                break
            if raw in _CHOICE_MAP:
                finding.validation_status = _CHOICE_MAP[raw]
                note = input_func("  Optional note (Enter to skip) > ").strip()
                if note:
                    finding.analyst_note = note
                break
            printer(f"  Unrecognized input: {raw!r}")

    confirmed = sum(1 for f in findings if f.validation_status == ValidationStatus.CONFIRMED)
    printer(f"\nReview complete. {confirmed}/{len(findings)} finding(s) confirmed.")
    return findings

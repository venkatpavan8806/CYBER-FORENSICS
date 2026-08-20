"""Correlation ruleset v1.

Plain, readable rule functions - not a black box, not ML (see Section 2 of the
project spec: no ML/AI classifier). Every rule takes the full normalized Event
stream (or the findings from earlier rules, for the cross-artifact Rule 4) and
returns a list of Findings. Each Finding is fully traceable back to specific
Events via its `evidence` list - no unexplained scores.

Timing constants are named and documented here, not scattered as magic numbers.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from ransomtrace.correlation.mitre_map import MITRE_TECHNIQUES
from ransomtrace.models import Event, Finding, SourceExtractor

# --- Named, documented thresholds -------------------------------------------

# Rule 1 (mass rename/extension-change burst).
# T: ransomware encryption of a typical user's files completes within minutes,
# not hours - real-world incident write-ups (e.g. major ransomware family DFIR
# reports referenced in MITRE ATT&CK T1486) consistently show file trees of
# thousands of files being touched in single-digit minutes. 10 minutes gives
# headroom for slightly slower encryption (large files, throttled I/O) without
# being so wide it starts merging unrelated bulk file operations together.
BURST_WINDOW_MINUTES = 10
# N: a conservative floor meant to separate "mass encryption" from an ordinary
# user renaming a handful of files by hand. Real incidents touch far more than
# this; a low threshold is intentional so we err toward not missing a real
# burst, and rely on confidence scaling (see _burst_confidence) to communicate
# how far above the floor a given burst actually is.
BURST_MIN_FILES = 15

# Rule 4 (cross-artifact correlation window). Wider than the burst window
# because registry persistence and shadow-copy deletion are typically staged
# as separate steps of one attack execution (e.g. a script running several
# commands in sequence), not literally simultaneous with the encryption burst
# itself - but they still belong to the same incident, not different days.
CORRELATION_WINDOW_MINUTES = 30


def _finding_id(rule_id: str, *parts: str) -> str:
    digest = hashlib.sha1("|".join((rule_id, *parts)).encode("utf-8")).hexdigest()[:10]
    return f"{rule_id}-{digest}"


_CONFIDENCE_LEVELS = ["Low", "Medium", "High"]


def _burst_confidence(count: int, threshold: int, cluster: list[Event] | None = None) -> str:
    if count >= threshold * 3:
        level = "High"
    elif count >= threshold * 1.5:
        level = "Medium"
    else:
        level = "Low"

    # Entropy corroboration (SHOULD-HAVE, Section 8 #11): if we sampled real
    # file content and it reads as high-entropy (see extractors/filesystem.py
    # HIGH_ENTROPY_THRESHOLD), that's independent evidence this really is
    # encrypted output rather than an unrelated bulk rename - bump confidence
    # one level, capped at High. Events without an entropy sample (no read
    # access to the file content) simply don't participate in the average.
    if cluster:
        entropies = [
            e.raw_evidence["entropy_bits_per_byte"]
            for e in cluster
            if "entropy_bits_per_byte" in e.raw_evidence
        ]
        if entropies and (sum(entropies) / len(entropies)) >= 7.5:
            idx = min(_CONFIDENCE_LEVELS.index(level) + 1, len(_CONFIDENCE_LEVELS) - 1)
            level = _CONFIDENCE_LEVELS[idx]

    return level


def _time_clusters(
    events: list[Event], window: timedelta, min_count: int
) -> list[list[Event]]:
    """Greedy sliding-window clustering: find runs of >= min_count events all
    falling within `window` of each other. Non-overlapping - once a cluster is
    emitted, scanning resumes after it, so one contiguous burst is reported
    once rather than as many overlapping sub-windows."""
    ordered = sorted(events, key=lambda e: e.timestamp)
    clusters: list[list[Event]] = []
    left = 0
    n = len(ordered)
    while left < n:
        right = left
        while right + 1 < n and ordered[right + 1].timestamp - ordered[left].timestamp <= window:
            right += 1
        cluster = ordered[left : right + 1]
        if len(cluster) >= min_count:
            clusters.append(cluster)
            left = right + 1
        else:
            left += 1
    return clusters


# --- Rule 1: mass rename / extension-change burst ---------------------------

def rule_mass_rename_burst(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    extension_events: dict[str, list[Event]] = {}
    for event in events:
        if (
            event.source_extractor == SourceExtractor.FILESYSTEM
            and event.event_type == "file_extension_change"
        ):
            ext = event.raw_evidence.get("extension", "")
            extension_events.setdefault(ext, []).append(event)

    window = timedelta(minutes=BURST_WINDOW_MINUTES)
    for ext, ext_events in extension_events.items():
        for cluster in _time_clusters(ext_events, window, BURST_MIN_FILES):
            window_start = min(e.timestamp for e in cluster)
            window_end = max(e.timestamp for e in cluster)
            confidence = _burst_confidence(len(cluster), BURST_MIN_FILES, cluster)
            findings.append(
                Finding(
                    finding_id=_finding_id("R1", ext, window_start.isoformat()),
                    rule_id="R1",
                    title=f"Mass extension-change burst: .{ext} ({len(cluster)} files)",
                    mitre_techniques=["T1486"],
                    confidence=confidence,
                    description=(
                        f"{len(cluster)} files were changed to the unrecognized "
                        f"extension '.{ext}' within a {BURST_WINDOW_MINUTES}-minute "
                        f"window ({window_start.isoformat()} to {window_end.isoformat()}), "
                        f"consistent with mass file encryption."
                    ),
                    evidence=cluster,
                    window_start=window_start,
                    window_end=window_end,
                )
            )
    return findings


# --- Rule 2: shadow-copy deletion command evidence ---------------------------

def rule_shadow_copy_deletion(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if (
            event.source_extractor == SourceExtractor.EVENTLOG_VSS
            and event.event_type == "shadow_copy_deletion_command"
        ):
            findings.append(
                Finding(
                    finding_id=_finding_id("R2", event.timestamp.isoformat(), event.description),
                    rule_id="R2",
                    title="Shadow-copy / system-recovery deletion command",
                    mitre_techniques=["T1490"],
                    confidence="High",
                    description=event.description,
                    evidence=[event],
                    window_start=event.timestamp,
                    window_end=event.timestamp,
                )
            )
    return findings


# --- Rule 3: new persistence registry key ------------------------------------

def rule_persistence_registry(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if event.source_extractor != SourceExtractor.REGISTRY:
            continue

        if event.event_type == "run_key_persistence":
            techniques = ["T1112", "T1547.001"]
            title = "New Run/RunOnce autostart persistence value"
        elif event.event_type == "suspicious_service_created":
            techniques = ["T1112", "T1543.003"]
            title = "New service with non-standard ImagePath"
        else:
            continue

        findings.append(
            Finding(
                finding_id=_finding_id("R3", event.timestamp.isoformat(), event.description),
                rule_id="R3",
                title=title,
                mitre_techniques=techniques,
                confidence="Medium",
                description=event.description,
                evidence=[event],
                window_start=event.timestamp,
                window_end=event.timestamp,
            )
        )
    return findings


# --- Rule 4: correlated ransomware execution sequence (the core rule) -------

def rule_correlated_execution_sequence(
    burst_findings: list[Finding],
    vss_findings: list[Finding],
    registry_findings: list[Finding],
) -> list[Finding]:
    """If a Rule-2 (VSS deletion) finding and a Rule-3 (registry persistence)
    finding both fall within CORRELATION_WINDOW_MINUTES of a Rule-1 (mass
    rename burst) finding's window, merge all three into one high-confidence
    'Ransomware Execution Sequence' finding. This is the cross-artifact
    correlation the whole project exists to demonstrate."""
    findings: list[Finding] = []
    window = timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    for burst in burst_findings:
        expanded_start = burst.window_start - window
        expanded_end = burst.window_end + window

        nearby_vss = [
            f for f in vss_findings if expanded_start <= f.window_start <= expanded_end
        ]
        nearby_registry = [
            f for f in registry_findings if expanded_start <= f.window_start <= expanded_end
        ]

        if nearby_vss and nearby_registry:
            all_evidence = list(burst.evidence)
            for f in nearby_vss:
                all_evidence.extend(f.evidence)
            for f in nearby_registry:
                all_evidence.extend(f.evidence)

            all_timestamps = [e.timestamp for e in all_evidence]
            merged_start, merged_end = min(all_timestamps), max(all_timestamps)

            techniques = sorted(
                {"T1486", "T1490", "T1112"}
                | {t for f in nearby_registry for t in f.mitre_techniques}
            )

            findings.append(
                Finding(
                    finding_id=_finding_id("R4", burst.finding_id, merged_start.isoformat()),
                    rule_id="R4",
                    title="Ransomware Execution Sequence (correlated)",
                    mitre_techniques=techniques,
                    confidence="High",
                    description=(
                        f"Correlated attack chain: {burst.title}, combined with "
                        f"{len(nearby_vss)} shadow-copy-deletion finding(s) and "
                        f"{len(nearby_registry)} registry-persistence finding(s) "
                        f"within {CORRELATION_WINDOW_MINUTES} minutes of each other. "
                        f"This cross-artifact pattern (mass encryption + backup "
                        f"destruction + persistence) is the signature sequence of "
                        f"a ransomware execution, not an isolated event."
                    ),
                    evidence=all_evidence,
                    window_start=merged_start,
                    window_end=merged_end,
                )
            )

    return findings


# --- Rule 5: anti-forensics / log tampering signal ---------------------------

def rule_anti_forensics_signal(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if (
            event.source_extractor == SourceExtractor.EVENTLOG_VSS
            and event.event_type == "audit_log_cleared"
        ):
            findings.append(
                Finding(
                    finding_id=_finding_id("R5", event.timestamp.isoformat()),
                    rule_id="R5",
                    title="Audit log cleared (anti-forensics)",
                    mitre_techniques=["T1070.001"],
                    confidence="High",
                    description=(
                        "Event ID 1102 (audit log cleared) was found. Evidence may "
                        "be incomplete due to log clearing - other findings in this "
                        "report should be treated as a lower bound, not a complete "
                        "picture of attacker activity."
                    ),
                    evidence=[event],
                    window_start=event.timestamp,
                    window_end=event.timestamp,
                )
            )
    return findings


assert set(MITRE_TECHNIQUES) >= {
    "T1486", "T1490", "T1112", "T1547.001", "T1070.001", "T1543.003"
}, "mitre_map.py is missing a technique ID referenced by rules.py"

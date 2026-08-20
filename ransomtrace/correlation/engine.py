"""Correlation engine: runs all rules against a normalized Event stream and
returns the combined list of Findings.

Both the granular per-rule findings (R1/R2/R3/R5) and the merged cross-artifact
finding (R4) are returned - an analyst should be able to see the individual
evidence as well as the higher-confidence correlated story built on top of it.
"""
from __future__ import annotations

from ransomtrace.correlation import rules
from ransomtrace.models import Event, Finding


def run_correlation(events: list[Event]) -> list[Finding]:
    burst_findings = rules.rule_mass_rename_burst(events)
    vss_findings = rules.rule_shadow_copy_deletion(events)
    registry_findings = rules.rule_persistence_registry(events)
    anti_forensics_findings = rules.rule_anti_forensics_signal(events)

    correlated_findings = rules.rule_correlated_execution_sequence(
        burst_findings, vss_findings, registry_findings
    )

    all_findings = (
        correlated_findings
        + burst_findings
        + vss_findings
        + registry_findings
        + anti_forensics_findings
    )
    all_findings.sort(key=lambda f: (f.window_start, f.rule_id))
    return all_findings

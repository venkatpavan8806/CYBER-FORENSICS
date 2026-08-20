from datetime import datetime, timezone

from ransomtrace.models import Finding, ValidationStatus
from ransomtrace.validation.web_review import apply_review_decisions


def _finding(finding_id: str) -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        finding_id=finding_id,
        rule_id="R1",
        title="Test finding",
        mitre_techniques=["T1486"],
        confidence="Medium",
        description="test",
        evidence=[],
        window_start=now,
        window_end=now,
    )


def test_apply_decisions_sets_status_and_note():
    findings = [_finding("a")]
    apply_review_decisions(findings, {"a": {"status": "Confirmed", "note": "matches pattern"}})
    assert findings[0].validation_status == ValidationStatus.CONFIRMED
    assert findings[0].analyst_note == "matches pattern"


def test_unknown_finding_id_is_ignored():
    findings = [_finding("a")]
    apply_review_decisions(findings, {"does-not-exist": {"status": "Confirmed"}})
    assert findings[0].validation_status == ValidationStatus.UNREVIEWED


def test_missing_status_defaults_to_unreviewed():
    findings = [_finding("a")]
    apply_review_decisions(findings, {"a": {"note": "just a note"}})
    assert findings[0].validation_status == ValidationStatus.UNREVIEWED
    assert findings[0].analyst_note == "just a note"


def test_multiple_findings_independent_decisions():
    findings = [_finding("a"), _finding("b")]
    apply_review_decisions(
        findings,
        {
            "a": {"status": "False Positive", "note": "benign bulk rename"},
            "b": {"status": "Uncertain", "note": ""},
        },
    )
    assert findings[0].validation_status == ValidationStatus.FALSE_POSITIVE
    assert findings[1].validation_status == ValidationStatus.UNCERTAIN

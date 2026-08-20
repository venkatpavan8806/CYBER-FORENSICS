from datetime import datetime, timezone

from ransomtrace.models import Finding, ValidationStatus
from ransomtrace.validation.cli_review import review_findings_cli


def _finding(finding_id: str) -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        finding_id=finding_id,
        rule_id="R1",
        title="Test finding",
        mitre_techniques=["T1486"],
        confidence="Medium",
        description="test description",
        evidence=[],
        window_start=now,
        window_end=now,
    )


def test_confirm_sets_status_and_note():
    findings = [_finding("a")]
    responses = iter(["c", "looks like real ransomware activity"])
    review_findings_cli(findings, input_func=lambda _: next(responses), printer=lambda _: None)
    assert findings[0].validation_status == ValidationStatus.CONFIRMED
    assert findings[0].analyst_note == "looks like real ransomware activity"


def test_false_positive_sets_status():
    findings = [_finding("a")]
    responses = iter(["f", ""])
    review_findings_cli(findings, input_func=lambda _: next(responses), printer=lambda _: None)
    assert findings[0].validation_status == ValidationStatus.FALSE_POSITIVE


def test_uncertain_sets_status():
    findings = [_finding("a")]
    responses = iter(["u", ""])
    review_findings_cli(findings, input_func=lambda _: next(responses), printer=lambda _: None)
    assert findings[0].validation_status == ValidationStatus.UNCERTAIN


def test_skip_leaves_unreviewed():
    findings = [_finding("a")]
    review_findings_cli(findings, input_func=lambda _: "s", printer=lambda _: None)
    assert findings[0].validation_status == ValidationStatus.UNREVIEWED


def test_invalid_input_reprompts_then_accepts():
    findings = [_finding("a")]
    responses = iter(["nonsense", "c", ""])
    review_findings_cli(findings, input_func=lambda _: next(responses), printer=lambda _: None)
    assert findings[0].validation_status == ValidationStatus.CONFIRMED


def test_multiple_findings_reviewed_independently():
    findings = [_finding("a"), _finding("b")]
    responses = iter(["c", "", "f", ""])
    review_findings_cli(findings, input_func=lambda _: next(responses), printer=lambda _: None)
    assert findings[0].validation_status == ValidationStatus.CONFIRMED
    assert findings[1].validation_status == ValidationStatus.FALSE_POSITIVE

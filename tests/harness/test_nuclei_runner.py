from __future__ import annotations

import json
import subprocess

from waf_factory.harness import nuclei_runner
from waf_factory.harness.mock_waf import HarnessEvent
from waf_factory.models import (
    Condition,
    EnforcementMode,
    FieldType,
    IntermediateRule,
    Operator,
    Severity,
)


def _rule() -> IntermediateRule:
    return IntermediateRule(
        rule_id="test-rule",
        name="Test Rule",
        cve_id="CVE-2099-0001",
        severity=Severity.HIGH,
        action=EnforcementMode.BLOCK,
        confidence=0.9,
        conditions=[
            Condition(field_type=FieldType.QUERY, operator=Operator.CONTAINS, pattern="UNION SELECT"),
        ],
    )


def test_classify_outcome_blocked_when_no_findings_and_events_blocked() -> None:
    events = [HarnessEvent(timestamp=1.0, method="GET", path="/x", query="q=UNION SELECT", body_snippet="", matched_rule_ids=["test-rule"], blocked=True)]
    outcome, matched = nuclei_runner._classify_outcome([], events)
    assert outcome == "blocked"
    assert "test-rule" in matched


def test_classify_outcome_matched_but_allowed_when_not_blocked() -> None:
    events = [HarnessEvent(timestamp=1.0, method="GET", path="/x", query="q=UNION SELECT", body_snippet="", matched_rule_ids=["test-rule"], blocked=False)]
    outcome, _ = nuclei_runner._classify_outcome([], events)
    assert outcome == "matched-but-allowed"


def test_classify_outcome_undetected_when_findings_but_no_block() -> None:
    events = [HarnessEvent(timestamp=1.0, method="GET", path="/x", query="q=x", body_snippet="", matched_rule_ids=[], blocked=False)]
    outcome, _ = nuclei_runner._classify_outcome([{"template-id": "x"}], events)
    assert outcome == "undetected"


def test_classify_outcome_template_did_not_fire_when_nothing_happened() -> None:
    outcome, _ = nuclei_runner._classify_outcome([], [])
    assert outcome == "template_did_not_fire"


def test_run_effectiveness_skips_when_binary_missing(monkeypatch) -> None:
    monkeypatch.setattr(nuclei_runner, "nuclei_available", lambda: False)
    report = nuclei_runner.run_effectiveness(rules=[_rule()], cve_id="CVE-2099-0001", templates=[])
    assert report.available is False
    assert any("nuclei" in note for note in report.notes)


def test_run_effectiveness_reports_no_templates(monkeypatch) -> None:
    monkeypatch.setattr(nuclei_runner, "nuclei_available", lambda: True)
    monkeypatch.setattr(nuclei_runner, "resolve_templates_for_cve", lambda *a, **k: [])
    report = nuclei_runner.run_effectiveness(rules=[_rule()], cve_id="CVE-2099-0001")
    assert report.available is True
    assert report.templates_run == 0
    assert any("No nuclei templates matched" in note for note in report.notes)


def test_run_effectiveness_end_to_end_with_stub_nuclei(monkeypatch, tmp_path) -> None:
    # Craft a fake template on disk that classify_outcome can identify by id
    template_file = tmp_path / "fake.yaml"
    template_file.write_text(
        "id: cve-fake-sqli\n"
        "info:\n  name: Fake\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/x?q=UNION SELECT\"\n    matchers:\n      - type: word\n        words:\n          - \"admin\"\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(nuclei_runner, "nuclei_available", lambda: True)

    def fake_run_once(target_url: str, template_path, timeout: float):
        # simulate an attacker request from nuclei that the mock WAF should block
        import httpx

        try:
            httpx.get(f"{target_url}/x", params={"q": "1 UNION SELECT password"}, timeout=2.0)
        except Exception:
            pass
        # Nuclei found nothing because harness blocked with 403
        return [], ""

    monkeypatch.setattr(nuclei_runner, "_run_nuclei_once", fake_run_once)

    report = nuclei_runner.run_effectiveness(
        rules=[_rule()],
        cve_id="CVE-FAKE",
        templates=[template_file],
        include_benign=False,
    )

    assert report.available is True
    assert report.templates_run >= 1
    assert report.exploit_templates_run == 1
    assert report.exploit_blocked == 1
    assert report.block_rate == 1.0
    assert any(o.template_id == "cve-fake-sqli" for o in report.outcomes)

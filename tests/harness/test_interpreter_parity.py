from __future__ import annotations

from waf_factory.harness.interpreter import match_pattern, matches_condition, rule_matches_payload
from waf_factory.models import (
    Condition,
    EnforcementMode,
    FieldType,
    IntermediateRule,
    Operator,
    Severity,
)
from waf_factory.simulation import _matches, replay_rules
from waf_factory.models import PocArtifact


def test_match_pattern_regex_contains_equals_parity() -> None:
    assert match_pattern("hello UNION select", Operator.REGEX, "(?i)union") is True
    assert _matches("hello UNION select", Operator.REGEX, "(?i)union") is True
    assert match_pattern("Hello", Operator.CONTAINS, "hello") is True
    assert _matches("Hello", Operator.CONTAINS, "hello") is True
    assert match_pattern("abc", Operator.EQUALS, "abc") is True
    assert _matches("abc", Operator.EQUALS, "abc") is True
    assert match_pattern("nope", Operator.REGEX, "[invalid") is False


def test_rule_matches_payload_or_semantics() -> None:
    rule = IntermediateRule(
        rule_id="r1",
        name="test",
        cve_id="CVE-X",
        severity=Severity.HIGH,
        action=EnforcementMode.BLOCK,
        confidence=0.9,
        conditions=[
            Condition(field_type=FieldType.QUERY, operator=Operator.CONTAINS, pattern="alpha"),
            Condition(field_type=FieldType.QUERY, operator=Operator.CONTAINS, pattern="beta"),
        ],
    )
    assert rule_matches_payload(rule, "beta value") is True
    assert rule_matches_payload(rule, "gamma") is False


def test_replay_still_works_after_interpreter_extraction() -> None:
    rule = IntermediateRule(
        rule_id="r1",
        name="test",
        cve_id="CVE-X",
        severity=Severity.HIGH,
        action=EnforcementMode.BLOCK,
        confidence=0.9,
        conditions=[
            Condition(field_type=FieldType.QUERY, operator=Operator.REGEX, pattern="(?i)union\\s+select"),
        ],
    )
    pocs = [PocArtifact(cve_id="CVE-X", source="test", payload="q=1 UNION SELECT")]
    results = replay_rules([rule], pocs)
    assert results
    assert results[0].exploit_detection_rate == 1.0

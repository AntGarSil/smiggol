from __future__ import annotations

import httpx

from waf_factory.harness.mock_waf import MockWaf
from waf_factory.models import (
    Condition,
    EnforcementMode,
    FieldType,
    IntermediateRule,
    Operator,
    Severity,
)


def _sqli_rule(action: EnforcementMode) -> IntermediateRule:
    return IntermediateRule(
        rule_id="test-sqli",
        name="SQLi guard",
        cve_id="CVE-2099-0001",
        severity=Severity.HIGH,
        action=action,
        confidence=0.9,
        conditions=[
            Condition(field_type=FieldType.QUERY, operator=Operator.REGEX, pattern="(?i)union\\s+select"),
            Condition(field_type=FieldType.BODY, operator=Operator.CONTAINS, pattern="' OR '1'='1"),
        ],
    )


def test_mock_waf_blocks_matching_query() -> None:
    with MockWaf(rules=[_sqli_rule(EnforcementMode.BLOCK)]) as waf:
        response = httpx.get(f"{waf.base_url}/items", params={"q": "1 UNION SELECT password"})
        assert response.status_code == 403
        assert response.headers.get("X-WAF-Rule") == "test-sqli"

        response = httpx.get(f"{waf.base_url}/items", params={"q": "hello"})
        assert response.status_code == 200
        assert "X-WAF-Match" not in response.headers

    events = waf.snapshot_events()
    assert any(event.blocked for event in events)
    assert any(not event.blocked for event in events)


def test_mock_waf_count_mode_reports_match_without_blocking() -> None:
    with MockWaf(rules=[_sqli_rule(EnforcementMode.BLOCK)], enforcement=EnforcementMode.COUNT) as waf:
        response = httpx.get(f"{waf.base_url}/items", params={"q": "1 UNION SELECT password"})
        assert response.status_code == 200
        assert response.headers.get("X-WAF-Match") == "test-sqli"


def test_mock_waf_body_and_header_matching() -> None:
    header_rule = IntermediateRule(
        rule_id="test-header",
        name="Bad UA",
        cve_id="CVE-2099-0002",
        severity=Severity.MEDIUM,
        action=EnforcementMode.BLOCK,
        confidence=0.8,
        conditions=[
            Condition(field_type=FieldType.HEADER, operator=Operator.CONTAINS, pattern="EvilBot", header_name="user-agent"),
        ],
    )
    with MockWaf(rules=[header_rule]) as waf:
        blocked = httpx.get(f"{waf.base_url}/", headers={"User-Agent": "EvilBot/1.0"})
        assert blocked.status_code == 403
        allowed = httpx.get(f"{waf.base_url}/", headers={"User-Agent": "Mozilla/5.0"})
        assert allowed.status_code == 200

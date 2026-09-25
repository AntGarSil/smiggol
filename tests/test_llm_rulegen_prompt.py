from __future__ import annotations

from waf_factory.llm_rulegen import LlmRuleGenerator
from waf_factory.models import CveIntel, PocArtifact, Provider, Severity


def test_prompt_contains_nuclei_template_context() -> None:
    llm = LlmRuleGenerator(model="test-model")
    intel = CveIntel(
        cve_id="CVE-2026-7777",
        description="Template-driven SQLi exploit",
        severity=Severity.HIGH,
        tags=["sqli"],
        references=["https://example.com/cve"],
    )
    pocs = [
        PocArtifact(
            cve_id="CVE-2026-7777",
            source="nuclei-templates/http/cves/2026/test.yaml",
            payload="GET /vuln?id=1' UNION SELECT user,password-- HTTP/1.1",
        )
    ]

    prompt = llm._build_prompt(intel, pocs)

    assert "Nuclei templates involved:" in prompt
    assert "nuclei-templates/http/cves/2026/test.yaml" in prompt
    assert "Known exploit payloads:" in prompt
    assert "UNION SELECT" in prompt


def test_prompt_includes_explicit_header_coverage_requirements() -> None:
    llm = LlmRuleGenerator(model="test-model")
    intel = CveIntel(
        cve_id="CVE-2021-44228",
        description="Log4Shell",
        severity=Severity.CRITICAL,
        tags=["rce"],
    )
    pocs = [
        PocArtifact(
            cve_id="CVE-2021-44228",
            source="nuclei-templates/http/cves/2021/CVE-2021-44228.yaml",
            payload="GET /?x=${jndi:ldap://x} HTTP/1.1",
        ),
        PocArtifact(
            cve_id="CVE-2021-44228",
            source="nuclei-templates/http/cves/2021/CVE-2021-44228.yaml",
            payload="User-Agent: ${jndi:ldap://x}",
        ),
        PocArtifact(
            cve_id="CVE-2021-44228",
            source="nuclei-templates/http/cves/2021/CVE-2021-44228.yaml",
            payload="Accept: ${jndi:ldap://x}",
        ),
    ]

    prompt = llm._build_prompt(intel, pocs)

    assert "Observed injection surfaces:" in prompt
    assert "query_injection_present: yes" in prompt
    assert "observed_header_names: accept, user-agent" in prompt
    assert "COVERAGE REQUIREMENTS (must satisfy all):" in prompt
    assert "field_type=query" in prompt
    assert "exact header_name: accept, user-agent" in prompt
    assert "QUALITY BAR (must satisfy):" in prompt


def test_prompt_includes_log4shell_quality_pattern_families() -> None:
    llm = LlmRuleGenerator(model="test-model")
    intel = CveIntel(
        cve_id="CVE-2021-44228",
        description="Apache Log4j JNDI injection",
        severity=Severity.CRITICAL,
        tags=["rce"],
    )
    pocs = [
        PocArtifact(
            cve_id="CVE-2021-44228",
            source="nuclei-templates:http/cves/2021/CVE-2021-44228.yaml",
            payload="GET /?x=${jndi:ldap://x} HTTP/1.1",
        ),
        PocArtifact(
            cve_id="CVE-2021-44228",
            source="nuclei-templates:http/cves/2021/CVE-2021-44228.yaml",
            payload="Cookie: a=${jndi:ldap://x}",
        ),
    ]

    prompt = llm._build_prompt(intel, pocs)

    assert "Log4Shell/JNDI-specific minimum pattern families to cover" in prompt
    assert "Obfuscated jndi token assembly" in prompt
    assert "lookup fallback patterns".lower() in prompt.lower()
    assert "cookie coverage" in prompt.lower()


def test_prompt_for_non_log4shell_does_not_force_jndi_guidance() -> None:
    llm = LlmRuleGenerator(model="test-model")
    intel = CveIntel(
        cve_id="CVE-2024-34102",
        description="WordPress REST API batch endpoint abuse",
        severity=Severity.CRITICAL,
        tags=["rce"],
    )
    pocs = [
        PocArtifact(
            cve_id="CVE-2024-34102",
            source="nuclei-templates:http/cves/2024/CVE-2024-34102.yaml",
            payload="GET /wp-json/wp/v2/users?rest_route=/batch/v1 HTTP/1.1",
        ),
        PocArtifact(
            cve_id="CVE-2024-34102",
            source="nuclei-templates:http/cves/2024/CVE-2024-34102.yaml",
            payload='{"requests":[{"method":"POST","path":"///wp/v2/users"}],"validation":"parse_path_failed"}',
        ),
    ]

    prompt = llm._build_prompt(intel, pocs)

    assert "JNDI-focused" not in prompt
    assert "Log4Shell/JNDI-specific minimum pattern families to cover" not in prompt


def test_stabilize_prompt_includes_prior_audit_recommendations() -> None:
    from waf_factory.models import Condition, EnforcementMode, FieldType, IntermediateRule, Operator

    llm = LlmRuleGenerator(model="test-model")
    intel = CveIntel(cve_id="CVE-2026-7777", description="SQL injection", severity=Severity.HIGH)
    rule = IntermediateRule(
        rule_id="cve-2026-7777-llm",
        name="SQL injection rule",
        cve_id=intel.cve_id,
        severity=intel.severity,
        action=EnforcementMode.COUNT,
        confidence=0.8,
        conditions=[
            Condition(field_type=FieldType.QUERY, operator=Operator.REGEX, pattern="(?i)union")
        ],
    )

    prompt = llm.build_stabilize_prompt(
        intel=intel,
        pocs=[],
        current_rule=rule,
        replay_results=[],
        validation_issues=[],
        providers=[Provider.AWS, Provider.AZURE],
        audit_feedback="- Require UNION and SELECT in the same expression to reduce false positives.",
    )

    assert "Prior audit recommendations" in prompt
    assert "Require UNION and SELECT" in prompt
    assert "Revise the current rule in place" in prompt
    assert "each regex pattern must be at most 200 characters" in prompt
    assert 'oversize_handling="MATCH"' in prompt

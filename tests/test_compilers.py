import pytest

from waf_factory.compilers import compile_aws, compile_azure
from waf_factory.models import Condition, EnforcementMode, FieldType, IntermediateRule, Operator, Provider, Severity
from waf_factory.validation import validate_rules


def _rule(mode: EnforcementMode) -> IntermediateRule:
    return IntermediateRule(
        rule_id="cve-2021-44228-llm",
        name="Log4Shell",
        cve_id="CVE-2021-44228",
        severity=Severity.CRITICAL,
        action=mode,
        confidence=0.9,
        conditions=[
            Condition(
                field_type=FieldType.HEADER,
                operator=Operator.REGEX,
                pattern=r"\$\{jndi:(ldap|ldaps)://",
                header_name="User-Agent",
            )
        ],
    )


def test_compile_aws_uses_count_action_for_monitoring_mode() -> None:
    artifact = compile_aws([_rule(EnforcementMode.COUNT)])
    assert "action {" in artifact.terraform
    assert "count {}" in artifact.terraform
    assert "allow {}" not in artifact.terraform.split("rule {")[1]


def test_compile_aws_renders_all_headers_block_and_cookie_coverage_for_jndi() -> None:
    artifact = compile_aws([_rule(EnforcementMode.BLOCK)])
    assert "headers {" in artifact.terraform
    assert "match_pattern {" in artifact.terraform
    assert "all {}" in artifact.terraform
    assert "single_header:" not in artifact.terraform
    assert "cookies {" in artifact.terraform


def test_compile_aws_uses_url_decode_then_lowercase_transformations() -> None:
    artifact = compile_aws([_rule(EnforcementMode.BLOCK)])
    assert 'type     = "URL_DECODE"' in artifact.terraform
    assert 'type     = "LOWERCASE"' in artifact.terraform


def test_compile_aws_escapes_terraform_interpolation_marker() -> None:
    artifact = compile_aws([_rule(EnforcementMode.BLOCK)])
    # Generated regex strings should not contain a raw unescaped `${` interpolation marker.
    assert "${jndi:" not in artifact.terraform
    assert "\\$\\{jndi:" in artifact.terraform or "$${jndi:" in artifact.terraform


def test_compile_aws_uses_pattern_sets_per_surface() -> None:
    rule = IntermediateRule
    artifact = compile_aws(
        [
            rule(
                rule_id="cve-2021-44228-llm",
                name="Log4Shell",
                cve_id="CVE-2021-44228",
                severity=Severity.CRITICAL,
                action=EnforcementMode.COUNT,
                confidence=0.9,
                conditions=[
                    Condition(field_type=FieldType.QUERY, operator=Operator.REGEX, pattern=r"foo"),
                    Condition(field_type=FieldType.QUERY, operator=Operator.REGEX, pattern=r"bar"),
                    Condition(field_type=FieldType.BODY, operator=Operator.REGEX, pattern=r"body-one"),
                    Condition(field_type=FieldType.BODY, operator=Operator.REGEX, pattern=r"body-two"),
                    Condition(
                        field_type=FieldType.HEADER,
                        operator=Operator.REGEX,
                        pattern=r"\$\{jndi:ldap://",
                        header_name="User-Agent",
                    ),
                    Condition(
                        field_type=FieldType.HEADER,
                        operator=Operator.REGEX,
                        pattern=r"\$\{[^}]{0,20}j[^}]{0,10}n[^}]{0,10}d[^}]{0,10}i[^}]{0,50}:ldap://",
                        header_name="X-Api-Version",
                    ),
                ],
            )
        ]
    )

    # One each for query, body, headers, plus one cookie statement.
    assert artifact.terraform.count('resource "aws_wafv2_regex_pattern_set"') == 4
    assert artifact.terraform.count("regex_pattern_set_reference_statement {") == 4
    assert 'regex_string = "foo"' in artifact.terraform
    assert 'regex_string = "bar"' in artifact.terraform
    assert "(?:foo)|(?:bar)" not in artifact.terraform
    assert 'oversize_handling = "MATCH"' in artifact.terraform


@pytest.mark.parametrize("compiler", [compile_aws, compile_azure])
def test_compilers_reject_oversized_regex(compiler) -> None:
    rule = _rule(EnforcementMode.COUNT)
    rule.conditions[0].pattern = "x" * 201

    with pytest.raises(ValueError, match="exceeds 200"):
        compiler([rule])


def test_validation_reports_selected_provider_regex_limit() -> None:
    rule = _rule(EnforcementMode.COUNT)
    rule.conditions[0].pattern = "x" * 613

    issues = validate_rules([rule], [Provider.AWS, Provider.AZURE])

    assert len([issue for issue in issues if issue.level == "error"]) == 2
    assert any("aws regex pattern length 613 exceeds" in issue.message for issue in issues)
    assert any("azure regex pattern length 613 exceeds" in issue.message for issue in issues)

from __future__ import annotations

from collections import OrderedDict
import re

from waf_factory.models import Condition, IntermediateRule, Provider, ProviderArtifact
from waf_factory.provider_constraints import REGEX_PATTERN_MAX_LENGTH


_AWS_PATTERN_SET_MAX_PATTERNS = 10


def _action(mode: str) -> str:
    # In monitoring mode, matching requests should be counted, not allowed-by-rule.
    return "count" if mode == "count" else "block"


def _aws_field_lines(condition: Condition) -> list[str]:
    if condition.field_type.value == "uri_path":
        return ["              uri_path {}"]
    if condition.field_type.value == "query":
        return ["              query_string {}"]
    if condition.field_type.value == "body":
        return [
            "              body {",
            '                oversize_handling = "MATCH"',
            "              }",
        ]
    if condition.field_type.value == "header":
        return [
            "              headers {",
            "                match_pattern {",
            "                  all {}",
            "                }",
            '                match_scope       = "ALL"',
            '                oversize_handling = "MATCH"',
            "              }",
        ]
    return ["              uri_path {}"]


def _cookies_field_lines() -> list[str]:
    return [
        "              cookies {",
        "                match_pattern {",
        "                  all {}",
        "                }",
        '                match_scope       = "ALL"',
        '                oversize_handling = "MATCH"',
        "              }",
    ]


def _combine_regexes(patterns: list[str]) -> str:
    if not patterns:
        return ""
    if len(patterns) == 1:
        return patterns[0]
    return "|".join(f"(?:{pattern})" for pattern in patterns)


def _dedupe_conditions(conditions: list[Condition]) -> list[Condition]:
    seen: set[tuple[str, str]] = set()
    normalized: list[Condition] = []
    for cond in conditions:
        key = (cond.field_type.value, cond.pattern)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(cond)
    return normalized


def _group_patterns_by_field(conditions: list[Condition]) -> OrderedDict[str, list[str]]:
    grouped: OrderedDict[str, list[str]] = OrderedDict()
    for cond in _dedupe_conditions(conditions):
        grouped.setdefault(cond.field_type.value, []).append(cond.pattern)
    return grouped


def _escape_hcl_regex(pattern: str) -> str:
    # Terraform HCL interpolation starts with `${`; use `$${` for a literal `${`.
    return pattern.replace("${", "$${").replace('"', '\\"')


def _is_jndi_like(pattern: str) -> bool:
    low = pattern.lower()
    return "jndi" in low or "ldap" in low or "ldaps" in low or "rmi" in low or "dns" in low


def _assert_provider_pattern_lengths(rules: list[IntermediateRule], provider: Provider) -> None:
    max_length = REGEX_PATTERN_MAX_LENGTH[provider]
    for rule in rules:
        for condition in rule.conditions:
            if len(condition.pattern) > max_length:
                raise ValueError(
                    f"{provider.value} cannot compile rule {rule.rule_id}: regex pattern length "
                    f"{len(condition.pattern)} exceeds {max_length}; stabilize it into multiple atomic conditions"
                )


def _chunks(patterns: list[str], size: int) -> list[list[str]]:
    return [patterns[index:index + size] for index in range(0, len(patterns), size)]


def _hcl_identifier(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_]", "_", value)
    return normalized if not normalized[:1].isdigit() else f"rule_{normalized}"


def compile_aws(rules: list[IntermediateRule]) -> ProviderArtifact:
    _assert_provider_pattern_lengths(rules, Provider.AWS)

    pattern_sets: list[tuple[int, str, str, list[str]]] = []
    for rule_index, rule in enumerate(rules):
        grouped_patterns = _group_patterns_by_field(rule.conditions)
        for field_type, patterns in grouped_patterns.items():
            for chunk_index, chunk in enumerate(_chunks(patterns, _AWS_PATTERN_SET_MAX_PATTERNS)):
                label = _hcl_identifier(f"rule_{rule_index}_{field_type}_{chunk_index}")
                pattern_sets.append((rule_index, field_type, label, chunk))

        cookie_patterns = [
            condition.pattern
            for condition in _dedupe_conditions(rule.conditions)
            if condition.field_type.value == "header" and _is_jndi_like(condition.pattern)
        ]
        for chunk_index, chunk in enumerate(_chunks(cookie_patterns, _AWS_PATTERN_SET_MAX_PATTERNS)):
            label = _hcl_identifier(f"rule_{rule_index}_cookies_{chunk_index}")
            pattern_sets.append((rule_index, "cookies", label, chunk))

    lines: list[str] = [
    ]
    for rule_index, field_type, label, patterns in pattern_sets:
        rule = rules[rule_index]
        lines.extend(
            [
                f'resource "aws_wafv2_regex_pattern_set" "{label}" {{',
                f'  name  = "{rule.rule_id}-{field_type}-{label[-1]}"',
                '  scope = "REGIONAL"',
                "",
            ]
        )
        for pattern in patterns:
            lines.extend(
                [
                    "  regular_expression {",
                    f'    regex_string = "{_escape_hcl_regex(pattern)}"',
                    "  }",
                ]
            )
        lines.extend(["}", ""])

    lines.extend([
        'resource "aws_wafv2_web_acl" "generated" {',
        '  name  = "generated-cve-acl"',
        '  scope = "REGIONAL"',
        '',
        '  default_action {',
        '    allow {}',
        '  }',
        '',
    ])

    priority = 10
    for rule in rules:
        lines.extend(
            [
                "  rule {",
                f'    name     = "{rule.rule_id}"',
                f"    priority = {priority}",
                "",
                "    action {",
                f"      {_action(rule.action.value)} {{}}",
                "    }",
                "",
                "    statement {",
                "      or_statement {",
            ]
        )
        for rule_index, field_type, label, _patterns in pattern_sets:
            if rules[rule_index].rule_id != rule.rule_id:
                continue
            field_lines = (
                _cookies_field_lines()
                if field_type == "cookies"
                else _aws_field_lines(Condition(field_type=field_type, operator="regex", pattern=""))
            )
            lines.extend(
                [
                    "        statement {",
                    "          regex_pattern_set_reference_statement {",
                    f"            arn = aws_wafv2_regex_pattern_set.{label}.arn",
                    "            field_to_match {",
                    *field_lines,
                    "            }",
                    "            text_transformation {",
                    "              priority = 0",
                    '              type     = "URL_DECODE"',
                    "            }",
                    "            text_transformation {",
                    "              priority = 1",
                    '              type     = "LOWERCASE"',
                    "            }",
                    "          }",
                    "        }",
                ]
            )
        lines.extend(
            [
                "      }",
                "    }",
                "",
                "    visibility_config {",
                '      cloudwatch_metrics_enabled = true',
                f'      metric_name                = "{rule.rule_id}"',
                '      sampled_requests_enabled   = true',
                "    }",
                "  }",
                "",
            ]
        )
        priority += 10

    lines.extend(
        [
            "  visibility_config {",
            '    cloudwatch_metrics_enabled = true',
            '    metric_name                = "generated-cve-acl"',
            '    sampled_requests_enabled   = true',
            "  }",
            "}",
            "",
        ]
    )

    return ProviderArtifact(
        provider=Provider.AWS,
        terraform="\n".join(lines),
        metadata={"rule_count": len(rules)},
    )


def compile_azure(rules: list[IntermediateRule]) -> ProviderArtifact:
    _assert_provider_pattern_lengths(rules, Provider.AZURE)
    lines: list[str] = [
        'resource "azurerm_web_application_firewall_policy" "generated" {',
        '  name                = "generated-cve-waf-policy"',
        '  location            = var.location',
        '  resource_group_name = var.resource_group_name',
        '',
        '  policy_settings {',
        '    enabled = true',
        '    mode    = "Detection"',
        '  }',
        '',
    ]

    priority = 100
    for rule in rules:
        lines.extend(
            [
                "  custom_rules {",
                f'    name      = "{rule.rule_id}"',
                f"    priority  = {priority}",
                '    rule_type = "MatchRule"',
                '    action    = "Block"',
            ]
        )
        for cond in rule.conditions:
            variable = "RequestUri"
            if cond.field_type.value == "query":
                variable = "QueryString"
            elif cond.field_type.value == "body":
                variable = "RequestBody"
            elif cond.field_type.value == "header":
                variable = "RequestHeaders"

            lines.extend(
                [
                    "    match_conditions {",
                    f'      match_variables {{ variable_name = "{variable}" }}',
                    '      operator           = "Regex"',
                    f'      match_values       = ["{cond.pattern.replace('"', '\\"')}"]',
                    '      transforms         = ["Lowercase", "UrlDecode"]',
                    "    }",
                ]
            )

        lines.extend(["  }", ""])
        priority += 10

    lines.append("}")

    return ProviderArtifact(
        provider=Provider.AZURE,
        terraform="\n".join(lines),
        metadata={"rule_count": len(rules)},
    )

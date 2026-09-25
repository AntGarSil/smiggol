from __future__ import annotations

import re

from waf_factory.models import IntermediateRule, Provider, ValidationIssue
from waf_factory.provider_constraints import REGEX_PATTERN_MAX_LENGTH


def validate_rules(
    rules: list[IntermediateRule],
    providers: list[Provider] | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    broad_patterns = {".*", ".+", "(?i).*", "^.*$"}

    for rule in rules:
        if not rule.conditions:
            issues.append(
                ValidationIssue(
                    rule_id=rule.rule_id,
                    level="error",
                    message="Rule has no conditions",
                )
            )

        if rule.confidence < 0.65:
            issues.append(
                ValidationIssue(
                    rule_id=rule.rule_id,
                    level="warning",
                    message="Low confidence rule; manual review required",
                )
            )

        for cond in rule.conditions:
            if cond.operator.value in {"contains", "equals"} and len(cond.pattern.strip()) < 3:
                issues.append(
                    ValidationIssue(
                        rule_id=rule.rule_id,
                        level="warning",
                        message="Very short literal pattern may overmatch benign traffic",
                    )
                )

            if cond.pattern.strip() in broad_patterns:
                issues.append(
                    ValidationIssue(
                        rule_id=rule.rule_id,
                        level="error",
                        message="Overly broad pattern is not allowed",
                    )
                )

            if cond.operator.value == "regex":
                for provider in providers or list(REGEX_PATTERN_MAX_LENGTH):
                    max_length = REGEX_PATTERN_MAX_LENGTH[provider]
                    if len(cond.pattern) > max_length:
                        issues.append(
                            ValidationIssue(
                                rule_id=rule.rule_id,
                                level="error",
                                message=(
                                    f"{provider.value} regex pattern length {len(cond.pattern)} exceeds "
                                    f"the {max_length}-character deployment limit; split it into "
                                    "multiple equivalent atomic conditions"
                                ),
                            )
                        )
                try:
                    re.compile(cond.pattern)
                except re.error as exc:
                    issues.append(
                        ValidationIssue(
                            rule_id=rule.rule_id,
                            level="error",
                            message=f"Invalid regex pattern: {exc}",
                        )
                    )

    return issues

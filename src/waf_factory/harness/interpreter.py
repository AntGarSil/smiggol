"""Shared rule-matching primitives used by the local simulation and mock WAF."""
from __future__ import annotations

import re

from waf_factory.models import Condition, IntermediateRule, Operator


def match_pattern(payload: str, operator: Operator, pattern: str) -> bool:
    if operator == Operator.REGEX:
        try:
            return re.search(pattern, payload) is not None
        except re.error:
            return False
    if operator == Operator.CONTAINS:
        return pattern.lower() in payload.lower()
    if operator == Operator.EQUALS:
        return pattern == payload
    return False


def matches_condition(payload: str, condition: Condition) -> bool:
    return match_pattern(payload, condition.operator, condition.pattern)


def rule_matches_payload(rule: IntermediateRule, payload: str) -> bool:
    return any(matches_condition(payload, cond) for cond in rule.conditions)

from __future__ import annotations

from waf_factory.models import Provider


REGEX_PATTERN_MAX_LENGTH: dict[Provider, int] = {
    Provider.AWS: 200,
    # Keep the portable intermediate representation within the same conservative
    # ceiling so a rule selected for both providers has identical conditions.
    Provider.AZURE: 200,
}


def regex_max_length(providers: list[Provider]) -> int:
    selected = providers or list(REGEX_PATTERN_MAX_LENGTH)
    return min(REGEX_PATTERN_MAX_LENGTH[provider] for provider in selected)


def provider_constraint_text(providers: list[Provider]) -> str:
    selected = providers or list(REGEX_PATTERN_MAX_LENGTH)
    lines = [
        "- Every individual regex condition must be deployable without truncation or semantic rewriting.",
        "- Split oversized expressions into multiple equivalent, exploit-specific atomic conditions.",
        "- Never split a regex at an arbitrary character boundary.",
    ]
    for provider in selected:
        lines.append(
            f"- {provider.value}: each regex pattern must be at most "
            f"{REGEX_PATTERN_MAX_LENGTH[provider]} characters."
        )
    if Provider.AWS in selected:
        lines.append(
            '- aws: regex conditions compile through aws_wafv2_regex_pattern_set; body, headers, and cookies use oversize_handling="MATCH".'
        )
    return "\n".join(lines)
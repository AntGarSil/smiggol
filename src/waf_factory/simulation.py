from __future__ import annotations

from waf_factory.harness.interpreter import match_pattern
from waf_factory.models import IntermediateRule, Operator, PocArtifact, ReplayResult


def synthetic_payloads() -> list[str]:
    return [
        "q=1 UNION SELECT user,password FROM users",
        "search=<script>alert(1)</script>",
        "file=../../../../etc/passwd",
        "product=normal-shirt",
        "q=hello+world",
    ]


def _matches(payload: str, operator: Operator, pattern: str) -> bool:
    return match_pattern(payload, operator, pattern)


def replay_rules(
    rules: list[IntermediateRule],
    pocs: list[PocArtifact],
) -> list[ReplayResult]:
    exploit_payloads = [p.payload for p in pocs]
    benign_payloads = synthetic_payloads()
    payloads = exploit_payloads + benign_payloads
    if not payloads:
        return []

    results: list[ReplayResult] = []
    for rule in rules:
        detected = 0
        for payload in payloads:
            if any(_matches(payload, cond.operator, cond.pattern) for cond in rule.conditions):
                detected += 1

        exploit_detected = 0
        for payload in exploit_payloads:
            if any(_matches(payload, cond.operator, cond.pattern) for cond in rule.conditions):
                exploit_detected += 1

        benign_detected = 0
        for payload in benign_payloads:
            if any(_matches(payload, cond.operator, cond.pattern) for cond in rule.conditions):
                benign_detected += 1

        rate = detected / len(payloads)
        exploit_rate = (exploit_detected / len(exploit_payloads)) if exploit_payloads else 0.0
        benign_rate = benign_detected / len(benign_payloads)
        results.append(
            ReplayResult(
                rule_id=rule.rule_id,
                payload_count=len(payloads),
                detected_count=detected,
                detection_rate=round(rate, 4),
                exploit_payload_count=len(exploit_payloads),
                exploit_detected_count=exploit_detected,
                exploit_detection_rate=round(exploit_rate, 4),
                benign_payload_count=len(benign_payloads),
                benign_detected_count=benign_detected,
                benign_match_rate=round(benign_rate, 4),
            )
        )
    return results

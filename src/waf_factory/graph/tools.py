"""Graph node functions that wrap the existing agent implementations.

Each node reads its inputs from ``WafFactoryState`` and returns a partial state
delta. Nodes never mutate state in place; the reducer configured in
``waf_factory.graph.state`` merges the returned dict into the checkpointed state.
"""
from __future__ import annotations

import logging
import os
import re

from waf_factory.agents import CveIntelAgent, PocCollectorAgent, RuleAuditAgent, RuleGeneratorAgent, RuleStabilizerAgent
from waf_factory.compilers import compile_aws, compile_azure
from waf_factory.graph.state import WafFactoryState
from waf_factory.models import (
    CveIntel,
    EnforcementMode,
    IntermediateRule,
    PocArtifact,
    Provider,
    RuleAuditReport,
)
from waf_factory.simulation import replay_rules
from waf_factory.validation import validate_rules

logger = logging.getLogger("waf_factory.graph.tools")

_HTTP_VERBS = ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ")


def _mode(state: WafFactoryState) -> EnforcementMode:
    return EnforcementMode(state.get("mode", EnforcementMode.COUNT.value))


def _providers(state: WafFactoryState) -> list[Provider]:
    return [Provider(target) for target in state.get("targets", [])]


def fetch_cve_intel_node(state: WafFactoryState) -> dict:
    cve_id = state["cve_id"]
    intel, warnings = CveIntelAgent().collect(cve_id)
    logger.info("intel collected cve=%s warnings=%d", cve_id, len(warnings))
    return {
        "intel": intel.model_dump(mode="json"),
        "warnings": list(warnings),
        "stages_done": ["fetch_cve_intel"],
    }


def collect_nuclei_pocs_node(state: WafFactoryState) -> dict:
    cve_id = state["cve_id"]
    pocs, warnings = PocCollectorAgent().collect(cve_id)
    logger.info("nuclei payloads collected cve=%s count=%d", cve_id, len(pocs))
    return {
        "pocs": [poc.model_dump(mode="json") for poc in pocs],
        "warnings": list(warnings),
        "stages_done": ["collect_nuclei_pocs"],
    }


def generate_rules_node(state: WafFactoryState) -> dict:
    intel_dump = state.get("intel") or {"cve_id": state["cve_id"]}
    intel = CveIntel.model_validate(intel_dump)
    pocs = [PocArtifact.model_validate(item) for item in state.get("pocs", [])]

    rules, warnings = RuleGeneratorAgent().generate(
        intel=intel,
        pocs=pocs,
        mode=_mode(state),
        use_llm=state.get("use_llm", True),
        repair_feedback=state.get("repair_feedback"),
    )
    logger.info("rules generated cve=%s count=%d", intel.cve_id, len(rules))
    validation_issues = validate_rules(rules, _providers(state))
    replay_results = replay_rules(rules, pocs)
    missing_headers = _missing_header_coverage(rules, pocs)

    repair_feedback = None
    if missing_headers:
        repair_feedback = _build_header_coverage_feedback(missing_headers)
        warnings = list(warnings) + [
            "Rule is missing header coverage for extracted injection points: " + ", ".join(missing_headers)
        ]

    delta: dict = {
        "rules": [rule.model_dump(mode="json") for rule in rules],
        "validation_issues": [issue.model_dump(mode="json") for issue in validation_issues],
        "replay_results": [result.model_dump(mode="json") for result in replay_results],
        "warnings": list(warnings),
        "stages_done": ["generate_rules"],
        "repair_feedback": repair_feedback,
        "coverage_missing_headers": missing_headers,
    }
    return delta


def _missing_header_coverage(rules: list[IntermediateRule], pocs: list[PocArtifact]) -> list[str]:
    if not rules:
        return []

    extracted_headers: set[str] = set()
    for poc in pocs:
        payload = (poc.payload or "").strip()
        if not payload or payload.startswith(_HTTP_VERBS):
            continue
        header = re.match(r"^([A-Za-z0-9-]{2,64}):\s+.+$", payload)
        if not header:
            continue
        extracted_headers.add(header.group(1).lower())

    if not extracted_headers:
        return []

    covered_headers: set[str] = set()
    for cond in rules[0].conditions:
        if cond.field_type.value != "header":
            continue
        name = (cond.header_name or "").strip().lower()
        if name:
            covered_headers.add(name)

    return sorted(name for name in extracted_headers if name not in covered_headers)


def _build_header_coverage_feedback(missing_headers: list[str]) -> str:
    sample = ", ".join(missing_headers[:16])
    return (
        "Coverage repair required. Add explicit header conditions for every missing header injection point.\n"
        f"Missing header_name values: {sample}.\n"
        "Use field_type=header with exact header_name and exploit-specific patterns grounded in payload markers for this CVE."
    )


def stabilize_rules_node(state: WafFactoryState) -> dict:
    intel_dump = state.get("intel") or {"cve_id": state["cve_id"]}
    intel = CveIntel.model_validate(intel_dump)
    pocs = [PocArtifact.model_validate(item) for item in state.get("pocs", [])]
    rules = [IntermediateRule.model_validate(item) for item in state.get("rules", [])]
    replay_results = list(state.get("replay_results") or [])
    validation_issues = list(state.get("validation_issues") or [])

    if not rules:
        return {
            "warnings": ["Rule stabilization skipped: no generated rules available"],
            "stages_done": ["stabilize_rules"],
        }

    stabilized, warnings = RuleStabilizerAgent().stabilize(
        intel=intel,
        pocs=pocs,
        rule=rules[0],
        replay_results=replay_results,
        validation_issues=validation_issues,
        providers=_providers(state),
        audit_feedback=state.get("audit_feedback"),
    )

    final_rule = stabilized or rules[0]
    if stabilized is None:
        warnings = list(warnings) + ["Using pre-stabilization rule due to stabilizer unavailability/failure"]

    refreshed_validation = validate_rules([final_rule], _providers(state))
    refreshed_replay = replay_rules([final_rule], pocs)

    return {
        "rules": [final_rule.model_dump(mode="json")],
        "validation_issues": [issue.model_dump(mode="json") for issue in refreshed_validation],
        "replay_results": [result.model_dump(mode="json") for result in refreshed_replay],
        "warnings": list(warnings),
        "stages_done": ["stabilize_rules"],
    }


def audit_rules_node(state: WafFactoryState) -> dict:
    intel_dump = state.get("intel") or {"cve_id": state["cve_id"]}
    intel = CveIntel.model_validate(intel_dump)
    pocs = [PocArtifact.model_validate(item) for item in state.get("pocs", [])]
    rules = [IntermediateRule.model_validate(item) for item in state.get("rules", [])]
    replay_results = list(state.get("replay_results") or [])
    validation_issues = list(state.get("validation_issues") or [])

    if not rules:
        return {
            "warnings": ["Rule audit skipped: no generated rules available"],
            "stages_done": ["audit_rules"],
        }

    audit_report, warnings = RuleAuditAgent().audit(
        intel=intel,
        pocs=pocs,
        rule=rules[0],
        replay_results=replay_results,
        validation_issues=validation_issues,
        providers=_providers(state),
    )

    if audit_report is None:
        audit_report = RuleAuditReport(
            model="",
            provider="",
            effectiveness_score=0.0,
            false_positive_risk=1.0,
            verdict="blocked",
            summary="Audit unavailable",
            evidence=[],
            recommendations=["Investigate audit stage failures before promoting this rule."],
        )

    _apply_validation_gate(audit_report, validation_issues)

    logger.info(
        "rule audit completed cve=%s verdict=%s effectiveness=%.2f fp_risk=%.2f",
        intel.cve_id,
        audit_report.verdict,
        audit_report.effectiveness_score,
        audit_report.false_positive_risk,
    )
    recommendations = "\n".join(f"- {item}" for item in audit_report.recommendations)
    audit_feedback = (
        f"Audit score: {audit_report.effectiveness_score:.2f}\n"
        f"False-positive risk: {audit_report.false_positive_risk:.2f}\n"
        f"Summary: {audit_report.summary}\n"
        f"Recommendations:\n{recommendations or '- No explicit recommendations supplied; improve the weaknesses described in the summary.'}"
    )
    return {
        "audit_report": audit_report.model_dump(mode="json"),
        "audit_feedback": audit_feedback,
        "warnings": list(warnings),
        "stages_done": ["audit_rules"],
    }


def _apply_validation_gate(
    audit_report: RuleAuditReport,
    validation_issues: list[dict],
) -> None:
    errors = [str(issue.get("message") or "validation error") for issue in validation_issues if issue.get("level") == "error"]
    if not errors:
        return

    audit_report.effectiveness_score = 0.0
    audit_report.verdict = "blocked"
    evidence = [f"Deployment validation failed: {message}" for message in errors]
    audit_report.evidence = list(dict.fromkeys([*audit_report.evidence, *evidence]))
    recommendation = "Resolve every deployment validation error, then stabilize and audit the current rule again."
    if recommendation not in audit_report.recommendations:
        audit_report.recommendations.append(recommendation)


def compile_targets_node(state: WafFactoryState) -> dict:
    rules = [IntermediateRule.model_validate(item) for item in state.get("rules", [])]
    providers = _providers(state)

    artifacts = []
    if rules and Provider.AWS in providers:
        artifacts.append(compile_aws(rules))
    if rules and Provider.AZURE in providers:
        artifacts.append(compile_azure(rules))

    logger.info("artifacts compiled count=%d", len(artifacts))
    return {
        "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
        "stages_done": ["compile_targets"],
    }


def finalize_node(state: WafFactoryState) -> dict:
    """Compute promotion recommendation and mark the run terminated."""
    promotion = _compute_promotion(state)
    logger.info(
        "finalize cve=%s rules=%d artifacts=%d promotion=%s",
        state.get("cve_id", "?"),
        len(state.get("rules") or []),
        len(state.get("artifacts") or []),
        promotion,
    )
    return {
        "promotion_state": promotion,
        "terminated": True,
        "stages_done": ["finalize"],
    }


def _compute_promotion(state: WafFactoryState) -> str:
    if not state.get("rules"):
        return "blocked"

    for issue in state.get("validation_issues") or []:
        if issue.get("level") == "error":
            return "blocked"

    audit_report = state.get("audit_report") or {}
    verdict = str(audit_report.get("verdict") or "").strip().lower()
    if verdict == "blocked":
        return "blocked"
    if verdict == "needs_review":
        return "needs_review"

    fp_risk = float(audit_report.get("false_positive_risk") or 0.0)
    effectiveness = float(audit_report.get("effectiveness_score") or 1.0)
    regen_threshold = float(os.getenv("WAF_AUDIT_REGEN_THRESHOLD", "0.90"))
    ready_threshold = float(os.getenv("WAF_AUDIT_READY_THRESHOLD", "0.97"))

    if effectiveness < regen_threshold:
        return "blocked"
    if effectiveness < ready_threshold:
        return "needs_review"
    if fp_risk >= 0.5:
        return "needs_review"

    return "ready"

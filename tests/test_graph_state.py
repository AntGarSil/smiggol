from __future__ import annotations

import pytest

from waf_factory.graph.build import build_graph
from waf_factory.graph.state import WafFactoryState
from waf_factory.graph.supervisor import deterministic_next_action
from waf_factory.graph.tools import _apply_validation_gate, _compute_promotion
from waf_factory.models import EnforcementMode, Provider, RuleAuditReport
from waf_factory.orchestrator import RuleFactoryOrchestrator


def _initial_state(cve_id: str = "CVE-2024-99999") -> WafFactoryState:
    return {
        "job_id": "test-job",
        "cve_id": cve_id,
        "mode": EnforcementMode.COUNT.value,
        "targets": [Provider.AWS.value, Provider.AZURE.value],
        "use_llm": False,
        "warnings": [],
        "supervisor_trace": [],
        "stages_done": [],
        "iterations": 0,
        "repair_iterations": 0,
        "effectiveness_iterations": 0,
        "audit_regen_iterations": 0,
        "audit_regen_phase": None,
    }


def test_graph_blocks_when_llm_generation_is_disabled() -> None:
    graph = build_graph(supervisor_mode="deterministic")
    final = graph.invoke(
        _initial_state(),
        config={"configurable": {"thread_id": "test"}, "recursion_limit": 40},
    )

    assert final.get("artifacts", []) == []
    assert final.get("rules", []) == []
    assert final.get("terminated") is True
    stages = set(final.get("stages_done") or [])
    assert {"fetch_cve_intel", "collect_nuclei_pocs", "generate_rules", "finalize"} <= stages
    assert "compile_targets" not in stages
    trace = final.get("supervisor_trace") or []
    assert any(entry["action"] == "generate_rules" for entry in trace)
    assert final.get("promotion_state") == "blocked"


def test_orchestrator_returns_blocked_result_without_llm() -> None:
    orchestrator = RuleFactoryOrchestrator(supervisor_mode="deterministic")
    result = orchestrator.generate(
        cve_id="CVE-2024-12345",
        targets=[Provider.AWS, Provider.AZURE],
        mode=EnforcementMode.COUNT,
        use_llm=False,
    )
    assert result.artifacts == []
    assert result.rules == []
    assert result.replay_results == []
    assert result.promotion_state is not None
    assert result.promotion_state.value == "blocked"


def test_deterministic_supervisor_respects_available_tools() -> None:
    state: WafFactoryState = _initial_state()
    state["stages_done"] = ["fetch_cve_intel", "collect_nuclei_pocs", "generate_rules", "compile_targets"]
    state["rules"] = [{"rule_id": "r1"}]
    state["artifacts"] = [{"provider": "aws"}]

    action, _ = deterministic_next_action(
        state,
        available={
            "fetch_cve_intel",
            "collect_nuclei_pocs",
            "generate_rules",
            "stabilize_rules",
            "audit_rules",
            "compile_targets",
            "finalize",
        },
    )
    assert action == "finalize"


def test_deterministic_supervisor_repairs_missing_header_coverage_before_compile() -> None:
    state: WafFactoryState = _initial_state()
    state["stages_done"] = ["fetch_cve_intel", "collect_nuclei_pocs", "generate_rules"]
    state["rules"] = [{"rule_id": "r1"}]
    state["coverage_missing_headers"] = ["accept", "user-agent"]
    state["repair_iterations"] = 0

    action, rationale = deterministic_next_action(
        state,
        available={
            "fetch_cve_intel",
            "collect_nuclei_pocs",
            "generate_rules",
            "stabilize_rules",
            "audit_rules",
            "compile_targets",
            "finalize",
        },
    )
    assert action == "generate_rules"
    assert "header coverage" in rationale


def test_deterministic_supervisor_runs_stabilize_then_audit_before_compile() -> None:
    state: WafFactoryState = _initial_state()
    state["use_llm"] = True
    state["rules"] = [{"rule_id": "r1"}]
    state["stages_done"] = ["fetch_cve_intel", "collect_nuclei_pocs", "generate_rules"]

    action, rationale = deterministic_next_action(state)
    assert action == "stabilize_rules"
    assert "stabilization" in rationale

    state["stages_done"] = ["fetch_cve_intel", "collect_nuclei_pocs", "generate_rules", "stabilize_rules"]
    action, rationale = deterministic_next_action(state)
    assert action == "audit_rules"
    assert "false positives" in rationale

    state["stages_done"] = [
        "fetch_cve_intel",
        "collect_nuclei_pocs",
        "generate_rules",
        "stabilize_rules",
        "audit_rules",
    ]
    action, _ = deterministic_next_action(state)
    assert action == "compile_targets"


def test_deterministic_supervisor_refines_existing_rule_when_audit_score_below_threshold() -> None:
    state: WafFactoryState = _initial_state()
    state["use_llm"] = True
    state["rules"] = [{"rule_id": "r1"}]
    state["stages_done"] = [
        "fetch_cve_intel",
        "collect_nuclei_pocs",
        "generate_rules",
        "stabilize_rules",
        "audit_rules",
    ]
    state["audit_report"] = {
        "effectiveness_score": 0.82,
        "false_positive_risk": 0.1,
        "verdict": "needs_review",
    }
    state["audit_regen_iterations"] = 0

    action, rationale = deterministic_next_action(state)
    assert action == "stabilize_rules"
    assert "below threshold" in rationale
    assert "current rule" in rationale


def test_deterministic_supervisor_compiles_rule_after_low_audit_retries_exhausted() -> None:
    state: WafFactoryState = _initial_state()
    state["use_llm"] = True
    state["rules"] = [{"rule_id": "r1"}]
    state["stages_done"] = [
        "fetch_cve_intel",
        "collect_nuclei_pocs",
        "generate_rules",
        "stabilize_rules",
        "audit_rules",
    ]
    state["audit_report"] = {
        "effectiveness_score": 0.88,
        "false_positive_risk": 0.1,
        "verdict": "needs_review",
    }
    state["audit_regen_iterations"] = 2

    action, rationale = deterministic_next_action(state)
    assert action == "compile_targets"
    assert "blocked rule for inspection" in rationale


def test_deterministic_supervisor_compiles_existing_rule_at_iteration_cap() -> None:
    state: WafFactoryState = _initial_state()
    state["rules"] = [{"rule_id": "r1"}]
    state["stages_done"] = ["fetch_cve_intel", "collect_nuclei_pocs", "generate_rules"]
    state["iterations"] = 8

    action, rationale = deterministic_next_action(state)
    assert action == "compile_targets"
    assert "compile current rule" in rationale


def test_deterministic_supervisor_drives_regen_phase_stabilize_then_audit() -> None:
    state: WafFactoryState = _initial_state()
    state["use_llm"] = True
    state["rules"] = [{"rule_id": "r1"}]
    state["stages_done"] = ["fetch_cve_intel", "collect_nuclei_pocs", "generate_rules"]

    state["audit_regen_phase"] = "stabilize"
    action, _ = deterministic_next_action(state)
    assert action == "stabilize_rules"

    state["audit_regen_phase"] = "audit"
    action, _ = deterministic_next_action(state)
    assert action == "audit_rules"


def test_graph_checkpoints_intermediate_state() -> None:
    graph = build_graph(supervisor_mode="deterministic")
    config = {"configurable": {"thread_id": "checkpoint-test"}, "recursion_limit": 40}
    graph.invoke(_initial_state(), config=config)

    snapshot = graph.get_state(config)
    assert snapshot is not None
    assert snapshot.values.get("terminated") is True
    assert snapshot.values.get("cve_id") == "CVE-2024-99999"


def test_compute_promotion_uses_audit_score_bands() -> None:
    state: WafFactoryState = _initial_state()
    state["rules"] = [{"rule_id": "r1"}]

    state["audit_report"] = {"effectiveness_score": 0.89, "false_positive_risk": 0.1, "verdict": "ready"}
    assert _compute_promotion(state) == "blocked"

    state["audit_report"] = {"effectiveness_score": 0.93, "false_positive_risk": 0.1, "verdict": "ready"}
    assert _compute_promotion(state) == "needs_review"

    state["audit_report"] = {"effectiveness_score": 0.98, "false_positive_risk": 0.1, "verdict": "ready"}
    assert _compute_promotion(state) == "ready"


def test_validation_error_forces_audit_to_blocked() -> None:
    report = RuleAuditReport(
        model="test",
        provider="github",
        effectiveness_score=0.99,
        false_positive_risk=0.1,
        verdict="ready",
    )

    _apply_validation_gate(
        report,
        [{"level": "error", "message": "aws regex pattern length 613 exceeds the 200-character deployment limit"}],
    )

    assert report.effectiveness_score == 0.0
    assert report.verdict == "blocked"
    assert any("length 613" in item for item in report.evidence)
    assert any("stabilize and audit" in item for item in report.recommendations)



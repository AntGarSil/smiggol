"""Public orchestrator facade.

Backed by the LangGraph state graph in :mod:`waf_factory.graph`. Keeps the
``RuleFactoryOrchestrator.generate`` signature and ``GenerationResult`` shape
so upstream callers do not need to change.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any

from waf_factory.graph.build import build_graph
from waf_factory.graph.state import WafFactoryState
from waf_factory.models import (
    CveIntel,
    EnforcementMode,
    GenerationResult,
    IntermediateRule,
    PromotionState,
    Provider,
    ProviderArtifact,
    ReplayResult,
    RuleAuditReport,
    ValidationIssue,
)


class RuleFactoryOrchestrator:
    def __init__(
        self,
        *,
        chat_model: Any | None = None,
        supervisor_mode: str = "auto",
        checkpointer: Any | None = None,
        graph: Any | None = None,
    ) -> None:
        self.logger = logging.getLogger("waf_factory.orchestrator")
        self._graph = graph or build_graph(
            chat_model=chat_model,
            supervisor_mode=supervisor_mode,
            checkpointer=checkpointer,
        )

    @property
    def graph(self):
        return self._graph

    def generate(
        self,
        cve_id: str,
        targets: list[Provider],
        mode: EnforcementMode,
        use_llm: bool = True,
        job_id: str | None = None,
    ) -> GenerationResult:
        job_id = job_id or f"job-{uuid.uuid4().hex[:12]}"
        started = time.perf_counter()
        self.logger.info(
            "start generation job=%s cve=%s use_llm=%s targets=%s",
            job_id,
            cve_id,
            use_llm,
            [target.value for target in targets],
        )

        initial: WafFactoryState = {
            "job_id": job_id,
            "cve_id": cve_id,
            "mode": mode.value,
            "targets": [target.value for target in targets],
            "use_llm": use_llm,
            "warnings": [],
            "supervisor_trace": [],
            "stages_done": [],
            "iterations": 0,
            "repair_iterations": 0,
            "effectiveness_iterations": 0,
            "audit_regen_iterations": 0,
            "audit_regen_phase": None,
            "audit_feedback": None,
        }

        final_state = self._graph.invoke(
            initial,
            config={
                "configurable": {"thread_id": job_id},
                "recursion_limit": int(os.getenv("WAF_GRAPH_RECURSION_LIMIT", "40")),
            },
        )

        elapsed_ms = (time.perf_counter() - started) * 1000
        self.logger.info(
            "generation completed job=%s cve=%s rules=%d artifacts=%d promotion=%s duration_ms=%.2f",
            job_id,
            cve_id,
            len(final_state.get("rules") or []),
            len(final_state.get("artifacts") or []),
            final_state.get("promotion_state"),
            elapsed_ms,
        )

        return state_to_result(final_state)


def state_to_result(state: WafFactoryState) -> GenerationResult:
    intel_dump = state.get("intel") or {"cve_id": state.get("cve_id", "")}
    intel = CveIntel.model_validate(intel_dump)

    rules = [IntermediateRule.model_validate(item) for item in state.get("rules") or []]
    artifacts = [ProviderArtifact.model_validate(item) for item in state.get("artifacts") or []]
    validation_issues = [ValidationIssue.model_validate(item) for item in state.get("validation_issues") or []]
    replay_results = [ReplayResult.model_validate(item) for item in state.get("replay_results") or []]
    audit_dump = state.get("audit_report")
    audit_report = RuleAuditReport.model_validate(audit_dump) if audit_dump else None

    promotion_value = state.get("promotion_state")
    promotion_state = PromotionState(promotion_value) if promotion_value else None

    return GenerationResult(
        cve=intel,
        rules=rules,
        artifacts=artifacts,
        validation_issues=validation_issues,
        replay_results=replay_results,
        audit_report=audit_report,
        promotion_state=promotion_state,
        warnings=list(state.get("warnings") or []),
    )

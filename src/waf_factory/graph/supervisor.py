"""Supervisor node.

Chooses the next tool for the ReACT loop. Supports two policies:

* ``deterministic`` — a fixed order over the available tools based on which
  stages are complete. Used when no LLM credentials are available or when the
  caller explicitly requests deterministic execution (parity tests).
* ``react`` — the LLM examines a compact state summary and picks the next
  action from a fixed toolset. Rationale is appended to
  ``state["supervisor_trace"]``.

The supervisor sets ``next_action`` on the returned state delta; conditional
edges in the graph route to the matching tool node.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from waf_factory.graph.state import TOOL_ACTIONS, WafFactoryState

logger = logging.getLogger("waf_factory.graph.supervisor")


def _stages_done(state: WafFactoryState) -> set[str]:
    return set(state.get("stages_done") or [])


def _header_coverage_missing(state: WafFactoryState) -> bool:
    return bool(state.get("coverage_missing_headers"))


def _audit_effectiveness(state: WafFactoryState) -> float | None:
    report = state.get("audit_report") or {}
    raw = report.get("effectiveness_score")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def deterministic_next_action(state: WafFactoryState, available: set[str] | None = None) -> tuple[str, str]:
    stages = _stages_done(state)
    iterations = state.get("iterations", 0)
    max_iterations = int(os.getenv("WAF_SUPERVISOR_MAX_ITERATIONS", "8"))
    regen_threshold = float(os.getenv("WAF_AUDIT_REGEN_THRESHOLD", "0.90"))
    max_regen_iterations = int(os.getenv("WAF_SUPERVISOR_MAX_AUDIT_REGEN_ITERATIONS", "2"))
    if iterations >= max_iterations:
        if state.get("rules") and "compile_targets" not in stages:
            return "compile_targets", f"iteration cap {max_iterations} reached; compile current rule for inspection"
        return "finalize", f"iteration cap {max_iterations} reached"

    if "fetch_cve_intel" not in stages:
        return "fetch_cve_intel", "no CVE intel"
    if "collect_nuclei_pocs" not in stages:
        return "collect_nuclei_pocs", "no PoC artifacts collected yet"
    if "generate_rules" not in stages:
        return "generate_rules", "no rules generated yet"

    if not state.get("rules"):
        return "finalize", "no rules produced"

    repair_cap = int(os.getenv("WAF_SUPERVISOR_MAX_REPAIR_ITERATIONS", "2"))
    if _header_coverage_missing(state) and state.get("repair_iterations", 0) < repair_cap:
        return "generate_rules", "missing header coverage; retry rule generation"

    regen_phase = (state.get("audit_regen_phase") or "").strip().lower()
    if state.get("use_llm", True) and regen_phase == "stabilize":
        return "stabilize_rules", "audit-triggered regeneration: run stabilizer"
    if state.get("use_llm", True) and regen_phase == "audit":
        return "audit_rules", "audit-triggered regeneration: re-evaluate regenerated rule"

    effectiveness = _audit_effectiveness(state)
    if (
        state.get("use_llm", True)
        and effectiveness is not None
        and effectiveness < regen_threshold
    ):
        regen_iterations = state.get("audit_regen_iterations", 0)
        if regen_iterations < max_regen_iterations:
            return (
                "stabilize_rules",
                f"audit effectiveness {effectiveness:.2f} below threshold {regen_threshold:.2f}; refine current rule using audit recommendations",
            )
        return (
            "compile_targets",
            f"audit effectiveness {effectiveness:.2f} below threshold after {max_regen_iterations} refinement attempts; compile blocked rule for inspection",
        )

    if state.get("use_llm", True) and "stabilize_rules" not in stages:
        return "stabilize_rules", "run expensive model stabilization pass for rule quality"

    if state.get("use_llm", True) and "audit_rules" not in stages:
        return "audit_rules", "run expensive model audit for effectiveness and false positives"

    if "compile_targets" not in stages:
        return "compile_targets", "provider artifacts not compiled"

    return "finalize", "all gates satisfied"


def _summarize_state(state: WafFactoryState) -> dict[str, Any]:
    return {
        "cve_id": state.get("cve_id"),
        "stages_done": list(_stages_done(state)),
        "rule_count": len(state.get("rules") or []),
        "artifact_count": len(state.get("artifacts") or []),
        "validation_error_count": sum(
            1 for i in (state.get("validation_issues") or []) if i.get("level") == "error"
        ),
        "iterations": state.get("iterations", 0),
        "repair_iterations": state.get("repair_iterations", 0),
        "effectiveness_iterations": state.get("effectiveness_iterations", 0),
        "audit_regen_iterations": state.get("audit_regen_iterations", 0),
        "audit_regen_phase": state.get("audit_regen_phase"),
        "coverage_missing_headers": state.get("coverage_missing_headers") or [],
        "audit_present": bool(state.get("audit_report")),
        "audit_effectiveness": _audit_effectiveness(state),
        "audit_feedback": state.get("audit_feedback"),
    }


def _react_next_action(state: WafFactoryState, chat_model) -> tuple[str, str] | None:
    """Ask the LLM to pick the next tool. Returns (action, rationale) or None to fall back."""
    from langchain_core.messages import HumanMessage, SystemMessage

    summary = _summarize_state(state)
    system = SystemMessage(content=(
        "You are the WAF Rule Factory supervisor. You orchestrate a fixed set of tools by "
        "choosing exactly one next action. Respond with strict JSON only:\n"
        '{"action": "<tool_name>", "rationale": "<short reason>"}\n\n'
        f"Available tools: {list(TOOL_ACTIONS)}\n"
        "Rules:\n"
        "- Run fetch_cve_intel before collect_nuclei_pocs before generate_rules.\n"
        "- When rules exist and use_llm is true, run stabilize_rules then audit_rules before compile_targets.\n"
        "- If audit effectiveness_score is below 0.90, refine the current rule using audit recommendations, then re-audit (bounded retries). Never regenerate from scratch after audit.\n"
        "- Compile every generated rule before finalize, including rules blocked from promotion.\n"
        "- If generate_rules reports missing header coverage, call generate_rules again to repair.\n"
        "- Respect iteration caps. When work is done, choose finalize."
    ))
    human = HumanMessage(content=f"State summary:\n{json.dumps(summary, default=str)}")
    try:
        response = chat_model.invoke([system, human])
    except Exception as exc:
        logger.warning("supervisor LLM invocation failed; falling back to deterministic: %s", exc)
        return None

    content = getattr(response, "content", "") or ""
    if isinstance(content, list):
        content = "".join(part.get("text", "") if isinstance(part, dict) else str(part) for part in content)

    try:
        payload = json.loads(content)
        action = str(payload.get("action", "")).strip()
        rationale = str(payload.get("rationale", ""))
    except Exception:
        logger.warning("supervisor LLM returned non-JSON: %s", content[:200])
        return None

    if action not in TOOL_ACTIONS:
        logger.warning("supervisor LLM returned unknown action: %r", action)
        return None
    return action, rationale


def make_supervisor_node(chat_model=None, mode: str = "auto", available_tools: set[str] | None = None):
    """Return a supervisor node function.

    ``mode='deterministic'`` forces deterministic ordering (used by tests).
    ``mode='react'`` requires ``chat_model`` and never falls back.
    ``mode='auto'`` uses the LLM if one is supplied, deterministic otherwise.
    """
    available = available_tools or set(TOOL_ACTIONS)

    def supervisor(state: WafFactoryState) -> dict:
        action: str
        rationale: str

        if mode == "react" and chat_model is None:
            raise RuntimeError("react supervisor requires a chat model")

        picked = None
        if mode in ("react", "auto") and chat_model is not None:
            picked = _react_next_action(state, chat_model)
            if picked and picked[0] not in available:
                logger.warning("supervisor LLM picked unavailable tool %r; deterministic fallback", picked[0])
                picked = None

        if picked is not None:
            action, rationale = picked
            source = "react"
        else:
            action, rationale = deterministic_next_action(state, available)
            source = "deterministic"

        iterations = state.get("iterations", 0) + 1
        delta: dict = {
            "next_action": action,
            "iterations": iterations,
            "supervisor_trace": [
                {
                    "iteration": iterations,
                    "action": action,
                    "rationale": rationale,
                    "source": source,
                }
            ],
        }

        stages = _stages_done(state)
        if action == "generate_rules" and "generate_rules" in stages:
            if _header_coverage_missing(state):
                delta["repair_iterations"] = state.get("repair_iterations", 0) + 1
        if action == "stabilize_rules":
            phase = (state.get("audit_regen_phase") or "").strip().lower()
            effectiveness = _audit_effectiveness(state)
            regen_threshold = float(os.getenv("WAF_AUDIT_REGEN_THRESHOLD", "0.90"))
            if phase == "stabilize" or (effectiveness is not None and effectiveness < regen_threshold):
                delta["audit_regen_iterations"] = state.get("audit_regen_iterations", 0) + 1
                delta["audit_regen_phase"] = "audit"
        if action == "audit_rules":
            delta["effectiveness_iterations"] = state.get("effectiveness_iterations", 0) + 1
            if (state.get("audit_regen_phase") or "").strip().lower() == "audit":
                delta["audit_regen_phase"] = None

        logger.info(
            "supervisor decision cve=%s iter=%d action=%s source=%s rationale=%s",
            state.get("cve_id"),
            iterations,
            action,
            source,
            rationale,
        )
        return delta

    return supervisor



"""Graph state definition for the LangGraph-based WAF rule factory pipeline."""
from __future__ import annotations

from operator import add
from typing import Annotated, Any, TypedDict


def _replace_dict(_current: dict | None, incoming: dict | None) -> dict | None:
    return incoming if incoming is not None else _current


def _dedup_append(current: list[str] | None, incoming: list[str] | None) -> list[str]:
    combined = list(current or [])
    for item in incoming or []:
        if item not in combined:
            combined.append(item)
    return combined


class WafFactoryState(TypedDict, total=False):
    """State container passed between graph nodes.

    Pydantic models are stored as JSON-safe dicts so the checkpointer can persist them.
    """

    # Request inputs
    job_id: str
    cve_id: str
    mode: str
    targets: list[str]
    use_llm: bool

    # Tool outputs (JSON-safe dumps of the pydantic models in waf_factory.models)
    intel: dict[str, Any] | None
    pocs: list[dict[str, Any]]
    rules: list[dict[str, Any]]
    artifacts: list[dict[str, Any]]
    validation_issues: list[dict[str, Any]]
    replay_results: list[dict[str, Any]]
    audit_report: dict[str, Any] | None

    promotion_state: str | None

    # Aggregates
    warnings: Annotated[list[str], add]
    supervisor_trace: Annotated[list[dict[str, Any]], add]
    stages_done: Annotated[list[str], _dedup_append]

    # Control flow
    next_action: str
    iterations: int
    repair_iterations: int
    effectiveness_iterations: int
    audit_regen_iterations: int
    audit_regen_phase: str | None
    terminated: bool
    error: str | None

    # Feedback carried between supervisor loops when the LLM asks for rule repairs
    repair_feedback: str | None
    audit_feedback: str | None
    coverage_missing_headers: list[str]


TOOL_ACTIONS = (
    "fetch_cve_intel",
    "collect_nuclei_pocs",
    "generate_rules",
    "stabilize_rules",
    "audit_rules",
    "compile_targets",
    "finalize",
)

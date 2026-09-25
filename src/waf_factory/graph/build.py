"""Build the LangGraph state graph orchestrating the WAF rule factory pipeline."""
from __future__ import annotations

import logging
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from waf_factory.graph.state import TOOL_ACTIONS, WafFactoryState
from waf_factory.graph.supervisor import make_supervisor_node
from waf_factory.graph.tools import (
    audit_rules_node,
    collect_nuclei_pocs_node,
    compile_targets_node,
    fetch_cve_intel_node,
    finalize_node,
    generate_rules_node,
    stabilize_rules_node,
)

logger = logging.getLogger("waf_factory.graph.build")

TOOL_NODES = {
    "fetch_cve_intel": fetch_cve_intel_node,
    "collect_nuclei_pocs": collect_nuclei_pocs_node,
    "generate_rules": generate_rules_node,
    "stabilize_rules": stabilize_rules_node,
    "audit_rules": audit_rules_node,
    "compile_targets": compile_targets_node,
    "finalize": finalize_node,
}


def register_optional_tool(name: str, node) -> None:
    """Attach optional tool nodes here."""
    if name not in TOOL_ACTIONS:
        raise ValueError(f"unknown tool action: {name}")
    TOOL_NODES[name] = node


def _route_from_supervisor(state: WafFactoryState) -> str:
    return state.get("next_action") or "finalize"


def build_graph(
    *,
    chat_model=None,
    supervisor_mode: str = "auto",
    checkpointer=None,
    extra_tools: dict[str, Any] | None = None,
):
    """Compile the state graph.

    ``extra_tools`` allows callers (e.g. tests, Phase 1.5b/c) to register
    additional tool nodes without mutating module globals.
    """
    tools = dict(TOOL_NODES)
    if extra_tools:
        for name, node in extra_tools.items():
            if name not in TOOL_ACTIONS:
                raise ValueError(f"unknown tool action: {name}")
            tools[name] = node

    graph = StateGraph(WafFactoryState)
    supervisor = make_supervisor_node(
        chat_model=chat_model,
        mode=supervisor_mode,
        available_tools=set(tools.keys()),
    )
    graph.add_node("supervisor", supervisor)
    for name, node in tools.items():
        graph.add_node(name, node)

    graph.add_edge(START, "supervisor")

    routing: dict[str, str] = {name: name for name in tools}
    # Guarantee finalize is always reachable
    routing.setdefault("finalize", "finalize")
    graph.add_conditional_edges("supervisor", _route_from_supervisor, routing)

    for name in tools:
        if name == "finalize":
            graph.add_edge(name, END)
        else:
            graph.add_edge(name, "supervisor")

    return graph.compile(checkpointer=checkpointer or MemorySaver())

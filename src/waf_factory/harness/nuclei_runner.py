"""Drive nuclei against the mock WAF and correlate findings with harness events.

Runs one nuclei template per invocation so we can attribute HarnessEvents to
their originating template.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterable

import httpx
import yaml

from waf_factory.harness.mock_waf import HarnessEvent, MockWaf
from waf_factory.models import EffectivenessOutcome, EffectivenessReport
from waf_factory.simulation import synthetic_payloads

logger = logging.getLogger("waf_factory.harness.nuclei_runner")


NUCLEI_BIN = os.getenv("NUCLEI_BIN", "nuclei")
NUCLEI_PER_TEMPLATE_TIMEOUT = float(os.getenv("NUCLEI_PER_TEMPLATE_TIMEOUT_SECONDS", "30"))
NUCLEI_MAX_DURATION = float(os.getenv("NUCLEI_MAX_DURATION_SECONDS", "90"))
NUCLEI_TEMPLATES_ROOT = Path(os.getenv("NUCLEI_TEMPLATES_ROOT", "data/nuclei-templates"))


def nuclei_available() -> bool:
    return shutil.which(NUCLEI_BIN) is not None


def resolve_templates_for_cve(cve_id: str, root: Path | None = None, max_templates: int = 6) -> list[Path]:
    root = root or NUCLEI_TEMPLATES_ROOT
    if not root.exists():
        return []
    candidates: list[Path] = []
    for pattern in (f"{cve_id}.yaml", f"{cve_id}.yml", f"{cve_id.lower()}.yaml", f"{cve_id.lower()}.yml"):
        candidates.extend(root.rglob(pattern))
    unique: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = path.as_posix()
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
        if len(unique) >= max_templates:
            break
    return unique


def extract_template_id(template_path: Path) -> str:
    try:
        for doc in yaml.safe_load_all(template_path.read_text(encoding="utf-8")):
            if isinstance(doc, dict) and doc.get("id"):
                return str(doc["id"])
    except Exception:
        pass
    return template_path.stem


def extract_template_words(template_path: Path) -> list[str]:
    """Pull out matcher `words` so the harness can echo them into stub responses."""
    words: list[str] = []
    try:
        docs = list(yaml.safe_load_all(template_path.read_text(encoding="utf-8")))
    except Exception:
        return words
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        for section in ("http", "requests"):
            for block in doc.get(section, []) or []:
                if not isinstance(block, dict):
                    continue
                for matcher in block.get("matchers", []) or []:
                    if isinstance(matcher, dict) and matcher.get("type") == "word":
                        for word in matcher.get("words", []) or []:
                            if isinstance(word, str):
                                words.append(word)
    return words


def _stub_body_for_template(template_path: Path) -> str:
    words = extract_template_words(template_path)
    if not words:
        return (
            "<html><body>Welcome, admin!<br>"
            "SQL syntax error near 'UNION SELECT'<br>"
            "alert(1)<br>"
            "root:x:0:0:root:/root:/bin/bash"
            "</body></html>"
        )
    body_parts = ["<html><body>"]
    body_parts.extend(f"<div>{word}</div>" for word in words[:20])
    body_parts.append("</body></html>")
    return "".join(body_parts)


def _run_nuclei_once(target_url: str, template_path: Path, timeout: float) -> tuple[list[dict], str]:
    cmd = [
        NUCLEI_BIN,
        "-u", target_url,
        "-t", str(template_path),
        "-j",
        "-silent",
        "-no-interactsh",
        "-disable-update-check",
        "-timeout", "5",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return [], "timeout"

    findings: list[dict] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings, ""


def _classify_outcome(
    findings: list[dict],
    events_during_window: list[HarnessEvent],
) -> tuple[str, list[str]]:
    """Return (outcome, matched_rule_ids)."""
    matched_rule_ids: list[str] = []
    any_match = False
    any_block = False
    for event in events_during_window:
        if event.matched_rule_ids:
            any_match = True
            matched_rule_ids.extend(event.matched_rule_ids)
            if event.blocked:
                any_block = True

    if findings and not any_block:
        # nuclei detected the exploit despite the WAF
        return "undetected", matched_rule_ids
    if not findings and any_block:
        return "blocked", matched_rule_ids
    if not findings and any_match:
        return "matched-but-allowed", matched_rule_ids
    if not findings and not events_during_window:
        return "template_did_not_fire", matched_rule_ids
    if not findings:
        return "blocked", matched_rule_ids
    return "undetected", matched_rule_ids


def _run_benign_probes(waf: MockWaf) -> tuple[int, int, list[str]]:
    """Fire synthetic benign-looking probes at the harness; return (total, matched, matched_payloads)."""
    payloads = synthetic_payloads()
    matched = 0
    matched_payloads: list[str] = []
    with httpx.Client(timeout=5.0) as client:
        for payload in payloads:
            waf.clear_events()
            try:
                client.get(f"{waf.base_url}/probe", params={"q": payload})
            except Exception:
                continue
            events = waf.snapshot_events()
            if any(event.matched_rule_ids for event in events):
                matched += 1
                matched_payloads.append(payload)
    return len(payloads), matched, matched_payloads


def run_effectiveness(
    rules: list,
    *,
    cve_id: str,
    templates: Iterable[Path] | None = None,
    max_duration_seconds: float | None = None,
    include_benign: bool = True,
) -> EffectivenessReport:
    started = time.perf_counter()
    max_duration = max_duration_seconds or NUCLEI_MAX_DURATION

    if not nuclei_available():
        return EffectivenessReport(
            available=False,
            notes=[f"nuclei binary '{NUCLEI_BIN}' not on PATH; effectiveness gate skipped"],
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    template_paths = list(templates) if templates is not None else resolve_templates_for_cve(cve_id)
    if not template_paths:
        return EffectivenessReport(
            available=True,
            notes=[f"No nuclei templates matched {cve_id}"],
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    outcomes: list[EffectivenessOutcome] = []
    undetected: list[str] = []
    exploit_blocked = 0
    exploit_run = 0

    with MockWaf(rules=rules) as waf:
        for template_path in template_paths:
            if (time.perf_counter() - started) > max_duration:
                break
            template_id = extract_template_id(template_path)
            waf.clear_events()
            waf.set_stub_body(_stub_body_for_template(template_path))
            t_start = time.perf_counter()
            findings, err = _run_nuclei_once(waf.base_url, template_path, NUCLEI_PER_TEMPLATE_TIMEOUT)
            events = waf.snapshot_events()
            outcome, matched_ids = _classify_outcome(findings, events)
            latency_ms = (time.perf_counter() - t_start) * 1000

            outcomes.append(
                EffectivenessOutcome(
                    template_id=template_id,
                    cve_id=cve_id,
                    category="exploit",
                    outcome=outcome,
                    matched_rule_ids=sorted(set(matched_ids)),
                    latency_ms=latency_ms,
                )
            )

            if outcome != "template_did_not_fire":
                exploit_run += 1
                if outcome == "blocked":
                    exploit_blocked += 1
                elif outcome == "undetected":
                    undetected.append(template_id)

        # Benign probes
        benign_run = 0
        benign_matched = 0
        false_positive_payloads: list[str] = []
        if include_benign:
            waf.set_stub_body(None)
            benign_run, benign_matched, false_positive_payloads = _run_benign_probes(waf)
            for payload in false_positive_payloads:
                outcomes.append(
                    EffectivenessOutcome(
                        template_id=f"benign::{payload[:32]}",
                        cve_id=None,
                        category="benign",
                        outcome="benign_fp",
                    )
                )

    block_rate = exploit_blocked / exploit_run if exploit_run else 0.0
    false_negative_rate = len(undetected) / exploit_run if exploit_run else 0.0
    benign_fp_rate = benign_matched / benign_run if benign_run else 0.0

    return EffectivenessReport(
        available=True,
        templates_run=len(outcomes),
        exploit_templates_run=exploit_run,
        benign_templates_run=benign_run,
        exploit_blocked=exploit_blocked,
        benign_matched=benign_matched,
        block_rate=round(block_rate, 4),
        false_negative_rate=round(false_negative_rate, 4),
        benign_false_positive_rate=round(benign_fp_rate, 4),
        outcomes=outcomes,
        undetected_templates=undetected,
        false_positive_payloads=false_positive_payloads,
        duration_ms=(time.perf_counter() - started) * 1000,
    )

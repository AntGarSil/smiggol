"""tflint gate — runs tflint with aws + azurerm rulesets against provider scratch dirs.

Called after ``terraform init`` has succeeded (see ``terraform_syntax.run_syntax_gate``).
The gate is advisory when ``tflint`` is not installed unless ``WAF_REQUIRE_TFLINT=1``.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

from waf_factory.models import Provider, SyntaxIssue

logger = logging.getLogger("waf_factory.validation.tflint_gate")

TFLINT_BIN = os.getenv("TFLINT_BIN", "tflint")
TFLINT_TIMEOUT_SECONDS = float(os.getenv("WAF_TFLINT_TIMEOUT_SECONDS", "45"))
AWS_RULESET_VERSION = os.getenv("WAF_TFLINT_AWS_VERSION", "0.30.0")
AZURERM_RULESET_VERSION = os.getenv("WAF_TFLINT_AZURERM_VERSION", "0.26.0")


TFLINT_CONFIG = """\
config {
  format = "json"
}

plugin "aws" {
  enabled = true
  version = "%(aws)s"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

plugin "azurerm" {
  enabled = true
  version = "%(azurerm)s"
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}
""" % {"aws": AWS_RULESET_VERSION, "azurerm": AZURERM_RULESET_VERSION}


def _tflint_available() -> bool:
    return shutil.which(TFLINT_BIN) is not None


def _write_config(dir_: Path) -> Path:
    config_path = dir_ / ".tflint.hcl"
    if not config_path.exists():
        config_path.write_text(TFLINT_CONFIG, encoding="utf-8")
    return config_path


def _run(cmd: list[str], cwd: Path, timeout: float | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout or TFLINT_TIMEOUT_SECONDS,
        check=False,
    )


def _map_severity(level: str) -> str:
    lvl = (level or "").lower()
    if lvl in {"error", "critical"}:
        return "error"
    if lvl in {"warning", "notice"}:
        return "warning"
    return "info"


def _issues_from_json(provider: Provider, payload: dict) -> list[SyntaxIssue]:
    issues: list[SyntaxIssue] = []
    for entry in payload.get("issues", []) or []:
        rule = entry.get("rule") or {}
        range_ = entry.get("range") or {}
        start = range_.get("start") or {}
        issues.append(
            SyntaxIssue(
                provider=provider,
                level=_map_severity(rule.get("severity", "warning")),
                code=rule.get("name", "tflint"),
                message=entry.get("message", ""),
                source_tool="tflint",
                path=range_.get("filename"),
                line=start.get("line"),
            )
        )
    for err in payload.get("errors", []) or []:
        issues.append(
            SyntaxIssue(
                provider=provider,
                level=_map_severity(err.get("severity", "error")),
                code="tflint_runtime",
                message=err.get("message", ""),
                source_tool="tflint",
            )
        )
    return issues


def run_tflint(provider: Provider, scratch_dir: Path) -> tuple[list[SyntaxIssue], bool, list[str]]:
    notes: list[str] = []
    if not _tflint_available():
        message = f"tflint binary '{TFLINT_BIN}' not on PATH; tflint gate is advisory."
        if os.getenv("WAF_REQUIRE_TFLINT") == "1":
            raise RuntimeError(message)
        notes.append(message)
        return [], False, notes

    _write_config(scratch_dir)

    init = _run([TFLINT_BIN, "--init"], scratch_dir, timeout=max(TFLINT_TIMEOUT_SECONDS, 90.0))
    if init.returncode != 0:
        notes.append((init.stderr or init.stdout or "tflint --init failed").strip()[:2000])
        return [
            SyntaxIssue(
                provider=provider,
                level="error",
                code="tflint_init",
                message=notes[-1],
                source_tool="tflint",
            )
        ], False, notes

    started = time.perf_counter()
    result = _run([TFLINT_BIN, "--format=json", "--no-color"], scratch_dir)
    duration_ms = (time.perf_counter() - started) * 1000
    logger.info("tflint provider=%s duration_ms=%.2f rc=%d", provider.value, duration_ms, result.returncode)

    if not result.stdout.strip():
        if result.returncode == 0:
            return [], True, notes
        notes.append((result.stderr or "tflint returned no output").strip()[:2000])
        return [], False, notes

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        notes.append("tflint returned non-JSON output; captured stderr in notes")
        notes.append((result.stderr or result.stdout).strip()[:2000])
        return [], False, notes

    issues = _issues_from_json(provider, payload)
    ok = result.returncode == 0 and not any(issue.level == "error" for issue in issues)
    return issues, ok, notes

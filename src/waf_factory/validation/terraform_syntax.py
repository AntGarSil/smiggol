"""Terraform syntax validation gate.

Runs ``terraform fmt``, ``terraform init -backend=false`` and
``terraform validate`` against generated provider artifacts.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

from waf_factory.models import Provider, ProviderArtifact, SyntaxIssue, SyntaxReport
from waf_factory.validation.tflint_gate import run_tflint

logger = logging.getLogger("waf_factory.validation.terraform_syntax")


AWS_PROVIDER_CONSTRAINT = os.getenv("WAF_TF_AWS_VERSION", "~> 5.0")
AZURE_PROVIDER_CONSTRAINT = os.getenv("WAF_TF_AZURERM_VERSION", "~> 3.0")
CACHE_ROOT_DEFAULT = Path(os.getenv("WAF_TF_CACHE_DIR", ".waf_factory_cache/tf"))
PLUGIN_CACHE_DEFAULT = Path(os.getenv("TF_PLUGIN_CACHE_DIR", ".waf_factory_cache/tf-plugins"))
TERRAFORM_BIN = os.getenv("TERRAFORM_BIN", "terraform")
TF_TIMEOUT_SECONDS = float(os.getenv("WAF_TF_TIMEOUT_SECONDS", "60"))


def _versions_hcl(provider: Provider) -> str:
    if provider == Provider.AWS:
        return (
            "terraform {\n"
            "  required_version = \">= 1.3\"\n"
            "  required_providers {\n"
            "    aws = {\n"
            "      source  = \"hashicorp/aws\"\n"
            f"      version = \"{AWS_PROVIDER_CONSTRAINT}\"\n"
            "    }\n"
            "  }\n"
            "}\n\n"
            "provider \"aws\" {\n"
            "  region                      = \"us-east-1\"\n"
            "  skip_credentials_validation = true\n"
            "  skip_metadata_api_check     = true\n"
            "  skip_requesting_account_id  = true\n"
            "  access_key                  = \"mock\"\n"
            "  secret_key                  = \"mock\"\n"
            "}\n"
        )
    return (
        "terraform {\n"
        "  required_version = \">= 1.3\"\n"
        "  required_providers {\n"
        "    azurerm = {\n"
        "      source  = \"hashicorp/azurerm\"\n"
        f"      version = \"{AZURE_PROVIDER_CONSTRAINT}\"\n"
        "    }\n"
        "  }\n"
        "}\n\n"
        "provider \"azurerm\" {\n"
        "  features {}\n"
        "  skip_provider_registration = true\n"
        "}\n\n"
        "variable \"location\" {\n"
        "  type    = string\n"
        "  default = \"eastus\"\n"
        "}\n\n"
        "variable \"resource_group_name\" {\n"
        "  type    = string\n"
        "  default = \"waf-factory-rg\"\n"
        "}\n"
    )


def _terraform_available() -> bool:
    return shutil.which(TERRAFORM_BIN) is not None


def _run(cmd: list[str], cwd: Path, env_extra: dict[str, str] | None = None, timeout: float | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["TF_IN_AUTOMATION"] = "1"
    env["TF_INPUT"] = "0"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout or TF_TIMEOUT_SECONDS,
        check=False,
    )


def prepare_scratch_dir(job_id: str, provider: Provider, artifact: ProviderArtifact, cache_root: Path | None = None) -> Path:
    root = cache_root or CACHE_ROOT_DEFAULT
    provider_dir = root / job_id / provider.value
    provider_dir.mkdir(parents=True, exist_ok=True)
    (provider_dir / "main.tf").write_text(artifact.terraform, encoding="utf-8")
    (provider_dir / "versions.tf").write_text(_versions_hcl(provider), encoding="utf-8")
    return provider_dir


def _diagnostics_to_issues(provider: Provider, tool: str, payload: dict) -> list[SyntaxIssue]:
    issues: list[SyntaxIssue] = []
    for diag in payload.get("diagnostics", []) or []:
        level = str(diag.get("severity", "error")).lower()
        message = diag.get("summary") or diag.get("detail") or ""
        if diag.get("detail") and diag.get("summary"):
            message = f"{diag['summary']}: {diag['detail']}"
        range_ = diag.get("range") or {}
        issues.append(
            SyntaxIssue(
                provider=provider,
                level=level,
                code=diag.get("summary", "")[:80] or "diagnostic",
                message=message,
                source_tool=tool,
                path=range_.get("filename"),
                line=(range_.get("start") or {}).get("line"),
            )
        )
    return issues


def run_syntax_gate(
    artifacts: list[ProviderArtifact],
    *,
    job_id: str,
    cache_root: Path | None = None,
    plugin_cache_dir: Path | None = None,
) -> tuple[dict[Provider, SyntaxReport], list[str]]:
    warnings: list[str] = []

    if not artifacts:
        return {}, ["Terraform syntax gate skipped: no artifacts"]

    if not _terraform_available():
        message = f"Terraform binary '{TERRAFORM_BIN}' not on PATH; syntax gate is advisory."
        if os.getenv("WAF_REQUIRE_TF_VALIDATE") == "1":
            raise RuntimeError(message)
        warnings.append(message)
        return {
            artifact.provider: SyntaxReport(provider=artifact.provider, available=False, notes=[message])
            for artifact in artifacts
        }, warnings

    plugin_cache = plugin_cache_dir or PLUGIN_CACHE_DEFAULT
    plugin_cache.mkdir(parents=True, exist_ok=True)
    env_extra = {"TF_PLUGIN_CACHE_DIR": str(plugin_cache.resolve())}

    reports: dict[Provider, SyntaxReport] = {}
    for artifact in artifacts:
        started = time.perf_counter()
        provider_dir = prepare_scratch_dir(job_id, artifact.provider, artifact, cache_root=cache_root)
        issues: list[SyntaxIssue] = []
        notes: list[str] = []

        fmt = _run([TERRAFORM_BIN, "fmt", "-check", "-diff"], provider_dir)
        fmt_ok = fmt.returncode == 0
        if not fmt_ok:
            issues.append(
                SyntaxIssue(
                    provider=artifact.provider,
                    level="warning",
                    code="terraform_fmt",
                    message=(fmt.stdout or fmt.stderr or "terraform fmt reported formatting issues").strip()[:2000],
                    source_tool="terraform fmt",
                )
            )

        init = _run(
            [TERRAFORM_BIN, "init", "-backend=false", "-input=false", "-no-color"],
            provider_dir,
            env_extra=env_extra,
            timeout=max(TF_TIMEOUT_SECONDS, 120.0),
        )
        if init.returncode != 0:
            notes.append("terraform init failed; validate will be skipped")
            issues.append(
                SyntaxIssue(
                    provider=artifact.provider,
                    level="error",
                    code="terraform_init",
                    message=(init.stderr or init.stdout or "terraform init failed").strip()[:2000],
                    source_tool="terraform init",
                )
            )
            reports[artifact.provider] = SyntaxReport(
                provider=artifact.provider,
                available=True,
                fmt_ok=fmt_ok,
                validate_ok=False,
                tflint_ok=False,
                issues=issues,
                notes=notes,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
            continue

        validate = _run(
            [TERRAFORM_BIN, "validate", "-json", "-no-color"],
            provider_dir,
            env_extra=env_extra,
        )
        validate_ok = False
        try:
            payload = json.loads(validate.stdout or "{}")
            validate_ok = bool(payload.get("valid"))
            issues.extend(_diagnostics_to_issues(artifact.provider, "terraform validate", payload))
        except json.JSONDecodeError:
            issues.append(
                SyntaxIssue(
                    provider=artifact.provider,
                    level="error",
                    code="terraform_validate_parse",
                    message=(validate.stderr or validate.stdout or "terraform validate returned non-JSON").strip()[:2000],
                    source_tool="terraform validate",
                )
            )

        tflint_ok = False
        if validate_ok:
            try:
                tflint_issues, tflint_ok, tflint_notes = run_tflint(artifact.provider, provider_dir)
                issues.extend(tflint_issues)
                notes.extend(tflint_notes)
            except Exception as exc:
                notes.append(f"tflint failed: {exc}")

        reports[artifact.provider] = SyntaxReport(
            provider=artifact.provider,
            available=True,
            fmt_ok=fmt_ok,
            validate_ok=validate_ok,
            tflint_ok=tflint_ok,
            issues=issues,
            notes=notes,
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    return reports, warnings

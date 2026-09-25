"""Shared LLM configuration used by the rule generator and the supervisor."""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class LlmConfig:
    provider: str
    api_key: str
    base_url: str | None
    generator_model: str
    supervisor_model: str
    timeout_seconds: float


def _gh_cli_token() -> str:
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except Exception:
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def resolve_api_key(provider: str) -> str:
    if provider == "github":
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if token:
            return token
        return _gh_cli_token()
    return os.getenv("OPENAI_API_KEY", "").strip()


def resolve_base_url(provider: str) -> str | None:
    if provider == "github":
        return os.getenv("GITHUB_COPILOT_BASE_URL", "https://api.githubcopilot.com")
    return os.getenv("OPENAI_BASE_URL")


def load_config() -> LlmConfig:
    provider = os.getenv("WAF_LLM_PROVIDER", "github").strip().lower()
    default_gen = "gpt-4o-mini" if provider == "github" else "gpt-4o-mini"
    default_sup = "gpt-4o-mini" if provider == "github" else "gpt-4o-mini"
    return LlmConfig(
        provider=provider,
        api_key=resolve_api_key(provider),
        base_url=resolve_base_url(provider),
        generator_model=os.getenv("WAF_RULEGEN_MODEL", default_gen),
        supervisor_model=os.getenv("WAF_SUPERVISOR_MODEL", default_sup),
        timeout_seconds=float(os.getenv("WAF_LLM_TIMEOUT_SECONDS", os.getenv("OPENAI_TIMEOUT_SECONDS", "30"))),
    )


def build_supervisor_chat_model():
    """Return a LangChain ChatOpenAI (or None if credentials are missing)."""
    cfg = load_config()
    if not cfg.api_key:
        return None
    try:
        from langchain_openai import ChatOpenAI
    except ModuleNotFoundError:
        return None
    return ChatOpenAI(
        model=cfg.supervisor_model,
        api_key=cfg.api_key,
        base_url=cfg.base_url,
        temperature=0,
        timeout=cfg.timeout_seconds,
        max_retries=0,
    )

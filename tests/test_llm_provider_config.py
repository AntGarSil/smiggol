from __future__ import annotations

import subprocess

from waf_factory.llm_rulegen import LlmRuleGenerator


def test_llm_provider_defaults_to_github(monkeypatch) -> None:
    monkeypatch.delenv("WAF_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("WAF_RULEGEN_MODEL", raising=False)

    llm = LlmRuleGenerator()

    assert llm.provider == "github"
    assert llm.model == "gpt-4o-mini"


def test_llm_enabled_with_github_token(monkeypatch) -> None:
    monkeypatch.setenv("WAF_LLM_PROVIDER", "github")
    monkeypatch.setenv("GITHUB_TOKEN", "token")

    llm = LlmRuleGenerator()

    assert llm.enabled()


def test_llm_enabled_with_gh_auth_token(monkeypatch) -> None:
    monkeypatch.setenv("WAF_LLM_PROVIDER", "github")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="gh-cli-token\n", stderr="")

    monkeypatch.setattr("waf_factory.llm_rulegen.subprocess.run", fake_run)

    llm = LlmRuleGenerator()

    assert llm.enabled()


def test_llm_missing_message_for_openai_provider(monkeypatch) -> None:
    monkeypatch.setenv("WAF_LLM_PROVIDER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    llm = LlmRuleGenerator()

    assert "OPENAI_API_KEY" in llm.missing_credentials_message()


def test_llm_missing_message_for_github_provider(monkeypatch) -> None:
    monkeypatch.setenv("WAF_LLM_PROVIDER", "github")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="not logged in")

    monkeypatch.setattr("waf_factory.llm_rulegen.subprocess.run", fake_run)

    llm = LlmRuleGenerator()

    assert not llm.enabled()
    assert "gh auth login" in llm.missing_credentials_message()


def test_expensive_models_are_pinned_to_gpt_5_6(monkeypatch) -> None:
    monkeypatch.setenv("WAF_LLM_PROVIDER", "github")
    monkeypatch.setenv("WAF_RULEGEN_MODEL", "gpt-4o-mini")

    llm = LlmRuleGenerator()
    assert llm.expensive_model("repair") == "gpt-5.6-sol"
    assert llm.expensive_model("audit") == "gpt-5.6-sol"


def test_expensive_invocation_uses_dedicated_timeout(monkeypatch) -> None:
    monkeypatch.setenv("WAF_LLM_TIMEOUT_SECONDS", "30")
    monkeypatch.setenv("WAF_LLM_EXPENSIVE_TIMEOUT_SECONDS", "180")
    llm = LlmRuleGenerator()
    observed: list[tuple[str, float]] = []

    def fake_invoke(prompt: str) -> str:
        observed.append((llm.model, llm.timeout_seconds))
        return "{}"

    monkeypatch.setattr(llm, "_invoke_llm", fake_invoke)

    assert llm.invoke_with_model(prompt="test", model="gpt-5.6-sol") == "{}"
    assert observed == [("gpt-5.6-sol", 180.0)]
    assert llm.timeout_seconds == 30.0

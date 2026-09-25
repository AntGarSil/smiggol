from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from waf_factory.models import Condition, CveIntel, FieldType, IntermediateRule, Operator, PocArtifact, Provider, RuleAuditReport
from waf_factory.provider_constraints import provider_constraint_text


class LlmCondition(BaseModel):
    field_type: FieldType
    operator: Operator
    pattern: str = Field(min_length=1)
    header_name: str | None = None


class LlmRuleDraft(BaseModel):
    name: str = Field(min_length=3)
    confidence: float = Field(ge=0.0, le=1.0)
    conditions: list[LlmCondition] = Field(min_length=1)
    rationale: str = ""
    fp_risk: str = ""


class LlmAuditDraft(BaseModel):
    effectiveness_score: float = Field(ge=0.0, le=1.0)
    false_positive_risk: float = Field(ge=0.0, le=1.0)
    verdict: str = Field(pattern=r"^(ready|needs_review|blocked)$")
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class LlmRuleGenerator:
    def __init__(self, model: str | None = None) -> None:
        self.provider = os.getenv("WAF_LLM_PROVIDER", "github").strip().lower()
        self.model = model or self._default_model_for_provider(self.provider)
        self.timeout_seconds = float(
            os.getenv("WAF_LLM_TIMEOUT_SECONDS", os.getenv("OPENAI_TIMEOUT_SECONDS", "30"))
        )
        self.expensive_timeout_seconds = float(
            os.getenv("WAF_LLM_EXPENSIVE_TIMEOUT_SECONDS", "180")
        )
        self.max_retries = int(os.getenv("WAF_LLM_MAX_RETRIES", "2"))
        self.logger = logging.getLogger("waf_factory.llm")
        self._resolved_api_key: str | None = None

    def enabled(self) -> bool:
        return bool(self._api_key())

    def missing_credentials_message(self) -> str:
        if self.provider == "github":
            return (
                "LLM generation skipped: no GitHub credentials found. "
                "Use `gh auth login` (preferred) or set GITHUB_TOKEN."
            )
        return "LLM generation skipped: OPENAI_API_KEY is not configured"

    def _default_model_for_provider(self, provider: str) -> str:
        if provider == "github":
            return os.getenv("WAF_RULEGEN_MODEL", "gpt-4o-mini")
        return os.getenv("WAF_RULEGEN_MODEL", "gpt-4o-mini")

    def expensive_model(self, purpose: str) -> str:
        # Stabilization and audit are pinned to the expensive model tier.
        if purpose == "repair":
            return "gpt-5.6-sol"
        if purpose == "audit":
            return "gpt-5.6-sol"
        return self.model

    def _api_key(self) -> str:
        if self._resolved_api_key is not None:
            return self._resolved_api_key

        if self.provider == "github":
            env_token = os.getenv("GITHUB_TOKEN", "").strip()
            if env_token:
                self._resolved_api_key = env_token
                return self._resolved_api_key

            gh_token = self._gh_cli_token()
            self._resolved_api_key = gh_token
            return self._resolved_api_key

        self._resolved_api_key = os.getenv("OPENAI_API_KEY", "").strip()
        return self._resolved_api_key

    def _gh_cli_token(self) -> str:
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

    def _base_url(self) -> str | None:
        if self.provider == "github":
            return os.getenv("GITHUB_COPILOT_BASE_URL", "https://api.githubcopilot.com")
        return os.getenv("OPENAI_BASE_URL")

    def generate_rule(
        self,
        *,
        intel: CveIntel,
        pocs: list[PocArtifact],
        rule_id: str,
        action: Any,
        repair_feedback: str | None = None,
    ) -> IntermediateRule:
        selected = [p for p in pocs if p.payload][:30]
        payloads = [p.payload for p in selected]
        prompt = self._build_prompt(intel, selected, repair_feedback=repair_feedback)
        self.logger.info(
            "invoking llm model=%s cve=%s payloads=%d timeout_seconds=%.1f repair=%s",
            self.model,
            intel.cve_id,
            len(selected),
            self.timeout_seconds,
            bool(repair_feedback),
        )
        response_json = self._invoke_llm(prompt)
        draft = self._parse_json(response_json)

        template_sources = sorted({p.source for p in selected})

        return IntermediateRule(
            rule_id=rule_id,
            name=draft.name,
            cve_id=intel.cve_id,
            severity=intel.severity,
            action=action,
            confidence=draft.confidence,
            conditions=[
                Condition(
                    field_type=cond.field_type,
                    operator=cond.operator,
                    pattern=cond.pattern,
                    header_name=cond.header_name,
                )
                for cond in draft.conditions
            ],
            source_pocs=payloads,
            provenance={
                "generator": "llm",
                "provider": self.provider,
                "model": self.model,
                "prompt_version": "v2-nuclei-aware",
                "rationale": draft.rationale,
                "fp_risk": draft.fp_risk,
                "nuclei_template_count": len(template_sources),
                "repair_applied": bool(repair_feedback),
            },
        )

    def _build_prompt(
        self,
        intel: CveIntel,
        pocs: list[PocArtifact],
        repair_feedback: str | None = None,
    ) -> str:
        payload_block = (
            "\n".join(f"- [{p.source}] {p.payload}" for p in pocs)
            if pocs
            else "- (none)"
        )
        template_block = self._template_context_block(pocs)
        surface_summary = self._surface_summary_block(pocs)
        coverage_requirements = self._coverage_requirements_block(intel, pocs)
        quality_bar = self._quality_bar_block(intel, pocs)
        tags = ", ".join(intel.tags) if intel.tags else "none"
        refs = "\n".join(intel.references[:8]) if intel.references else "(none)"

        repair_block = ""
        if repair_feedback:
            repair_block = (
                "\nPRIOR ATTEMPT FEEDBACK (repair the previous rule based on these issues):\n"
                f"{repair_feedback}\n"
            )

        return (
            "You are generating defensive WAF rules from known exploit payloads. "
            "Return JSON only. Do not include markdown or prose outside JSON.\n\n"
            "JSON schema:\n"
            "{\n"
            "  \"name\": \"string\",\n"
            "  \"confidence\": 0.0,\n"
            "  \"rationale\": \"string\",\n"
            "  \"fp_risk\": \"low|medium|high with short note\",\n"
            "  \"conditions\": [\n"
            "    {\"field_type\": \"uri_path|query|body|header|ip\", \"operator\": \"regex|contains|equals\", \"pattern\": \"string\", \"header_name\": \"optional\"}\n"
            "  ]\n"
            "}\n\n"
            "Constraints:\n"
            "- Prefer exploit-specific conditions from payloads.\n"
            "- Ensure any rules are set to count mode; do not generate any block rules or rules which allow exploit traffic.\n"
            "- Ground your patterns in the nuclei template contexts and request payloads listed below.\n"
            "- Avoid broad catch-all signatures.\n"
            "- Include all required exploit surfaces listed under COVERAGE REQUIREMENTS.\n"
            "- Generate as many conditions as needed to satisfy coverage requirements; avoid duplicates.\n"
            "- Patterns must be valid regex if operator=regex.\n"
            "- For header field_type, set header_name.\n\n"
            f"CVE: {intel.cve_id}\n"
            f"Severity: {intel.severity.value}\n"
            f"Tags: {tags}\n"
            f"Description: {intel.description}\n"
            f"References:\n{refs}\n\n"
            f"Observed injection surfaces:\n{surface_summary}\n\n"
            f"COVERAGE REQUIREMENTS (must satisfy all):\n{coverage_requirements}\n\n"
            f"QUALITY BAR (must satisfy):\n{quality_bar}\n\n"
            f"Nuclei templates involved:\n{template_block}\n\n"
            f"Known exploit payloads:\n{payload_block}\n"
            f"{repair_block}"
        )

    def build_stabilize_prompt(
        self,
        *,
        intel: CveIntel,
        pocs: list[PocArtifact],
        current_rule: IntermediateRule,
        replay_results: list[dict[str, Any]],
        validation_issues: list[dict[str, Any]],
        providers: list[Provider] | None = None,
        audit_feedback: str | None = None,
    ) -> str:
        payload_block = self._safe_payload_evidence_block(pocs)
        current_rule_json = json.dumps(
            current_rule.model_dump(mode="json", exclude={"source_pocs"}),
            separators=(",", ":"),
        )
        return (
            "You are a WAF expert repairing an unstable defensive WAF rule and making it enterprise ready. Return JSON only and only this schema:\n"
            "{\n"
            "  \"name\": \"string\",\n"
            "  \"confidence\": 0.0,\n"
            "  \"rationale\": \"string\",\n"
            "  \"fp_risk\": \"low|medium|high with short note\",\n"
            "  \"conditions\": [\n"
            "    {\"field_type\": \"uri_path|query|body|header|ip\", \"operator\": \"regex|contains|equals\", \"pattern\": \"string\", \"header_name\": \"optional\"}\n"
            "  ]\n"
            "}\n\n"
            "Goals:\n"
            "- Preserve exploit detection coverage from payloads.\n"
            "- Reduce false positives by tightening overly broad patterns.\n"
            "- Keep conditions provider-friendly and avoid unnecessary duplicates.\n"
            "- Build a rule that can compile against your target WAF engine.\n"
            "- Keep rule action in count mode semantics; produce detection conditions only.\n\n"
            f"PROVIDER COMPILATION CONSTRAINTS (must satisfy all):\n{provider_constraint_text(providers or [])}\n\n"
            f"CVE: {intel.cve_id}\n"
            f"Description: {intel.description}\n"
            f"Current rule JSON (raw source_pocs omitted): {current_rule_json}\n"
            f"Replay results: {json.dumps(replay_results, default=str)}\n"
            f"Validation issues: {json.dumps(validation_issues, default=str)}\n"
            f"Prior audit recommendations: {audit_feedback or '(none; initial stabilization pass)'}\n"
            "Revise the current rule in place to address every applicable audit recommendation; do not generate an unrelated replacement rule.\n"
            f"Known exploit payloads:\n{payload_block}\n"
        )

    def build_audit_prompt(
        self,
        *,
        intel: CveIntel,
        pocs: list[PocArtifact],
        rule: IntermediateRule,
        replay_results: list[dict[str, Any]],
        validation_issues: list[dict[str, Any]],
        providers: list[Provider] | None = None,
    ) -> str:
        payload_block = self._safe_payload_evidence_block(pocs)
        rule_json = json.dumps(
            rule.model_dump(mode="json", exclude={"source_pocs"}),
            separators=(",", ":"),
        )
        return (
            "You are auditing a generated WAF rule for detection effectiveness and false-positive risk. You must consider operational impact."
            "Return strict JSON only with this schema:\n"
            "{\n"
            "  \"effectiveness_score\": 0.0,\n"
            "  \"false_positive_risk\": 0.0,\n"
            "  \"verdict\": \"ready|needs_review|blocked\",\n"
            "  \"summary\": \"string\",\n"
            "  \"evidence\": [\"string\"],\n"
            "  \"recommendations\": [\"string\"]\n"
            "}\n\n"
            "Scoring guidance:\n"
            "- effectiveness_score measures expected exploit catch rate across observed payload families and surfaces. Surfaces must be relevant to the CVE\n"
            "- false_positive_risk estimates benign match likelihood from pattern breadth and anchors.\n"
            "- consider aspects which may impact cost or performance, such as expensive regex patterns leading to ReDoS or complex rule logic.\n"
            "- ensure any produced ruleset can compile by the target WAF engine. A ruleset which cannot be deployed has an effectiveness of 0\n"
            "- verdict must be blocked while any provider compilation constraint or validation error remains.\n"
            "- verdict=blocked only for severe coverage gaps or unusable precision.\n\n"
            f"PROVIDER COMPILATION CONSTRAINTS:\n{provider_constraint_text(providers or [])}\n\n"
            f"CVE: {intel.cve_id}\n"
            f"Description: {intel.description}\n"
            f"Rule JSON (raw source_pocs omitted): {rule_json}\n"
            f"Replay results: {json.dumps(replay_results, default=str)}\n"
            f"Validation issues: {json.dumps(validation_issues, default=str)}\n"
            f"Known exploit payloads:\n{payload_block}\n"
        )

    def _safe_payload_evidence_block(self, pocs: list[PocArtifact]) -> str:
        lines: list[str] = []
        replacements = (
            ("${", "<EXPRESSION_OPEN>"),
            ("{{", "<TEMPLATE_OPEN>"),
            ("}}", "<TEMPLATE_CLOSE>"),
            ("://", ":<SCHEME_SEPARATOR>"),
        )
        for poc in pocs[:40]:
            payload = poc.payload
            for raw, placeholder in replacements:
                payload = payload.replace(raw, placeholder)
            lines.append(f"- [{poc.source}] {payload}")
        return "\n".join(lines) or "- (none)"

    def _quality_bar_block(self, intel: CveIntel, pocs: list[PocArtifact]) -> str:
        lines: list[str] = [
            "- Ensure conditions are precise enough to block exploit traffic, not generic noise.",
            "- If multiple exploit pattern families are observed, include conditions for each family.",
            "- For each required request surface, include explicit coverage (uri_path, query, body, headers when observed).",
            "- Prefer robust regexes that tolerate mild obfuscation and URL-encoded variants.",
            "- Where possible consolidate rules to minimise WAF capacity impact while still covering all observed injection surfaces.",
        ]

        if self._looks_like_log4shell(intel, pocs):
            lines.extend(
                [
                    "- Log4Shell/JNDI-specific minimum pattern families to cover:",
                    "  1) Direct JNDI protocol sink: (?i)(ldap|ldaps|rmi|dns|iiop|corba|nis|nds)://",
                    "  2) Obfuscated jndi token assembly: (?i)\\{[^}]{0,20}j[^}]{0,10}n[^}]{0,10}d[^}]{0,10}i[^}]{0,50}:(ldap|ldaps|rmi|dns|iiop|corba|nis|nds)://",
                    "  3) Common wrapper / transform primitives: (?i)\\{(lower|upper|::-)[^}]{0,50}\\}",
                    "  4) Lookup fallback patterns: (?i)\\{(env|sys|date|main|java|marker|log4j):[^}:-]{0,50}:-[^}]{0,10}\\}",
                    "- If headers are observed, include header conditions for each observed header_name; include cookie coverage when cookie injection is observed.",
                    "- Confidence should reflect strong coverage only when all observed surfaces and families are covered.",
                ]
            )

        return "\n".join(lines)

    def _looks_like_log4shell(self, intel: CveIntel, pocs: list[PocArtifact]) -> bool:
        cve = (intel.cve_id or "").upper()
        if cve == "CVE-2021-44228":
            return True

        text_parts = [intel.description or ""] + [p.payload or "" for p in pocs]
        joined = "\n".join(text_parts).lower()
        return "${jndi:" in joined or "log4j" in joined or "jndi" in joined

    def _surface_summary_block(self, pocs: list[PocArtifact]) -> str:
        headers: set[str] = set()
        query_present = False
        body_present = False
        uri_paths: list[str] = []

        for poc in pocs:
            payload = (poc.payload or "").strip()
            if not payload:
                continue

            req_line = re.match(
                r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/",
                payload,
                flags=re.IGNORECASE,
            )
            if req_line:
                path = req_line.group(2)
                if "?" in path:
                    query_present = True
                uri_paths.append(path)
                continue

            header = re.match(r"^([A-Za-z0-9-]{2,64}):\s+(.+)$", payload)
            if header:
                headers.add(header.group(1).lower())
                continue

            if "=" in payload or "${" in payload:
                body_present = True

        sample_paths = ", ".join(uri_paths[:5]) if uri_paths else "none"
        sample_headers = ", ".join(sorted(headers)[:20]) if headers else "none"
        return (
            f"- query_injection_present: {'yes' if query_present else 'no'}\n"
            f"- body_injection_present: {'yes' if body_present else 'no'}\n"
            f"- observed_header_names: {sample_headers}\n"
            f"- sample_request_paths: {sample_paths}"
        )

    def _coverage_requirements_block(self, intel: CveIntel, pocs: list[PocArtifact]) -> str:
        headers: set[str] = set()
        query_present = False

        for poc in pocs:
            payload = (poc.payload or "").strip()
            if not payload:
                continue

            req_line = re.match(
                r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/",
                payload,
                flags=re.IGNORECASE,
            )
            if req_line and "?" in req_line.group(2):
                query_present = True

            header = re.match(r"^([A-Za-z0-9-]{2,64}):\s+.+$", payload)
            if header:
                headers.add(header.group(1).lower())

        lines = [
            "- Use exploit-specific patterns tied to payload markers for this CVE; do not introduce unrelated exploit families.",
            "- Apply each exploit regex family symmetrically across required surfaces; do not limit stronger obfuscation checks to only one field.",
        ]
        if query_present:
            lines.append("- Include at least one condition with field_type=query for query-string injection vectors.")

        if headers:
            lines.append(
                "- Include header conditions for every observed header name below, each with exact header_name: "
                + ", ".join(sorted(headers))
            )
        else:
            lines.append("- No header payloads were observed; header conditions are optional.")

        if self._looks_like_log4shell(intel=intel, pocs=pocs):
            lines.append(
                "- For Log4Shell/JNDI, include coverage across uri_path, query, body, and header surfaces; "
                "do not restrict advanced obfuscation checks to query-only."
            )

        return "\n".join(lines)

    def _template_context_block(self, pocs: list[PocArtifact]) -> str:
        sources = sorted({p.source for p in pocs})
        if not sources:
            return "- (none)"
        return "\n".join(f"- {source}" for source in sources)

    def _invoke_llm(self, prompt: str) -> str:
        try:
            from openai import OpenAI
        except ModuleNotFoundError as exc:
            raise ValueError(
                "LLM generation failed: missing dependency `openai`. "
                "Activate the project virtualenv and run `pip install -r requirements.txt`."
            ) from exc

        started = time.perf_counter()
        api_key = self._api_key()
        if not api_key:
            raise ValueError(self.missing_credentials_message())

        client_kwargs: dict[str, Any] = {
            "api_key": api_key,
            "timeout": self.timeout_seconds,
            "max_retries": self.max_retries,
        }
        base_url = self._base_url()
        if base_url:
            client_kwargs["base_url"] = base_url

        client = OpenAI(**client_kwargs)
        messages = [
            {
                "role": "system",
                "content": "Generate only strict JSON for defensive WAF rule creation.",
            },
            {"role": "user", "content": prompt},
        ]

        if self.model == "gpt-5.6-sol":
            with client.responses.stream(
                model=self.model,
                input=messages,
            ) as stream:
                response = stream.get_final_response()
                content = response.output_text or ""
        else:
            response = client.chat.completions.create(
                model=self.model,
                temperature=0.1,
                messages=messages,
            )
            content = response.choices[0].message.content or ""

        elapsed_ms = (time.perf_counter() - started) * 1000
        self.logger.info("llm call completed model=%s duration_ms=%.2f", self.model, elapsed_ms)

        return content

    def invoke_with_model(self, *, prompt: str, model: str) -> str:
        previous = self.model
        previous_timeout = self.timeout_seconds
        try:
            self.model = model
            self.timeout_seconds = self.expensive_timeout_seconds
            return self._invoke_llm(prompt)
        finally:
            self.model = previous
            self.timeout_seconds = previous_timeout

    def _parse_json(self, payload: str) -> LlmRuleDraft:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM did not return valid JSON: {exc}") from exc

        try:
            return LlmRuleDraft.model_validate(data)
        except ValidationError as exc:
            raise ValueError(f"LLM JSON failed schema validation: {exc}") from exc

    def parse_audit_json(self, payload: str) -> RuleAuditReport:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM did not return valid JSON: {exc}") from exc

        try:
            draft = LlmAuditDraft.model_validate(data)
        except ValidationError as exc:
            raise ValueError(f"LLM JSON failed schema validation: {exc}") from exc

        return RuleAuditReport(
            model=self.model,
            provider=self.provider,
            effectiveness_score=draft.effectiveness_score,
            false_positive_risk=draft.false_positive_risk,
            verdict=draft.verdict,
            summary=draft.summary,
            evidence=list(draft.evidence),
            recommendations=list(draft.recommendations),
        )

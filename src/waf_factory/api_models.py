from typing import Any

from pydantic import BaseModel, Field

from waf_factory.models import CveIntel, EnforcementMode, Provider


class GenerateRulesRequest(BaseModel):
    cve_id: str = Field(min_length=8)
    targets: list[Provider] = Field(default_factory=lambda: [Provider.AWS, Provider.AZURE])
    mode: EnforcementMode = EnforcementMode.COUNT
    use_llm: bool = True


class GenerateRulesResponse(BaseModel):
    cve_id: str
    cve: CveIntel | None = None
    warnings: list[str]
    rule_count: int
    rules: list[dict[str, Any]]
    provider_outputs: dict[str, str]
    replay_summary: dict[str, float]
    validation_issues: list[dict[str, str]]
    audit_report: dict[str, Any] | None = None
    promotion_state: str | None = None


class JobAcceptedResponse(BaseModel):
    job_id: str
    status: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    stages_done: list[str]
    warnings: list[str]
    error: str | None = None
    result: GenerateRulesResponse | None = None

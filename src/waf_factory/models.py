from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Provider(str, Enum):
    AWS = "aws"
    AZURE = "azure"


class EnforcementMode(str, Enum):
    COUNT = "count"
    BLOCK = "block"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FieldType(str, Enum):
    URI_PATH = "uri_path"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    IP = "ip"


class Operator(str, Enum):
    CONTAINS = "contains"
    REGEX = "regex"
    EQUALS = "equals"


class Condition(BaseModel):
    field_type: FieldType
    operator: Operator
    pattern: str
    header_name: str | None = None


class IntermediateRule(BaseModel):
    rule_id: str
    name: str
    cve_id: str
    severity: Severity
    action: EnforcementMode
    confidence: float = Field(ge=0.0, le=1.0)
    conditions: list[Condition]
    source_pocs: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)


class CveIntel(BaseModel):
    cve_id: str
    description: str = ""
    vector: str = ""
    severity: Severity = Severity.MEDIUM
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class PocArtifact(BaseModel):
    cve_id: str
    source: str
    payload: str


class ValidationIssue(BaseModel):
    rule_id: str
    level: str
    message: str


class ProviderArtifact(BaseModel):
    provider: Provider
    terraform: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReplayResult(BaseModel):
    rule_id: str
    payload_count: int
    detected_count: int
    detection_rate: float
    exploit_payload_count: int = 0
    exploit_detected_count: int = 0
    exploit_detection_rate: float = 0.0
    benign_payload_count: int = 0
    benign_detected_count: int = 0
    benign_match_rate: float = 0.0


class SyntaxIssue(BaseModel):
    provider: Provider
    level: str
    code: str = ""
    message: str
    source_tool: str = ""
    path: str | None = None
    line: int | None = None


class SyntaxReport(BaseModel):
    provider: Provider
    available: bool = True
    fmt_ok: bool = False
    validate_ok: bool = False
    tflint_ok: bool = False
    issues: list[SyntaxIssue] = Field(default_factory=list)
    duration_ms: float = 0.0
    notes: list[str] = Field(default_factory=list)


class EffectivenessOutcome(BaseModel):
    template_id: str
    cve_id: str | None = None
    category: str = ""
    outcome: str  # blocked | matched-but-allowed | undetected | benign_fp
    matched_rule_ids: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0


class EffectivenessReport(BaseModel):
    available: bool = True
    templates_run: int = 0
    exploit_templates_run: int = 0
    benign_templates_run: int = 0
    exploit_blocked: int = 0
    benign_matched: int = 0
    block_rate: float = 0.0
    false_negative_rate: float = 0.0
    benign_false_positive_rate: float = 0.0
    outcomes: list[EffectivenessOutcome] = Field(default_factory=list)
    undetected_templates: list[str] = Field(default_factory=list)
    false_positive_payloads: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0


class RuleAuditReport(BaseModel):
    model: str = ""
    provider: str = ""
    effectiveness_score: float = Field(ge=0.0, le=1.0)
    false_positive_risk: float = Field(ge=0.0, le=1.0)
    verdict: str = "needs_review"
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class PromotionState(str, Enum):
    READY = "ready"
    NEEDS_REVIEW = "needs_review"
    BLOCKED = "blocked"


class GenerationResult(BaseModel):
    cve: CveIntel
    rules: list[IntermediateRule]
    artifacts: list[ProviderArtifact]
    validation_issues: list[ValidationIssue]
    replay_results: list[ReplayResult]
    audit_report: RuleAuditReport | None = None
    promotion_state: PromotionState | None = None
    warnings: list[str] = Field(default_factory=list)

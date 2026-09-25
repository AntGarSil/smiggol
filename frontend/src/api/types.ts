export type Provider = 'aws' | 'azure'
export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'

export interface CveIntel {
  cve_id: string
  description: string
  vector: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  tags: string[]
  references: string[]
}

export interface RuleCondition {
  field_type: string
  operator: string
  pattern: string
  header_name?: string | null
}

export interface WafRule {
  rule_id: string
  name: string
  cve_id: string
  severity: string
  action: string
  confidence: number
  conditions: RuleCondition[]
  provenance?: Record<string, unknown>
}

export interface AuditReport {
  effectiveness_score: number
  false_positive_risk: number
  verdict: string
  summary: string
  evidence: string[]
  recommendations: string[]
}

export interface GenerationResult {
  cve_id: string
  cve?: CveIntel | null
  warnings: string[]
  rule_count: number
  rules: WafRule[]
  provider_outputs: Partial<Record<Provider, string>>
  replay_summary: Record<string, number>
  validation_issues: Array<{ rule_id: string; level: string; message: string }>
  audit_report?: AuditReport | null
  promotion_state?: string | null
}

export interface JobSnapshot {
  job_id: string
  status: JobStatus
  stages_done: string[]
  warnings: string[]
  error?: string | null
  result?: GenerationResult | null
}

export interface GenerationRequest {
  cve_id: string
  targets: Provider[]
  mode: 'count' | 'block'
  use_llm: boolean
}
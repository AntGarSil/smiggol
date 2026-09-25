import { useEffect, useRef, useState } from 'react'
import {
  BookOpen,
  Check,
  ChevronDown,
  ChevronUp,
  Clipboard,
  Cloud,
  CloudCog,
  Download,
  ExternalLink,
  Layers,
  RefreshCw,
  ShieldCheck,
  Square,
  Terminal,
  Trash2,
  X,
} from 'lucide-react'
import type { GenerationRequest, GenerationResult, Provider, WafRule } from './api/types'
import { useJobQueue, type JobEntry } from './hooks/useJobQueue'
import { useRuleLibrary, type LibraryEntry } from './hooks/useRuleLibrary'

const stages = [
  ['fetch_cve_intel', 'Gather intelligence'],
  ['collect_nuclei_pocs', 'Collect exploit evidence'],
  ['generate_rules', 'Forge candidate rule'],
  ['stabilize_rules', 'Stabilize conditions'],
  ['audit_rules', 'Audit effectiveness'],
  ['compile_targets', 'Compile providers'],
  ['finalize', 'Finalize result'],
] as const

// ── Helpers ────────────────────────────────────────────────────────────────

function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    await navigator.clipboard.writeText(value)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1600)
  }
  return (
    <button className="icon-action" type="button" onClick={copy} title={label}>
      {copied ? <Check /> : <Clipboard />}
      <span>{copied ? 'Copied' : label}</span>
    </button>
  )
}

function StatusSprite({ status }: { status: string }) {
  return (
    <div className={`status-sprite status-${status}`} aria-hidden="true">
      <span className="spark spark-a" />
      <span className="spark spark-b" />
      <span className="hammer" />
    </div>
  )
}

function MaturityBadge({ state }: { state: string | null | undefined }) {
  const cls =
    state === 'ready' ? 'ready' : state === 'needs_review' ? 'review' : state ? 'other' : 'unaudited'
  const label =
    state === 'ready'
      ? 'Ready'
      : state === 'needs_review'
        ? 'Needs review'
        : state
          ? state.replace(/_/g, ' ')
          : 'Unaudited'
  return <span className={`maturity-badge maturity-${cls}`}>{label}</span>
}

function RuleViewer({ rule }: { rule: WafRule }) {
  return (
    <article className="rule-block">
      <header className="rule-header">
        <div>
          <span className="eyebrow">
            {rule.action} · {Math.round(rule.confidence * 100)}% confidence
          </span>
          <h3>{rule.name}</h3>
          <code>{rule.rule_id}</code>
        </div>
        <CopyButton value={JSON.stringify(rule, null, 2)} label="Copy JSON" />
      </header>
      <div className="condition-list">
        {rule.conditions.map((condition, index) => (
          <div className="condition" key={`${condition.field_type}-${index}`}>
            <div className="condition-meta">
              <span>{condition.field_type}</span>
              <span>{condition.operator}</span>
              {condition.header_name && <span>{condition.header_name}</span>}
            </div>
            <code>{condition.pattern}</code>
            <CopyButton value={condition.pattern} label="Copy pattern" />
          </div>
        ))}
      </div>
    </article>
  )
}

// ── Shared result detail view ──────────────────────────────────────────────

function ResultDetail({
  result,
  defaultProvider,
}: {
  result: GenerationResult
  defaultProvider: Provider
}) {
  const available = Object.keys(result.provider_outputs) as Provider[]
  const [activeProvider, setActiveProvider] = useState<Provider>(
    available.includes(defaultProvider) ? defaultProvider : (available[0] ?? defaultProvider),
  )
  const providerOutput = result.provider_outputs[activeProvider]

  return (
    <div className="result-stack">
      <section className="cve-section">
        <div>
          <span className="eyebrow">{result.cve?.severity ?? 'unknown'} severity</span>
          <h2>{result.cve_id}</h2>
          <p>{result.cve?.description || 'No CVE description was available from the intelligence sources.'}</p>
        </div>
        <div className="cve-facts">
          {result.cve?.vector && <code>{result.cve.vector}</code>}
          <div className="tags">{result.cve?.tags.map(tag => <span key={tag}>{tag}</span>)}</div>
          {result.cve?.references.slice(0, 4).map(ref => (
            <a href={ref} target="_blank" rel="noreferrer" key={ref}>
              Reference <ExternalLink />
            </a>
          ))}
        </div>
      </section>

      {result.audit_report && (
        <section className="audit-grid">
          <div>
            <span>Promotion</span>
            <strong>{result.promotion_state ?? result.audit_report.verdict}</strong>
          </div>
          <div>
            <span>Effectiveness</span>
            <strong>{Math.round(result.audit_report.effectiveness_score * 100)}%</strong>
          </div>
          <div>
            <span>False-positive risk</span>
            <strong>{Math.round(result.audit_report.false_positive_risk * 100)}%</strong>
          </div>
          <p>{result.audit_report.summary}</p>
        </section>
      )}

      <section>
        <div className="section-heading">
          <div>
            <span className="eyebrow">Provider-neutral</span>
            <h2>WAF rules</h2>
          </div>
          <span>{result.rule_count} generated</span>
        </div>
        {result.rules.map(rule => (
          <RuleViewer rule={rule} key={rule.rule_id} />
        ))}
      </section>

      <section className="compiled">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Deployment output</span>
            <h2>Compiled Terraform</h2>
          </div>
        </div>
        <div className="output-tabs">
          {available.map(p => (
            <button
              className={activeProvider === p ? 'active' : ''}
              onClick={() => setActiveProvider(p)}
              key={p}
            >
              {p.toUpperCase()}
            </button>
          ))}
        </div>
        {providerOutput ? (
          <div className="code-output">
            <div className="code-toolbar">
              <span>
                <Terminal />
                {activeProvider}.tf
              </span>
              <div>
                <CopyButton value={providerOutput} />
                <a
                  className="icon-action"
                  href={`data:text/plain;charset=utf-8,${encodeURIComponent(providerOutput)}`}
                  download={`${result.cve_id}-${activeProvider}.tf`}
                >
                  <Download />
                  <span>Download</span>
                </a>
              </div>
            </div>
            <pre>
              <code>{providerOutput}</code>
            </pre>
          </div>
        ) : (
          <div className="alert">No {activeProvider.toUpperCase()} compilation was produced.</div>
        )}
      </section>

      {(result.validation_issues.length > 0 || result.warnings.length > 0) && (
        <section className="diagnostics">
          <h2>Diagnostics</h2>
          {result.validation_issues.map((issue, i) => (
            <div className={`alert ${issue.level}`} key={i}>
              {issue.message}
            </div>
          ))}
          {result.warnings.map(w => (
            <div className="alert" key={w}>
              {w}
            </div>
          ))}
        </section>
      )}
    </div>
  )
}

// ── Job card (active queue) ────────────────────────────────────────────────

function JobCard({
  job,
  onCancel,
  onDismiss,
}: {
  job: JobEntry
  onCancel: () => void
  onDismiss: () => void
}) {
  const [expanded, setExpanded] = useState(true)
  const { snapshot, error, params, transport } = job
  const status = snapshot?.status ?? 'pending'
  const running = status === 'queued' || status === 'running'
  const result = snapshot?.result
  const wasDone = useRef(false)

  // Auto-collapse when the job reaches a terminal state
  useEffect(() => {
    const done = status === 'succeeded' || status === 'failed' || status === 'cancelled'
    if (done && !wasDone.current) setExpanded(false)
    wasDone.current = done
  }, [status])

  return (
    <div className="job-card">
      <div className="job-card-header" onClick={() => setExpanded(v => !v)}>
        <div className="job-card-title">
          <span className="job-cve-id">{params.cve_id}</span>
          <span className={`status-pill status-pill-${status}`}>{status}</span>
          {result && <MaturityBadge state={result.promotion_state} />}
        </div>
        <div className="job-card-actions" onClick={e => e.stopPropagation()}>
          {running && (
            <button className="icon-action" type="button" onClick={onCancel}>
              <Square />
              <span>Cancel</span>
            </button>
          )}
          {!running && (
            <button className="icon-action" type="button" onClick={onDismiss}>
              <X />
              <span>Dismiss</span>
            </button>
          )}
          <span className="chevron-icon">{expanded ? <ChevronUp /> : <ChevronDown />}</span>
        </div>
      </div>

      {expanded && (
        <div className="job-card-body">
          <p className="job-meta eyebrow">
            {snapshot?.job_id ?? 'Submitting…'} · {transport ?? 'connecting'}
          </p>
          <div className="timeline">
            {stages.map(([id, label]) => (
              <div className={snapshot?.stages_done.includes(id) ? 'stage done' : 'stage'} key={id}>
                <span>{snapshot?.stages_done.includes(id) ? <Check /> : null}</span>
                <p>{label}</p>
              </div>
            ))}
          </div>
          {error && (
            <div className="alert error" style={{ marginTop: 16 }}>
              <X />
              {error}
            </div>
          )}
          {result && <ResultDetail result={result} defaultProvider={params.targets[0] ?? 'aws'} />}
        </div>
      )}
    </div>
  )
}

// ── Library card ───────────────────────────────────────────────────────────

function LibraryCard({
  entry,
  onRegenerate,
  onRemove,
}: {
  entry: LibraryEntry
  onRegenerate: () => void
  onRemove: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const { result, params, savedAt } = entry
  const severity = result.cve?.severity
  const desc = result.cve?.description
  const preview = desc
    ? desc.length > 160
      ? desc.slice(0, 160) + '…'
      : desc
    : 'No description available.'

  return (
    <div className="library-card">
      <div className="library-card-header" onClick={() => setExpanded(v => !v)}>
        <div className="library-card-meta">
          <div className="library-card-title">
            {severity && <span className={`severity-badge severity-${severity}`}>{severity}</span>}
            <strong className="library-cve-id">{entry.cveId}</strong>
            <MaturityBadge state={result.promotion_state} />
          </div>
          <p className="library-description">{preview}</p>
          <div className="library-card-stats">
            <span>
              {result.rule_count} rule{result.rule_count !== 1 ? 's' : ''}
            </span>
            <span>{params.targets.map(t => t.toUpperCase()).join(', ')}</span>
            <span>{new Date(savedAt).toLocaleDateString()}</span>
          </div>
        </div>
        <div className="library-card-actions" onClick={e => e.stopPropagation()}>
          <button className="icon-action" type="button" onClick={onRegenerate}>
            <RefreshCw />
            <span>Regenerate</span>
          </button>
          <button className="icon-action danger" type="button" onClick={onRemove} title="Remove from library">
            <Trash2 />
          </button>
          <span className="chevron-icon">{expanded ? <ChevronUp /> : <ChevronDown />}</span>
        </div>
      </div>

      {expanded && (
        <div className="library-card-body">
          <ResultDetail result={result} defaultProvider={params.targets[0] ?? 'aws'} />
        </div>
      )}
    </div>
  )
}

// ── App ────────────────────────────────────────────────────────────────────

function App() {
  const { jobs, submit, cancel, dismiss } = useJobQueue()
  const { entries, upsert, remove } = useRuleLibrary()
  const [cve, setCve] = useState('CVE-2025-55182')
  const [providers, setProviders] = useState<Provider[]>(['aws', 'azure'])
  const [mode, setMode] = useState<'count' | 'block'>('count')
  const [apiHealthy, setApiHealthy] = useState<boolean | null>(null)
  const [tab, setTab] = useState<'jobs' | 'library'>('jobs')
  const savedKeys = useRef(new Set<number>())

  const activeCount = jobs.filter(
    j => j.snapshot?.status === 'queued' || j.snapshot?.status === 'running',
  ).length
  const validCve = /^CVE-\d{4}-\d{4,}$/i.test(cve.trim())

  useEffect(() => {
    fetch('/health')
      .then(r => setApiHealthy(r.ok))
      .catch(() => setApiHealthy(false))
  }, [])

  // Auto-save succeeded jobs to the library — one entry per CVE, latest wins
  useEffect(() => {
    for (const job of jobs) {
      if (
        job.snapshot?.status === 'succeeded' &&
        job.snapshot.result &&
        !savedKeys.current.has(job.key)
      ) {
        savedKeys.current.add(job.key)
        upsert({
          cveId: job.snapshot.result.cve_id,
          params: job.params,
          result: job.snapshot.result,
          jobId: job.snapshot.job_id,
          savedAt: new Date().toISOString(),
        })
      }
    }
  }, [jobs, upsert])

  function toggleProvider(p: Provider) {
    setProviders(cur => (cur.includes(p) ? cur.filter(x => x !== p) : [...cur, p]))
  }

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    const payload: GenerationRequest = {
      cve_id: cve.trim().toUpperCase(),
      targets: providers,
      mode,
      use_llm: true,
    }
    void submit(payload)
    setTab('jobs')
  }

  function handleRegenerate(entry: LibraryEntry) {
    void submit(entry.params)
    setTab('jobs')
  }

  return (
    <main>
      <header className="topbar">
        <div className="brand-mark">
          <ShieldCheck />
          <div>
            <strong>SMIGGOL</strong>
            <span>WAF rule forge</span>
          </div>
        </div>
        <div className={`health ${apiHealthy ? 'healthy' : apiHealthy === false ? 'unhealthy' : ''}`}>
          <span />
          {apiHealthy ? 'API connected' : apiHealthy === false ? 'API unavailable' : 'Checking API'}
        </div>
      </header>

      <section className="workspace">
        <aside className="control-panel">
          <div>
            <span className="eyebrow">New generation</span>
            <h1>Forge a deployable rule</h1>
            <p>
              Choose a vulnerability and target providers. Smiggol gathers evidence, stabilizes
              coverage, and audits the result.
            </p>
          </div>
          <form onSubmit={handleSubmit}>
            <label htmlFor="cve">CVE identifier</label>
            <input
              id="cve"
              value={cve}
              onChange={e => setCve(e.target.value)}
              aria-invalid={!validCve}
              placeholder="CVE-2025-55182"
            />
            {!validCve && <small>Use the format CVE-YYYY-NNNN.</small>}
            <fieldset>
              <legend>Providers</legend>
              <div className="provider-options">
                <button
                  type="button"
                  className={providers.includes('aws') ? 'selected' : ''}
                  onClick={() => toggleProvider('aws')}
                >
                  <Cloud />
                  AWS
                  {providers.includes('aws') && <Check />}
                </button>
                <button
                  type="button"
                  className={providers.includes('azure') ? 'selected' : ''}
                  onClick={() => toggleProvider('azure')}
                >
                  <CloudCog />
                  Azure
                  {providers.includes('azure') && <Check />}
                </button>
              </div>
            </fieldset>
            <fieldset>
              <legend>Mode</legend>
              <div className="segmented">
                <button
                  type="button"
                  className={mode === 'count' ? 'selected' : ''}
                  onClick={() => setMode('count')}
                >
                  Count
                </button>
                <button
                  type="button"
                  className={mode === 'block' ? 'selected' : ''}
                  onClick={() => setMode('block')}
                >
                  Block
                </button>
              </div>
            </fieldset>
            <button className="primary" disabled={!validCve || providers.length === 0}>
              {activeCount > 0
                ? `${activeCount} job${activeCount > 1 ? 's' : ''} running · Add another`
                : 'Generate rules'}
            </button>
          </form>
        </aside>

        <div className="results-panel">
          <div className="pane-tabs">
            <button className={tab === 'jobs' ? 'active' : ''} onClick={() => setTab('jobs')}>
              <Layers />
              Active jobs
              {jobs.length > 0 && <span className="tab-count">{jobs.length}</span>}
            </button>
            <button
              className={tab === 'library' ? 'active' : ''}
              onClick={() => setTab('library')}
            >
              <BookOpen />
              Rule library
              {entries.length > 0 && <span className="tab-count">{entries.length}</span>}
            </button>
          </div>

          {tab === 'jobs' && (
            <>
              {jobs.length === 0 && (
                <section className="empty-state">
                  <StatusSprite status="idle" />
                  <span className="eyebrow">The forge is ready</span>
                  <h2>Submit a CVE to begin</h2>
                  <p>
                    Multiple jobs can run concurrently. Live stages, audited conditions, and
                    provider compilations will appear here.
                  </p>
                </section>
              )}
              <div className="job-list">
                {jobs.map(job => (
                  <JobCard
                    key={job.key}
                    job={job}
                    onCancel={() => void cancel(job.key)}
                    onDismiss={() => dismiss(job.key)}
                  />
                ))}
              </div>
            </>
          )}

          {tab === 'library' && (
            <>
              {entries.length === 0 && (
                <section className="empty-state">
                  <StatusSprite status="idle" />
                  <span className="eyebrow">Nothing saved yet</span>
                  <h2>Your rule library is empty</h2>
                  <p>
                    Completed generations are saved here automatically — one rule set per CVE,
                    always showing the latest result.
                  </p>
                </section>
              )}
              <div className="library-list">
                {entries.map(entry => (
                  <LibraryCard
                    key={entry.cveId}
                    entry={entry}
                    onRegenerate={() => handleRegenerate(entry)}
                    onRemove={() => remove(entry.cveId)}
                  />
                ))}
              </div>
            </>
          )}
        </div>
      </section>
    </main>
  )
}

export default App
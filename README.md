# Smiggol WAF Rule Factory

CVE-to-WAF rule factory that generates provider-ready Terraform for AWS WAF and Azure WAF from a CVE ID.

The backend runs an async LangGraph pipeline and exposes a job-based API. The frontend is a React app that submits jobs and streams progress in real time.

## What this project does

- Accepts a CVE ID and target providers (`aws`, `azure`) through an API request.
- Enriches CVE intelligence and collects candidate exploit payloads from a local nuclei templates corpus.
- Generates provider-agnostic intermediate rules with LLM-based agents.
- Validates and stabilizes rules, compiles provider Terraform, and computes replay and promotion signals.
- Returns all outputs through a persistent async job record in SQLite.

## Architecture at a glance

Main orchestration stages:

1. `fetch_cve_intel`
2. `collect_nuclei_pocs`
3. `generate_rules`
4. `stabilize_rules`
5. `audit_rules`
6. `compile_targets`
7. `finalize`

Outputs include:

- Intermediate rules
- Provider Terraform (`provider_outputs.aws`, `provider_outputs.azure`)
- Replay summary and validation issues
- Audit report and promotion state (`ready`, `needs_review`, `blocked`)

## Repository layout

- `src/waf_factory/`: backend API, orchestration graph, compilers, validation, harnesses, models.
- `frontend/`: React + Vite UI for job submission and monitoring.
- `data/nuclei-templates/`: local nuclei corpus used for CVE payload extraction.
- `scripts/sync_nuclei_templates.sh`: helper to sync nuclei templates.
- `tests/`: backend unit and integration-style tests.

## Prerequisites

- Python 3.11+
- Node.js 18+
- npm

Optional but recommended:

- GitHub CLI (`gh`) for GitHub-model authentication
- `jq` for easier CLI polling output

## Backend quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn waf_factory.main:app --app-dir src
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Important runtime note:

- Avoid `--reload` for long-running orchestration jobs. A reload can interrupt in-flight async tasks and leave jobs in non-terminal states.

## Frontend quick start

In a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

During local development, Vite proxies `/v1` and `/health` to `http://127.0.0.1:8000`.

For split frontend/API deployments, set API base URL at build time and allow the frontend origin on the API side:

```bash
export WAF_CORS_ORIGINS=https://smiggol.example.com
cd frontend
VITE_API_BASE_URL=https://api.smiggol.example.com npm run build
```

## API usage

### Submit generation job

`POST /v1/rules/generate`

Example request body:

```json
{
  "cve_id": "CVE-2021-44228",
  "targets": ["aws", "azure"],
  "mode": "count",
  "use_llm": true
}
```

Returns `202 Accepted`:

```json
{
  "job_id": "job-abc123def456",
  "status": "queued"
}
```

### Check status

`GET /v1/jobs/{job_id}`

Possible status values:

- `queued`
- `running`
- `succeeded`
- `failed`
- `cancelled`

Example in-progress response:

```json
{
  "job_id": "job-abc123def456",
  "status": "running",
  "stages_done": ["fetch_cve_intel", "collect_nuclei_pocs"],
  "warnings": [],
  "error": null,
  "result": null
}
```

### Stream status updates

`GET /v1/jobs/{job_id}/stream`

- Emits `snapshot` events while running.
- Emits one terminal event when job reaches a terminal state.
- Uses `text/event-stream` and requires proxy buffering disabled.
- Frontend falls back to REST polling automatically if SSE is unavailable.

### Cancel job

`DELETE /v1/jobs/{job_id}`

## End-to-end CLI example

```bash
# 1) submit
JOB=$(curl -sX POST http://127.0.0.1:8000/v1/rules/generate \
  -H "content-type: application/json" \
  -d '{"cve_id":"CVE-2021-44228","targets":["aws","azure"],"mode":"count"}' \
  | python -c 'import sys,json; print(json.load(sys.stdin)["job_id"])')
echo "$JOB"

# 2) poll until terminal
while true; do
  STATUS=$(curl -s "http://127.0.0.1:8000/v1/jobs/$JOB" \
    | tee /tmp/smiggol-job.json \
    | python -c 'import sys,json; print(json.load(sys.stdin)["status"])')
  echo "status=$STATUS"
  [[ "$STATUS" == "succeeded" || "$STATUS" == "failed" || "$STATUS" == "cancelled" ]] && break
  sleep 2
done

# 3) inspect final result
jq . /tmp/smiggol-job.json
```

## LLM authentication and provider selection

Default LLM provider is GitHub-hosted models.

Preferred authentication path:

```bash
gh auth login
```

Alternative:

```bash
export GITHUB_TOKEN=your_token
```

Common provider settings:

```bash
export WAF_LLM_PROVIDER=github
export WAF_RULEGEN_MODEL=gpt-4o-mini
export WAF_SUPERVISOR_MODEL=o4-mini
export GITHUB_COPILOT_BASE_URL=https://api.githubcopilot.com
```

To use OpenAI directly:

```bash
export WAF_LLM_PROVIDER=openai
export OPENAI_API_KEY=your_openai_api_key
```

## Configuration reference

### API and orchestration

| Variable | Purpose | Default |
| --- | --- | --- |
| `WAF_JOB_DB_PATH` | SQLite path for persisted async jobs | `.waf_factory_cache/jobs.db` |
| `WAF_GRAPH_RECURSION_LIMIT` | Max LangGraph recursion per run | `40` |
| `WAF_JOB_PROGRESS_POLL_SECONDS` | API job progress sync interval | `1.0` |
| `WAF_JOB_SSE_POLL_SECONDS` | SSE snapshot polling interval | `0.5` |
| `WAF_CORS_ORIGINS` | Allowed browser origins (comma-separated) | `http://localhost:5173` |

### LLM and supervisor

| Variable | Purpose | Default |
| --- | --- | --- |
| `WAF_LLM_PROVIDER` | Model backend (`github` or `openai`) | `github` |
| `WAF_RULEGEN_MODEL` | Rule generation model | `gpt-4o-mini` |
| `WAF_SUPERVISOR_MODEL` | Supervisor model | `o4-mini` |
| `WAF_LLM_TIMEOUT_SECONDS` | Standard LLM timeout | `30` |
| `WAF_LLM_EXPENSIVE_TIMEOUT_SECONDS` | Timeout for expensive calls | `180` |
| `WAF_LLM_MAX_RETRIES` | LLM retry count | `2` |
| `WAF_SUPERVISOR_MAX_ITERATIONS` | Supervisor loop cap | `8` |
| `WAF_SUPERVISOR_MAX_REPAIR_ITERATIONS` | Rule repair loop cap | `2` |
| `WAF_SUPERVISOR_MAX_AUDIT_REGEN_ITERATIONS` | Audit regen loop cap | `2` |
| `WAF_AUDIT_REGEN_THRESHOLD` | Effectiveness threshold to trigger regeneration | `0.90` |
| `WAF_AUDIT_READY_THRESHOLD` | Effectiveness threshold for ready promotion | `0.97` |

### Terraform validation and lint gates

| Variable | Purpose | Default |
| --- | --- | --- |
| `WAF_TF_AWS_VERSION` | AWS provider constraint used in validation harness | `~> 5.0` |
| `WAF_TF_AZURERM_VERSION` | AzureRM provider constraint used in validation harness | `~> 3.0` |
| `WAF_TF_CACHE_DIR` | Terraform working cache root | `.waf_factory_cache/tf` |
| `TF_PLUGIN_CACHE_DIR` | Terraform plugin cache | `.waf_factory_cache/tf-plugins` |
| `WAF_TF_TIMEOUT_SECONDS` | Terraform validation timeout | `60` |
| `WAF_REQUIRE_TF_VALIDATE` | Fail if terraform validate cannot run (`1` to enforce) | unset |
| `WAF_TFLINT_TIMEOUT_SECONDS` | TFLint timeout | `45` |
| `WAF_TFLINT_AWS_VERSION` | AWS ruleset version for TFLint | `0.30.0` |
| `WAF_TFLINT_AZURERM_VERSION` | AzureRM ruleset version for TFLint | `0.26.0` |
| `WAF_REQUIRE_TFLINT` | Fail if tflint unavailable (`1` to enforce) | unset |

## Nuclei data source

This project expects a local nuclei templates checkout under `data/nuclei-templates/`.

Sync/update it with:

```bash
./scripts/sync_nuclei_templates.sh
```

If no templates match a CVE, the pipeline still runs with synthetic vectors and reports warnings.

## Testing

Run backend tests:

```bash
pytest
```

Run frontend lint/build checks:

```bash
cd frontend
npm run lint
npm run build
```

## Troubleshooting

- Job appears stuck in `queued`:
  - Confirm status URL is `/v1/jobs/{job_id}`.
  - Ensure API was not started with `--reload` during long job execution.
  - Check LLM auth (`gh auth status` or `GITHUB_TOKEN`).
- SSE not updating:
  - Verify reverse proxy disables buffering for `text/event-stream`.
  - Confirm frontend can fall back to polling `/v1/jobs/{job_id}`.
- Rules compile but promotion is blocked:
  - Inspect `validation_issues` and `audit_report` in final job `result`.

## Status

Current implementation provides an async API plus a supervised LangGraph pipeline for CVE-to-rule generation, replay, and Terraform compilation for AWS and Azure. Real cloud firewall deployment and promotion flows remain manual by design.

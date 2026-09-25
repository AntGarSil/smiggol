# Smiggol — WAF Rule Factory

## Summary

Smiggol is a CVE-to-WAF rule factory that generates provider-ready Terraform for cloud WAFs (AWS and Azure) from a CVE identifier. It runs an asynchronous orchestration pipeline that: collects exploit payloads, generates provider-agnostic rules with LLM assistance, stabilizes and validates rules, and compiles provider Terraform artifacts.

Key points:
- Backend: Python (async FastAPI) with an orchestration graph and job API.
- Frontend: React + Vite for submitting jobs and streaming progress.
- Data: Local nuclei templates corpus used for payload extraction.

## Quick Start (developer)

Requirements:
- Python 3.11+
- Node.js 18+ and npm
- Git

1. Create a Python virtual environment and install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Start the backend API (development)

```bash
# from repository root
uvicorn waf_factory.main:app --app-dir src
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

3. Start the frontend (in a separate terminal)

```bash
cd frontend
npm install
npm run dev
```

Open the app at: http://localhost:5173

Notes:
- Avoid `--reload` for long-running orchestration jobs (reload can interrupt in-flight tasks).

## Data: nuclei templates

The project expects a local checkout of `projectdiscovery/nuclei-templates` at `data/nuclei-templates/`.
Common workflows to get and keep the templates in sync:

- Clone the repository with submodules (recommended):

```bash
git clone --recurse-submodules https://github.com/AntGarSil/smiggol.git
```

## Repository layout

- `src/waf_factory/` — backend API, orchestration graph, compilers, validation, harnesses, models
  - `graph/` — orchestration graph builder and graph nodes
  - `harness/` — test harnesses and mock WAF/nuclei runner
  - `jobs/` — job persistence and lifecycle store
  - `validation/` — rule validators and TF/TFLint gates
- `frontend/` — React + Vite frontend
- `data/` — local data (nuclei templates submodule lives here)
- `tests/` — unit and integration-style tests
- `scripts/` — utility scripts (e.g., sync nuclei templates)

## Configuration

Environment variables control runtime behavior. Common variables:

- `WAF_LLM_PROVIDER` — `github` (default) or `openai`
- `GITHUB_TOKEN` — GitHub token if not using `gh auth` for GitHub-hosted models
- `WAF_RULEGEN_MODEL`, `WAF_SUPERVISOR_MODEL` — model names used by LLM components
- `WAF_JOB_DB_PATH` — SQLite path for persisted jobs (default: `.waf_factory_cache/jobs.db`)

See `README` sections in the former doc for a fuller list of env vars.

## Tests

Run backend tests:

```bash
pytest
```

Frontend checks:

```bash
cd frontend
npm run lint
npm run build
```

## Troubleshooting

- If commits fail due to GPG `pinentry` errors when using VS Code, either install a `pinentry` GUI or disable commit signing locally:

  ```bash
  git config --local commit.gpgSign false
  git config --local gpg.program "$(which gpg)"
  ```

- If VS Code integrated terminal opens a `sh` session instead of `bash`, set the workspace settings in `.vscode/settings.json`:

  ```json
  {
    "terminal.integrated.defaultProfile.linux": "bash",
    "terminal.integrated.profiles.linux": {
      "bash": { "path": "/usr/bin/bash", "args": ["-l"] }
    }
  }
  ```

## Contributing

- Fork the repository, branch from `main`, and open a PR with a clear description.
- Write tests for new features and ensure existing tests pass.
- Keep changes focused and documented in the PR description.

## License

MIT

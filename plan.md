## Plan: Agentic CVE-to-WAF Rule Factory
Build a Python-based ReAct agent workflow that takes a CVE ID and produces tailored AWS WAF and Azure WAF Terraform rules, with parallel provider-specific rule generation and a real-firewall testing path. Use https://github.com/trickest/cve as the primary proof-of-concept corpus for exploit payloads and include real POC replay validation against generated rulesets. Phase 1 delivers design, local validation/simulation, and deploy scripts; Phase 2 executes tests on real cloud WAF environments once staging is provisioned.

**Steps**
1. Phase 0: Define scope and contracts. Lock supported providers to AWS WAF and Azure WAF only, input to CVE ID, and output to Terraform modules plus structured audit report. Define non-goals: no additional WAF vendors, no auto-blocking in first release.
2. Phase 0: Define ReAct-safe execution model. Specify that Thought/Action/Observation remains internal only; user/API receives structured action log and rationale summary. Add deterministic controls (fixed prompts, temperature policy, schema validation, run hash).
3. Phase 1: Design canonical intermediate rule schema. Create provider-agnostic rule AST supporting match fields (headers, body, query, URI, IP), boolean logic, transformations, action, and confidence metadata. *Depends on 1-2*.
4. Phase 1: Build CVE intelligence and POC intake pipeline spec. Ingest from NVD + GitHub Advisories + CISA KEV + trickest/cve, normalize vulnerability type and request-level indicators, extract usable payloads from public POCs, and map to attack primitives used by rule generation. *Parallel with 5 once schema is stable*.
5. Phase 1: Define agent fleet and orchestration DAG. Agents: CVE fetch/normalize, POC collector/sanitizer, tactic extractor, rule generator (provider-parallel workers), validator, compiler, test-vector generator, audit reporter. Add queueing, retries, timeouts, and partial-failure handling. *Depends on 2-3*.
6. Phase 1: Define provider compilers and constraints. Implement AWS compiler and Azure compiler from intermediate AST, with compatibility transforms (regex dialect checks, JSON-body limitations, rate-limit differences). *Depends on 3*.
7. Phase 1: Define validation gates. Add static gates for syntax correctness, provider quota checks, contradiction detection, and false-positive risk heuristics. Fail closed on invalid rules, fail open with warnings on low-confidence heuristics. *Depends on 5-6*.
8. Phase 1: Define local simulation and POC replay harness. Generate malicious/benign test vectors from CVE patterns, replay both synthetic vectors and trickest/cve-derived payloads against compiled rule logic locally, compute precision/recall proxy metrics, and emit a promotion recommendation. *Depends on 4, 6, 7*.
9. Phase 1: Define Terraform deployment artifact structure. Emit Terraform for AWS WAFv2 WebACL/rule groups and Azure WAF policy/custom rules, plus env variables and parameter files for count/detection mode defaults. *Depends on 6-7*.
10. Phase 1: Define operator workflow and API. API accepts CVE + target env + mode and returns artifacts, risk score, and approval checklist. Include manual promotion flow only (Count/Detection -> human review -> enforce). *Depends on 5, 8, 9*.
12. Phase 1.5: Linting of produced terraform output and validation of assumptions.
11. Phase 2: Real-firewall testing enablement. Provision dedicated staging footprints for AWS and Azure, run generated rules in Count/Detection mode, collect logs/metrics for at least 24-48h, and compare against baseline benign traffic. *Depends on 10 and cloud credentials/resources*.
12. Phase 2: Real POC validation gate on live WAF. Replay curated trickest/cve payloads in an isolated test harness against staging firewalls with generated rulesets enabled, measure block/detect outcomes per POC, and require pass thresholds before promotion. *Depends on 11*.
13. Phase 2: Controlled canary and rollback design. Define optional canary routing and rollback runbooks; keep manual promotion as default for now, with hooks for later automation. *Depends on 12*.
14. Phase 3: Hardening and scale. Add Temporal workers autoscaling, cache of CVE parse outputs and rule fingerprints, policy/version registry, and regression corpus for previously generated CVEs and validated POCs. *Depends on 10-13*.

**Relevant files**
- Repository is currently empty; implementation should establish a new service structure in the workspace root with separate domains for orchestrator, agents, compiler, validation, tests, terraform templates, and ops runbooks.

**Verification**
1. Contract validation: confirm every agent input/output validates against declared schemas and rejects malformed payloads.
2. Determinism check: run the same CVE through pipeline multiple times and confirm identical normalized artifacts and rule fingerprints.
3. Provider compilation tests: compile representative CVEs (SQLi, XSS, path traversal, RCE indicators) to both AWS and Azure and verify provider-specific syntax checks pass.
4. Local simulation quality: run malicious and benign fixtures and confirm minimum quality threshold agreed by team (for example precision >= 0.9 proxy score).
5. Real POC replay quality: execute curated trickest/cve payloads for the target CVE and confirm expected detect/block outcome with no critical parser failures.
6. Terraform validation: run terraform validate against generated AWS and Azure artifacts in CI.
7. Pre-prod readiness: ensure generated rules default to Count/Detection mode and require manual approval metadata before enforcement.
8. Real firewall acceptance (Phase 2): deploy to staging WAFs, collect 24-48h telemetry, review false-positive rate and coverage evidence before any enforcing action.

**Decisions**
- Confirmed stack: Python with FastAPI + Temporal.
- ReAct policy: internal traces only; expose structured audit summaries externally.
- Phase 1 delivery: design + local simulation + deploy scripts.
- Real-firewall policy: Count/Detection mode with manual promotion first.
- Data sources for Phase 1: NVD + GitHub Advisories + CISA KEV + trickest/cve for POCs.
- Artifact target: Terraform modules as primary output.
- SLA target: under 30 minutes per CVE-to-rule run.
- Included scope: AWS WAF and Azure WAF only.
- Excluded for first release: auto-block rollout, non-AWS/Azure providers.

**Further Considerations**
1. Environment bootstrap path: Option A provision both clouds in parallel now; Option B start AWS staging first then mirror Azure; Option C keep local-only until access approvals land. Recommendation: Option B for faster first real-firewall milestone.
2. Quality gate policy: Option A strict conservative blocking candidate threshold; Option B balanced threshold by app profile; Option C permissive discovery-first threshold. Recommendation: Option B.
3. Promotion governance: Option A security engineer approval only; Option B app owner + security dual approval; Option C CAB-style weekly window. Recommendation: Option B.
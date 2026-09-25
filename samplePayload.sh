#!/bin/bash
# 1. Submit — returns 202 with a job_id
JOB=$(curl -sX POST http://127.0.0.1:8000/v1/rules/generate \
  -H "content-type: application/json" \
  -d '{"cve_id":"CVE-2025-55182","targets":["aws","azure"],"mode":"count"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["job_id"])')
echo "$JOB"

# 2. Poll until terminal (status one of: succeeded | failed | cancelled)
while true; do
  STATE=$(curl -s "http://127.0.0.1:8000/v1/jobs/$JOB" | tee /tmp/job.json | python -c 'import sys,json;print(json.load(sys.stdin)["status"])')
  echo "status=$STATE"
  [[ "$STATE" == "succeeded" || "$STATE" == "failed" || "$STATE" == "cancelled" ]] && break
  sleep 2
done

# 3. Read final result
jq . /tmp/job.json

# 4. Always pretty print generated rules, including rules blocked from promotion
printf '\n=== Generated Rules ===\n'
jq '.result.rules // []' /tmp/job.json

# 5. Pretty print generated AWS Terraform, if present
AWS_RULE=$(jq -r '.result.provider_outputs.aws // empty' /tmp/job.json)
if [[ -n "$AWS_RULE" ]]; then
  printf '\n=== AWS Rule ===\n'
  printf '%s\n' "$AWS_RULE"
fi


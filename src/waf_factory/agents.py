from __future__ import annotations

from collections.abc import Iterable
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any

import httpx
import yaml

from waf_factory.models import Condition, CveIntel, EnforcementMode, FieldType, IntermediateRule, Operator, PocArtifact, Provider, RuleAuditReport, Severity
from waf_factory.llm_rulegen import LlmRuleGenerator

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CveIntelAgent:
    def collect(self, cve_id: str) -> tuple[CveIntel, list[str]]:
        warnings: list[str] = []
        intel = CveIntel(cve_id=cve_id)

        try:
            with httpx.Client(timeout=8.0) as client:
                response = client.get(NVD_API, params={"cveId": cve_id})
                response.raise_for_status()
                payload = response.json()
                vulns = payload.get("vulnerabilities", [])
                if vulns:
                    cve = vulns[0].get("cve", {})
                    descriptions = cve.get("descriptions", [])
                    english = next(
                        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                        "",
                    )
                    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
                    tags = self._infer_tags(english)
                    severity = self._infer_severity(cve)
                    intel = CveIntel(
                        cve_id=cve_id,
                        description=english,
                        vector=self._extract_vector(cve),
                        severity=severity,
                        tags=tags,
                        references=refs,
                    )
                else:
                    warnings.append(f"No NVD record found for {cve_id}")
        except Exception as exc:
            warnings.append(f"NVD lookup failed: {exc}")

        try:
            with httpx.Client(timeout=8.0) as client:
                kev = client.get(CISA_KEV)
                kev.raise_for_status()
                records = kev.json().get("vulnerabilities", [])
                if any(v.get("cveID") == cve_id for v in records):
                    intel.tags.append("cisa_kev")
        except Exception as exc:
            warnings.append(f"CISA KEV lookup failed: {exc}")

        intel.tags = sorted(set(intel.tags))
        return intel, warnings

    def _extract_vector(self, cve: dict) -> str:
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            rows = metrics.get(key, [])
            if rows:
                data = rows[0].get("cvssData", {})
                vector = data.get("vectorString")
                if vector:
                    return vector
        return ""

    def _infer_severity(self, cve: dict) -> Severity:
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            rows = metrics.get(key, [])
            if rows:
                score = rows[0].get("cvssData", {}).get("baseScore", 0)
                if score >= 9.0:
                    return Severity.CRITICAL
                if score >= 7.0:
                    return Severity.HIGH
                if score >= 4.0:
                    return Severity.MEDIUM
                return Severity.LOW
        return Severity.MEDIUM

    def _infer_tags(self, description: str) -> list[str]:
        low = description.lower()
        tags: list[str] = []
        if "sql" in low and "inject" in low:
            tags.append("sqli")
        if "cross-site" in low or "xss" in low:
            tags.append("xss")
        if "path traversal" in low or "directory traversal" in low:
            tags.append("path_traversal")
        if "remote code execution" in low or "rce" in low:
            tags.append("rce")
        if not tags:
            tags.append("generic_web_attack")
        return tags


class PocCollectorAgent:
    def __init__(self, local_root: str = "data/nuclei-templates") -> None:
        self.local_root = Path(local_root)
        self.collect_timeout_seconds = float(os.getenv("NUCLEI_COLLECT_TIMEOUT_SECONDS", "8"))
        self.search_timeout_seconds = float(os.getenv("NUCLEI_SEARCH_TIMEOUT_SECONDS", "3"))
        self.max_candidate_files = int(os.getenv("NUCLEI_MAX_CANDIDATE_FILES", "400"))
        self.max_yaml_parse = int(os.getenv("NUCLEI_MAX_YAML_FILES", "150"))
        self.max_payloads = int(os.getenv("NUCLEI_MAX_PAYLOADS", "200"))

    def collect(self, cve_id: str) -> tuple[list[PocArtifact], list[str]]:
        warnings: list[str] = []
        started = time.perf_counter()
        if not self.local_root.exists():
            warnings.append(
                "No local nuclei-templates corpus found. Expected "
                f"{self.local_root.as_posix()}"
            )
            return [], warnings

        cve_lower = cve_id.lower()
        artifacts: list[PocArtifact] = []
        seen_payloads: set[str] = set()

        template_files = self._candidate_template_files(cve_id)
        if not template_files:
            warnings.append(
                f"No candidate nuclei templates found for {cve_id}. "
                "Check template sync path and CVE coverage."
            )
            return [], warnings

        parsed_files = 0
        for template_path in template_files:
            if (time.perf_counter() - started) > self.collect_timeout_seconds:
                warnings.append(
                    f"Nuclei collection timed out after {self.collect_timeout_seconds:.1f}s; returning partial results"
                )
                break

            if parsed_files >= self.max_yaml_parse:
                warnings.append(
                    f"Nuclei collection reached parse cap ({self.max_yaml_parse} files); returning partial results"
                )
                break

            try:
                raw_text = template_path.read_text(encoding="utf-8")
            except Exception:
                continue

            parsed_files += 1

            if cve_lower not in raw_text.lower() and "classification:" not in raw_text.lower():
                continue

            for doc in self._load_yaml_documents(raw_text):
                if not self._document_matches_cve(doc, cve_lower):
                    continue

                for payload in self._extract_payload_candidates(doc):
                    norm = self._normalize_payload(payload)
                    if not norm or norm in seen_payloads:
                        continue
                    if not self._looks_exploit_signal(norm):
                        continue
                    seen_payloads.add(norm)
                    artifacts.append(
                        PocArtifact(
                            cve_id=cve_id,
                            source=f"nuclei-templates:{template_path.relative_to(self.local_root).as_posix()}",
                            payload=norm,
                        )
                    )
                    if len(artifacts) >= self.max_payloads:
                        return artifacts, warnings

        if not artifacts:
            warnings.append(
                f"No nuclei templates matched {cve_id}. Ensure nuclei-templates is synced and contains relevant templates."
            )

        return artifacts, warnings

    def _candidate_template_files(self, cve_id: str) -> list[Path]:
        started = time.perf_counter()
        budget = min(self.search_timeout_seconds, self.collect_timeout_seconds)

        def remaining_timeout() -> float:
            elapsed = time.perf_counter() - started
            return max(0.2, budget - elapsed)

        # Zero-cost direct match path for common nuclei CVE naming.
        direct_candidates = [
            self.local_root / "http" / "cves" / cve_id.split("-")[1] / f"{cve_id}.yaml",
            self.local_root / "http" / "cves" / cve_id.split("-")[1] / f"{cve_id}.yml",
            self.local_root / "http" / "cves" / cve_id.split("-")[1] / f"{cve_id.lower()}.yaml",
            self.local_root / "http" / "cves" / cve_id.split("-")[1] / f"{cve_id.lower()}.yml",
        ]
        direct_existing = [path for path in direct_candidates if path.exists()]
        if direct_existing:
            return direct_existing[: self.max_candidate_files]

        # Fast filename lookup across repo before heavier content search.
        filename_hits: list[Path] = []
        for name_pattern in (f"{cve_id}.yaml", f"{cve_id}.yml", f"{cve_id.lower()}.yaml", f"{cve_id.lower()}.yml"):
            filename_hits.extend(self.local_root.rglob(name_pattern))
        if filename_hits:
            uniq: list[Path] = []
            seen: set[str] = set()
            for path in filename_hits:
                key = path.as_posix()
                if key in seen:
                    continue
                seen.add(key)
                uniq.append(path)
                if len(uniq) >= self.max_candidate_files:
                    break
            if uniq:
                return uniq

        # Fast path: use ripgrep for content match when available.
        if shutil.which("rg"):
            command = [
                "rg",
                "-l",
                "--ignore-case",
                "--glob",
                "*.yaml",
                "--glob",
                "*.yml",
                cve_id,
                self.local_root.as_posix(),
            ]
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=remaining_timeout(),
                    check=False,
                )
                files = [Path(line.strip()) for line in result.stdout.splitlines() if line.strip()]
                files = [path for path in files if path.exists()]
                if files:
                    return files[: self.max_candidate_files]
            except Exception:
                pass

        if (time.perf_counter() - started) >= budget:
            return []

        # Fallback: grep recursive content search.
        if shutil.which("grep"):
            command = [
                "grep",
                "-Ril",
                "--include=*.yaml",
                "--include=*.yml",
                cve_id,
                self.local_root.as_posix(),
            ]
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=remaining_timeout(),
                    check=False,
                )
                files = [Path(line.strip()) for line in result.stdout.splitlines() if line.strip()]
                files = [path for path in files if path.exists()]
                if files:
                    return files[: self.max_candidate_files]
            except Exception:
                pass

        if (time.perf_counter() - started) >= budget:
            return []

        # Last resort: bounded filesystem scan.
        candidates: list[Path] = []
        token = cve_id.lower()
        checked = 0
        scan_cap = self.max_candidate_files * 20
        deadline = time.perf_counter() + remaining_timeout()

        for path in self.local_root.rglob("*.y*ml"):
            if time.perf_counter() > deadline:
                break

            checked += 1
            matched = token in path.name.lower()

            if not matched:
                try:
                    with path.open("r", encoding="utf-8", errors="ignore") as handle:
                        sample = handle.read(16_384).lower()
                    matched = token in sample
                except Exception:
                    matched = False

            if matched:
                candidates.append(path)
                if len(candidates) >= self.max_candidate_files:
                    break

            if checked >= scan_cap:
                break

        return candidates

    def _load_yaml_documents(self, raw_text: str) -> list[dict[str, Any]]:
        docs: list[dict[str, Any]] = []
        try:
            parsed = list(yaml.safe_load_all(raw_text))
        except Exception:
            return docs

        for item in parsed:
            if isinstance(item, dict):
                docs.append(item)
        return docs

    def _document_matches_cve(self, doc: dict[str, Any], cve_lower: str) -> bool:
        info = doc.get("info", {}) if isinstance(doc.get("info"), dict) else {}
        classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
        cve_in_classification = classification.get("cve-id")

        values: list[str] = []
        values.extend(self._to_strings(cve_in_classification))
        values.extend(self._to_strings(info.get("tags")))

        for value in values:
            if cve_lower in value.lower():
                return True

        return cve_lower in yaml.safe_dump(doc, sort_keys=False).lower()

    def _extract_payload_candidates(self, doc: dict[str, Any]) -> list[str]:
        payloads: list[str] = []

        for key in ("http", "requests"):
            entries = doc.get(key)
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        payloads.extend(self._extract_from_request_block(entry))

        if isinstance(doc.get("network"), list):
            for entry in doc["network"]:
                if isinstance(entry, dict):
                    payloads.extend(self._extract_from_network_block(entry))

        return payloads

    def _extract_from_request_block(self, block: dict[str, Any]) -> list[str]:
        payloads: list[str] = []
        for raw in self._to_strings(block.get("raw")):
            payloads.extend(self._extract_from_raw_http(raw))

        for body in self._to_strings(block.get("body")):
            payloads.append(body)

        for path in self._to_strings(block.get("path")):
            payloads.append(path)

        headers = block.get("headers")
        if isinstance(headers, dict):
            for key, value in headers.items():
                key_l = str(key).lower()
                # Keep headers that can carry exploit strings; skip common routing noise.
                if key_l in {"host", "user-agent", "accept", "connection"}:
                    continue
                payloads.append(f"{key}: {value}")

        return payloads

    def _extract_from_network_block(self, block: dict[str, Any]) -> list[str]:
        payloads: list[str] = []
        payloads.extend(self._to_strings(block.get("data")))
        return payloads

    def _extract_from_raw_http(self, raw: str) -> list[str]:
        lines = raw.splitlines()
        if not lines:
            return []

        out: list[str] = []
        request_line = lines[0].strip()
        if request_line:
            out.append(request_line)

        # Preserve raw headers as candidate payload sources; some templates
        # inject exploits only via header values (e.g. Log4Shell).
        header_lines: list[str] = []

        # Include body-like tail as before.
        body_started = False
        body_lines: list[str] = []
        for line in lines[1:]:
            stripped = line.strip()
            if stripped == "":
                body_started = True
                continue
            if not body_started:
                if ":" in stripped:
                    header_lines.append(stripped)
                continue
            if body_started:
                body_lines.append(stripped)

        out.extend(header_lines)

        if body_lines:
            out.append("\n".join(body_lines))

        return out

    def _normalize_payload(self, payload: str) -> str:
        normalized = payload.replace("\r", "").strip()
        # Remove common nuclei variable placeholders to focus on exploit fragments.
        normalized = normalized.replace("{{BaseURL}}", "")
        normalized = normalized.replace("{{Hostname}}", "")
        normalized = normalized.replace("{{Host}}", "")
        normalized = normalized.replace("{{URL}}", "")
        return " ".join(normalized.split())

    def _looks_exploit_signal(self, payload: str) -> bool:
        low = payload.lower()
        indicators = (
            "union select",
            "../",
            "..\\",
            "<script",
            "onerror=",
            "onload=",
            "javascript:",
            "sleep(",
            "benchmark(",
            "cmd=",
            "/bin/sh",
            "%2e%2e",
            "${jndi:",
            "{{",
            "}}",
            "' or ",
            "\" or ",
            "rest_route=/batch/v1",
            "/batch/v1",
            '"requests":[',
            '"path":"///"',
            "parse_path_failed",
            "rest_batch_not_allowed",
        )
        if any(token in low for token in indicators):
            return True

        # Keep obviously parameterized request paths/bodies when they carry operators.
        if ("?" in payload or "=" in payload) and any(ch in payload for ch in ["'", "\"", "<", ">", "(", ")", ";"]):
            return True

        return False

    def _to_strings(self, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [str(v) for v in value.values() if isinstance(v, (str, int, float, bool))]
        if isinstance(value, Iterable):
            out: list[str] = []
            for item in value:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, (int, float, bool)):
                    out.append(str(item))
            return out
        if isinstance(value, (int, float, bool)):
            return [str(value)]
        return []


class RuleGeneratorAgent:
    def __init__(self) -> None:
        self.llm = LlmRuleGenerator()

    def generate(
        self,
        intel: CveIntel,
        pocs: list[PocArtifact],
        mode: EnforcementMode,
        use_llm: bool = True,
        repair_feedback: str | None = None,
    ) -> tuple[list[IntermediateRule], list[str]]:
        if not use_llm:
            return [], ["Rule generation skipped: heuristic fallback has been removed and use_llm is false"]

        llm_rule, warnings = self._generate_with_llm(intel, pocs, mode, repair_feedback)
        if llm_rule is None:
            return [], warnings

        coverage_feedback = self._coverage_feedback(llm_rule, pocs)
        if coverage_feedback:
            warnings.append("LLM rule missing exploit-surface coverage; requesting one repair pass")
            repaired_rule, repair_warnings = self._generate_with_llm(
                intel,
                pocs,
                mode,
                repair_feedback=coverage_feedback,
            )
            warnings.extend(repair_warnings)
            if repaired_rule is not None:
                llm_rule = repaired_rule

        llm_rule, hardening_notes = self._enforce_minimum_expression_family_coverage(llm_rule, pocs)
        warnings.extend(hardening_notes)

        llm_rule, symmetry_notes = self._enforce_surface_symmetry(llm_rule, pocs)
        warnings.extend(symmetry_notes)
        return [llm_rule], warnings

    def _coverage_feedback(self, rule: IntermediateRule, pocs: list[PocArtifact]) -> str | None:
        expects_query = False
        header_names: set[str] = set()
        uri_path_present = False
        body_present = False

        for poc in pocs:
            payload = (poc.payload or "").strip()
            if not payload:
                continue

            req = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/", payload, flags=re.IGNORECASE)
            if req:
                uri_path_present = True
                if "?" in req.group(2):
                    expects_query = True

            header = re.match(r"^([A-Za-z0-9-]{2,64}):\s+(.+)$", payload)
            if header:
                header_names.add(header.group(1).lower())

            if not req and not header and ("=" in payload or "${" in payload):
                body_present = True

        rule_header_names = {
            (cond.header_name or "").strip().lower()
            for cond in rule.conditions
            if cond.field_type == FieldType.HEADER
        }
        has_header_condition = any(cond.field_type == FieldType.HEADER for cond in rule.conditions)
        has_query_condition = any(cond.field_type == FieldType.QUERY for cond in rule.conditions)
        has_uri_path_condition = any(cond.field_type == FieldType.URI_PATH for cond in rule.conditions)
        has_body_condition = any(cond.field_type == FieldType.BODY for cond in rule.conditions)

        missing_bits: list[str] = []
        if expects_query and not has_query_condition:
            missing_bits.append("- Add at least one query condition covering the observed query-string exploit vector.")

        if uri_path_present and not has_uri_path_condition:
            missing_bits.append("- Add at least one uri_path condition; path-based injection must be covered.")

        if body_present and not has_body_condition:
            missing_bits.append("- Add at least one body condition; POST/PUT payload injection must be covered.")

        # Require at least one header condition when header payloads are present.
        if header_names and not has_header_condition:
            sample = ", ".join(sorted(header_names)[:6])
            missing_bits.append(
                "- Add header conditions for the observed injection vectors "
                f"(examples: {sample}). Set header_name for each header condition."
            )
        elif header_names and has_header_condition and not (rule_header_names & header_names):
            sample = ", ".join(sorted(header_names)[:6])
            missing_bits.append(
                "- Existing header conditions do not align with extracted payload headers. "
                f"Use header_name values that match observed headers (examples: {sample})."
            )

        symmetry_gap = self._symmetry_gap_feedback(rule, pocs)
        if symmetry_gap:
            missing_bits.extend(symmetry_gap)

        family_gap = self._missing_required_families_feedback(rule, pocs)
        if family_gap:
            missing_bits.extend(family_gap)

        if not missing_bits:
            return None

        return (
            "Coverage repair required for this nuclei template:\n"
            + "\n".join(missing_bits)
            + "\nKeep exploit specificity; do not add broad catch-all patterns."
        )

    def _required_surfaces(self, pocs: list[PocArtifact]) -> set[FieldType]:
        surfaces: set[FieldType] = set()
        header_seen = False
        high_risk_multi_surface = False
        for poc in pocs:
            payload = (poc.payload or "").strip()
            if not payload:
                continue

            req = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/", payload, flags=re.IGNORECASE)
            if req:
                surfaces.add(FieldType.URI_PATH)
                if "?" in req.group(2):
                    surfaces.add(FieldType.QUERY)

            header = re.match(r"^([A-Za-z0-9-]{2,64}):\s+(.+)$", payload)
            if header:
                header_seen = True

            low = payload.lower()
            if "${" in payload or "://" in low:
                high_risk_multi_surface = True

            if not req and not header and ("=" in payload or "${" in payload):
                surfaces.add(FieldType.BODY)

        if header_seen:
            surfaces.add(FieldType.HEADER)

        # For high-risk payload families, enforce baseline coverage across core surfaces.
        if high_risk_multi_surface:
            surfaces |= {FieldType.URI_PATH, FieldType.QUERY, FieldType.BODY}
            if header_seen:
                surfaces.add(FieldType.HEADER)

        return surfaces

    def _pattern_family(self, pattern: str) -> str:
        low = pattern.lower()
        if "\\$\\{" in pattern and re.search(r"\([^)]+\):", pattern):
            return "direct_lookup"
        if "${" in pattern and "://" in low:
            return "protocol_sink"
        if low.count("[^}]") >= 3 and ":" in low and "${" in pattern:
            return "obfuscated_token"
        if "lower" in low or "upper" in low or "::-" in low:
            return "wrapper_transform"
        if ":-" in low and "${" in pattern:
            return "fallback_default"
        return "generic"

    def _family_surface_map(self, rule: IntermediateRule) -> dict[str, set[FieldType]]:
        family_map: dict[str, set[FieldType]] = {}
        for cond in rule.conditions:
            family = self._pattern_family(cond.pattern)
            family_map.setdefault(family, set()).add(cond.field_type)
        return family_map

    def _symmetry_gap_feedback(self, rule: IntermediateRule, pocs: list[PocArtifact]) -> list[str]:
        required = self._required_surfaces(pocs)
        if not required:
            return []

        family_map = self._family_surface_map(rule)
        gaps: list[str] = []
        for family, covered in family_map.items():
            if family == "generic":
                continue
            missing = [s.value for s in sorted(required, key=lambda s: s.value) if s not in covered]
            if missing:
                gaps.append(
                    f"- Pattern family '{family}' is asymmetrical. Add matching conditions on: {', '.join(missing)}."
                )
        return gaps

    def _observed_header_names(self, pocs: list[PocArtifact]) -> list[str]:
        headers: set[str] = set()
        for poc in pocs:
            payload = (poc.payload or "").strip()
            if not payload:
                continue
            header = re.match(r"^([A-Za-z0-9-]{2,64}):\s+(.+)$", payload)
            if header:
                headers.add(header.group(1))
        return sorted(headers)

    def _is_expression_context(self, rule: IntermediateRule, pocs: list[PocArtifact]) -> bool:
        text = "\n".join([(p.payload or "") for p in pocs] + [c.pattern for c in rule.conditions])
        return "${" in text and ":" in text

    def _extract_lookup_heads(self, pocs: list[PocArtifact], rule: IntermediateRule) -> list[str]:
        heads: set[str] = set()
        text = "\n".join([(p.payload or "") for p in pocs] + [c.pattern for c in rule.conditions])
        for head in re.findall(r"\$\{\s*([A-Za-z][A-Za-z0-9_.-]{1,24})\s*:", text):
            low = head.lower()
            if low in {"lower", "upper"}:
                continue
            if len(low) >= 3:
                heads.add(low)
        return sorted(heads)

    def _obfuscated_token_pattern(self, token: str) -> str:
        chunks = "[^}]{0,10}".join(re.escape(ch) for ch in token)
        return rf"(?i)\$\{{[^}}]{{0,20}}{chunks}[^}}]{{0,60}}:"

    def _required_family_specs(self, pocs: list[PocArtifact], rule: IntermediateRule) -> dict[str, str]:
        specs: dict[str, str] = {}
        heads = self._extract_lookup_heads(pocs, rule)
        if heads:
            direct_alt = "|".join(re.escape(h) for h in heads)
            specs["direct_lookup"] = rf"(?i)\$\{{({direct_alt}):"
            specs["obfuscated_token"] = self._obfuscated_token_pattern(heads[0])

        combined = "\n".join((p.payload or "") for p in pocs).lower()
        if "${" in combined and ("${${" in combined or "${::-" in combined or "${lower:" in combined or "${upper:" in combined):
            specs["wrapper_transform"] = r"(?i)\$\{[^}]{0,80}(lower|upper|::-)[^}]{0,80}\}"
        if "${" in combined and ":-" in combined:
            specs["fallback_default"] = r"(?i)\$\{[a-z0-9_.-]{1,24}:[^}:-]{0,80}:-[^}]{0,120}\}"

        # Keep protocol sink generic for URL-based exploit payloads.
        if re.search(r"://", combined):
            specs["protocol_sink"] = r"(?i)\$\{[^}:]{2,32}:[^}]{0,80}://"

        return specs

    def _missing_required_families_feedback(self, rule: IntermediateRule, pocs: list[PocArtifact]) -> list[str]:
        if not self._is_expression_context(rule, pocs):
            return []

        required_specs = self._required_family_specs(pocs, rule)
        if not required_specs:
            return []

        present = set(self._family_surface_map(rule).keys())
        missing = [fam for fam in required_specs if fam not in present]
        if not missing:
            return []

        return [
            "- Add explicit conditions for missing exploit-expression evasion families: "
            + ", ".join(missing)
            + ". Do not rely only on a single literal ${token:...} matcher."
        ]

    def _append_unique_condition(
        self,
        rule: IntermediateRule,
        *,
        field_type: FieldType,
        pattern: str,
        header_name: str | None,
    ) -> bool:
        for cond in rule.conditions:
            if cond.field_type != field_type:
                continue
            if cond.pattern != pattern:
                continue
            existing_header = (cond.header_name or "").lower()
            wanted_header = (header_name or "").lower()
            if existing_header == wanted_header:
                return False

        rule.conditions.append(
            Condition(
                field_type=field_type,
                operator=rule.conditions[0].operator if rule.conditions else Operator.REGEX,
                pattern=pattern,
                header_name=header_name,
            )
        )
        return True

    def _enforce_minimum_expression_family_coverage(
        self,
        rule: IntermediateRule,
        pocs: list[PocArtifact],
    ) -> tuple[IntermediateRule, list[str]]:
        if not self._is_expression_context(rule, pocs):
            return rule, []

        required_surfaces = self._required_surfaces(pocs)
        if not required_surfaces:
            return rule, []

        required_specs = self._required_family_specs(pocs, rule)
        if not required_specs:
            return rule, []

        observed_headers = self._observed_header_names(pocs)
        family_map = self._family_surface_map(rule)
        added = 0

        for family, pattern in required_specs.items():
            covered = set(family_map.get(family, set()))
            for surface in required_surfaces:
                if surface in covered:
                    continue

                if surface == FieldType.HEADER:
                    if not observed_headers:
                        continue
                    for header in observed_headers:
                        if self._append_unique_condition(
                            rule,
                            field_type=FieldType.HEADER,
                            pattern=pattern,
                            header_name=header,
                        ):
                            added += 1
                    covered.add(FieldType.HEADER)
                    continue

                if self._append_unique_condition(
                    rule,
                    field_type=surface,
                    pattern=pattern,
                    header_name=None,
                ):
                    added += 1
                covered.add(surface)

        if not added:
            return rule, []

        return (
            rule,
            [
                "Applied deterministic exploit-expression hardening: added missing obfuscation/fallback family conditions."
            ],
        )

    def _enforce_surface_symmetry(
        self,
        rule: IntermediateRule,
        pocs: list[PocArtifact],
    ) -> tuple[IntermediateRule, list[str]]:
        required = self._required_surfaces(pocs)
        if not required:
            return rule, []

        family_map = self._family_surface_map(rule)
        added = 0
        notes: list[str] = []

        # Clone strongest family conditions across missing required surfaces as a safety net.
        for family, covered in family_map.items():
            if family == "generic":
                continue

            exemplar = next((c for c in rule.conditions if self._pattern_family(c.pattern) == family), None)
            if exemplar is None:
                continue

            for surface in required:
                if surface in covered:
                    continue
                rule.conditions.append(
                    exemplar.model_copy(
                        update={
                            "field_type": surface,
                            "header_name": exemplar.header_name if surface == FieldType.HEADER else None,
                        }
                    )
                )
                covered.add(surface)
                added += 1

        if added:
            notes.append(
                f"Applied deterministic surface-symmetry augmentation: added {added} conditions across missing fields."
            )
        return rule, notes

    def _generate_with_llm(
        self,
        intel: CveIntel,
        pocs: list[PocArtifact],
        mode: EnforcementMode,
        repair_feedback: str | None = None,
    ) -> tuple[IntermediateRule | None, list[str]]:
        warnings: list[str] = []
        if not self.llm.enabled():
            warnings.append(self.llm.missing_credentials_message())
            return None, warnings

        if not pocs:
            warnings.append("LLM generation skipped: no known exploit payloads available")
            return None, warnings

        try:
            rule = self.llm.generate_rule(
                intel=intel,
                pocs=pocs,
                rule_id=f"{intel.cve_id.lower()}-llm",
                action=mode,
                repair_feedback=repair_feedback,
            )
            return rule, warnings
        except Exception as exc:
            warnings.append(f"LLM generation failed: {exc}")
            return None, warnings


class RuleStabilizerAgent:
    def __init__(self) -> None:
        self.llm = LlmRuleGenerator()
        self.model = self.llm.expensive_model("repair")

    def stabilize(
        self,
        *,
        intel: CveIntel,
        pocs: list[PocArtifact],
        rule: IntermediateRule,
        replay_results: list[dict[str, Any]],
        validation_issues: list[dict[str, Any]],
        providers: list[Provider] | None = None,
        audit_feedback: str | None = None,
    ) -> tuple[IntermediateRule | None, list[str]]:
        warnings: list[str] = []
        if not self.llm.enabled():
            warnings.append(self.llm.missing_credentials_message())
            return None, warnings

        prompt = self.llm.build_stabilize_prompt(
            intel=intel,
            pocs=pocs,
            current_rule=rule,
            replay_results=replay_results,
            validation_issues=validation_issues,
            providers=providers,
            audit_feedback=audit_feedback,
        )

        try:
            raw = self.llm.invoke_with_model(prompt=prompt, model=self.model)
            draft = self.llm._parse_json(raw)
        except Exception as exc:
            warnings.append(f"Expensive stabilization pass failed: {exc}")
            return None, warnings

        stabilized = IntermediateRule(
            rule_id=rule.rule_id,
            name=draft.name,
            cve_id=rule.cve_id,
            severity=rule.severity,
            action=rule.action,
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
            source_pocs=rule.source_pocs,
            provenance={
                **rule.provenance,
                "stabilized_by": "llm_expensive",
                "stabilizer_model": self.model,
                "stabilizer_rationale": draft.rationale,
                "stabilizer_fp_risk": draft.fp_risk,
            },
        )
        return stabilized, warnings


class RuleAuditAgent:
    def __init__(self) -> None:
        self.llm = LlmRuleGenerator()
        self.model = self.llm.expensive_model("audit")

    def audit(
        self,
        *,
        intel: CveIntel,
        pocs: list[PocArtifact],
        rule: IntermediateRule,
        replay_results: list[dict[str, Any]],
        validation_issues: list[dict[str, Any]],
        providers: list[Provider] | None = None,
    ) -> tuple[RuleAuditReport | None, list[str]]:
        warnings: list[str] = []

        if not self.llm.enabled():
            warnings.append(self.llm.missing_credentials_message())
            return None, warnings

        prompt = self.llm.build_audit_prompt(
            intel=intel,
            pocs=pocs,
            rule=rule,
            replay_results=replay_results,
            validation_issues=validation_issues,
            providers=providers,
        )
        try:
            raw = self.llm.invoke_with_model(prompt=prompt, model=self.model)
            report = self.llm.parse_audit_json(raw)
            report.model = self.model
            return report, warnings
        except Exception as exc:
            warnings.append(f"Expensive audit pass failed: {exc}")
            return None, warnings

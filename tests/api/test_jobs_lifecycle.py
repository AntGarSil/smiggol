from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from waf_factory import main as main_module
from waf_factory.jobs import SqliteJobStore
from waf_factory.models import (
    Condition,
    CveIntel,
    FieldType,
    GenerationResult,
    IntermediateRule,
    Operator,
    Provider,
    ProviderArtifact,
    ReplayResult,
    Severity,
)


class _StubOrchestrator:
    """Minimal orchestrator that mimics `RuleFactoryOrchestrator.generate`."""

    def __init__(self, *, delay: float = 0.0, fail: bool = False) -> None:
        self.delay = delay
        self.fail = fail
        self.calls: list[dict] = []
        self._release = threading.Event()

    def release(self) -> None:
        self._release.set()

    def generate(
        self,
        cve_id: str,
        targets,
        mode,
        use_llm: bool,
        job_id: str,
    ) -> GenerationResult:
        self.calls.append(
            {
                "job_id": job_id,
                "cve_id": cve_id,
                "targets": list(targets),
                "mode": mode,
            }
        )
        if self.delay:
            self._release.wait(timeout=self.delay)
        if self.fail:
            raise RuntimeError("boom")
        rule = IntermediateRule(
            rule_id=f"waf-{cve_id.lower()}",
            name=f"Block {cve_id}",
            cve_id=cve_id,
            severity=Severity.HIGH,
            action=mode,
            confidence=0.9,
            conditions=[
                Condition(field_type=FieldType.URI_PATH, operator=Operator.CONTAINS, pattern="/vulnerable")
            ],
        )
        artifacts = [ProviderArtifact(provider=t, terraform=f"# stub {t.value}") for t in targets]
        replay = [
            ReplayResult(
                rule_id=rule.rule_id,
                payload_count=1,
                detected_count=1,
                detection_rate=1.0,
                exploit_payload_count=1,
                exploit_detected_count=1,
                exploit_detection_rate=1.0,
            )
            for _ in targets
        ]
        return GenerationResult(
            cve=CveIntel(cve_id=cve_id, description="stub"),
            rules=[rule],
            artifacts=artifacts,
            validation_issues=[],
            replay_results=replay,
            warnings=[],
        )


@pytest.fixture()
def stub() -> _StubOrchestrator:
    return _StubOrchestrator()


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub: _StubOrchestrator):
    store = SqliteJobStore(path=tmp_path / "jobs.db")
    monkeypatch.setattr(main_module, "_PROGRESS_POLL_SECONDS", 0.05)
    monkeypatch.setattr(main_module, "job_store", store)
    monkeypatch.setattr(main_module, "orchestrator", stub)
    with TestClient(main_module.app) as tc:
        yield tc


def _wait_until_terminal(client: TestClient, job_id: str, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = client.get(f"/v1/jobs/{job_id}")
        assert response.status_code == 200, response.text
        payload = response.json()
        if payload["status"] in {"succeeded", "failed", "cancelled"}:
            return payload
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not reach terminal state within {timeout}s")


def test_generate_returns_accepted_and_completes(client: TestClient, stub: _StubOrchestrator) -> None:
    response = client.post(
        "/v1/rules/generate",
        json={"cve_id": "CVE-2024-11111", "targets": ["aws", "azure"], "mode": "count", "use_llm": False},
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    assert body["job_id"].startswith("job-")

    final = _wait_until_terminal(client, body["job_id"])
    assert final["status"] == "succeeded"
    assert final["result"]["cve"]["description"] == "stub"
    assert final["result"]["rule_count"] == 1
    assert final["result"]["rules"][0]["cve_id"] == "CVE-2024-11111"
    assert set(final["result"]["provider_outputs"].keys()) == {"aws", "azure"}
    assert stub.calls[0]["cve_id"] == "CVE-2024-11111"


def test_get_job_not_found(client: TestClient) -> None:
    response = client.get("/v1/jobs/nonexistent")
    assert response.status_code == 404


def test_stream_job_not_found(client: TestClient) -> None:
    response = client.get("/v1/jobs/nonexistent/stream")
    assert response.status_code == 404


def test_stream_terminal_job_emits_result_and_closes(client: TestClient) -> None:
    response = client.post(
        "/v1/rules/generate",
        json={"cve_id": "CVE-2024-55555", "targets": ["aws"], "mode": "count", "use_llm": False},
    )
    job_id = response.json()["job_id"]
    _wait_until_terminal(client, job_id)

    stream = client.get(f"/v1/jobs/{job_id}/stream")

    assert stream.status_code == 200
    assert stream.headers["content-type"].startswith("text/event-stream")
    assert "event: terminal" in stream.text
    data_line = next(line for line in stream.text.splitlines() if line.startswith("data: "))
    payload = json.loads(data_line.removeprefix("data: "))
    assert payload["status"] == "succeeded"
    assert payload["result"]["cve"]["cve_id"] == "CVE-2024-55555"


def test_delete_job_not_found(client: TestClient) -> None:
    response = client.delete("/v1/jobs/nonexistent")
    assert response.status_code == 404


def test_cancel_marks_job_cancelled(client: TestClient, stub: _StubOrchestrator) -> None:
    stub.delay = 5.0
    response = client.post(
        "/v1/rules/generate",
        json={"cve_id": "CVE-2024-22222", "targets": ["aws"], "mode": "count", "use_llm": False},
    )
    job_id = response.json()["job_id"]
    cancel = client.delete(f"/v1/jobs/{job_id}")
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "cancelled"
    stub.release()


def test_failed_job_records_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SqliteJobStore(path=tmp_path / "jobs.db")
    failing = _StubOrchestrator(fail=True)
    monkeypatch.setattr(main_module, "_PROGRESS_POLL_SECONDS", 0.05)
    monkeypatch.setattr(main_module, "job_store", store)
    monkeypatch.setattr(main_module, "orchestrator", failing)
    with TestClient(main_module.app) as client:
        response = client.post(
            "/v1/rules/generate",
            json={"cve_id": "CVE-2024-33333", "targets": ["aws"], "mode": "count", "use_llm": False},
        )
        job_id = response.json()["job_id"]
        final = _wait_until_terminal(client, job_id)
    assert final["status"] == "failed"
    assert "boom" in (final["error"] or "")


def test_health_endpoint(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}

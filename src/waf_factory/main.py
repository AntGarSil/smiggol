"""FastAPI app exposing the WAF Rule Factory as async jobs."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from waf_factory.api_models import (
    GenerateRulesRequest,
    GenerateRulesResponse,
    JobAcceptedResponse,
    JobStatusResponse,
)
from waf_factory.jobs import SqliteJobStore
from waf_factory.models import EnforcementMode, GenerationResult, Provider
from waf_factory.orchestrator import RuleFactoryOrchestrator

logger = logging.getLogger("waf_factory.api")

_PROGRESS_POLL_SECONDS = float(os.getenv("WAF_JOB_PROGRESS_POLL_SECONDS", "1.0"))
_SSE_POLL_SECONDS = float(os.getenv("WAF_JOB_SSE_POLL_SECONDS", "0.5"))
_TERMINAL_STATUSES = {"succeeded", "failed", "cancelled"}


@asynccontextmanager
async def _lifespan(app: FastAPI):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger.info("API startup complete")
    yield


app = FastAPI(title="CVE WAF Rule Factory", version="0.2.0", lifespan=_lifespan)
cors_origins = [origin.strip() for origin in os.getenv("WAF_CORS_ORIGINS", "http://localhost:5173").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
orchestrator = RuleFactoryOrchestrator()
job_store = SqliteJobStore()


@app.middleware("http")
async def request_logging(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - started) * 1000
    logger.info(
        "request completed method=%s path=%s status=%s duration_ms=%.2f",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/rules/generate", response_model=JobAcceptedResponse, status_code=202)
async def generate_rules(request: GenerateRulesRequest) -> JobAcceptedResponse:
    record = job_store.create(request.model_dump(mode="json"))
    logger.info(
        "job accepted job=%s cve=%s targets=%s mode=%s",
        record.id,
        request.cve_id,
        [t.value for t in request.targets],
        request.mode.value,
    )
    asyncio.create_task(_run_job(record.id, request))
    return JobAcceptedResponse(job_id=record.id, status=record.status)


@app.get("/v1/jobs/{job_id}", response_model=JobStatusResponse)
def get_job(job_id: str) -> JobStatusResponse:
    record = job_store.get(job_id)
    if record is None:
        raise HTTPException(status_code=404, detail={"message": f"Job {job_id} not found"})
    return _record_to_response(record)


def _record_to_response(record) -> JobStatusResponse:
    result = None
    if record.result:
        result = GenerateRulesResponse.model_validate(record.result)
    return JobStatusResponse(
        job_id=record.id,
        status=record.status,
        stages_done=record.stages_done,
        warnings=record.warnings,
        error=record.error,
        result=result,
    )


@app.get("/v1/jobs/{job_id}/stream")
async def stream_job(job_id: str, request: Request) -> StreamingResponse:
    if job_store.get(job_id) is None:
        raise HTTPException(status_code=404, detail={"message": f"Job {job_id} not found"})

    async def events():
        previous = ""
        while not await request.is_disconnected():
            record = job_store.get(job_id)
            if record is None:
                return
            snapshot = _record_to_response(record)
            payload = snapshot.model_dump_json()
            if payload != previous:
                event_name = "terminal" if record.status in _TERMINAL_STATUSES else "snapshot"
                yield f"event: {event_name}\ndata: {payload}\n\n"
                previous = payload
            else:
                yield ": keep-alive\n\n"
            if record.status in _TERMINAL_STATUSES:
                return
            await asyncio.sleep(_SSE_POLL_SECONDS)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.delete("/v1/jobs/{job_id}", response_model=JobStatusResponse)
def cancel_job(job_id: str) -> JobStatusResponse:
    if not job_store.request_cancel(job_id):
        raise HTTPException(status_code=404, detail={"message": f"Job {job_id} not found"})
    return get_job(job_id)


async def _run_job(job_id: str, request: GenerateRulesRequest) -> None:
    # Flip queued -> running immediately so pollers see progress.
    job_store.update_progress(job_id, stages_done=[])
    task = asyncio.create_task(
        asyncio.to_thread(
            orchestrator.generate,
            request.cve_id,
            list(request.targets),
            request.mode,
            request.use_llm,
            job_id,
        )
    )
    try:
        while not task.done():
            await asyncio.sleep(_PROGRESS_POLL_SECONDS)
            _report_graph_progress(job_id)
        result = await task
        _report_graph_progress(job_id)
        if job_store.is_cancel_requested(job_id):
            logger.info("job cancelled before completion job=%s", job_id)
            return
        response = _result_to_response(request.cve_id, result)
        job_store.mark_succeeded(job_id, response.model_dump(mode="json"))
        logger.info("job succeeded job=%s cve=%s", job_id, request.cve_id)
    except Exception as exc:
        logger.exception("job failed job=%s: %s", job_id, exc)
        job_store.mark_failed(job_id, str(exc))


def _report_graph_progress(job_id: str) -> None:
    """Read intermediate LangGraph state from the checkpointer and write it to the job store."""
    try:
        snapshot = orchestrator.graph.get_state({"configurable": {"thread_id": job_id}})
    except Exception:
        return
    values = getattr(snapshot, "values", None) or {}
    stages = values.get("stages_done") or []
    warnings = values.get("warnings") or []
    if stages or warnings:
        job_store.update_progress(job_id, stages_done=list(stages), warnings=list(warnings))


def _result_to_response(cve_id: str, result: GenerationResult) -> GenerateRulesResponse:
    replay_summary = {r.rule_id: r.detection_rate for r in result.replay_results}
    provider_outputs = {a.provider.value: a.terraform for a in result.artifacts}
    validation_issues = [issue.model_dump() for issue in result.validation_issues]
    audit_report = result.audit_report.model_dump(mode="json") if result.audit_report else None
    promotion = result.promotion_state.value if result.promotion_state else None

    return GenerateRulesResponse(
        cve_id=cve_id,
        cve=result.cve,
        warnings=result.warnings,
        rule_count=len(result.rules),
        rules=[rule.model_dump(mode="json") for rule in result.rules],
        provider_outputs=provider_outputs,
        replay_summary=replay_summary,
        validation_issues=validation_issues,
        audit_report=audit_report,
        promotion_state=promotion,
    )

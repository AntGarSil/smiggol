"""In-process HTTP harness that applies IntermediateRule AST as a mock WAF.

Nuclei fires exploit requests against this harness. If the WAF rule matches,
the harness returns 403; otherwise it returns a synthetic "vulnerable" response
that includes common markers so a well-written nuclei template can detect a hit.
Every request is recorded in a :class:`HarnessEvent` log for correlation.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from waf_factory.harness.interpreter import matches_condition
from waf_factory.models import Condition, EnforcementMode, FieldType, IntermediateRule

logger = logging.getLogger("waf_factory.harness.mock_waf")


VULNERABLE_STUB_BODY = (
    "<html><head><title>Sample App</title></head><body>"
    "<h1>Welcome, admin!</h1>"
    "<p>SQL syntax error near 'UNION SELECT'</p>"
    "<p>alert(1)</p>"
    "<pre>root:x:0:0:root:/root:/bin/bash</pre>"
    "</body></html>"
)


@dataclass
class HarnessEvent:
    timestamp: float
    method: str
    path: str
    query: str
    body_snippet: str
    matched_rule_ids: list[str] = field(default_factory=list)
    blocked: bool = False


class MockWaf:
    """Starlette app + uvicorn server running in a background thread."""

    def __init__(
        self,
        rules: Iterable[IntermediateRule] | None = None,
        *,
        host: str = "127.0.0.1",
        port: int | None = None,
        enforcement: EnforcementMode = EnforcementMode.BLOCK,
    ) -> None:
        self.host = host
        self.port = port or _find_free_port()
        self.enforcement = enforcement
        self.rules: list[IntermediateRule] = list(rules or [])
        self.events: list[HarnessEvent] = []
        self._events_lock = threading.Lock()
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._response_body_override: str | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def set_rules(self, rules: Iterable[IntermediateRule]) -> None:
        self.rules = list(rules)

    def set_stub_body(self, body: str | None) -> None:
        """Override the fake vulnerable response body (for template-tuned runs)."""
        self._response_body_override = body

    def snapshot_events(self) -> list[HarnessEvent]:
        with self._events_lock:
            return list(self.events)

    def clear_events(self) -> None:
        with self._events_lock:
            self.events.clear()

    # ------- request handling ------------------------------------------------
    async def _handle(self, request: Request) -> Response:
        body = await request.body()
        body_text = body.decode("utf-8", errors="replace")
        matched = _evaluate_rules(self.rules, request, body_text)

        event = HarnessEvent(
            timestamp=time.time(),
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            body_snippet=body_text[:512],
            matched_rule_ids=[rule.rule_id for rule, _ in matched],
        )

        if matched and self.enforcement == EnforcementMode.BLOCK:
            event.blocked = True
            with self._events_lock:
                self.events.append(event)
            headers = {"X-WAF-Rule": event.matched_rule_ids[0]}
            return Response("blocked by mock waf", status_code=403, headers=headers)

        with self._events_lock:
            self.events.append(event)

        headers: dict[str, str] = {}
        if matched:
            headers["X-WAF-Match"] = event.matched_rule_ids[0]
        body_out = self._response_body_override if self._response_body_override is not None else VULNERABLE_STUB_BODY
        return Response(body_out, status_code=200, media_type="text/html", headers=headers)

    def _build_app(self) -> Starlette:
        async def handler(request: Request) -> Response:
            return await self._handle(request)

        return Starlette(routes=[Route("/{full_path:path}", endpoint=handler, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])])

    # ------- lifecycle -------------------------------------------------------
    def start(self, ready_timeout: float = 5.0) -> None:
        if self._server is not None:
            return
        app = self._build_app()
        config = uvicorn.Config(
            app,
            host=self.host,
            port=self.port,
            log_level="warning",
            access_log=False,
            lifespan="off",
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()

        deadline = time.time() + ready_timeout
        while time.time() < deadline:
            if getattr(self._server, "started", False):
                logger.info("mock waf started at %s", self.base_url)
                return
            time.sleep(0.05)
        raise RuntimeError("mock waf failed to start within timeout")

    def _run_server(self) -> None:
        try:
            asyncio.run(self._server.serve())
        except Exception as exc:
            logger.error("mock waf server crashed: %s", exc)

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        self._server = None
        self._thread = None

    def __enter__(self) -> "MockWaf":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


def _find_free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _payload_for_condition(request: Request, body_text: str, cond: Condition) -> str:
    field = cond.field_type
    if field == FieldType.URI_PATH:
        return urllib.parse.unquote(request.url.path)
    if field == FieldType.QUERY:
        return urllib.parse.unquote_plus(request.url.query)
    if field == FieldType.BODY:
        try:
            return urllib.parse.unquote_plus(body_text)
        except Exception:
            return body_text
    if field == FieldType.HEADER:
        header_name = (cond.header_name or "").lower()
        if not header_name:
            return "\n".join(f"{k}: {v}" for k, v in request.headers.items())
        return request.headers.get(header_name, "")
    if field == FieldType.IP:
        return request.client.host if request.client else ""
    return ""


def _evaluate_rules(
    rules: list[IntermediateRule],
    request: Request,
    body_text: str,
) -> list[tuple[IntermediateRule, Condition]]:
    matched: list[tuple[IntermediateRule, Condition]] = []
    for rule in rules:
        for cond in rule.conditions:
            payload = _payload_for_condition(request, body_text, cond)
            if payload and matches_condition(payload, cond):
                matched.append((rule, cond))
                break
    return matched

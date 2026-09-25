"""Persistent job store backing the async /v1/rules/generate API.

Uses SQLite so job records survive API restarts. The LangGraph checkpointer
writes to the same file under a separate table namespace.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

JOB_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")

DEFAULT_DB_PATH = Path(os.getenv("WAF_JOB_DB_PATH", ".waf_factory_cache/jobs.db"))


@dataclass
class JobRecord:
    id: str
    status: str
    request: dict[str, Any]
    stages_done: list[str]
    warnings: list[str]
    result: dict[str, Any] | None
    error: str | None
    created_at: float
    updated_at: float


class SqliteJobStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DEFAULT_DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=5, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS waf_jobs (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    request TEXT NOT NULL,
                    stages_done TEXT NOT NULL DEFAULT '[]',
                    warnings TEXT NOT NULL DEFAULT '[]',
                    result TEXT,
                    error TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    cancel_requested INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.commit()

    def create(self, request: dict[str, Any]) -> JobRecord:
        job_id = f"job-{uuid.uuid4().hex[:12]}"
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO waf_jobs (id, status, request, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (job_id, "queued", json.dumps(request), now, now),
            )
            conn.commit()
        return JobRecord(
            id=job_id,
            status="queued",
            request=request,
            stages_done=[],
            warnings=[],
            result=None,
            error=None,
            created_at=now,
            updated_at=now,
        )

    def _hydrate(self, row: sqlite3.Row) -> JobRecord:
        return JobRecord(
            id=row["id"],
            status=row["status"],
            request=json.loads(row["request"]),
            stages_done=json.loads(row["stages_done"]) if row["stages_done"] else [],
            warnings=json.loads(row["warnings"]) if row["warnings"] else [],
            result=json.loads(row["result"]) if row["result"] else None,
            error=row["error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock, self._connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM waf_jobs WHERE id = ?", (job_id,)).fetchone()
        return self._hydrate(row) if row else None

    def update_progress(self, job_id: str, *, stages_done: list[str] | None = None, warnings: list[str] | None = None) -> None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT stages_done, warnings FROM waf_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                return
            existing_stages = json.loads(row[0]) if row[0] else []
            existing_warnings = json.loads(row[1]) if row[1] else []
            if stages_done:
                for stage in stages_done:
                    if stage not in existing_stages:
                        existing_stages.append(stage)
            if warnings:
                for warning in warnings:
                    if warning not in existing_warnings:
                        existing_warnings.append(warning)
            conn.execute(
                "UPDATE waf_jobs SET status = 'running', stages_done = ?, warnings = ?, updated_at = ? WHERE id = ?",
                (json.dumps(existing_stages), json.dumps(existing_warnings), time.time(), job_id),
            )
            conn.commit()

    def mark_succeeded(self, job_id: str, result: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE waf_jobs SET status = 'succeeded', result = ?, updated_at = ? WHERE id = ?",
                (json.dumps(result), time.time(), job_id),
            )
            conn.commit()

    def mark_failed(self, job_id: str, error: str, result: dict[str, Any] | None = None) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE waf_jobs SET status = 'failed', error = ?, result = ?, updated_at = ? WHERE id = ?",
                (error, json.dumps(result) if result is not None else None, time.time(), job_id),
            )
            conn.commit()

    def request_cancel(self, job_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE waf_jobs SET cancel_requested = 1, status = CASE WHEN status IN ('queued','running') THEN 'cancelled' ELSE status END, updated_at = ? WHERE id = ?",
                (time.time(), job_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def is_cancel_requested(self, job_id: str) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT cancel_requested FROM waf_jobs WHERE id = ?", (job_id,)).fetchone()
        return bool(row and row[0])

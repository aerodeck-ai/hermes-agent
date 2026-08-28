"""Legacy ``hermes_events.db`` SQLite writer for CoS profile telemetry.

This plugin intentionally records only coarse operational metadata: event
type, model/tool names, token counts, provider, status, and a coarse error
class. It does not persist prompts, responses, tool arguments, tool results,
or credentials.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hermes_constants import get_hermes_home

logger = logging.getLogger(__name__)

_LOCK = threading.RLock()


def _safe(fn):
    def wrapper(*args: Any, **kwargs: Any) -> None:
        try:
            fn(*args, **kwargs)
        except Exception:
            logger.debug(
                "hermes_events_sqlite hook %s failed",
                getattr(fn, "__name__", "?"),
                exc_info=True,
            )

    wrapper.__name__ = getattr(fn, "__name__", "wrapper")
    return wrapper


def _db_path() -> Path:
    return Path(get_hermes_home()) / "hermes_events.db"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _intent_id(kwargs: dict[str, Any]) -> str:
    value = (
        kwargs.get("session_id")
        or kwargs.get("task_id")
        or kwargs.get("conversation_id")
        or kwargs.get("turn_id")
    )
    if value:
        return _text(value)
    return f"process:{os.getpid()}"


def _span_id(kind: str, label: str, kwargs: dict[str, Any]) -> str:
    for key in ("span_id", "api_request_id", "tool_call_id", "call_id", "request_id"):
        value = kwargs.get(key)
        if value:
            return _text(value)
    digest = hashlib.sha256(
        f"{kind}|{label}|{_intent_id(kwargs)}|{_now_iso()}|{uuid.uuid4().hex}".encode(
            "utf-8"
        )
    ).hexdigest()
    return digest[:32]


def _source_app(kwargs: dict[str, Any]) -> str:
    return _text(kwargs.get("platform") or kwargs.get("source") or "hermes", "hermes")


def _usage(kwargs: dict[str, Any]) -> tuple[int | None, int | None]:
    usage = kwargs.get("usage")
    if not isinstance(usage, dict):
        usage = {}

    def to_int(value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    input_tokens = (
        usage.get("input_tokens")
        or usage.get("prompt_tokens")
        or kwargs.get("input_tokens")
        or kwargs.get("prompt_tokens")
    )
    output_tokens = (
        usage.get("output_tokens")
        or usage.get("completion_tokens")
        or kwargs.get("output_tokens")
        or kwargs.get("completion_tokens")
    )
    return to_int(input_tokens), to_int(output_tokens)


def _coarse_error(value: Any) -> str:
    raw = _text(value).lower()
    if not raw:
        return ""
    if "timeout" in raw:
        return "timeout"
    if "rate" in raw and "limit" in raw:
        return "rate_limit"
    if any(part in raw for part in ("401", "403", "auth", "unauthor", "forbidden")):
        return "auth"
    if any(part in raw for part in ("connection", "network", "dns", "socket")):
        return "network"
    if any(part in raw for part in ("context", "token limit", "too long")):
        return "context"
    if any(part in raw for part in ("500", "502", "503", "provider")):
        return "provider"
    return "error"


def _tool_status(result: Any) -> tuple[str, str]:
    if result is None:
        return "ok", ""
    if isinstance(result, dict):
        if result.get("blocked"):
            return "blocked", "blocked"
        if result.get("error"):
            return "error", "error"
        return "ok", ""
    text = _text(result).lower()
    if '"blocked"' in text or "blocked" in text[:200]:
        return "blocked", "blocked"
    if '"error"' in text[:500] or text.startswith("error"):
        return "error", "error"
    return "ok", ""


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS hermes_events (
            intent_id      TEXT    NOT NULL,
            span_id        TEXT    NOT NULL PRIMARY KEY,
            parent_span_id TEXT,
            ts             TEXT    NOT NULL,
            source_app     TEXT    NOT NULL,
            kind           TEXT    NOT NULL,
            label          TEXT    NOT NULL,
            mcp_server     TEXT,
            tool_name      TEXT,
            model_req      TEXT,
            model_used     TEXT,
            provider       TEXT,
            input_tokens   INTEGER,
            output_tokens  INTEGER,
            cost_usd       REAL,
            status         TEXT    NOT NULL DEFAULT 'ok',
            error_message  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_hermes_events_intent_id
            ON hermes_events (intent_id);
        CREATE INDEX IF NOT EXISTS idx_hermes_events_ts
            ON hermes_events (ts);
        CREATE INDEX IF NOT EXISTS idx_hermes_events_source_app
            ON hermes_events (source_app);
        """
    )


def _write_event(
    *,
    kind: str,
    label: str,
    kwargs: dict[str, Any],
    mcp_server: str | None = None,
    tool_name: str | None = None,
    model_req: str | None = None,
    model_used: str | None = None,
    provider: str | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    cost_usd: float | None = None,
    status: str = "ok",
    error_message: str | None = None,
) -> None:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_span_id = kwargs.get("parent_span_id")
    span_id = _span_id(kind, label, kwargs)
    with _LOCK:
        with sqlite3.connect(path) as conn:
            _ensure_schema(conn)
            conn.execute(
                """
                INSERT OR IGNORE INTO hermes_events (
                    intent_id, span_id, parent_span_id, ts, source_app, kind, label,
                    mcp_server, tool_name, model_req, model_used, provider,
                    input_tokens, output_tokens, cost_usd, status, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _intent_id(kwargs),
                    span_id,
                    _text(parent_span_id) if parent_span_id else None,
                    _now_iso(),
                    _source_app(kwargs),
                    kind,
                    label,
                    mcp_server,
                    tool_name,
                    model_req,
                    model_used,
                    provider,
                    input_tokens,
                    output_tokens,
                    cost_usd,
                    status,
                    error_message,
                ),
            )
            conn.commit()
    logger.info("hermes_events_sqlite event.flush kind=%s label=%s", kind, label)


@_safe
def on_session_start(**kwargs: Any) -> None:
    _write_event(kind="session", label="session.start", kwargs=dict(kwargs))


@_safe
def on_session_end(**kwargs: Any) -> None:
    _write_event(kind="session", label="session.end", kwargs=dict(kwargs))


@_safe
def on_session_finalize(**kwargs: Any) -> None:
    _write_event(kind="session", label="session.finalize", kwargs=dict(kwargs))


@_safe
def on_session_reset(**kwargs: Any) -> None:
    _write_event(kind="session", label="session.reset", kwargs=dict(kwargs))


@_safe
def on_post_api_request(**kwargs: Any) -> None:
    data = dict(kwargs)
    input_tokens, output_tokens = _usage(data)
    model = _text(data.get("model") or data.get("model_used") or data.get("model_req"))
    _write_event(
        kind="model",
        label=model or "model.call",
        kwargs=data,
        model_req=_text(data.get("model_req") or data.get("model"), "") or None,
        model_used=_text(data.get("model_used") or data.get("model"), "") or None,
        provider=_text(data.get("provider"), "") or None,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=data.get("cost_usd") if isinstance(data.get("cost_usd"), float) else None,
    )


@_safe
def on_api_request_error(**kwargs: Any) -> None:
    data = dict(kwargs)
    error_class = _coarse_error(data.get("error_type") or data.get("error"))
    _write_event(
        kind="model",
        label="model.error",
        kwargs=data,
        model_req=_text(data.get("model_req") or data.get("model"), "") or None,
        model_used=_text(data.get("model_used") or data.get("model"), "") or None,
        provider=_text(data.get("provider"), "") or None,
        status="error",
        error_message=error_class or "error",
    )


@_safe
def on_post_tool_call(**kwargs: Any) -> None:
    data = dict(kwargs)
    tool_name = _text(data.get("function_name") or data.get("tool_name"), "")
    status, error_message = _tool_status(data.get("result"))
    _write_event(
        kind="tool",
        label=tool_name or "tool.call",
        kwargs=data,
        mcp_server=_text(data.get("mcp_server") or data.get("server"), "") or None,
        tool_name=tool_name or None,
        status=status,
        error_message=error_message or None,
    )


def register(ctx: Any) -> None:
    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("on_session_end", on_session_end)
    ctx.register_hook("on_session_finalize", on_session_finalize)
    ctx.register_hook("on_session_reset", on_session_reset)
    ctx.register_hook("post_api_request", on_post_api_request)
    ctx.register_hook("api_request_error", on_api_request_error)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    logger.debug("hermes_events_sqlite registered 7 hooks")

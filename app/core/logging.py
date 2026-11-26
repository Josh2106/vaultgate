"""Structured logging via structlog with secret redaction."""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

_SENSITIVE = (
    "password",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "cookie",
)
_SENSITIVE_EXACT = frozenset({"value", "code", "otp", "recovery_codes"})


def _redact(_: Any, __: str, event_dict: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for key in list(event_dict):
        lowered = key.lower()
        if lowered == "event":
            continue
        if lowered in _SENSITIVE_EXACT or any(s in lowered for s in _SENSITIVE):
            event_dict[key] = "[REDACTED]"
    return event_dict


def configure_logging(level: str = "INFO", *, json: bool = True) -> None:
    shared: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )
    # Route stdlib logs (uvicorn, sqlalchemy) through the same level.
    logging.basicConfig(level=level.upper(), stream=sys.stdout, format="%(message)s", force=True)

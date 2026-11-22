"""Auth-owned log safety for the HTTPX/httpcore loggers.

The filters rewrite records at the emitting logger, so handlers and levels are
left alone. Only the method, a safe URL and the numeric status of an HTTPX
request survive, and httpcore records are reduced to their event identifier.
"""
from __future__ import annotations

import logging
import re

from mountainash_auth_client._safe_errors import safe_location

_HTTPX_FORMAT = 'HTTP Request: %s %s "%s %d %s"'
_HTTPX_SAFE = re.compile(r"HTTP Request: ([A-Za-z]{1,32}) (\S+) ([0-9]{3})")
_HTTPX_EVENT = "HTTPX event"
_METHOD = re.compile(r"[A-Za-z]{1,32}")
_HTTPCORE_EVENT = "httpcore event"
_HTTPCORE_ID = re.compile(r"([a-z_0-9]+\.(?:started|complete|failed))(?: |$)")


def _httpx_message(record: logging.LogRecord) -> str:
    args = record.args
    if record.msg == _HTTPX_FORMAT and isinstance(args, tuple) and len(args) == 5:
        method, url, _version, status, _reason = args
        if (
            isinstance(method, str)
            and _METHOD.fullmatch(method)
            and isinstance(status, int)
            and not isinstance(status, bool)
        ):
            return f"HTTP Request: {method} {safe_location(str(url))} {status}"
        return _HTTPX_EVENT
    try:
        text = record.getMessage()
    except Exception:  # noqa: BLE001 - never raise from logging
        return _HTTPX_EVENT
    found = _HTTPX_SAFE.fullmatch(text)
    if found:
        method, url, status = found.groups()
        return f"HTTP Request: {method} {safe_location(url)} {status}"
    return _HTTPX_EVENT


def _httpcore_message(record: logging.LogRecord) -> str:
    try:
        text = record.getMessage()
    except Exception:  # noqa: BLE001 - never raise from logging
        return _HTTPCORE_EVENT
    found = _HTTPCORE_ID.match(text)
    return found.group(1) if found else _HTTPCORE_EVENT


class _AuthLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "httpx":
            message = _httpx_message(record)
        else:
            message = _httpcore_message(record)
        record.msg = message
        if "message" in record.__dict__:
            record.message = message
        record.args = None
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def install_log_filters() -> None:
    for name in (
        "httpx",
        "httpcore.connection",
        "httpcore.http11",
        "httpcore.http2",
        "httpcore.proxy",
        "httpcore.socks",
    ):
        logger = logging.getLogger(name)
        if not any(isinstance(item, _AuthLogFilter) for item in logger.filters):
            logger.addFilter(_AuthLogFilter())

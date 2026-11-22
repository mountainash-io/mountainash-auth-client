"""Auth-owned HTTPX/httpcore log safety, exercised through real library paths."""
from __future__ import annotations

import logging
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpcore
import httpx
import pytest
from httpcore._trace import Trace

from mountainash_auth_client.oauth._log_safety import install_log_filters


MARKER = "SENTINEL-reason-7f3a91"
HEADER_MARKER = "SENTINEL-header-4c2d08"
EMITTERS = (
    "httpx",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
)
_EVENT_ID = re.compile(r"^[a-z_0-9]+\.(started|complete|failed)$")


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []
        self.snapshots: list[dict] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.snapshots.append(dict(vars(record)))  # before any later formatter
        self.records.append(record)


@pytest.fixture
def captured():
    """Capture the emitters at DEBUG, restoring all global logger state."""
    loggers = [logging.getLogger(n) for n in EMITTERS]
    saved = [
        (lg, list(lg.filters), list(lg.handlers), lg.level, lg.propagate)
        for lg in loggers
    ]
    handler = _Capture()
    try:
        for lg in loggers:
            lg.filters.clear()
            lg.setLevel(logging.DEBUG)
            lg.handlers[:] = [handler]
            lg.propagate = False
        yield handler
    finally:
        for lg, filters, handlers, level, propagate in saved:
            lg.filters[:] = filters
            lg.handlers[:] = handlers
            lg.setLevel(level)
            lg.propagate = propagate


def _assert_clean(records, marker=MARKER):
    assert records
    for r in records:
        assert marker not in r.getMessage()
        assert marker not in repr(r.__dict__)


@pytest.fixture
def server():
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen.append(self.path)
            self.send_response(200, MARKER)
            self.send_header("X-Secret", HEADER_MARKER)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1], seen
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(5)


def test_loopback_request_leaks_nothing_but_keeps_useful_events(captured, server):
    port, seen = server
    install_log_filters()

    with httpx.Client() as client:
        response = client.get(f"http://127.0.0.1:{port}/ok")

    assert seen == ["/ok"]  # server really received the request
    assert response.status_code == 200
    by_logger: dict[str, list[logging.LogRecord]] = {}
    for r in captured.records:
        by_logger.setdefault(r.name, []).append(r)
    assert by_logger["httpx"], "HTTPX INFO record was not emitted"
    assert by_logger["httpcore.http11"], "httpcore records were not emitted"

    for r in captured.records:
        for marker in (MARKER, HEADER_MARKER):
            assert marker not in r.getMessage()
            assert marker not in repr(r.__dict__)

    (httpx_record,) = by_logger["httpx"]
    msg = httpx_record.getMessage()
    assert "GET" in msg and "127.0.0.1" in msg and "200" in msg

    for name in ("httpcore.connection", "httpcore.http11"):
        for r in by_logger[name]:
            assert _EVENT_ID.match(r.getMessage()), r.getMessage()
    events = {r.getMessage() for r in by_logger["httpcore.http11"]}
    assert "receive_response_headers.complete" in events


class _FailingBackend(httpcore.NetworkBackend):
    def connect_tcp(self, *a, **kw):
        raise httpcore.ConnectError(f"connect {MARKER}")


class _TlsFailingStream(httpcore.NetworkStream):
    def start_tls(self, *a, **kw):
        raise httpcore.ConnectError(f"tls {MARKER}")

    def read(self, *a, **kw):
        return b""

    def write(self, *a, **kw):
        return None

    def close(self):
        return None

    def get_extra_info(self, info):
        return None


class _TlsBackend(httpcore.NetworkBackend):
    def connect_tcp(self, *a, **kw):
        return _TlsFailingStream()


def _client_with_backend(backend):
    client = httpx.Client(transport=httpx.HTTPTransport(retries=0))
    client._transport._pool._network_backend = backend
    return client


def test_native_httpcore_connect_failed_event_drops_exception_text(captured):
    install_log_filters()
    with _client_with_backend(_FailingBackend()) as client:
        with pytest.raises(httpx.ConnectError):
            client.get("http://127.0.0.1:9/x")

    records = [r for r in captured.records if r.name == "httpcore.connection"]
    assert [r.getMessage() for r in records if r.getMessage().endswith(".failed")] == [
        "connect_tcp.failed"
    ]
    _assert_clean(captured.records)


def test_native_httpcore_start_tls_failed_event_drops_exception_text(captured):
    install_log_filters()
    with _client_with_backend(_TlsBackend()) as client:
        with pytest.raises(httpx.ConnectError):
            client.get("https://127.0.0.1:9/x")

    messages = [r.getMessage() for r in captured.records]
    assert "start_tls.failed" in messages
    _assert_clean(captured.records)


@pytest.mark.parametrize("name", EMITTERS[1:])
def test_each_httpcore_emitter_keeps_only_event_identity(captured, name):
    install_log_filters()
    logger = logging.getLogger(name)
    with pytest.raises(RuntimeError):
        # Dependency's real Trace path, driven by a failing body; narrower than
        # a live endpoint, labelled as such.
        with Trace("connect_tcp", logger, None, {"host": MARKER}):
            raise RuntimeError(MARKER)

    own = [r for r in captured.records if r.name == name]
    assert [r.getMessage() for r in own] == ["connect_tcp.started", "connect_tcp.failed"]
    _assert_clean(own)


def test_unknown_record_shapes_get_fixed_categories(captured):
    install_log_filters()
    logging.getLogger("httpx").info("novel shape %s", MARKER)
    logging.getLogger("httpx").info("HTTP Request: malformed %s", MARKER)
    logging.getLogger("httpcore.http11").debug("weird %s event", MARKER)
    logging.getLogger("httpcore.proxy").debug("%s.started host=%r", MARKER, MARKER)

    _assert_clean(captured.records)
    httpcore_msgs = [r.getMessage() for r in captured.records if r.name != "httpx"]
    assert httpcore_msgs == ["httpcore event", "httpcore event"]
    httpx_msgs = {r.getMessage() for r in captured.records if r.name == "httpx"}
    assert len(httpx_msgs) == 1 and httpx_msgs != {""}


@pytest.mark.parametrize("name", EMITTERS)
def test_exception_and_stack_payloads_dropped(captured, name):
    install_log_filters()
    try:
        raise RuntimeError(MARKER)
    except RuntimeError:
        import sys

        exc_info = sys.exc_info()
    record = logging.getLogger(name).makeRecord(
        name, logging.DEBUG, __file__, 1, "connect_tcp.failed", (), exc_info
    )
    record.exc_text = f"Traceback {MARKER}"
    record.stack_info = f"stack {MARKER}"
    logging.getLogger(name).handle(record)

    (kept,) = captured.records
    assert kept.exc_info in (None, (None, None, None))
    assert kept.exc_text is None
    assert kept.stack_info is None
    _assert_clean(captured.records)


def test_install_is_idempotent_and_leaves_levels_and_handlers(captured):
    before = [(lg.level, list(lg.handlers)) for lg in map(logging.getLogger, EMITTERS)]
    install_log_filters()
    install_log_filters()
    after = [(lg.level, list(lg.handlers)) for lg in map(logging.getLogger, EMITTERS)]
    assert after == before

    logging.getLogger("httpcore.connection").debug("connect_tcp.started host=%r", "h")
    assert [r.getMessage() for r in captured.records] == ["connect_tcp.started"]


class _GenericTransportFilter(logging.Filter):
    _w8_log_filter = True  # transport's generic marker; no equivalent protection

    def filter(self, record):
        return True


def test_generic_transport_marker_does_not_suppress_auth_filter(captured):
    other = _GenericTransportFilter()
    for name in EMITTERS:
        logging.getLogger(name).addFilter(other)
    install_log_filters()
    logging.getLogger("httpx").info('HTTP Request: GET http://h/p "HTTP/1.1 200 %s"', MARKER)
    logging.getLogger("httpcore.http11").debug("response.complete reason=%r", MARKER)
    _assert_clean(captured.records)


def test_already_safe_httpx_string_from_other_filter_stays_safe(captured):
    class Rewrite(logging.Filter):
        _w8_log_filter = True

        def filter(self, record):
            record.msg = "HTTP Request: GET http://127.0.0.1/p 200"
            record.args = ()
            return True

    logging.getLogger("httpx").addFilter(Rewrite())
    install_log_filters()
    logging.getLogger("httpx").info('HTTP Request: GET http://127.0.0.1/p "HTTP/1.1 200 %s"', MARKER)

    _assert_clean(captured.records)
    (r,) = captured.records
    assert "GET" in r.getMessage() and "200" in r.getMessage()


@pytest.mark.parametrize("name", EMITTERS)
def test_preformatted_message_cache_is_not_retained(captured, name):
    """An earlier filter may format the record, caching raw ``record.message``."""
    logger = logging.getLogger(name)
    if name == "httpx":
        record = logger.makeRecord(
            name, logging.INFO, __file__, 1,
            'HTTP Request: %s %s "%s %d %s"',
            ("GET", "http://127.0.0.1:1/p", "HTTP/1.1", 200, MARKER), None,
        )
    else:
        record = logger.makeRecord(
            name, logging.DEBUG, __file__, 1,
            "receive_response_headers.complete return_value=%r", (MARKER,), None,
        )

    class Preformat(logging.Filter):
        def filter(self, rec):
            logging.Formatter().format(rec)  # caches rec.message
            assert MARKER in rec.message  # raw cache really present before auth
            return True

    logger.addFilter(Preformat())
    install_log_filters()
    logger.handle(record)

    (kept,) = captured.records
    (snapshot,) = captured.snapshots
    assert MARKER not in repr(snapshot)  # as retained at emit time
    assert MARKER not in repr(vars(kept))
    assert MARKER not in kept.getMessage()
    assert MARKER not in logging.Formatter().format(kept)

# Injectable Callback Servers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the OAuth callback receiver an injectable dependency behind a `CallbackServerProtocol`, keeping `LocalCallbackServer` as the default and folding manual entry into the protocol.

**Architecture:** A `CallbackServerProtocol` (`port`/`redirect_uri`/`obtain_callback`) with two built-ins (`LocalCallbackServer`, `ManualCallbackServer`). Flows resolve a zero-arg factory via a shared `resolve_callback_factory` helper (per-call override → construction default → `redirect_mode` builtin) and drive it through `server.redirect_uri` + `server.obtain_callback(url)`. A callback error taxonomy (`CallbackError` base) replaces bare `KeyError`s.

**Tech Stack:** Python 3.11+, `typing.Protocol` (runtime-checkable), stdlib `http.server`/`webbrowser`, pytest + pytest-mock, hatch.

**Spec:** `docs/superpowers/specs/2026-06-11-injectable-callback-servers-design.md`

**Conventions:**
- Run a single test: `hatch run test:test <path>::<test> -v`
- Run a file: `hatch run test:test <path>`
- Full suite: `hatch run test:test`
- Lint: `hatch run ruff:check src tests`
- Branch: `feature/injectable-callback-servers` (already created off `develop`).

---

### Task 1: Callback error taxonomy

**Files:**
- Modify: `src/mountainash_auth_client/errors.py`
- Test: `tests/connections/test_callback_errors.py`

- [ ] **Step 1: Write the failing test**

Create `tests/connections/test_callback_errors.py`:

```python
"""Tests for the OAuth callback error taxonomy."""
from __future__ import annotations

from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    CallbackError,
    CallbackTimeoutError,
    MalformedCallbackError,
)


def test_denied_is_callback_error_and_carries_fields():
    e = AuthorizationDeniedError(error="access_denied", description="user declined")
    assert isinstance(e, CallbackError)
    assert e.error == "access_denied"
    assert e.description == "user declined"
    assert "access_denied" in str(e)
    assert "user declined" in str(e)


def test_denied_without_description():
    e = AuthorizationDeniedError(error="access_denied")
    assert e.description == ""
    assert "access_denied" in str(e)


def test_malformed_is_callback_error():
    assert isinstance(MalformedCallbackError("missing code"), CallbackError)


def test_timeout_is_callback_error_and_builtin_timeout():
    e = CallbackTimeoutError("no callback in time")
    assert isinstance(e, CallbackError)
    assert isinstance(e, TimeoutError)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `hatch run test:test tests/connections/test_callback_errors.py -v`
Expected: FAIL — `ImportError: cannot import name 'CallbackError'`.

- [ ] **Step 3: Add the exceptions**

Append to `src/mountainash_auth_client/errors.py`:

```python


class CallbackError(Exception):
    """Base for failures while obtaining or validating an OAuth callback."""


class AuthorizationDeniedError(CallbackError):
    """The provider returned an OAuth2 ``error`` instead of an authorization code."""

    def __init__(self, *, error: str, description: str = "") -> None:
        self.error = error
        self.description = description
        message = f"Authorization denied: {error}"
        if description:
            message += f" — {description}"
        super().__init__(message)


class MalformedCallbackError(CallbackError):
    """Callback passed CSRF/state validation but is missing a required parameter."""


class CallbackTimeoutError(CallbackError, TimeoutError):
    """No OAuth callback was received before the deadline.

    Subclasses the builtin ``TimeoutError`` so existing ``except TimeoutError``
    handlers keep working while callers can also catch ``CallbackError``.
    """
```

- [ ] **Step 4: Run test to verify it passes**

Run: `hatch run test:test tests/connections/test_callback_errors.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/errors.py tests/connections/test_callback_errors.py
git commit -m "feat: add OAuth callback error taxonomy"
```

---

### Task 2: CallbackServerProtocol

**Files:**
- Create: `src/mountainash_auth_client/connections/protocols/__init__.py`
- Create: `src/mountainash_auth_client/connections/protocols/prtcl_callback.py`
- Test: `tests/connections/test_callback_protocol.py`

- [ ] **Step 1: Write the failing test**

Create `tests/connections/test_callback_protocol.py`:

```python
"""Tests for CallbackServerProtocol conformance."""
from __future__ import annotations

from mountainash_auth_client.connections.protocols import CallbackServerProtocol


class _Conforming:
    @property
    def port(self) -> int | None:
        return 1234

    @property
    def redirect_uri(self) -> str:
        return "http://localhost:1234/callback"

    def obtain_callback(self, authorize_url: str) -> dict[str, str]:
        return {"code": "abc"}


class _Incomplete:
    @property
    def redirect_uri(self) -> str:
        return "x"


def test_conforming_instance_passes_isinstance():
    assert isinstance(_Conforming(), CallbackServerProtocol)


def test_incomplete_instance_fails_isinstance():
    assert not isinstance(_Incomplete(), CallbackServerProtocol)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `hatch run test:test tests/connections/test_callback_protocol.py -v`
Expected: FAIL — `ModuleNotFoundError: ...connections.protocols`.

- [ ] **Step 3: Create the protocol module**

Create `src/mountainash_auth_client/connections/protocols/prtcl_callback.py`:

```python
"""Protocol for OAuth callback collectors."""
from __future__ import annotations

import typing as t


@t.runtime_checkable
class CallbackServerProtocol(t.Protocol):
    """Interface for OAuth callback collectors.

    An implementation knows the redirect URI to advertise in the authorize
    request, and how to present that request to the user and return the raw
    callback query parameters.
    """

    @property
    def port(self) -> int | None:
        """Bound TCP port, or None when there is no port (manual/remote)."""
        ...

    @property
    def redirect_uri(self) -> str:
        """Redirect URI to embed in the authorization request."""
        ...

    def obtain_callback(self, authorize_url: str) -> dict[str, str]:
        """Present ``authorize_url`` to the user, then block until the OAuth
        callback parameters are available and return them as a flat, raw
        ``{key: value}`` dict. Must release any acquired resources before
        returning OR raising. Validation is the flow's responsibility."""
        ...


CallbackServerFactory = t.Callable[[], CallbackServerProtocol]
```

- [ ] **Step 4: Create the package init**

Create `src/mountainash_auth_client/connections/protocols/__init__.py`:

```python
"""Connection protocols."""
from __future__ import annotations

from .prtcl_callback import CallbackServerFactory, CallbackServerProtocol

__all__ = ["CallbackServerFactory", "CallbackServerProtocol"]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `hatch run test:test tests/connections/test_callback_protocol.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit**

```bash
git add src/mountainash_auth_client/connections/protocols/ tests/connections/test_callback_protocol.py
git commit -m "feat: add CallbackServerProtocol + factory type alias"
```

---

### Task 3: LocalCallbackServer.obtain_callback

**Files:**
- Modify: `src/mountainash_auth_client/connections/server/callback.py`
- Test: `tests/connections/test_callback_servers.py`

- [ ] **Step 1: Write the failing test**

Create `tests/connections/test_callback_servers.py`:

```python
"""Tests for the built-in callback servers."""
from __future__ import annotations

import pytest

import mountainash_auth_client.connections.server.callback as cb
from mountainash_auth_client.connections.protocols import CallbackServerProtocol
from mountainash_auth_client.connections.server.callback import LocalCallbackServer
from mountainash_auth_client.errors import CallbackTimeoutError


def test_local_conforms_to_protocol():
    s = LocalCallbackServer(port=0)
    try:
        assert isinstance(s, CallbackServerProtocol)
        assert isinstance(s.port, int)
        assert s.redirect_uri == f"http://localhost:{s.port}/callback"
    finally:
        s._server.server_close()


def test_obtain_callback_opens_browser_and_returns_params(monkeypatch):
    s = LocalCallbackServer(port=0)
    opened = {}
    monkeypatch.setattr(cb.webbrowser, "open", lambda url: opened.setdefault("url", url) or True)
    monkeypatch.setattr(s, "wait_for_callback", lambda: {"code": "abc", "state": "xyz"})
    result = s.obtain_callback("https://auth/authorize?x=1")
    assert opened["url"] == "https://auth/authorize?x=1"
    assert result == {"code": "abc", "state": "xyz"}


def test_obtain_callback_prints_url_when_no_browser(monkeypatch, capsys):
    s = LocalCallbackServer(port=0)
    monkeypatch.setattr(cb.webbrowser, "open", lambda url: False)
    monkeypatch.setattr(s, "wait_for_callback", lambda: {"code": "abc"})
    s.obtain_callback("https://auth/SHOWME")
    assert "https://auth/SHOWME" in capsys.readouterr().out


def test_obtain_callback_closes_socket_on_failure(monkeypatch):
    s = LocalCallbackServer(port=0)
    monkeypatch.setattr(cb.webbrowser, "open", lambda url: True)

    def boom():
        raise CallbackTimeoutError("nope")

    monkeypatch.setattr(s, "wait_for_callback", boom)
    calls = {"n": 0}
    real_close = s._server.server_close

    def counting_close():
        calls["n"] += 1
        real_close()

    monkeypatch.setattr(s._server, "server_close", counting_close)
    with pytest.raises(CallbackTimeoutError):
        s.obtain_callback("https://auth/x")
    assert calls["n"] >= 1


def test_wait_for_callback_times_out_with_callback_timeout_error():
    s = LocalCallbackServer(port=0, timeout=1)
    try:
        with pytest.raises(CallbackTimeoutError):
            s.wait_for_callback()
    finally:
        s._server.server_close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `hatch run test:test tests/connections/test_callback_servers.py -v`
Expected: FAIL — `AttributeError: 'LocalCallbackServer' object has no attribute 'obtain_callback'` (and `cb.webbrowser` missing).

- [ ] **Step 3: Update `callback.py`**

Replace the full contents of `src/mountainash_auth_client/connections/server/callback.py` with:

```python
from __future__ import annotations

import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from mountainash_auth_client.errors import CallbackTimeoutError


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        self.server._callback_params = {k: v[0] for k, v in params.items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Authorization complete.</h1>"
                         b"<p>You can close this window.</p></body></html>")

    def log_message(self, format, *args) -> None:
        pass


class LocalCallbackServer:
    """Ephemeral HTTP server that captures a single OAuth callback."""

    def __init__(self, port: int = 0, timeout: int = 120) -> None:
        self._server = HTTPServer(("localhost", port), _CallbackHandler)
        self._server._callback_params = None
        self._timeout = timeout

    @property
    def port(self) -> int | None:
        return self._server.server_address[1]

    @property
    def redirect_uri(self) -> str:
        return f"http://localhost:{self.port}/callback"

    def wait_for_callback(self) -> dict[str, str]:
        """Block until a callback arrives or the timeout expires.

        Pure blocking wait — resource cleanup is the caller's responsibility
        (see :meth:`obtain_callback`).
        """
        self._server.timeout = self._timeout
        self._server.handle_request()
        if self._server._callback_params is None:
            raise CallbackTimeoutError("No callback received within timeout")
        return self._server._callback_params

    def obtain_callback(self, authorize_url: str) -> dict[str, str]:
        """Open the URL in a browser (or print it if none is available), then
        wait for the callback. Always releases the socket — on success or
        failure.
        """
        if not webbrowser.open(authorize_url):
            print(f"Open this URL to authorize:\n\n  {authorize_url}\n")
        try:
            return self.wait_for_callback()
        finally:
            self._server.server_close()
```

Note: `webbrowser` is imported at module top (not inside the method) so tests can monkeypatch `cb.webbrowser.open`. `wait_for_callback` no longer closes the socket (the close moved into `obtain_callback`'s `finally`).

- [ ] **Step 4: Run test to verify it passes**

Run: `hatch run test:test tests/connections/test_callback_servers.py -v`
Expected: PASS (5 passed). The timeout test takes ~1s.

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/server/callback.py tests/connections/test_callback_servers.py
git commit -m "feat: LocalCallbackServer.obtain_callback with cleanup + browser fallback"
```

---

### Task 4: ManualCallbackServer

**Files:**
- Modify: `src/mountainash_auth_client/connections/server/manual.py`
- Modify: `src/mountainash_auth_client/connections/server/__init__.py`
- Test: `tests/connections/test_callback_servers.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/connections/test_callback_servers.py`:

```python
import mountainash_auth_client.connections.server.manual as man
from mountainash_auth_client.connections.server.manual import ManualCallbackServer


def test_manual_conforms_and_defaults_to_oauth2_oob():
    s = ManualCallbackServer()
    assert isinstance(s, CallbackServerProtocol)
    assert s.port is None
    assert s.redirect_uri == "urn:ietf:wg:oauth:2.0:oob"


def test_manual_accepts_custom_redirect_uri():
    assert ManualCallbackServer(redirect_uri="oob").redirect_uri == "oob"


def test_manual_obtain_callback_delegates_to_prompt(monkeypatch):
    monkeypatch.setattr(man, "prompt_for_code", lambda url: {"code": "PASTED", "seen": url})
    out = ManualCallbackServer().obtain_callback("https://auth/q")
    assert out == {"code": "PASTED", "seen": "https://auth/q"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `hatch run test:test tests/connections/test_callback_servers.py -k manual -v`
Expected: FAIL — `ImportError: cannot import name 'ManualCallbackServer'`.

- [ ] **Step 3: Add `ManualCallbackServer`**

Append to `src/mountainash_auth_client/connections/server/manual.py`:

```python


class ManualCallbackServer:
    """Out-of-band manual callback: prints the URL and reads the redirect/code.

    ``redirect_uri`` is parameterized because the OOB token differs by protocol:
    OAuth2 uses ``urn:ietf:wg:oauth:2.0:oob`` (the default); OAuth1 uses ``oob``.
    """

    DEFAULT_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"

    def __init__(self, redirect_uri: str | None = None) -> None:
        self._redirect_uri = redirect_uri or self.DEFAULT_REDIRECT_URI

    @property
    def port(self) -> int | None:
        return None

    @property
    def redirect_uri(self) -> str:
        return self._redirect_uri

    def obtain_callback(self, authorize_url: str) -> dict[str, str]:
        return prompt_for_code(authorize_url)
```

- [ ] **Step 4: Export it**

Replace `src/mountainash_auth_client/connections/server/__init__.py` with:

```python
"""OAuth callback server and manual auth utilities."""
from .callback import LocalCallbackServer
from .manual import ManualCallbackServer, prompt_for_code

__all__ = ["LocalCallbackServer", "ManualCallbackServer", "prompt_for_code"]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `hatch run test:test tests/connections/test_callback_servers.py -v`
Expected: PASS (8 passed).

- [ ] **Step 6: Commit**

```bash
git add src/mountainash_auth_client/connections/server/manual.py src/mountainash_auth_client/connections/server/__init__.py tests/connections/test_callback_servers.py
git commit -m "feat: add ManualCallbackServer (parameterized redirect_uri)"
```

---

### Task 5: resolve_callback_factory helper

**Files:**
- Create: `src/mountainash_auth_client/connections/server/factory.py`
- Test: `tests/connections/test_callback_factory.py`

- [ ] **Step 1: Write the failing test**

Create `tests/connections/test_callback_factory.py`:

```python
"""Tests for resolve_callback_factory precedence."""
from __future__ import annotations

from mountainash_auth_client.connections.server.callback import LocalCallbackServer
from mountainash_auth_client.connections.server.factory import resolve_callback_factory
from mountainash_auth_client.connections.server.manual import ManualCallbackServer


def _explicit():
    return ManualCallbackServer(redirect_uri="EXPLICIT")


def _default():
    return ManualCallbackServer(redirect_uri="DEFAULT")


def test_per_call_callback_server_wins():
    f = resolve_callback_factory(
        redirect_mode="local_server", callback_server=_explicit,
        instance_default=_default, metadata={},
    )
    assert f().redirect_uri == "EXPLICIT"


def test_construction_default_beats_redirect_mode():
    f = resolve_callback_factory(
        redirect_mode="manual", callback_server=None,
        instance_default=_default, metadata={},
    )
    assert f().redirect_uri == "DEFAULT"


def test_manual_builtin_oauth2_default_urn():
    f = resolve_callback_factory(
        redirect_mode="manual", callback_server=None,
        instance_default=None, metadata={},
    )
    assert f().redirect_uri == "urn:ietf:wg:oauth:2.0:oob"


def test_manual_builtin_with_custom_oob():
    f = resolve_callback_factory(
        redirect_mode="manual", callback_server=None,
        instance_default=None, metadata={}, manual_redirect_uri="oob",
    )
    assert f().redirect_uri == "oob"


def test_local_builtin_reads_metadata_port():
    f = resolve_callback_factory(
        redirect_mode="local_server", callback_server=None,
        instance_default=None, metadata={"callback_port": 0},
    )
    server = f()
    try:
        assert isinstance(server, LocalCallbackServer)
    finally:
        server._server.server_close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `hatch run test:test tests/connections/test_callback_factory.py -v`
Expected: FAIL — `ModuleNotFoundError: ...server.factory`.

- [ ] **Step 3: Create `factory.py`**

Create `src/mountainash_auth_client/connections/server/factory.py`:

```python
"""Shared precedence logic for resolving a callback-server factory."""
from __future__ import annotations

import typing as t

from .callback import LocalCallbackServer
from .manual import ManualCallbackServer

if t.TYPE_CHECKING:
    from ..protocols import CallbackServerFactory


def resolve_callback_factory(
    *,
    redirect_mode: str,
    callback_server: CallbackServerFactory | None,
    instance_default: CallbackServerFactory | None,
    metadata: dict,
    manual_redirect_uri: str | None = None,
) -> CallbackServerFactory:
    """Resolve the callback-server factory to use for one authorize() call.

    Precedence: explicit per-call ``callback_server`` → flow ``instance_default``
    → built-in selected by ``redirect_mode``. A ``callback_server`` (per-call or
    construction default) shadows ``redirect_mode`` entirely.
    """
    if callback_server is not None:
        return callback_server
    if instance_default is not None:
        return instance_default
    if redirect_mode == "manual":
        if manual_redirect_uri is not None:
            return lambda: ManualCallbackServer(redirect_uri=manual_redirect_uri)
        return ManualCallbackServer
    port = metadata.get("callback_port", 0)
    return lambda: LocalCallbackServer(port=port)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `hatch run test:test tests/connections/test_callback_factory.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/server/factory.py tests/connections/test_callback_factory.py
git commit -m "feat: add resolve_callback_factory precedence helper"
```

---

### Task 6: OAuth2 flow injection

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth2/flow.py`
- Test: `tests/connections/test_oauth2_flow.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/connections/test_oauth2_flow.py`:

```python
from urllib.parse import parse_qs, urlparse

from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    MalformedCallbackError,
)


class _EchoServer:
    """Test double: echoes the state from the authorize URL back as a callback."""

    port = None

    def __init__(self, redirect_uri="https://fake/cb", extra=None):
        self.redirect_uri = redirect_uri
        self._extra = extra or {}

    def obtain_callback(self, authorize_url):
        state = parse_qs(urlparse(authorize_url).query)["state"][0]
        return {"code": "CODE", "state": state, **self._extra}


def _no_http(flow, monkeypatch, sink):
    monkeypatch.setattr(flow, "exchange_code",
                        lambda **kw: sink.update(kw) or {"access_token": "tok"})


class TestAuthorizeInjection:
    def test_uses_injected_server_redirect_uri_and_params(self, monkeypatch):
        flow = OAuthFlow(FakeSpec())
        sink = {}
        _no_http(flow, monkeypatch, sink)
        result = flow.authorize("cid", "csec",
                                callback_server=lambda: _EchoServer("https://INJECT/cb"))
        assert sink["redirect_uri"] == "https://INJECT/cb"
        assert sink["code"] == "CODE"
        assert result["access_token"] == "tok"

    def test_per_call_beats_construction_default(self, monkeypatch):
        flow = OAuthFlow(FakeSpec(),
                         callback_server=lambda: _EchoServer("https://CONSTRUCT/cb"))
        sink = {}
        _no_http(flow, monkeypatch, sink)
        flow.authorize("cid", "csec",
                       callback_server=lambda: _EchoServer("https://PERCALL/cb"))
        assert sink["redirect_uri"] == "https://PERCALL/cb"

    def test_construction_default_shadows_redirect_mode(self, monkeypatch):
        flow = OAuthFlow(FakeSpec(),
                         callback_server=lambda: _EchoServer("https://CONSTRUCT/cb"))
        sink = {}
        _no_http(flow, monkeypatch, sink)
        flow.authorize("cid", "csec", redirect_mode="manual")
        assert sink["redirect_uri"] == "https://CONSTRUCT/cb"

    def test_default_uses_local_callback_server(self, monkeypatch):
        import mountainash_auth_client.connections.server.factory as factory
        monkeypatch.setattr(
            factory, "LocalCallbackServer",
            lambda port=0: _EchoServer(f"http://localhost/{port}/callback"))
        flow = OAuthFlow(FakeSpec())
        sink = {}
        _no_http(flow, monkeypatch, sink)
        flow.authorize("cid", "csec")
        assert sink["redirect_uri"].startswith("http://localhost/")


class TestAuthorizeCallbackValidation:
    def test_denied_raises(self, monkeypatch):
        flow = OAuthFlow(FakeSpec())
        with pytest.raises(AuthorizationDeniedError) as ei:
            flow.authorize("cid", "csec",
                           callback_server=lambda: _EchoServer(extra={"error": "access_denied", "code": None}))
        assert ei.value.error == "access_denied"

    def test_missing_code_raises_malformed(self, monkeypatch):
        class _NoCode(_EchoServer):
            def obtain_callback(self, authorize_url):
                state = parse_qs(urlparse(authorize_url).query)["state"][0]
                return {"state": state}

        flow = OAuthFlow(FakeSpec())
        with pytest.raises(MalformedCallbackError):
            flow.authorize("cid", "csec", callback_server=lambda: _NoCode())
```

Note: `_EchoServer` returns `code` by default; the denial test overrides it with `code: None` plus `error`, and the params include the matching `state` so CSRF passes and the `error` branch is reached. `FakeSpec` and `OAuthFlow`/`pytest` are already imported at the top of this test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `hatch run test:test tests/connections/test_oauth2_flow.py -k "Injection or CallbackValidation" -v`
Expected: FAIL — `TypeError: authorize() got an unexpected keyword argument 'callback_server'`.

- [ ] **Step 3: Rewrite `oauth2/flow.py` imports, `__init__`, and `authorize`**

In `src/mountainash_auth_client/connections/oauth2/flow.py`:

(a) Replace the import block (top of file, lines under `from __future__ import annotations`) with:

```python
from __future__ import annotations

import hashlib
import base64
import json
import secrets
import time
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlencode

import httpx

from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    MalformedCallbackError,
    TokenExchangeError,
    TokenRefreshError,
)
from mountainash_auth_client.connections.server.factory import resolve_callback_factory

if TYPE_CHECKING:
    from mountainash_settings import ProfileSpec
    from mountainash_auth_client.connections.protocols import CallbackServerFactory
```

(This removes the now-unused `import webbrowser`, `LocalCallbackServer`, and `prompt_for_code` imports.)

(b) Replace `__init__`:

```python
    def __init__(
        self,
        spec: ProfileSpec,
        *,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._spec = spec
        self._metadata = spec.metadata
        self._pending_verifiers: dict[str, str] = {}
        self._last_state: str | None = None
        self._callback_server = callback_server
```

(c) Replace the entire `authorize` method with:

```python
    def authorize(
        self,
        client_id: str,
        client_secret: str,
        redirect_mode: Literal["local_server", "manual"] = "local_server",
        scope: str | None = None,
        callback_server: CallbackServerFactory | None = None,
    ) -> dict[str, str | int | None]:
        """Run the full authorization code flow end-to-end. Returns flat token dict."""
        factory = resolve_callback_factory(
            redirect_mode=redirect_mode,
            callback_server=callback_server,
            instance_default=self._callback_server,
            metadata=self._metadata,
        )
        server = factory()
        url, state = self.build_authorize_url(
            client_id=client_id,
            redirect_uri=server.redirect_uri,
            scope=scope,
        )
        params = server.obtain_callback(url)
        self._validate_callback_state(params, state)
        if "error" in params:
            raise AuthorizationDeniedError(
                error=params["error"],
                description=params.get("error_description", ""),
            )
        if "code" not in params:
            raise MalformedCallbackError("OAuth2 callback missing 'code'")
        return self.exchange_code(
            code=params["code"],
            redirect_uri=server.redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            state=state,
        )
```

- [ ] **Step 4: Run the new tests + the existing flow tests**

Run: `hatch run test:test tests/connections/test_oauth2_flow.py -v`
Expected: PASS (all existing + new tests).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth2/flow.py tests/connections/test_oauth2_flow.py
git commit -m "feat: injectable callback server in OAuth2 flow"
```

---

### Task 7: OAuth1 flow injection + callback validation

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth1/flow.py`
- Test: `tests/connections/test_oauth1_flow.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/connections/test_oauth1_flow.py`:

```python
from mountainash_auth_client.errors import MalformedCallbackError


class _OAuth1Echo:
    """Test double whose obtain_callback returns a verifier (+ matching token)."""

    port = None

    def __init__(self, redirect_uri="http://localhost/cb", params=None):
        self.redirect_uri = redirect_uri
        self._params = params

    def obtain_callback(self, authorize_url):
        if self._params is not None:
            return self._params
        return {"oauth_verifier": "VERIF", "oauth_token": "REQTOKEN"}


def _stub_oauth1(flow, monkeypatch, sink):
    monkeypatch.setattr(
        flow, "request_token",
        lambda consumer_key, consumer_secret, callback_url:
            sink.update(callback_url=callback_url)
            or {"oauth_token": "REQTOKEN", "oauth_token_secret": "REQSECRET"})
    monkeypatch.setattr(
        flow, "exchange_verifier",
        lambda **kw: sink.update(kw) or {"oauth_token": "ACCESS", "oauth_token_secret": "ASEC"})


class TestOAuth1Authorize:
    def test_injected_server_drives_callback_url_and_verifier(self, monkeypatch):
        flow = OAuth1Flow(FakeSpec())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        flow.authorize("ckey", "csec",
                       callback_server=lambda: _OAuth1Echo("https://INJECT/cb"))
        assert sink["callback_url"] == "https://INJECT/cb"
        assert sink["verifier"] == "VERIF"

    def test_manual_builtin_uses_literal_oob(self, monkeypatch):
        flow = OAuth1Flow(FakeSpec())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        # Manual server returns a bare verifier via "code" fallback.
        monkeypatch.setattr(
            "mountainash_auth_client.connections.server.manual.prompt_for_code",
            lambda url: {"code": "BAREVERIF"})
        flow.authorize("ckey", "csec", redirect_mode="manual")
        assert sink["callback_url"] == "oob"
        assert sink["verifier"] == "BAREVERIF"

    def test_missing_verifier_raises_malformed(self, monkeypatch):
        flow = OAuth1Flow(FakeSpec())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        with pytest.raises(MalformedCallbackError):
            flow.authorize("ckey", "csec",
                           callback_server=lambda: _OAuth1Echo(params={"oauth_token": "REQTOKEN"}))

    def test_token_mismatch_raises_value_error(self, monkeypatch):
        flow = OAuth1Flow(FakeSpec())
        sink = {}
        _stub_oauth1(flow, monkeypatch, sink)
        with pytest.raises(ValueError, match="mismatch"):
            flow.authorize("ckey", "csec",
                           callback_server=lambda: _OAuth1Echo(
                               params={"oauth_verifier": "V", "oauth_token": "WRONG"}))
```

Note: `FakeSpec`, `OAuth1Flow`, and `pytest` are already imported at the top of this test file. `FakeSpec.metadata` must include `request_token_url`/`authorize_url`/`access_token_url` (it already does for the existing tests).

- [ ] **Step 2: Run test to verify it fails**

Run: `hatch run test:test tests/connections/test_oauth1_flow.py -k OAuth1Authorize -v`
Expected: FAIL — `TypeError: authorize() got an unexpected keyword argument 'callback_server'`.

- [ ] **Step 3: Rewrite `oauth1/flow.py` imports, `__init__`, and `authorize`**

In `src/mountainash_auth_client/connections/oauth1/flow.py`:

(a) Replace the import block with:

```python
"""OAuth1 3-legged flow for providers like Garmin Health API."""
from __future__ import annotations

from typing import TYPE_CHECKING, Literal
from urllib.parse import urlencode

import httpx

from mountainash_auth_client.errors import MalformedCallbackError, TokenExchangeError
from mountainash_auth_client.connections._optional import require_authlib
from mountainash_auth_client.connections.server.factory import resolve_callback_factory

if TYPE_CHECKING:
    from mountainash_settings import ProfileSpec
    from mountainash_auth_client.connections.protocols import CallbackServerFactory
```

(This removes the now-unused `import webbrowser`, `LocalCallbackServer`, and `prompt_for_code` imports.)

(b) Replace `__init__`:

```python
    def __init__(
        self,
        spec: ProfileSpec,
        *,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._metadata = spec.metadata
        self._callback_server = callback_server
```

(c) Replace the entire `authorize` method with:

```python
    def authorize(
        self,
        consumer_key: str,
        consumer_secret: str,
        redirect_mode: Literal["local_server", "manual"] = "local_server",
        callback_server: CallbackServerFactory | None = None,
    ) -> dict[str, str]:
        factory = resolve_callback_factory(
            redirect_mode=redirect_mode,
            callback_server=callback_server,
            instance_default=self._callback_server,
            metadata=self._metadata,
            manual_redirect_uri="oob",
        )
        server = factory()

        request_token = self.request_token(consumer_key, consumer_secret, server.redirect_uri)
        url = self.build_authorize_url(request_token["oauth_token"])
        params = server.obtain_callback(url)

        returned_token = params.get("oauth_token")
        if returned_token is not None and returned_token != request_token["oauth_token"]:
            raise ValueError("OAuth1 token mismatch — possible CSRF")

        # Bare manual paste lands the verifier in "code"; accept it as a fallback.
        verifier = params.get("oauth_verifier") or params.get("code")
        if not verifier:
            raise MalformedCallbackError("OAuth1 callback missing 'oauth_verifier'")

        return self.exchange_verifier(
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
            oauth_token=request_token["oauth_token"],
            oauth_token_secret=request_token["oauth_token_secret"],
            verifier=verifier,
        )
```

- [ ] **Step 4: Run the new tests + the existing OAuth1 tests**

Run: `hatch run test:test tests/connections/test_oauth1_flow.py -v`
Expected: PASS (existing + new).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth1/flow.py tests/connections/test_oauth1_flow.py
git commit -m "feat: injectable callback server + callback validation in OAuth1 flow"
```

---

### Task 8: Connection passthrough

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth2/connection.py`
- Modify: `src/mountainash_auth_client/connections/oauth1/connection.py`
- Test: `tests/connections/test_oauth2_connection.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/connections/test_oauth2_connection.py`:

```python
class TestCallbackServerPassthrough:
    def test_connect_forwards_callback_server_to_authorize(self, monkeypatch, backend):
        sentinel = object()
        captured = {}

        class FakeFlow:
            def __init__(self, spec):
                pass

            def is_expired(self, value):
                return False

            def authorize(self, **kwargs):
                captured.update(kwargs)
                return {"access_token": "tok", "refresh_token": "", "token_expires_at": None}

        monkeypatch.setattr(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow", FakeFlow)
        provider = FakeProvider()
        provider.connect(FakeAuth(), auto_authorize=True, callback_server=sentinel)
        assert captured["callback_server"] is sentinel
```

Note: `FakeProvider`, `FakeAuth`, and the `backend` fixture are already defined in this test file (no stored token, so `connect` takes the `authorize` path).

- [ ] **Step 2: Run test to verify it fails**

Run: `hatch run test:test tests/connections/test_oauth2_connection.py -k Passthrough -v`
Expected: FAIL — `TypeError: connect() got an unexpected keyword argument 'callback_server'`.

- [ ] **Step 3: Add the passthrough to `oauth2/connection.py`**

In `src/mountainash_auth_client/connections/oauth2/connection.py`:

(a) Add `CallbackServerFactory` to the `TYPE_CHECKING` block:

```python
if TYPE_CHECKING:
    from mountainash_settings import ProfileSpec
    from mountainash_auth_client.connections.protocols import CallbackServerFactory
```

(If the file has no `TYPE_CHECKING` import yet, add `from typing import TYPE_CHECKING` and `from __future__ import annotations` is already present.)

(b) Change the `connect` signature to accept the parameter:

```python
    def connect(
        self,
        auth_profile: OAuth2AuthProfile | OAuth2AuthCodeAuthProfile,
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> Self:
```

(c) In the `auto_authorize` branch, pass it through. Change:

```python
                new_tokens = flow.authorize(
                    client_id=auth_profile.CLIENT_ID,
                    client_secret=auth_profile.CLIENT_SECRET.get_secret_value(),
                    scope=auth_profile.SCOPE,
                )
```

to:

```python
                new_tokens = flow.authorize(
                    client_id=auth_profile.CLIENT_ID,
                    client_secret=auth_profile.CLIENT_SECRET.get_secret_value(),
                    scope=auth_profile.SCOPE,
                    callback_server=callback_server,
                )
```

- [ ] **Step 4: Mirror it in `oauth1/connection.py`**

In `src/mountainash_auth_client/connections/oauth1/connection.py`:

(a) Add `CallbackServerFactory` to the `TYPE_CHECKING` block (alongside `OAuth1AuthProfile`).

(b) Change `connect`'s signature to add `callback_server: CallbackServerFactory | None = None` (keyword-only, after `auto_authorize`).

(c) In the `auto_authorize` branch, change:

```python
            new_tokens = flow.authorize(
                consumer_key=auth_profile.CONSUMER_KEY,
                consumer_secret=auth_profile.CONSUMER_SECRET.get_secret_value(),
            )
```

to:

```python
            new_tokens = flow.authorize(
                consumer_key=auth_profile.CONSUMER_KEY,
                consumer_secret=auth_profile.CONSUMER_SECRET.get_secret_value(),
                callback_server=callback_server,
            )
```

- [ ] **Step 5: Run tests**

Run: `hatch run test:test tests/connections/test_oauth2_connection.py -v`
Expected: PASS (existing + new).

- [ ] **Step 6: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth2/connection.py src/mountainash_auth_client/connections/oauth1/connection.py tests/connections/test_oauth2_connection.py
git commit -m "feat: forward callback_server through OAuth connections"
```

---

### Task 9: Public exports

**Files:**
- Modify: `src/mountainash_auth_client/connections/__init__.py`
- Modify: `src/mountainash_auth_client/__init__.py`
- Test: `tests/connections/test_exports.py`

- [ ] **Step 1: Write the failing test**

Create `tests/connections/test_exports.py`:

```python
"""Public surface for the callback-server feature."""
from __future__ import annotations

import mountainash_auth_client as pkg
from mountainash_auth_client.connections import (
    CallbackServerProtocol,
    ManualCallbackServer,
)


def test_package_root_exports():
    for name in (
        "CallbackServerProtocol",
        "ManualCallbackServer",
        "CallbackError",
        "AuthorizationDeniedError",
        "MalformedCallbackError",
        "CallbackTimeoutError",
    ):
        assert name in pkg.__all__, name
        assert hasattr(pkg, name), name


def test_connections_exports():
    assert CallbackServerProtocol is not None
    assert ManualCallbackServer is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `hatch run test:test tests/connections/test_exports.py -v`
Expected: FAIL — `ImportError: cannot import name 'CallbackServerProtocol' from ...connections`.

- [ ] **Step 3: Extend `connections/__init__.py`**

In `src/mountainash_auth_client/connections/__init__.py`, add these imports near the existing `from .server...` imports:

```python
from .protocols import CallbackServerFactory, CallbackServerProtocol
from .server.manual import ManualCallbackServer
```

and add `"CallbackServerProtocol"`, `"CallbackServerFactory"`, `"ManualCallbackServer"` to `__all__`.

- [ ] **Step 4: Extend the package `__init__.py`**

In `src/mountainash_auth_client/__init__.py`:

(a) Add to the `errors` import:

```python
from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    AuthorizationRequired,
    CallbackError,
    CallbackTimeoutError,
    MalformedCallbackError,
    TokenExchangeError,
    TokenRefreshError,
)
```

(b) Add new imports for the protocol and manual server:

```python
from mountainash_auth_client.connections.protocols import CallbackServerProtocol
from mountainash_auth_client.connections.server.manual import ManualCallbackServer
```

(c) Add these names to `__all__` (keep it alphabetically sorted):
`"AuthorizationDeniedError"`, `"CallbackError"`, `"CallbackServerProtocol"`, `"CallbackTimeoutError"`, `"ManualCallbackServer"`, `"MalformedCallbackError"`.

- [ ] **Step 5: Run test to verify it passes**

Run: `hatch run test:test tests/connections/test_exports.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit**

```bash
git add src/mountainash_auth_client/connections/__init__.py src/mountainash_auth_client/__init__.py tests/connections/test_exports.py
git commit -m "feat: export callback protocol, ManualCallbackServer, and callback errors"
```

---

### Task 10: Full-suite + lint gate

**Files:** none (verification only).

- [ ] **Step 1: Run the whole suite**

Run: `hatch run test:test`
Expected: PASS — all tests green (no regressions in existing flow/connection/server tests).

- [ ] **Step 2: Lint**

Run: `hatch run ruff:check src tests`
Expected: `All checks passed!` (no unused-import warnings from the removed `webbrowser`/`prompt_for_code`/`LocalCallbackServer` imports).

- [ ] **Step 3: Fix any failures**

If the suite or lint fails, fix the cause (commonly: a leftover unused import in a flow file, or an existing test that relied on `wait_for_callback` closing the socket). Re-run until green.

- [ ] **Step 4: Push and open PR**

```bash
git push -u origin feature/injectable-callback-servers
gh pr create --base develop \
  --title "feat: injectable OAuth callback servers (CallbackServerProtocol)" \
  --body "Implements docs/superpowers/specs/2026-06-11-injectable-callback-servers-design.md"
```

---

## Self-Review

**Spec coverage:**
- `CallbackServerProtocol` (`port: int|None`, `redirect_uri`, `obtain_callback`) → Task 2. ✓
- `CallbackServerFactory` alias → Task 2. ✓
- `LocalCallbackServer.obtain_callback` (browser + fallback print + guaranteed close) → Task 3. ✓
- `ManualCallbackServer` (parameterized redirect_uri) → Task 4. ✓
- `resolve_callback_factory` precedence (per-call → construction default → redirect_mode builtin; OAuth1 `oob` vs OAuth2 urn) → Task 5. ✓
- Flow injection points (`__init__` default + `authorize` per-call) → Tasks 6, 7. ✓
- Error taxonomy (`CallbackError`, `AuthorizationDeniedError`, `MalformedCallbackError`, `CallbackTimeoutError`) → Task 1, used in Tasks 3/6/7. ✓
- OAuth2 order (state → error → code) → Task 6. ✓
- OAuth1 parity (oauth_token match → ValueError; absent verifier → MalformedCallbackError; bare-paste fallback preserved) → Task 7. ✓
- Connection passthrough → Task 8. ✓
- Public exports → Task 9. ✓
- Back-compat (`redirect_mode` default, `except TimeoutError`) → covered by Task 6 default test, Task 3 timeout test, and the unchanged existing suite (Task 10). ✓
- Deferred items (duplicate-key rejection, redirectable print) → intentionally not implemented, per spec §7. ✓

**Type consistency:** `resolve_callback_factory` keyword args match between definition (Task 5) and both call sites (Tasks 6, 7). `callback_server` is a `CallbackServerFactory | None` everywhere. `obtain_callback(authorize_url)`, `redirect_uri`, `port` names are consistent across protocol, both servers, and the test doubles.

**Placeholder scan:** none — every step has concrete code/commands.

# Injectable Callback Servers — Design

**Date:** 2026-06-11
**Status:** Adversarial review complete (Codex, two rounds); pending user spec review
**Scope:** `mountainash-auth-client` only. Transport's duplicated copy will be
deleted in a follow-up (auth-client becomes the single source of truth for
connections/OAuth/callback).

## Motivation

Both OAuth flows hardwire `LocalCallbackServer` inside `authorize()` and branch
on a `redirect_mode: Literal["local_server", "manual"]` enum:

```python
if redirect_mode == "local_server":
    port = self._metadata.get("callback_port", 0)
    server = LocalCallbackServer(port=port)
    redirect_uri = server.redirect_uri
else:
    redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
...
if redirect_mode == "local_server":
    webbrowser.open(url)
    params = server.wait_for_callback()
else:
    params = prompt_for_code(url)
```

A consuming tool cannot supply its own way of receiving the OAuth callback —
e.g. a server bound to a fixed port matching a registered redirect URI, a
desktop deep-link handler, or a hosted/remote callback. The callback mechanism
should be an injectable dependency behind a published protocol, with
`LocalCallbackServer` remaining the default.

## Goals

- Define a `CallbackServerProtocol` so client tools can implement their own
  callback servers.
- Make the callback server injectable: a construction-time default,
  overridable per `authorize()` call.
- Keep `LocalCallbackServer` as the default; keep existing
  `redirect_mode="local_server"|"manual"` working unchanged (backward
  compatible).
- Fold the `"manual"` path into the same protocol (it becomes a first-class
  implementation, not a special branch).
- Allow specifying the local callback port.

## Non-Goals

- Async/await support (flows remain synchronous).
- Changing token exchange/refresh internals or the returned token dict shape.
  (OAuth2 CSRF state validation is unchanged; OAuth1 *gains* a request-token
  match check for parity — see §5.)
- Applying the change to transport (separate follow-up; transport's copy is to
  be removed).

## Design

### 1. Protocol

New `connections/protocols/prtcl_callback.py` (populates the currently-empty
`protocols/` package, mirroring transport's `prtcl_*.py` layout):

```python
from __future__ import annotations

import typing as t


@t.runtime_checkable
class CallbackServerProtocol(t.Protocol):
    """Interface for OAuth callback collectors.

    An implementation knows the redirect URI to advertise in the authorize
    request, and how to present that request to the user and return the
    callback query parameters.
    """

    @property
    def port(self) -> int | None:
        """Bound TCP port, or None when the implementation has no port
        (e.g. manual entry or a remote/hosted callback)."""
        ...

    @property
    def redirect_uri(self) -> str:
        """Redirect URI to embed in the authorization request."""
        ...

    def obtain_callback(self, authorize_url: str) -> dict[str, str]:
        """Present `authorize_url` to the user however is appropriate, then
        block until the OAuth callback parameters are available and return
        them as a flat ``{key: value}`` dict.

        Returns the *raw* callback query parameters — single-valued, first
        value winning for any repeated key. The implementation does NOT
        interpret them: validation (state/CSRF, ``error`` detection, presence
        of ``code``) is the flow's responsibility. The implementation MUST
        release any resources it acquired (sockets, listeners) before
        returning OR raising. Timeout/cancellation is implementation-defined."""
        ...
```

A type alias lives next to it:

```python
CallbackServerFactory = t.Callable[[], CallbackServerProtocol]
```

**Rationale for `obtain_callback(authorize_url)` (vs a parameterless
`wait_for_callback()`):** unifying the manual path requires the collection
step to receive the authorize URL, because manual entry must present that URL
to the user. Folding "present the URL + collect params" into one method lets
each implementation own the entire authorization-prompt UX (open a browser,
show a dialog, email a link, etc.) and removes all `redirect_mode` branching
from the flow. The consequence is that `webbrowser.open(url)` moves out of the
flow and into `LocalCallbackServer.obtain_callback`.

**Rationale for `port: int | None`:** the flow itself never reads `port`; it is
exposed for callers that want to inspect/log the bound port. Making it optional
lets manual and remote implementations conform honestly instead of inventing a
meaningless sentinel.

### 2. Built-in implementations (`connections/server/`)

**`LocalCallbackServer`** (existing, `callback.py`) — already exposes
`port`/`redirect_uri`. Add:

```python
def obtain_callback(self, authorize_url: str) -> dict[str, str]:
    import webbrowser
    if not webbrowser.open(authorize_url):
        # Headless/remote: no browser. Print the URL so the user can open it.
        print(f"Open this URL to authorize:\n\n  {authorize_url}\n")
    try:
        return self.wait_for_callback()
    finally:
        self._server.server_close()      # guaranteed close on success AND failure
```

`wait_for_callback()` is retained as the internal blocking socket-wait helper
(it performs `handle_request()` and returns params; the socket close moves up
into `obtain_callback`'s `finally`, so a `CallbackTimeoutError` or any other
failure still releases the port — important for fixed-port servers). `port`
returns the bound `int`. `wait_for_callback()` keeps honoring the constructor
`timeout`, raising `CallbackTimeoutError` (a `TimeoutError` subclass) when no
callback arrives.

**`ManualCallbackServer`** (new, in `manual.py` alongside `prompt_for_code`):

```python
class ManualCallbackServer:
    """Out-of-band manual callback: prints the URL and reads the redirect/code."""

    DEFAULT_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"   # OAuth2 OOB

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

The `redirect_uri` is parameterized because the OOB token differs by protocol:
OAuth2 uses `urn:ietf:wg:oauth:2.0:oob` (the default), OAuth1 uses the literal
`"oob"`. The per-flow manual builtin supplies the right one (see §4).

### 3. Injection points (per-call override layered on a construction default)

- `OAuthFlow.__init__(spec, *, callback_server: CallbackServerFactory | None = None)`
- `OAuthFlow.authorize(..., callback_server: CallbackServerFactory | None = None)`
- `OAuth1Flow` mirrors both.
- `OAuth2Connection.connect(auth_profile, *, auto_authorize=False, callback_server: CallbackServerFactory | None = None)`
  forwards `callback_server` to `flow.authorize`. `OAuth1Connection` mirrors it.

A **factory** (zero-arg callable returning a fresh `CallbackServerProtocol`) is
injected, not an instance — `LocalCallbackServer` binds a socket in `__init__`
and is single-use, so each `authorize()` needs a fresh server. The class itself
is a valid factory (`callback_server=LocalCallbackServer`); to fix a port, pass
`callback_server=lambda: LocalCallbackServer(port=8080)`.

### 4. Resolution order inside `authorize()`

The flow resolves a factory, calls it to get a server, advertises
`server.redirect_uri` in the authorize URL, then calls
`server.obtain_callback(url)`:

1. explicit `callback_server=` argument (per-call), else
2. the flow's construction-time default, else
3. a built-in factory selected by `redirect_mode`:
   - `"local_server"` → `lambda: LocalCallbackServer(port=self._metadata.get("callback_port", 0))`
   - `"manual"` → `ManualCallbackServer` for OAuth2 (default urn);
     `lambda: ManualCallbackServer(redirect_uri="oob")` for OAuth1.

This precedence logic lives in one shared helper,
`connections/server/factory.py::resolve_callback_factory(...)`, called by both
flows (it takes a `manual_redirect_uri` so the OAuth1/OAuth2 OOB difference is
the only thing that varies). Keeping it in one place prevents the precedence
rules from drifting between the two flows.

`redirect_mode` still defaults to `"local_server"`, so with no injection the
behaviour is identical to today (`LocalCallbackServer` on the metadata port,
browser opened).

**Precedence is absolute, not "explicitness"-aware:** a `callback_server`
(per-call OR construction default) shadows `redirect_mode` entirely — there is
no detection of whether `redirect_mode` was "explicitly passed." So on a flow
constructed with a default factory, `authorize(redirect_mode="manual")` does
**not** select manual mode; the construction default wins. To force manual on
such a flow, pass it per call: `authorize(..., callback_server=ManualCallbackServer)`.
This is documented because it is the one surprising interaction.

Resulting `authorize()` body (oauth2; oauth1 analogous, no scope/PKCE):

```python
def authorize(self, client_id, client_secret,
              redirect_mode="local_server", scope=None,
              callback_server=None):
    factory = self._resolve_callback_factory(redirect_mode, callback_server)
    server = factory()                       # may raise (e.g. OSError: port in use)
    url, state = self.build_authorize_url(client_id, server.redirect_uri, scope)
    params = server.obtain_callback(url)     # owns its own resource cleanup
    self._validate_callback_state(params, state)          # 1. CSRF (ValueError on mismatch)
    if "error" in params:                                 # 2. provider denial
        raise AuthorizationDeniedError(
            error=params["error"],
            description=params.get("error_description", ""),
        )
    if "code" not in params:                              # 3. malformed/incomplete
        raise MalformedCallbackError("OAuth2 callback missing 'code'")
    return self.exchange_code(code=params["code"], ..., state=state)  # 4. success
```

`factory()` is called inside `authorize()`; the only code between it and
`obtain_callback` is `build_authorize_url` (pure string assembly, no I/O), so
the server cannot leak in that window. Any `factory()` failure (occupied fixed
port → `OSError`, missing optional dep, misconfigured remote client) propagates
unchanged, distinguishable from a `CallbackTimeoutError` (no callback) or an
`AuthorizationDeniedError` (user/provider declined).

### 5. Callback semantics, failure handling & lifecycle

- **Server owns presentation + cleanup, flow owns interpretation.**
  `obtain_callback` returns raw, single-valued params (first value wins for any
  repeated key — OAuth callback params are single-valued by spec). The flow is
  the sole place that validates state, detects `error`, and requires `code`.
- **Error taxonomy (new `errors.py` additions).** A shared base lets callers
  catch all callback failures with one `except`:
  - `CallbackError(Exception)` — base.
  - `AuthorizationDeniedError(CallbackError)` — OAuth2 provider returned
    `error` (e.g. `access_denied`); carries `error` + `description`.
  - `MalformedCallbackError(CallbackError)` — callback passed CSRF state but is
    missing a required parameter (OAuth2 `code`; OAuth1 `oauth_verifier`).
    Replaces today's bare `KeyError`.
  - `CallbackTimeoutError(CallbackError, TimeoutError)` — no callback before the
    deadline. Multiple-inherits `TimeoutError` so existing `except TimeoutError`
    keeps working while callers can also catch the shared base.
  CSRF mismatches remain a plain `ValueError` (unchanged for OAuth2;
  see OAuth1 below). User interrupts (`KeyboardInterrupt`) are intentionally
  **not** wrapped.
- **OAuth2 order in `authorize()`:** CSRF state check → `error` →
  `MalformedCallbackError` if `code` absent → exchange. State is validated even
  on the `error` path (the `error` redirect still carries `state`).
- **OAuth1 callback validation (new, for parity).** After `obtain_callback`,
  the flow (a) verifies the returned `oauth_token` matches the request token —
  the OAuth1 analog of the CSRF state check — raising `ValueError` on mismatch,
  and (b) raises `MalformedCallbackError` when `oauth_verifier` is absent
  (instead of passing an empty verifier on to the provider). This closes the
  previously-undefined OAuth1 denial/incomplete behaviour.
- **Resource lifecycle.** Each implementation releases its own resources in
  `obtain_callback` on both success and failure. The protocol intentionally has
  **no** `close()`/context-manager — the flow performs no resource management,
  and the factory→obtain_callback window is pure. (Resolves open question 1.)
- **Timeout/cancellation** is implementation-defined: `LocalCallbackServer`
  honors its constructor `timeout`, raising `CallbackTimeoutError` (still a
  `TimeoutError` subclass); `ManualCallbackServer` blocks on `input()` by
  design. Implementations may raise their own `CallbackError` subclasses (e.g. a
  `CallbackCancelledError`) so callers get a uniform base to catch.
- **Unchanged:** oauth1 `oauth_verifier` extraction; the param shapes the flow
  consumes (`code`/`state`; `oauth_verifier`/`oauth_token`); token
  exchange/refresh.

### 6. Enabled but not built (deferred)

These are made *possible* by the protocol but are out of scope for this spec:

- **Paste-the-redirected-URL manual flow.** The built-in `ManualCallbackServer`
  preserves today's OOB (`urn:…:oob`) behaviour. Because manual is now a
  first-class protocol implementation, a client (or a future built-in) can
  define a manual server that advertises a *registered* `redirect_uri` and asks
  the user to paste the full redirected URL — the better option where providers
  have dropped OOB. Not built here; current behaviour preserved.
- **Hosted/remote callback correlation.** `obtain_callback` receives the
  `authorize_url`, which embeds `state`, so a remote/hosted implementation can
  correlate a callback to its flow via `state`. Delivery mechanics (polling,
  webhook, expiry) are the implementation's concern and are not specified here.

### 7. Known limitations (deferred hardening)

Raised in adversarial review, consciously not addressed here:

- **Duplicate reserved-key detection.** `obtain_callback` returns a flat
  `dict[str, str]` (first value wins), so a callback with a repeated `state`/
  `code`/`error`/`oauth_verifier` is silently flattened rather than rejected.
  Detecting duplicates would require a richer return type than `dict[str, str]`
  (the dupes are gone after flattening), trading the clean contract for defence
  against a low-likelihood crafted callback. Deferred; revisit if a threat model
  warrants it.
- **Redirectable presentation.** `LocalCallbackServer`'s browser-failure
  fallback uses `print()` to stdout, which an embedding tool cannot silence or
  redirect. The design's intended escape hatch is "custom UX → custom server"
  (implement the protocol), so a `stream`/presenter parameter on the built-in is
  deliberately omitted to keep its surface small.

## File-by-file changes

| File | Change |
|------|--------|
| `connections/protocols/__init__.py` | new — export `CallbackServerProtocol`, `CallbackServerFactory` |
| `connections/protocols/prtcl_callback.py` | new — protocol + factory alias |
| `connections/server/callback.py` | add `obtain_callback` (browser-open + fallback print + guaranteed `server_close`); `wait_for_callback` becomes pure blocking wait |
| `connections/server/manual.py` | add `ManualCallbackServer` (optional `redirect_uri`) |
| `connections/server/factory.py` | new — `resolve_callback_factory(...)` shared precedence helper |
| `errors.py` | add `CallbackError` base + `AuthorizationDeniedError`, `MalformedCallbackError`, `CallbackTimeoutError(CallbackError, TimeoutError)` |
| `connections/server/__init__.py` | export `ManualCallbackServer` |
| `connections/oauth2/flow.py` | `__init__` + `authorize` gain `callback_server`; add `_resolve_callback_factory`; remove presentation branching; raise `MalformedCallbackError` on absent `code` |
| `connections/oauth1/flow.py` | same, plus validate returned `oauth_token` vs request token and raise `MalformedCallbackError` on absent `oauth_verifier` |
| `connections/oauth2/connection.py` | `connect` gains `callback_server` passthrough |
| `connections/oauth1/connection.py` | same |
| `connections/__init__.py`, package `__init__.py` | export new public symbols |

## Testing strategy

- **Protocol conformance:** `isinstance(LocalCallbackServer(...), CallbackServerProtocol)`
  and `isinstance(ManualCallbackServer(), CallbackServerProtocol)` (runtime-checkable).
- **Injection:** a fake in-test server implementing the protocol, supplied via a
  factory, drives `authorize()` — assert the built authorize URL carries the
  fake's `redirect_uri` and that the fake's `obtain_callback` return flows
  through to `exchange_code`.
- **Precedence:** per-call `callback_server` beats construction default beats
  `redirect_mode` builtin.
- **Manual:** `ManualCallbackServer` with monkeypatched `input` yields the OOB
  redirect URI and an `oauth_verifier`.
- **Port:** `callback_server=lambda: LocalCallbackServer(port=N)` advertises a
  `redirect_uri` containing `N`.
- **Back-compat:** existing `redirect_mode="local_server"|"manual"` tests still
  pass; default `authorize()` still opens a browser and waits on a local server
  (mocked).
- **Authorization denial:** a callback carrying `error=access_denied` (valid
  `state`) raises `AuthorizationDeniedError`, not `KeyError`, and never reaches
  `exchange_code`.
- **Browser fallback:** when `webbrowser.open` returns `False`, the URL is
  printed and the wait still proceeds.
- **Cleanup on failure:** if `obtain_callback` raises (e.g. `CallbackTimeoutError`),
  the socket is closed — a second `LocalCallbackServer` on the same fixed port
  can bind again (no leaked port).
- **Malformed OAuth2 callback:** valid `state`, no `error`, no `code` → raises
  `MalformedCallbackError` (and it's catchable as `CallbackError`); never reaches
  `exchange_code`.
- **OAuth1 validation:** mismatched returned `oauth_token` → `ValueError`;
  absent `oauth_verifier` → `MalformedCallbackError`.
- **Timeout base:** `CallbackTimeoutError` is catchable as both `TimeoutError`
  (back-compat) and `CallbackError`.
- **Precedence surprise:** a flow with a construction-time default factory and
  `authorize(redirect_mode="manual")` still uses the default; per-call
  `callback_server=ManualCallbackServer` overrides it.

## Follow-ups (out of scope here)

- Delete transport's duplicated `connections/` OAuth/callback/protocol copy and
  repoint transport at `mountainash-auth-client`.

# Connections Dedup — auth-client resolver extraction (Part A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift the OAuth2/OAuth1 token lifecycle out of auth-client's connection classes into reusable, client-agnostic flow methods (`OAuthFlow.resolve_access_token`, `OAuth1Flow.resolve_token_pair`) so transport can later import the one lifecycle instead of carrying a stale fork.

**Architecture:** The cache→refresh→authorize→persist body currently embedded in `OAuth2Connection.connect()` and `OAuth1Connection.connect()` moves verbatim onto the flow objects (which already own `refresh`/`authorize`/`is_expired`). The connections shrink to "resolve token → build client". This de-dupes auth-client *internally* (the connections call the new primitive), proving the seam before transport consumes it. The OAuth2 resolver adopts the strictly-safer fail-closed `if not access_token` guard (was `is None`).

**Tech Stack:** Python 3.12, httpx, mountainash-settings secrets backend, pytest (unit), ruff, mypy.

**Repo / branch:** `mountainash-auth-client`. Branch `feature/connections-dedup-authclient` off **`origin/develop`** (Phase 2 / PR #5 is already merged to develop at `6173770`; do NOT branch off the stale `feature/unified-emission-phase2`).

**Spec:** `mountainash-utils-files/docs/superpowers/specs/2026-06-13-connections-dedup-design.md` (Part A). This plan is the auth-client prerequisite; the transport consumer PR is a separate plan, sequenced after this merges + a version bump.

---

## File Structure

- `src/mountainash_auth_client/connections/oauth2/flow.py` — **modify**: add `resolve_access_token`; add `get_secrets_backend` + `AuthorizationRequired` imports.
- `src/mountainash_auth_client/connections/oauth2/connection.py` — **modify**: `connect()` delegates to `resolve_access_token`; drops the inline lifecycle + the now-unused `get_secrets_backend` import.
- `src/mountainash_auth_client/connections/oauth1/flow.py` — **modify**: store `self._spec`; add `resolve_token_pair`; add imports.
- `src/mountainash_auth_client/connections/oauth1/connection.py` — **modify**: `connect()` delegates to `resolve_token_pair`; drops the inline lifecycle + the now-unused `get_secrets_backend` import.
- `src/mountainash_auth_client/__version__.py` — **modify**: `26.5.0` → `26.6.0`.
- `tests/connections/test_oauth2_flow.py` — **modify**: add `TestResolveAccessToken` (lifecycle behaviors relocated here from the connection test).
- `tests/connections/test_oauth2_connection.py` — **modify**: remove the three mock-`OAuthFlow` lifecycle tests (now covered at flow level); add one connection-level test that a mocked `resolve_access_token` yields a Bearer client. Real-flow tests are untouched.
- `tests/connections/test_oauth1_flow.py` — **modify**: add `TestResolveTokenPair`.
- `tests/connections/test_oauth1_connection.py` — **modify**: retarget the callback-passthrough test to mock `resolve_token_pair`.

**Test-migration rationale (read before Task 2/4):** The refresh/persist/callback-forwarding behaviors are *lifecycle* behaviors. After extraction they are the *flow's* responsibility and are tested against the flow. The connection's only remaining responsibility — build an authenticated client from a resolved token — gets its own focused test. This is the logic moving and its tests moving with it, NOT deleting tests to force a pass. The connection tests that drive the **real** flow (valid stored token, no-token-raises, expired-no-refresh, bearer header) are unchanged and must still pass.

**Preserved-not-hardened (Codex item 3 — verbatim lift, do NOT "fix" in this PR):** Two pre-existing quirks are lifted as-is and are explicitly out of scope:
- The OAuth2 refresh path re-reads `tokens` inside `backend.transaction(key)` and then indexes `tokens["refresh_token"]`; a concurrent delete between reads would raise. This is the existing `connect()` behavior — the dedup must not change it.
- The OAuth1 cache check is `if tokens and tokens.get("oauth_token")` but the build then indexes `tokens["oauth_token_secret"]`; a partially-persisted entry (token without secret) raises `KeyError`. Also the existing behavior. Do **not** add a test that pins this quirk (it would encode arguably-buggy current behavior — see the "never encode brittle behavior" guidance); hardening it is a separate follow-up.

---

### Task 1: Extract `OAuthFlow.resolve_access_token` (OAuth2 lifecycle)

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth2/flow.py`
- Test: `tests/connections/test_oauth2_flow.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/connections/test_oauth2_flow.py` (add imports at top of file if missing: `import time`, `from contextlib import contextmanager`, `from unittest.mock import patch`, `import pytest`, `from mountainash_auth_client.errors import AuthorizationRequired`, `from mountainash_auth_client.connections.oauth2.flow import OAuthFlow`, `from mountainash_settings.secrets.registry import clear_secrets_registry, register_secrets_backend`):

```python
class _MemBackend:
    def __init__(self):
        self._store = {}

    def get(self, key):
        return self._store.get(key)

    def set(self, key, data):
        self._store[key] = data

    def delete(self, key):
        self._store.pop(key, None)

    @contextmanager
    def transaction(self, key):
        yield


class _Spec:
    name = "testprovider"

    @property
    def metadata(self):
        return {
            "authorize_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
        }


class _Auth:
    CLIENT_ID = "cid"
    CLIENT_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "csec"})()
    )
    SCOPE = "read"
    SETTINGS_SOURCE_SECRETS_PROVIDER = "rat_mem"

    def persist_key(self):
        return "rat.oauth2"


@pytest.fixture(autouse=True)
def _clean_rat():
    clear_secrets_registry()
    yield
    clear_secrets_registry()


@pytest.fixture
def rat_backend():
    b = _MemBackend()
    register_secrets_backend("rat_mem", b)
    return b


class TestResolveAccessToken:
    def test_returns_cached_unexpired_token(self, rat_backend):
        rat_backend.set("rat.oauth2", {
            "access_token": "cached_tok",
            "refresh_token": "r",
            "token_expires_at": int(time.time()) + 3600,
        })
        token = OAuthFlow(_Spec()).resolve_access_token(_Auth())
        assert token == "cached_tok"

    def test_raises_when_no_token_and_not_auto(self, rat_backend):
        with pytest.raises(AuthorizationRequired) as exc:
            OAuthFlow(_Spec()).resolve_access_token(_Auth())
        assert exc.value.provider == "testprovider"

    def test_raises_when_expired_and_no_refresh(self, rat_backend):
        rat_backend.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        with pytest.raises(AuthorizationRequired):
            OAuthFlow(_Spec()).resolve_access_token(_Auth())

    def test_refresh_persists_and_returns_new_token(self, rat_backend):
        rat_backend.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": "r_xyz",
            "token_expires_at": int(time.time()) - 1000,
        })
        with patch.object(OAuthFlow, "refresh", return_value={
            "access_token": "new_tok",
            "refresh_token": "new_r",
            "token_expires_at": int(time.time()) + 3600,
        }):
            token = OAuthFlow(_Spec()).resolve_access_token(_Auth())
        assert token == "new_tok"
        assert rat_backend.get("rat.oauth2")["access_token"] == "new_tok"

    def test_persist_failure_after_refresh_propagates_and_keeps_token(self, rat_backend):
        rat_backend.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": "r_xyz",
            "token_expires_at": int(time.time()) - 1000,
        })

        def boom(key, data):
            raise RuntimeError("disk full")

        rat_backend.set = boom
        with patch.object(OAuthFlow, "refresh", return_value={
            "access_token": "new_tok",
            "refresh_token": "new_r",
            "token_expires_at": int(time.time()) + 3600,
        }):
            with pytest.raises(RuntimeError, match="disk full"):
                OAuthFlow(_Spec()).resolve_access_token(_Auth())
        assert rat_backend.get("rat.oauth2")["refresh_token"] == "r_xyz"

    def test_auto_authorize_forwards_callback_server(self, rat_backend):
        sentinel = object()
        captured = {}

        def fake_authorize(**kwargs):
            captured.update(kwargs)
            return {"access_token": "auth_tok", "refresh_token": "", "token_expires_at": None}

        with patch.object(OAuthFlow, "authorize", side_effect=fake_authorize):
            token = OAuthFlow(_Spec()).resolve_access_token(
                _Auth(), auto_authorize=True, callback_server=sentinel)
        assert token == "auth_tok"
        assert captured["callback_server"] is sentinel

    def test_empty_cached_token_is_failclosed(self, rat_backend):
        # An empty-string access_token with no refresh path must NOT be returned;
        # it fails closed to AuthorizationRequired (the `if not access_token` guard).
        rat_backend.set("rat.oauth2", {
            "access_token": "",
            "refresh_token": None,
            "token_expires_at": int(time.time()) + 3600,
        })
        with pytest.raises(AuthorizationRequired):
            OAuthFlow(_Spec()).resolve_access_token(_Auth())

    def test_empty_token_from_authorize_is_failclosed(self, rat_backend):
        # Even when authorize() succeeds, an empty access_token must fail closed
        # rather than be handed back as a valid Bearer (post-authorize guard).
        with patch.object(OAuthFlow, "authorize", return_value={
            "access_token": "", "refresh_token": "", "token_expires_at": None,
        }):
            with pytest.raises(AuthorizationRequired):
                OAuthFlow(_Spec()).resolve_access_token(_Auth(), auto_authorize=True)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `hatch run test:test tests/connections/test_oauth2_flow.py -k ResolveAccessToken -v`
Expected: FAIL with `AttributeError: 'OAuthFlow' object has no attribute 'resolve_access_token'`.

- [ ] **Step 3: Add imports + implement the method**

At the top of `flow.py`, add to the existing imports:

```python
from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    AuthorizationRequired,
    MalformedCallbackError,
    TokenExchangeError,
    TokenRefreshError,
)
from mountainash_settings.secrets.registry import get_secrets_backend
```

(Add `AuthorizationRequired` into the existing `errors` import block; add the `get_secrets_backend` line.)

Add this method to `OAuthFlow` (place it directly above `authorize`):

```python
    def resolve_access_token(
        self,
        auth_profile,
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> str:
        """Resolve a valid access token: cached → refresh → authorize → persist.

        Client construction is the caller's responsibility. Raises
        ``AuthorizationRequired`` when no usable token exists and
        ``auto_authorize`` is False. Uses the fail-closed ``if not
        access_token`` guard — an empty cached token is never returned.
        """
        provider = self._spec.name
        backend = get_secrets_backend(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth_profile.persist_key()
        tokens = backend.get(key)

        access_token: str | None = None

        if tokens and not self.is_expired(tokens.get("token_expires_at")):
            access_token = tokens["access_token"]
        elif tokens and tokens.get("refresh_token"):
            with backend.transaction(key):
                tokens = backend.get(key)
                if tokens and not self.is_expired(tokens.get("token_expires_at")):
                    access_token = tokens["access_token"]
                else:
                    try:
                        new_tokens = self.refresh(
                            refresh_token=tokens["refresh_token"],
                            client_id=auth_profile.CLIENT_ID,
                            client_secret=auth_profile.CLIENT_SECRET.get_secret_value(),
                        )
                    except Exception:
                        backend.delete(key)
                        if not auto_authorize:
                            raise AuthorizationRequired(provider=provider, user="default")
                    else:
                        backend.set(key, new_tokens)
                        access_token = new_tokens["access_token"]

        if not access_token and auto_authorize:
            new_tokens = self.authorize(
                client_id=auth_profile.CLIENT_ID,
                client_secret=auth_profile.CLIENT_SECRET.get_secret_value(),
                scope=auth_profile.SCOPE,
                callback_server=callback_server,
            )
            backend.set(key, new_tokens)
            access_token = new_tokens["access_token"]

        # Fail closed: no usable token — nothing cached/refreshed, authorize
        # disabled, OR authorize itself returned an empty token → raise.
        if not access_token:
            raise AuthorizationRequired(provider=provider, user="default")

        return access_token
```

> Note on the restructure (Codex item 1): the original `connect()` nested the
> authorize call inside `if access_token is None:`. Flattening to
> `if not access_token and auto_authorize:` followed by a single trailing
> `if not access_token: raise` preserves every original path (cached, refresh,
> refresh-failure-not-auto already raised inside the transaction, no-token-not-auto)
> AND closes the gap where `authorize()` returning an empty token would otherwise
> be handed back as a valid Bearer. This is the fail-closed guarantee made total.

> Note: `self._spec` exists on `OAuthFlow` (`__init__` line 35). `TokenRefreshError`/`TokenExchangeError` may already be imported — keep the block deduplicated, do not introduce duplicate names.

- [ ] **Step 4: Run tests to verify they pass**

Run: `hatch run test:test tests/connections/test_oauth2_flow.py -k ResolveAccessToken -v`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth2/flow.py tests/connections/test_oauth2_flow.py
git commit -m "feat: add OAuthFlow.resolve_access_token (lifecycle extraction)"
```

---

### Task 2: Refactor `OAuth2Connection.connect` onto the resolver

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth2/connection.py`
- Test: `tests/connections/test_oauth2_connection.py`

- [ ] **Step 1: Refactor `connect()`**

Replace the body of `connect()` (the block from `provider = self._spec.name` through the `httpx.Client(...)` construction) with:

```python
    def connect(
        self,
        auth_profile: OAuth2AuthProfile | OAuth2AuthCodeAuthProfile,
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> Self:
        access_token = OAuthFlow(self._spec).resolve_access_token(
            auth_profile,
            auto_authorize=auto_authorize,
            callback_server=callback_server,
        )
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )
        return self
```

Remove the now-unused import `from mountainash_settings.secrets.registry import get_secrets_backend` and the unused `from mountainash_auth_client.errors import AuthorizationRequired` (the resolver owns both now). Keep the `OAuthFlow` import.

- [ ] **Step 2: Migrate the three mock-`OAuthFlow` tests out of the connection test**

In `tests/connections/test_oauth2_connection.py`, **delete** these three tests (their behavior is now covered by `TestResolveAccessToken` added in Task 1):
- `TestOAuth2ConnectionRefresh.test_successful_refresh_persists_and_connects`
- `TestOAuth2ConnectionRefresh.test_persist_failure_after_refresh_propagates_and_keeps_token`
- `TestCallbackServerPassthrough.test_connect_forwards_callback_server_to_authorize`

Delete the now-empty `TestOAuth2ConnectionRefresh` class (and its `_store_expired_token`/`_fake_flow` helpers) and the `TestCallbackServerPassthrough` class. Remove the now-unused `from unittest.mock import MagicMock, patch` import if nothing else uses it.

Then add a focused connection-level test that the connection builds a Bearer client from whatever the resolver returns:

```python
class TestConnectBuildsBearerClient:
    def test_connect_uses_resolved_token_for_bearer_header(self, backend):
        from unittest.mock import patch
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "resolved_tok"
            provider = FakeProvider()
            provider.connect(FakeAuth())
        assert "Bearer resolved_tok" in provider._client.headers.get("authorization", "")

    def test_connect_forwards_callback_server_to_resolver(self, backend):
        # The connection→resolver forwarding seam (was previously asserted by the
        # now-relocated TestCallbackServerPassthrough). connect() must thread
        # callback_server into resolve_access_token.
        from unittest.mock import patch
        sentinel = object()
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "tok"
            provider = FakeProvider()
            provider.connect(FakeAuth(), auto_authorize=True, callback_server=sentinel)
            _, kwargs = flow_cls.return_value.resolve_access_token.call_args
        assert kwargs["callback_server"] is sentinel
```

- [ ] **Step 3: Run the full OAuth2 suite**

Run: `hatch run test:test tests/connections/test_oauth2_connection.py tests/connections/test_oauth2_flow.py -v`
Expected: PASS. The real-flow connection tests (`test_connects_with_valid_stored_token`, `test_raises_authorization_required_when_no_token`, `test_client_has_bearer_auth_header`, `test_connect_with_unexpired_token_no_refresh`, `test_raises_authorization_required_when_token_expired_and_no_refresh`, `TestClientProperty`) pass unchanged.

- [ ] **Step 4: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth2/connection.py tests/connections/test_oauth2_connection.py
git commit -m "refactor: OAuth2Connection.connect delegates to resolve_access_token"
```

---

### Task 3: Extract `OAuth1Flow.resolve_token_pair`

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth1/flow.py`
- Test: `tests/connections/test_oauth1_flow.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/connections/test_oauth1_flow.py` (add imports if missing: `from contextlib import contextmanager`, `from unittest.mock import patch`, `import pytest`, `from mountainash_auth_client.errors import AuthorizationRequired`, `from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow`, `from mountainash_settings.secrets.registry import clear_secrets_registry, register_secrets_backend`):

```python
class _Mem1Backend:
    def __init__(self):
        self._store = {}

    def get(self, key):
        return self._store.get(key)

    def set(self, key, data):
        self._store[key] = data

    def delete(self, key):
        self._store.pop(key, None)

    @contextmanager
    def transaction(self, key):
        yield


class _Spec1:
    name = "testprovider_oauth1"

    @property
    def metadata(self):
        return {
            "request_token_url": "https://auth.example.com/request_token",
            "authorize_url": "https://auth.example.com/authorize",
            "access_token_url": "https://auth.example.com/access_token",
        }


class _Auth1:
    CONSUMER_KEY = "ck"
    CONSUMER_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "cs"})()
    )
    SETTINGS_SOURCE_SECRETS_PROVIDER = "rtp_mem"

    def persist_key(self):
        return "rtp.oauth1"


@pytest.fixture(autouse=True)
def _clean_rtp():
    clear_secrets_registry()
    yield
    clear_secrets_registry()


@pytest.fixture
def rtp_backend():
    b = _Mem1Backend()
    register_secrets_backend("rtp_mem", b)
    return b


class TestResolveTokenPair:
    def test_returns_cached_pair(self, rtp_backend):
        rtp_backend.set("rtp.oauth1", {"oauth_token": "AT", "oauth_token_secret": "ATS"})
        pair = OAuth1Flow(_Spec1()).resolve_token_pair(_Auth1())
        assert pair == ("AT", "ATS")

    def test_raises_when_no_token_and_not_auto(self, rtp_backend):
        with pytest.raises(AuthorizationRequired) as exc:
            OAuth1Flow(_Spec1()).resolve_token_pair(_Auth1())
        assert exc.value.provider == "testprovider_oauth1"

    def test_auto_authorize_persists_and_returns_pair(self, rtp_backend):
        with patch.object(OAuth1Flow, "authorize", return_value={
            "oauth_token": "newAT", "oauth_token_secret": "newATS",
        }):
            pair = OAuth1Flow(_Spec1()).resolve_token_pair(_Auth1(), auto_authorize=True)
        assert pair == ("newAT", "newATS")
        assert rtp_backend.get("rtp.oauth1")["oauth_token"] == "newAT"

    def test_auto_authorize_forwards_callback_server(self, rtp_backend):
        sentinel = object()
        captured = {}

        def fake_authorize(**kwargs):
            captured.update(kwargs)
            return {"oauth_token": "AT", "oauth_token_secret": "ATS"}

        with patch.object(OAuth1Flow, "authorize", side_effect=fake_authorize):
            OAuth1Flow(_Spec1()).resolve_token_pair(
                _Auth1(), auto_authorize=True, callback_server=sentinel)
        assert captured["callback_server"] is sentinel
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `hatch run test:test tests/connections/test_oauth1_flow.py -k ResolveTokenPair -v`
Expected: FAIL with `AttributeError: 'OAuth1Flow' object has no attribute 'resolve_token_pair'` (or `_spec`).

- [ ] **Step 3: Store `self._spec`, add imports, implement the method**

In `OAuth1Flow.__init__`, add `self._spec = spec` (the flow currently stores only `_metadata`/`_callback_server`):

```python
    def __init__(
        self,
        spec: ProfileSpec,
        *,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._spec = spec
        self._metadata = spec.metadata
        self._callback_server = callback_server
```

Add imports at the top of `flow.py`:

```python
from mountainash_auth_client.errors import (
    AuthorizationRequired,
    MalformedCallbackError,
    TokenExchangeError,
)
from mountainash_settings.secrets.registry import get_secrets_backend
```

(Merge `AuthorizationRequired` into the existing `errors` import; add `get_secrets_backend`.)

Add this method to `OAuth1Flow` (place it directly above `authorize`):

```python
    def resolve_token_pair(
        self,
        auth_profile,
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> tuple[str, str]:
        """Resolve an OAuth1 access token pair: cached → authorize → persist.

        Returns ``(oauth_token, oauth_token_secret)``. Raises
        ``AuthorizationRequired`` when no cached pair exists and
        ``auto_authorize`` is False.
        """
        provider = self._spec.name
        backend = get_secrets_backend(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth_profile.persist_key()
        tokens = backend.get(key)

        if tokens and tokens.get("oauth_token"):
            return tokens["oauth_token"], tokens["oauth_token_secret"]

        if auto_authorize:
            new_tokens = self.authorize(
                consumer_key=auth_profile.CONSUMER_KEY,
                consumer_secret=auth_profile.CONSUMER_SECRET.get_secret_value(),
                callback_server=callback_server,
            )
            backend.set(key, new_tokens)
            return new_tokens["oauth_token"], new_tokens["oauth_token_secret"]

        raise AuthorizationRequired(provider=provider, user="default")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `hatch run test:test tests/connections/test_oauth1_flow.py -k ResolveTokenPair -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth1/flow.py tests/connections/test_oauth1_flow.py
git commit -m "feat: add OAuth1Flow.resolve_token_pair (lifecycle extraction)"
```

---

### Task 4: Refactor `OAuth1Connection.connect` onto the resolver

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth1/connection.py`
- Test: `tests/connections/test_oauth1_connection.py`

- [ ] **Step 1: Refactor `connect()`**

Replace the body of `connect()` (from `provider = self._spec.name` through the final `raise AuthorizationRequired`) with:

```python
    def connect(
        self,
        auth_profile: OAuth1AuthProfile,
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> Self:
        oauth_token, oauth_token_secret = OAuth1Flow(self._spec).resolve_token_pair(
            auth_profile,
            auto_authorize=auto_authorize,
            callback_server=callback_server,
        )
        self._build_client(
            {"oauth_token": oauth_token, "oauth_token_secret": oauth_token_secret},
            auth_profile,
        )
        return self
```

Remove the now-unused imports `from mountainash_auth_client.errors import AuthorizationRequired` and `from mountainash_settings.secrets.registry import get_secrets_backend` (the resolver owns both). Keep `OAuth1Flow` and `require_authlib` imports (`_build_client` still uses `require_authlib`).

- [ ] **Step 2: Retarget the callback-passthrough test**

In `tests/connections/test_oauth1_connection.py`, replace `TestCallbackServerPassthrough` (which patches `OAuth1Flow` with a `FakeFlow` that has `authorize` but no `resolve_token_pair`) with a test that mocks the resolver:

```python
class TestConnectUsesResolver:
    def test_connect_builds_client_from_resolved_pair(self, monkeypatch, backend):
        captured = {}

        def fake_resolve(self, auth_profile, *, auto_authorize=False, callback_server=None):
            captured["callback_server"] = callback_server
            return ("AT", "ATS")

        monkeypatch.setattr(
            "mountainash_auth_client.connections.oauth1.flow.OAuth1Flow.resolve_token_pair",
            fake_resolve,
        )
        built = {}
        monkeypatch.setattr(
            FakeProvider, "_build_client",
            lambda self, tokens, auth: built.update(tokens),
        )
        sentinel = object()
        provider = FakeProvider()
        provider.connect(FakeAuth(), auto_authorize=True, callback_server=sentinel)
        assert built == {"oauth_token": "AT", "oauth_token_secret": "ATS"}
        assert captured["callback_server"] is sentinel
```

> Note: `connection.py` imports `OAuth1Flow` from `...oauth1.flow`, so patch the method on the flow module (`...oauth1.flow.OAuth1Flow.resolve_token_pair`), which the connection resolves at call time.

- [ ] **Step 3: Run the full OAuth1 suite**

Run: `hatch run test:test tests/connections/test_oauth1_connection.py tests/connections/test_oauth1_flow.py -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth1/connection.py tests/connections/test_oauth1_connection.py
git commit -m "refactor: OAuth1Connection.connect delegates to resolve_token_pair"
```

---

### Task 5: Version bump

**Files:**
- Modify: `src/mountainash_auth_client/__version__.py`

- [ ] **Step 1: Bump the version**

Change `__version__ = "26.5.0"` to `__version__ = "26.6.0"`.

> The bump is required so the transport dev-env wheel cache invalidates and the consumer PR can import `resolve_access_token`/`resolve_token_pair` (uv caches path-dep wheels by version — see memory `transport_env_staleness_and_profile_rename`). If a CHANGELOG.md exists, add a one-line entry under a new `26.6.0` heading: "Extract OAuthFlow.resolve_access_token / OAuth1Flow.resolve_token_pair (client-agnostic token lifecycle)."

- [ ] **Step 2: Commit**

```bash
git add src/mountainash_auth_client/__version__.py
git commit -m "chore: bump version to 26.6.0"
```

---

### Task 6: Full suite + lint + types

**Files:** none (verification only).

- [ ] **Step 1: Run the full test suite**

Run: `hatch run test:test -q`
Expected: all pass (no regressions outside the OAuth modules).

- [ ] **Step 2: Lint**

Run: `hatch run ruff:check`
Expected: clean. If unused-import warnings remain in the four edited modules, remove the offending imports.

- [ ] **Step 3: Type check**

Run: `hatch run mypy:check`
Expected: no new errors versus develop baseline.

- [ ] **Step 4: Commit any lint/type fixups**

```bash
git add -A
git commit -m "chore: lint + type fixups for connections dedup"
```

---

## Self-Review Checklist (controller runs before dispatch)

1. **Spec coverage (Part A):** `resolve_access_token` (Task 1), `resolve_token_pair` (Task 3), both connections refactored to call them (Tasks 2/4), fail-closed `if not access_token` adopted (Task 1 + `test_empty_cached_token_is_failclosed`), callback_server forwarded to `authorize` (Tasks 1/3 tests), version bump (Task 5). ✅
2. **Out of scope (correctly excluded):** transport deletions/collapse, re-export repoint, golden parity — those are the *consumer* PR (separate plan). ✅
3. **Type consistency:** `resolve_access_token -> str`; `resolve_token_pair -> tuple[str, str]`; connect signatures keep `auto_authorize`/`callback_server` keywords. ✅
4. **Test integrity:** relocated tests preserve every behavior (refresh-persist, persist-failure, callback-forward, no-token-raise) at the flow level; nothing silenced. Real-flow connection tests untouched. ✅

---

## Sequencing note

This is the **prerequisite** PR. After it merges to `develop` and the version is `26.6.0`, refresh the transport dev-env wheel before starting the transport consumer plan:

```bash
python3 -m pip wheel --no-deps --no-cache-dir --wheel-dir /tmp/dedup-wheels \
  /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
~/.local/bin/uv pip install --python .venv/bin/python --reinstall --no-cache --no-deps \
  /tmp/dedup-wheels/mountainash_auth_client-26.6.0-*.whl
```

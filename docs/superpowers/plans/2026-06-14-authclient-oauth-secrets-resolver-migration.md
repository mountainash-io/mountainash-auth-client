# auth-client OAuth → mountainash-secrets Resolver Migration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate mountainash-auth-client's OAuth token persistence off the global `mountainash_settings.secrets` registry onto an injected `mountainash_secrets.SecretStoreResolver`, using the canonical pattern from the mountainash-secrets spec §4.4/§5.2.

**Architecture:** `OAuthFlow`/`OAuth1Flow` gain an optional injected `resolver`; their persistence methods resolve the token store by name (`resolver.resolve_as(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER, ClearableStore)`) and wrap it in `NamespacedStore(store, "oauth")` — replacing `get_secrets_backend(...)`. `OAuth2Connection`/`OAuth1Connection` gain a required `resolver` and pass it down. The `get/set/delete/transaction` call sequence and `persist_key()` are unchanged; only the store *acquisition* changes. This deletes auth-client's last `mountainash_settings.secrets` dependency.

**Tech Stack:** Python ≥3.10, httpx, pydantic, mountainash-secrets (the new port), pytest, ruff.

**Spec:** `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-secrets/docs/superpowers/specs/2026-06-14-secrets-store-port-design.md` (§4.4 composition root, §5.2 auth-client migration).

**Conventions for every task:**
- **Repo root:** `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client`
- **Test runner (PY):** `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest`
- **Lint gate:** `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m ruff check src tests` (no mypy env).
- `mountainash-secrets` is already editable-installed in that shared venv (`import mountainash_secrets` works).
- All commands assume CWD = repo root.
- Commit messages end with the `Co-Authored-By` trailer shown in Task 0.
- **authlib note:** authlib is the `[oauth1]` optional extra and is NOT installed in the dev venv. The OAuth1 *connection* test already patches the `mountainash_auth_client.schemas.oauth1.require_authlib` seam with an `httpx.Auth` stub — keep that intact.

---

## Background: the canonical pattern (spec §5.2)

The flow's persistence methods change from:
```python
backend = get_secrets_backend(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER)
key = auth_profile.persist_key()
tokens = backend.get(key)
# ... .transaction/.get/.delete/.set on `backend`
```
to:
```python
store = self._resolver.resolve_as(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER, ClearableStore)
backend = NamespacedStore(store, "oauth")
key = auth_profile.persist_key()
tokens = backend.get(key)
# ... identical .transaction/.get/.delete/.set on `backend`
```
The variable stays named `backend`, so only the two acquisition lines change; the rest of each method is untouched. Tokens now live under the `oauth/` namespace inside whatever store the composition root registered.

---

## File Structure

```
src/mountainash_auth_client/connections/
  oauth2/flow.py          # Task 2 — inject resolver, resolve_as + NamespacedStore
  oauth1/flow.py          # Task 3 — same
  oauth2/connection.py    # Task 4 — required resolver, pass to OAuthFlow
  oauth1/connection.py    # Task 5 — required resolver, pass to OAuth1Flow
pyproject.toml            # Task 1 — add mountainash-secrets dep
tests/connections/
  test_oauth2_flow.py        # Task 2 — RED
  test_oauth1_flow.py        # Task 3 — RED
  test_oauth2_connection.py  # Task 4 — RED
  test_oauth1_connection.py  # Task 5 — RED
```

---

## Task 0: Branch setup

**Files:** none

- [ ] **Step 1: Create the feature branch off develop**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git checkout develop
git pull --ff-only
git checkout -b feature/oauth-secrets-resolver
git branch --show-current
```
Expected: prints `feature/oauth-secrets-resolver`.

---

## Task 1: Declare the mountainash-secrets dependency

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Read the current dependencies block**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -c "import tomllib,pathlib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['dependencies'])"`
Expected: a list like `['pydantic>=2.9.0', 'httpx>=0.27.0', 'pyaml', ...]` (note `mountainash-settings` is commented out in the file).

- [ ] **Step 2: Add the dependency**

In `pyproject.toml`, in `[project].dependencies`, add `"mountainash-secrets",` immediately after the `"pyaml",` line. The block becomes:
```toml
dependencies = [
    "pydantic>=2.9.0",
    "httpx>=0.27.0",
    "pyaml",
    "mountainash-secrets",
    # "mountainash-settings",
]
```

- [ ] **Step 3: Verify the new symbols import from the shared venv**

Run:
```bash
/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -c "from mountainash_secrets import ClearableStore, NamespacedStore, RegistryResolver, InMemoryStore, SecretStoreResolver; print('ok')"
```
Expected: prints `ok`.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "$(cat <<'EOF'
build: depend on mountainash-secrets for OAuth token persistence

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: OAuth2 flow → injected resolver

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth2/flow.py`
- Test: `tests/connections/test_oauth2_flow.py`

- [ ] **Step 1: Migrate the test scaffolding (RED)**

In `tests/connections/test_oauth2_flow.py`, replace the block from the second import group through the `rat_backend` fixture (currently the `from contextlib import contextmanager` line down to the end of the `rat_backend` fixture — the lines defining `_MemBackend`, `_Auth`, `_clean_rat`, `rat_backend`) with EXACTLY:

```python
from types import SimpleNamespace

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_secrets import InMemoryStore, NamespacedStore, RegistryResolver


class _Auth:
    CLIENT_ID = "cid"
    CLIENT_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "csec"})()
    )
    SCOPE = "read"
    SETTINGS_SOURCE_SECRETS_PROVIDER = "rat_mem"

    def persist_key(self):
        return "rat.oauth2"


@pytest.fixture
def rat_env():
    # A real mountainash-secrets store resolved by name exactly as the flow does.
    # `tokens` is the "oauth"-namespaced view the flow writes through, so tests
    # seed/read with the bare persist_key and the prefix is handled for them.
    store = InMemoryStore()
    return SimpleNamespace(
        resolver=RegistryResolver({"rat_mem": store}),
        tokens=NamespacedStore(store, "oauth"),
        store=store,
    )
```

(The old `from contextlib import contextmanager` local import and the
`from mountainash_settings.secrets.registry import ...` line are removed — they
were only there for `_MemBackend`/the global registry. If ruff later reports
`contextmanager` is still used elsewhere in this file, keep that import; it is
not expected to be.)

- [ ] **Step 2: Replace the `TestResolveAccessToken` class with the injected-resolver version**

Replace the entire `class TestResolveAccessToken:` block with EXACTLY:

```python
class TestResolveAccessToken:
    def test_returns_cached_unexpired_token(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "cached_tok",
            "refresh_token": "r",
            "token_expires_at": int(time.time()) + 3600,
        })
        token = OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())
        assert token == "cached_tok"

    def test_raises_when_no_token_and_not_auto(self, rat_env):
        with pytest.raises(AuthorizationRequired) as exc:
            OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())
        assert exc.value.provider == "testprovider"

    def test_raises_when_expired_and_no_refresh(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        with pytest.raises(AuthorizationRequired):
            OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())

    def test_refresh_persists_and_returns_new_token(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": "r_xyz",
            "token_expires_at": int(time.time()) - 1000,
        })
        with patch.object(OAuthFlow, "refresh", return_value={
            "access_token": "new_tok",
            "refresh_token": "new_r",
            "token_expires_at": int(time.time()) + 3600,
        }):
            token = OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())
        assert token == "new_tok"
        assert rat_env.tokens.get("rat.oauth2")["access_token"] == "new_tok"

    def test_persist_failure_after_refresh_propagates_and_keeps_token(self, rat_env):
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "old",
            "refresh_token": "r_xyz",
            "token_expires_at": int(time.time()) - 1000,
        })

        def boom(key, data):
            raise RuntimeError("disk full")

        rat_env.store.set = boom
        with patch.object(OAuthFlow, "refresh", return_value={
            "access_token": "new_tok",
            "refresh_token": "new_r",
            "token_expires_at": int(time.time()) + 3600,
        }):
            with pytest.raises(RuntimeError, match="disk full"):
                OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())
        assert rat_env.tokens.get("rat.oauth2")["refresh_token"] == "r_xyz"

    def test_auto_authorize_forwards_callback_server(self, rat_env):
        sentinel = object()
        captured = {}

        def fake_authorize(**kwargs):
            captured.update(kwargs)
            return {"access_token": "auth_tok", "refresh_token": "", "token_expires_at": None}

        with patch.object(OAuthFlow, "authorize", side_effect=fake_authorize):
            token = OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(
                _Auth(), auto_authorize=True, callback_server=sentinel)
        assert token == "auth_tok"
        assert captured["callback_server"] is sentinel

    def test_empty_cached_token_is_failclosed(self, rat_env):
        # An empty-string access_token with no refresh path must NOT be returned;
        # it fails closed to AuthorizationRequired (the `if not access_token` guard).
        rat_env.tokens.set("rat.oauth2", {
            "access_token": "",
            "refresh_token": None,
            "token_expires_at": int(time.time()) + 3600,
        })
        with pytest.raises(AuthorizationRequired):
            OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(_Auth())

    def test_empty_token_from_authorize_is_failclosed(self, rat_env):
        # Even when authorize() succeeds, an empty access_token must fail closed
        # rather than be handed back as a valid Bearer (post-authorize guard).
        with patch.object(OAuthFlow, "authorize", return_value={
            "access_token": "", "refresh_token": "", "token_expires_at": None,
        }):
            with pytest.raises(AuthorizationRequired):
                OAuthFlow(_provider(), resolver=rat_env.resolver).resolve_access_token(
                    _Auth(), auto_authorize=True)
```

- [ ] **Step 3: Run the persistence tests, confirm they FAIL (RED)**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/connections/test_oauth2_flow.py::TestResolveAccessToken -v`
Expected: FAIL — `OAuthFlow.__init__() got an unexpected keyword argument 'resolver'`.

- [ ] **Step 4: Migrate the source — imports + `__init__` (GREEN, part 1)**

In `src/mountainash_auth_client/connections/oauth2/flow.py`, replace the import line
`from mountainash_settings.secrets.registry import get_secrets_backend`
with:
```python
from mountainash_secrets import ClearableStore, NamespacedStore
```
and extend the `TYPE_CHECKING` block to add the resolver type:
```python
if TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver
    from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory
```

Then change `OAuthFlow.__init__` to accept an optional injected resolver:
```python
    def __init__(
        self,
        provider: OAuth2ProviderProfile,
        *,
        resolver: SecretStoreResolver | None = None,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._resolver = resolver
        self._pending_verifiers: dict[str, str] = {}
        self._last_state: str | None = None
        self._callback_server = callback_server
```

- [ ] **Step 5: Migrate the source — `resolve_access_token` acquisition (GREEN, part 2)**

In `resolve_access_token`, replace these three lines:
```python
        provider = self._provider.NAME
        backend = get_secrets_backend(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth_profile.persist_key()
```
with:
```python
        provider = self._provider.NAME
        if self._resolver is None:
            raise RuntimeError("OAuthFlow.resolve_access_token requires a resolver")
        store = self._resolver.resolve_as(
            auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER, ClearableStore
        )
        backend = NamespacedStore(store, "oauth")
        key = auth_profile.persist_key()
```
Leave the rest of the method (every `backend.get/.transaction/.delete/.set`) unchanged.

- [ ] **Step 6: Run the persistence tests, confirm PASS (GREEN)**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/connections/test_oauth2_flow.py -v`
Expected: PASS — the whole file (the non-persistence authorize/exchange tests were untouched and still construct `OAuthFlow(_provider())` with no resolver, which is fine because resolver is optional).

- [ ] **Step 7: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth2/flow.py tests/connections/test_oauth2_flow.py
git commit -m "$(cat <<'EOF'
refactor: OAuth2 flow resolves token store via injected resolver

Replaces get_secrets_backend (global mountainash_settings.secrets registry)
with resolver.resolve_as(name, ClearableStore) + NamespacedStore("oauth"),
per mountainash-secrets spec §5.2. Resolver is optional so the non-persistence
flow methods (authorize/exchange/refresh) need no resolver.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: OAuth1 flow → injected resolver

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth1/flow.py`
- Test: `tests/connections/test_oauth1_flow.py`

- [ ] **Step 1: Migrate the test scaffolding (RED)**

In `tests/connections/test_oauth1_flow.py`, replace the block from the second import group through the `rtp_backend` fixture (the `from contextlib import contextmanager` / `from unittest.mock import patch` group, the `from mountainash_settings.secrets.registry import ...` line, `_Mem1Backend`, `_Auth1`, `_clean_rtp`, `rtp_backend`) with EXACTLY:

```python
from types import SimpleNamespace
from unittest.mock import patch

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_secrets import InMemoryStore, NamespacedStore, RegistryResolver


class _Auth1:
    CONSUMER_KEY = "ck"
    CONSUMER_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "cs"})()
    )
    SETTINGS_SOURCE_SECRETS_PROVIDER = "rtp_mem"

    def persist_key(self):
        return "rtp.oauth1"


@pytest.fixture
def rtp_env():
    store = InMemoryStore()
    return SimpleNamespace(
        resolver=RegistryResolver({"rtp_mem": store}),
        tokens=NamespacedStore(store, "oauth"),
        store=store,
    )
```

(Keep `from unittest.mock import patch` — it is used by the tests below. As in
Task 2, the `from contextlib import contextmanager` local import is removed
because it existed only for `_Mem1Backend`; if ruff later reports it is still
used by a callback/echo-server helper above the migrated block in this file,
keep it.)

- [ ] **Step 2: Replace the `TestResolveTokenPair` class**

Replace the entire `class TestResolveTokenPair:` block with EXACTLY:

```python
class TestResolveTokenPair:
    def test_returns_cached_pair(self, rtp_env):
        rtp_env.tokens.set("rtp.oauth1", {"oauth_token": "AT", "oauth_token_secret": "ATS"})
        pair = OAuth1Flow(_provider(), resolver=rtp_env.resolver).resolve_token_pair(_Auth1())
        assert pair == ("AT", "ATS")

    def test_raises_when_no_token_and_not_auto(self, rtp_env):
        with pytest.raises(AuthorizationRequired) as exc:
            OAuth1Flow(_provider(), resolver=rtp_env.resolver).resolve_token_pair(_Auth1())
        assert exc.value.provider == "testprovider_oauth1"

    def test_auto_authorize_persists_and_returns_pair(self, rtp_env):
        with patch.object(OAuth1Flow, "authorize", return_value={
            "oauth_token": "newAT", "oauth_token_secret": "newATS",
        }):
            pair = OAuth1Flow(_provider(), resolver=rtp_env.resolver).resolve_token_pair(
                _Auth1(), auto_authorize=True)
        assert pair == ("newAT", "newATS")
        assert rtp_env.tokens.get("rtp.oauth1")["oauth_token"] == "newAT"

    def test_auto_authorize_forwards_callback_server(self, rtp_env):
        sentinel = object()
        captured = {}

        def fake_authorize(**kwargs):
            captured.update(kwargs)
            return {"oauth_token": "AT", "oauth_token_secret": "ATS"}

        with patch.object(OAuth1Flow, "authorize", side_effect=fake_authorize):
            OAuth1Flow(_provider(), resolver=rtp_env.resolver).resolve_token_pair(
                _Auth1(), auto_authorize=True, callback_server=sentinel)
        assert captured["callback_server"] is sentinel
```

- [ ] **Step 3: Run the persistence tests, confirm FAIL (RED)**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/connections/test_oauth1_flow.py::TestResolveTokenPair -v`
Expected: FAIL — `OAuth1Flow.__init__() got an unexpected keyword argument 'resolver'`.

- [ ] **Step 4: Migrate the source — imports + `__init__`**

In `src/mountainash_auth_client/connections/oauth1/flow.py`, replace the import line
`from mountainash_settings.secrets.registry import get_secrets_backend`
with:
```python
from mountainash_secrets import ClearableStore, NamespacedStore
```
and extend the `TYPE_CHECKING` block:
```python
if TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver
    from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory
```
Change `OAuth1Flow.__init__`:
```python
    def __init__(
        self,
        provider: OAuth1ProviderProfile,
        *,
        resolver: SecretStoreResolver | None = None,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._resolver = resolver
        self._callback_server = callback_server
```

- [ ] **Step 5: Migrate the source — `resolve_token_pair` acquisition**

In `resolve_token_pair`, replace these three lines:
```python
        provider = self._provider.NAME
        backend = get_secrets_backend(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth_profile.persist_key()
```
with:
```python
        provider = self._provider.NAME
        if self._resolver is None:
            raise RuntimeError("OAuth1Flow.resolve_token_pair requires a resolver")
        store = self._resolver.resolve_as(
            auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER, ClearableStore
        )
        backend = NamespacedStore(store, "oauth")
        key = auth_profile.persist_key()
```
Leave the rest (`backend.get`, `backend.set`) unchanged.

- [ ] **Step 6: Run the file, confirm PASS (GREEN)**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/connections/test_oauth1_flow.py -v`
Expected: PASS (the authorize/request-token tests above were untouched).

- [ ] **Step 7: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth1/flow.py tests/connections/test_oauth1_flow.py
git commit -m "$(cat <<'EOF'
refactor: OAuth1 flow resolves token store via injected resolver

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: OAuth2 connection → required resolver

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth2/connection.py`
- Test: `tests/connections/test_oauth2_connection.py`

- [ ] **Step 1: Replace the whole test file (RED)**

Overwrite `tests/connections/test_oauth2_connection.py` with EXACTLY:

```python
"""Tests for the parameterised OAuth2Connection."""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.connections.oauth2.connection import OAuth2Connection
from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
from mountainash_secrets import InMemoryStore, NamespacedStore, RegistryResolver


def _provider():
    return OAuth2ProviderProfile(
        NAME="testprovider",
        AUTHORIZE_URL="https://auth.example.com/authorize",
        TOKEN_URL="https://auth.example.com/token",
        BASE_URL="https://api.example.com",
    )


class FakeAuth:
    CLIENT_ID = "cid"
    CLIENT_SECRET = property(lambda self: type("S", (), {"get_secret_value": lambda s: "csec"})())
    SCOPE = "read"
    SETTINGS_SOURCE_SECRETS_PROVIDER = "test_mem"

    def persist_key(self):
        return "test.oauth2"


@pytest.fixture
def env():
    # `tokens` is the "oauth"-namespaced view the flow persists through.
    store = InMemoryStore()
    return SimpleNamespace(
        resolver=RegistryResolver({"test_mem": store}),
        tokens=NamespacedStore(store, "oauth"),
        store=store,
    )


class TestNoToken:
    def test_raises_authorization_required_when_no_token(self, env):
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        with pytest.raises(AuthorizationRequired) as exc_info:
            conn.connect()
        assert exc_info.value.provider == "testprovider"


class TestWithToken:
    def _seed(self, env):
        env.tokens.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })

    def test_connect_returns_self(self, env):
        self._seed(env)
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        assert conn.connect() is conn

    def test_client_set_after_connect(self, env):
        self._seed(env)
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        conn.connect()
        assert conn.client is not None

    def test_client_has_bearer_header(self, env):
        self._seed(env)
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        conn.connect()
        assert "Bearer tok_abc" in conn.client.headers.get("authorization", "")

    def test_client_base_url_from_provider(self, env):
        self._seed(env)
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        conn.connect()
        assert str(conn.client.base_url) == "https://api.example.com"


class TestExpiredToken:
    def test_raises_when_expired_and_no_refresh(self, env):
        env.tokens.set("test.oauth2", {
            "access_token": "old_tok",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        with pytest.raises(AuthorizationRequired):
            conn.connect()


class TestResolverSeam:
    def test_uses_resolved_token_for_bearer_header(self, env):
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "resolved_tok"
            conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
            conn.connect()
        assert "Bearer resolved_tok" in conn.client.headers.get("authorization", "")

    def test_forwards_auto_authorize_and_callback_server(self, env):
        sentinel = object()
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "tok"
            conn = OAuth2Connection(
                _provider(), FakeAuth(), resolver=env.resolver,
                auto_authorize=True, callback_server=sentinel)
            conn.connect()
            _, kwargs = flow_cls.return_value.resolve_access_token.call_args
        assert kwargs["auto_authorize"] is True
        assert kwargs["callback_server"] is sentinel


class TestClientProperty:
    def test_client_none_before_connect(self, env):
        conn = OAuth2Connection(_provider(), FakeAuth(), resolver=env.resolver)
        assert conn.client is None

    def test_context_manager_closes_client(self, env):
        env.tokens.set("test.oauth2", {
            "access_token": "tok_abc", "refresh_token": "r",
            "token_expires_at": int(time.time()) + 3600,
        })
        with OAuth2Connection(
            _provider(), FakeAuth(), resolver=env.resolver).connect() as conn:
            assert conn.client is not None
        assert conn.client is None
```

- [ ] **Step 2: Run it, confirm FAIL (RED)**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/connections/test_oauth2_connection.py -v`
Expected: FAIL — `OAuth2Connection.__init__() got an unexpected keyword argument 'resolver'`.

- [ ] **Step 3: Migrate the source**

In `src/mountainash_auth_client/connections/oauth2/connection.py`, add the resolver type to the `TYPE_CHECKING` block:
```python
if TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver
    from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
    from mountainash_auth_client.schemas.oauth2 import OAuth2AuthProfile
    from mountainash_auth_client.schemas.oauth2_authcode import OAuth2AuthCodeAuthProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory
```
Change `__init__` to require a resolver and store it:
```python
    def __init__(
        self,
        provider: OAuth2ProviderProfile,
        auth_profile: OAuth2AuthProfile | OAuth2AuthCodeAuthProfile,
        *,
        resolver: SecretStoreResolver,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._auth = auth_profile
        self._resolver = resolver
        self._auto_authorize = auto_authorize
        self._callback_server = callback_server
        self._client: httpx.Client | None = None
```
Change `connect()` to pass the resolver into the flow:
```python
    def connect(self) -> Self:
        token = OAuthFlow(self._provider, resolver=self._resolver).resolve_access_token(
            self._auth,
            auto_authorize=self._auto_authorize,
            callback_server=self._callback_server,
        )
        base = self._provider.emit(TargetFamily.HTTP)
        merged = TokenAuthProfile(TOKEN=token).emit(TargetFamily.HTTP, base=base)
        merged.setdefault("timeout", 30.0)
        self._client = httpx.Client(**merged)
        return self
```

- [ ] **Step 4: Run it, confirm PASS (GREEN)**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/connections/test_oauth2_connection.py -v`
Expected: PASS (all classes).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth2/connection.py tests/connections/test_oauth2_connection.py
git commit -m "$(cat <<'EOF'
refactor: OAuth2Connection takes a required resolver, passes it to the flow

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: OAuth1 connection → required resolver

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth1/connection.py`
- Test: `tests/connections/test_oauth1_connection.py`

- [ ] **Step 1: Replace the whole test file (RED)**

Overwrite `tests/connections/test_oauth1_connection.py` with EXACTLY:

```python
"""Tests for the parameterised OAuth1Connection."""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from mountainash_auth_client.connections.oauth1.connection import OAuth1Connection
from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
from mountainash_secrets import InMemoryStore, RegistryResolver


def _provider():
    return OAuth1ProviderProfile(
        NAME="testprovider_oauth1",
        REQUEST_TOKEN_URL="https://auth.example.com/request_token",
        AUTHORIZE_URL="https://auth.example.com/authorize",
        ACCESS_TOKEN_URL="https://auth.example.com/access_token",
        BASE_URL="https://api.example.com",
    )


class FakeAuth:
    CONSUMER_KEY = "consumer_key"
    CONSUMER_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "consumer_secret"})()
    )
    SETTINGS_SOURCE_SECRETS_PROVIDER = "test_mem_oauth1"

    def persist_key(self):
        return "test.oauth1"


@pytest.fixture
def resolver():
    return RegistryResolver({"test_mem_oauth1": InMemoryStore()})


class _StubSigner(httpx.Auth):
    """A valid httpx auth object standing in for authlib's OAuth1Auth.

    authlib is an OPTIONAL `[oauth1]` extra and is NOT installed in the local
    dev venv, so the connection's real emit path (which calls
    `require_authlib("OAuth1Auth")` inside `_oauth1_signer`) would raise
    ImportError rather than build a client. Patching the `require_authlib`
    seam to return this stub lets the wiring (resolved pair -> emit -> client
    with provider base_url + an `auth` signer) be verified green in any env,
    while still exercising the genuine two-stage emit.
    """

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def auth_flow(self, request):
        yield request


class TestConnect:
    def test_connect_builds_signed_client_from_resolved_pair(self, monkeypatch, resolver):
        captured = {}

        def fake_resolve(self, auth_profile, *, auto_authorize=False, callback_server=None):
            captured["auto_authorize"] = auto_authorize
            captured["callback_server"] = callback_server
            return ("AT", "ATS")

        monkeypatch.setattr(
            "mountainash_auth_client.connections.oauth1.flow.OAuth1Flow.resolve_token_pair",
            fake_resolve,
        )

        def _stub_require_authlib(name):
            assert name == "OAuth1Auth"
            return _StubSigner

        monkeypatch.setattr(
            "mountainash_auth_client.schemas.oauth1.require_authlib",
            _stub_require_authlib,
        )
        sentinel = object()
        conn = OAuth1Connection(
            _provider(), FakeAuth(), resolver=resolver,
            auto_authorize=True, callback_server=sentinel)
        conn.connect()

        assert captured["auto_authorize"] is True
        assert captured["callback_server"] is sentinel
        assert str(conn.client.base_url) == "https://api.example.com"
        assert isinstance(conn.client.auth, _StubSigner)
        assert conn.client.auth.kwargs["token"] == "AT"
        assert conn.client.auth.kwargs["token_secret"] == "ATS"

    def test_client_none_before_connect(self, resolver):
        conn = OAuth1Connection(_provider(), FakeAuth(), resolver=resolver)
        assert conn.client is None
```

- [ ] **Step 2: Run it, confirm FAIL (RED)**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/connections/test_oauth1_connection.py -v`
Expected: FAIL — `OAuth1Connection.__init__() got an unexpected keyword argument 'resolver'`.

- [ ] **Step 3: Migrate the source**

In `src/mountainash_auth_client/connections/oauth1/connection.py`, add the resolver type to `TYPE_CHECKING`:
```python
if TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver
    from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory
```
Change `__init__`:
```python
    def __init__(
        self,
        provider: OAuth1ProviderProfile,
        auth_profile: OAuth1AuthProfile,
        *,
        resolver: SecretStoreResolver,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._auth = auth_profile
        self._resolver = resolver
        self._auto_authorize = auto_authorize
        self._callback_server = callback_server
        self._client: httpx.Client | None = None
```
Change the first line of `connect()` to pass the resolver:
```python
        oauth_token, oauth_token_secret = OAuth1Flow(
            self._provider, resolver=self._resolver
        ).resolve_token_pair(
            self._auth,
            auto_authorize=self._auto_authorize,
            callback_server=self._callback_server,
        )
```
Leave the rest of `connect()` unchanged.

- [ ] **Step 4: Run it, confirm PASS (GREEN)**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/connections/test_oauth1_connection.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth1/connection.py tests/connections/test_oauth1_connection.py
git commit -m "$(cat <<'EOF'
refactor: OAuth1Connection takes a required resolver, passes it to the flow

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Full suite, lint, and dead-import audit

**Files:** none (verification only)

- [ ] **Step 1: Assert no `mountainash_settings.secrets` reference remains in src**

Run: `grep -rnE "mountainash_settings\.secrets|get_secrets_backend\(" src tests`
Expected: NO output (exit 1). The pattern is deliberately narrow — the import path `mountainash_settings.secrets` and actual `get_secrets_backend(` call sites — so an incidental word mention doesn't trigger a false hit. If anything prints, it is a live reference; migrate that site before continuing — the goal of this plan is to sever that dependency entirely.

- [ ] **Step 2: Run the full test suite**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest -q`
Expected: PASS — the full auth-client suite green (the four migrated test files plus everything untouched).

- [ ] **Step 3: Run the lint gate**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m ruff check src tests`
Expected: `All checks passed!`. If ruff reports unused imports (e.g. a leftover `contextmanager` in a migrated test file), run `... -m ruff check --fix src tests`, re-run Step 2, and review the diff.

- [ ] **Step 4: Commit any lint fixes (only if Step 3 changed files)**

```bash
git add -A
git commit -m "$(cat <<'EOF'
style: ruff clean after OAuth secrets-resolver migration

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Push and open the PR**

```bash
git push -u origin feature/oauth-secrets-resolver
gh pr create --base develop --title "refactor: OAuth token persistence via injected mountainash-secrets resolver" --body "$(cat <<'EOF'
Migrates OAuth2/OAuth1 token persistence off the global mountainash_settings.secrets
registry onto an injected mountainash_secrets.SecretStoreResolver, per the
mountainash-secrets spec §4.4/§5.2 (resolve_as + NamespacedStore("oauth")).

- Flows gain an optional injected resolver; only the persistence methods need it.
- Connections gain a required resolver and pass it down.
- get/set/delete/transaction sequence and persist_key() unchanged.
- auth-client no longer imports mountainash_settings.secrets.

Unblocks the wearables migration (it becomes the composition root that builds the
resolver + registers a mountainash_secrets.FilesystemStore).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Out of scope (later steps)

- **Wearables PR3** (the composition root): build a `RegistryResolver`, register a `mountainash_secrets.FilesystemStore`, inject it into the connections; migrate descriptors → ProviderProfile; rewire its own token store. Separate plan, separate repo.
- **settings deprecation shim** (§7.3) and **SDK store adapters** (§7.2) — not on the wearables path.
- Promoting `SETTINGS_SOURCE_SECRETS_PROVIDER` / `persist_key()` to typed ParameterSpec fields on the auth profiles — deferred (they remain client-supplied dynamic attributes, unchanged by this plan).

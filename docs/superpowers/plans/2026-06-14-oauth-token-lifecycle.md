# OAuth Token-Lifecycle Capability — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generic, reusable OAuth token-lifecycle capability to mountainash-auth-client — `OAuth2TokenManager` / `OAuth1TokenManager` (authorize / status / refresh / access_token / revoke) — backed by the §7.4 resolver persistence, with identity promoted to a typed `PersistableAuthProfile` contract.

**Architecture:** A leaf `persistence.py` (depends only on `mountainash_secrets`) defines the `PersistableAuthProfile` Protocol and the `token_store()` addressing helper. The two existing flows are refactored onto `token_store()`. A new `lifecycle/` package adds a typed `TokenStatus`/`TokenState` model, an OAuth2 classifier, and the two managers, which compose the existing flows + callback factory and serialize every mutation through the per-key `transaction(key)`.

**Tech Stack:** Python ≥3.10, httpx, pydantic, mountainash-secrets, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-06-14-oauth-token-lifecycle-design.md` (read it before starting; §5.1 = the write discipline, §4 = key grammar, §6 = status model).

**Conventions for every task:**
- **Repo root:** `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client` (CWD for all commands).
- **Test runner (PY):** `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest`
- **Lint gate:** `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/ruff check src tests` (no mypy env).
- `mountainash_secrets` is editable-installed in that venv. `CapabilityError`, `InMemoryStore`, `NamespacedStore`, `RegistryResolver`, `ClearableStore`, `SecretStoreResolver` import from its top level; `FilesystemStore` imports from `mountainash_secrets.stores.filesystem`.
- Commit messages end with the `Co-Authored-By` trailer shown in Task 1.
- **authlib note:** authlib is the `[oauth1]` extra and is NOT installed in the dev venv. No test in this plan may require it — the OAuth1 manager tests patch `OAuth1Flow.authorize`/`resolve_token_pair` (the interactive/authlib path), and status/revoke touch only the store.

**Branch:** `feature/oauth-token-lifecycle` (already created off `develop`; the design spec is already committed at `a5c29a9`). Start at Task 1.

**Pinned upstream signatures (already on `develop` — do not change them, call them):**
- `OAuthFlow.__init__(provider, *, resolver=None, callback_server=None)` (OAuth2 flow class is named `OAuthFlow`).
- `OAuthFlow.authorize(client_id, client_secret, redirect_mode="local_server", scope=None, callback_server=None) -> dict`
- `OAuthFlow.resolve_access_token(auth_profile, *, auto_authorize=False, callback_server=None) -> str`
- `OAuth1Flow.__init__(provider, *, resolver=None, callback_server=None)`
- `OAuth1Flow.authorize(consumer_key, consumer_secret, redirect_mode="local_server", callback_server=None) -> dict`
- `OAuth1Flow.resolve_token_pair(auth_profile, *, auto_authorize=False, callback_server=None) -> tuple[str, str]`
- `resolve_callback_factory(*, redirect_mode, callback_server, instance_default, callback_port=None, manual_redirect_uri=None) -> CallbackServerFactory` (all keyword-only; precedence: explicit `callback_server` → `instance_default` → built-in by `redirect_mode`).
- `OAuth2ProviderProfile` / `OAuth1ProviderProfile` both expose `NAME` and `CALLBACK_PORT`.
- `OAuth2AuthCodeAuthProfile` fields: `CLIENT_ID`, `CLIENT_SECRET` (secret), `SCOPE`, `ACCESS_TOKEN`/`REFRESH_TOKEN`/`TOKEN_EXPIRES_AT`. `OAuth1AuthProfile`: `CONSUMER_KEY`, `CONSUMER_SECRET` (secret). Neither defines `persist_key`/`SETTINGS_SOURCE_SECRETS_PROVIDER` — consumers add them (Task 1 makes the contract typed).
- `AuthorizationRequired(provider=..., user=...)`.

---

## File Structure

```
src/mountainash_auth_client/
  persistence.py                 # Task 1 — PersistableAuthProfile + token_store()
  connections/oauth2/flow.py     # Task 2 — acquisition → token_store(); typed param
  connections/oauth1/flow.py     # Task 2 — same
  lifecycle/__init__.py          # Task 6 — package exports
  lifecycle/status.py            # Task 3 — TokenState + TokenStatus + classify_oauth2
  lifecycle/oauth2.py            # Task 4 — OAuth2TokenManager
  lifecycle/oauth1.py            # Task 5 — OAuth1TokenManager
  __init__.py                    # Task 6 — re-export public surface
tests/
  test_persistence.py            # Task 1
  lifecycle/test_status.py       # Task 3
  lifecycle/test_oauth2_manager.py  # Task 4
  lifecycle/test_oauth1_manager.py  # Task 5
  test_lifecycle_exports.py      # Task 6
```

---

## Task 1: `persistence.py` — `PersistableAuthProfile` + `token_store()`

**Files:**
- Create: `src/mountainash_auth_client/persistence.py`
- Test: `tests/test_persistence.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_persistence.py`:
```python
from __future__ import annotations

import pytest

from mountainash_auth_client.persistence import PersistableAuthProfile, token_store
from mountainash_secrets import (
    CapabilityError,
    InMemoryStore,
    NamespacedStore,
    RegistryResolver,
)


class _Auth:
    SETTINGS_SOURCE_SECRETS_PROVIDER = "mem"

    def persist_key(self) -> str:
        return "garmin.default"


class _ReadOnly:
    """Satisfies SecretReader (get only) — NOT ClearableStore."""

    def get(self, key):
        return None


def test_satisfies_persistable_protocol():
    assert isinstance(_Auth(), PersistableAuthProfile)


def test_token_store_namespaces_under_oauth():
    store = InMemoryStore()
    resolver = RegistryResolver({"mem": store})
    ts = token_store(resolver, _Auth())
    assert isinstance(ts, NamespacedStore)
    ts.set("k", {"v": 1})
    # The raw underlying key carries the dot-prefixed "oauth" namespace.
    assert store.get("oauth.k") == {"v": 1}


def test_token_store_capability_error_for_read_only_store():
    resolver = RegistryResolver({"mem": _ReadOnly()})
    with pytest.raises(CapabilityError):
        token_store(resolver, _Auth())
```

- [ ] **Step 2: Run it, confirm it FAILS**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_persistence.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mountainash_auth_client.persistence'`.

- [ ] **Step 3: Create the module**

Create `src/mountainash_auth_client/persistence.py`:
```python
"""OAuth token persistence contract + addressing helper.

Single home for the §7.4 storage contract used by both the flows and the
lifecycle managers: WHERE tokens live (the named store, the "oauth" namespace)
and the typed identity an auth profile must carry.
"""
from __future__ import annotations

import typing as t

from mountainash_secrets import ClearableStore, NamespacedStore

if t.TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver

__all__ = ["PersistableAuthProfile", "token_store"]


@t.runtime_checkable
class PersistableAuthProfile(t.Protocol):
    """An auth profile that knows WHERE its tokens persist and under WHAT key.

    `SETTINGS_SOURCE_SECRETS_PROVIDER` names the store registered in the
    consumer's SecretStoreResolver. `persist_key()` returns a per-(provider,
    account) key, unique within that store, composed of `[a-z0-9_]+` segments
    joined by "." (no "/", "\\", "..", empty segments, or a leading "oauth"/
    "cred" segment). auth-client defines the contract; consumers supply values.
    """

    SETTINGS_SOURCE_SECRETS_PROVIDER: str

    def persist_key(self) -> str: ...


def token_store(
    resolver: SecretStoreResolver,
    auth_profile: PersistableAuthProfile,
) -> NamespacedStore:
    """Resolve the OAuth token store for an auth profile.

    Resolves the named store as a ClearableStore (raising CapabilityError if it
    cannot clear), then namespaces it under "oauth". Every OAuth-token read or
    write — flow OR manager — goes through this, so the namespace/capability
    decision lives in one place. Mutation *ordering* is the caller's job, via
    `transaction(key)` (see the design spec §5.1).
    """
    store = resolver.resolve_as(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER, ClearableStore)
    return NamespacedStore(store, "oauth")
```

- [ ] **Step 4: Run it, confirm PASS**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_persistence.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/persistence.py tests/test_persistence.py
git commit -m "$(cat <<'EOF'
feat: PersistableAuthProfile contract + token_store() addressing helper

Typed identity contract (persist_key + SETTINGS_SOURCE_SECRETS_PROVIDER) and a
single home for the "oauth"-namespaced store resolution, per the token-lifecycle
design spec §4/§5.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Refactor the flows onto `token_store()`

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth2/flow.py`
- Modify: `src/mountainash_auth_client/connections/oauth1/flow.py`
- Test: existing `tests/connections/test_oauth2_flow.py`, `tests/connections/test_oauth1_flow.py` (must stay green — behaviour is identical).

Two changes per flow: (a) the §7.4 two-line acquisition becomes one `token_store()` call (pure DRY), and (b) the existing `auto_authorize=True` persist path — which currently calls `backend.set(...)` **outside** any transaction — is wrapped in `with backend.transaction(key):` to bring it into spec §5.1 compliance (every mutation serialized). Both are behaviour-preserving in single-threaded tests, so the existing flow suites are the safety net (wrapping a `set` in the per-key lock does not change observable single-threaded behaviour).

- [ ] **Step 1: Confirm the flow suites are green BEFORE the change**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/connections/test_oauth2_flow.py tests/connections/test_oauth1_flow.py -q`
Expected: PASS (baseline — note the count).

- [ ] **Step 2: Refactor `oauth2/flow.py`**

In `src/mountainash_auth_client/connections/oauth2/flow.py`:
- Replace the runtime import line `from mountainash_secrets import ClearableStore, NamespacedStore` with:
  ```python
  from mountainash_auth_client.persistence import token_store
  ```
- In the `TYPE_CHECKING` block, add (for typing the param):
  ```python
      from mountainash_auth_client.persistence import PersistableAuthProfile
  ```
  (Keep the existing `from mountainash_secrets import SecretStoreResolver` and the provider/protocol imports.)
- In `resolve_access_token`, replace these four lines:
  ```python
          store = self._resolver.resolve_as(
              auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER, ClearableStore
          )
          backend = NamespacedStore(store, "oauth")
  ```
  with:
  ```python
          backend = token_store(self._resolver, auth_profile)
  ```
  (Leave the `provider = self._provider.NAME` line, the `if self._resolver is None:` guard immediately above, `key = auth_profile.persist_key()`, and every `backend.*` call UNCHANGED.)
- Type the parameter: change the `resolve_access_token` signature's `auth_profile,` to `auth_profile: PersistableAuthProfile,` (the file has `from __future__ import annotations`, so the annotation is a string and the `TYPE_CHECKING` import suffices). If `from __future__ import annotations` is NOT at the top of the file, add it as the first import line.
- **Serialize the `auto_authorize` write (§5.1).** In the same method, find the `if not access_token and auto_authorize:` block, whose `self.authorize(...)` call is immediately followed by `backend.set(key, new_tokens)`. Wrap **only the set** (leave the interactive `self.authorize(...)` call outside the lock):
  ```python
          if not access_token and auto_authorize:
              new_tokens = self.authorize(
                  client_id=auth_profile.CLIENT_ID,
                  client_secret=auth_profile.CLIENT_SECRET.get_secret_value(),
                  scope=auth_profile.SCOPE,
                  callback_server=callback_server,
              )
              with backend.transaction(key):
                  backend.set(key, new_tokens)
              access_token = new_tokens["access_token"]
  ```
  (The earlier refresh path is already inside its own `with backend.transaction(key):` — leave it as is.)

- [ ] **Step 3: Refactor `oauth1/flow.py` identically**

In `src/mountainash_auth_client/connections/oauth1/flow.py`:
- Replace `from mountainash_secrets import ClearableStore, NamespacedStore` with `from mountainash_auth_client.persistence import token_store`.
- Add `from mountainash_auth_client.persistence import PersistableAuthProfile` to the `TYPE_CHECKING` block.
- In `resolve_token_pair`, replace:
  ```python
          store = self._resolver.resolve_as(
              auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER, ClearableStore
          )
          backend = NamespacedStore(store, "oauth")
  ```
  with `backend = token_store(self._resolver, auth_profile)` (leave the guard, `key`, and `backend.get`/`backend.set` calls unchanged).
- Type the param `auth_profile: PersistableAuthProfile`.
- **Serialize the `auto_authorize` write (§5.1).** In `resolve_token_pair`, find the `if auto_authorize:` block whose `self.authorize(...)` is followed by `backend.set(key, new_tokens)`. Wrap only the set:
  ```python
          if auto_authorize:
              new_tokens = self.authorize(
                  consumer_key=auth_profile.CONSUMER_KEY,
                  consumer_secret=auth_profile.CONSUMER_SECRET.get_secret_value(),
                  callback_server=callback_server,
              )
              with backend.transaction(key):
                  backend.set(key, new_tokens)
              return new_tokens["oauth_token"], new_tokens["oauth_token_secret"]
  ```

- [ ] **Step 4: Run the flow suites, confirm still green**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/connections/test_oauth2_flow.py tests/connections/test_oauth1_flow.py -q`
Expected: PASS — identical count to Step 1 (including `test_persists_under_oauth_namespace_in_raw_store`, which proves the `"oauth."` prefix is unchanged).

- [ ] **Step 5: Lint the touched files (catch unused imports)**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/ruff check src/mountainash_auth_client/connections/oauth2/flow.py src/mountainash_auth_client/connections/oauth1/flow.py`
Expected: `All checks passed!` (if it flags a now-unused `ClearableStore`/`NamespacedStore`, the replacement above missed a usage — remove the dead import).

- [ ] **Step 6: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth2/flow.py src/mountainash_auth_client/connections/oauth1/flow.py
git commit -m "$(cat <<'EOF'
refactor: flows resolve token store via shared token_store() helper

Behaviour-identical DRY: the §7.4 resolve_as + NamespacedStore("oauth")
acquisition moves into persistence.token_store(); auth_profile typed against
PersistableAuthProfile.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `lifecycle/status.py` — `TokenState` + `TokenStatus` + `classify_oauth2`

**Files:**
- Create: `src/mountainash_auth_client/lifecycle/__init__.py` (empty for now — package marker; Task 6 fills it)
- Create: `src/mountainash_auth_client/lifecycle/status.py`
- Test: `tests/lifecycle/test_status.py`

- [ ] **Step 1: Write the failing test**

Create `tests/lifecycle/test_status.py`:
```python
from __future__ import annotations

from mountainash_auth_client.lifecycle.status import (
    TokenState,
    TokenStatus,
    classify_oauth2,
)

NOW = 1_000_000


def test_missing_when_record_none():
    assert classify_oauth2(None, now=NOW) == TokenStatus(TokenState.MISSING)


def test_valid_when_no_expiry():
    s = classify_oauth2({"access_token": "a", "refresh_token": "r"}, now=NOW)
    assert s.state is TokenState.VALID
    assert s.expires_at is None
    assert s.has_refresh_token is True


def test_valid_well_before_buffer():
    s = classify_oauth2({"access_token": "a", "token_expires_at": NOW + 4000}, now=NOW)
    assert s.state is TokenState.VALID
    assert s.expires_in_seconds == 4000
    assert s.has_refresh_token is False


def test_refresh_needed_inside_buffer():
    s = classify_oauth2(
        {"access_token": "a", "refresh_token": "r", "token_expires_at": NOW + 100},
        buffer_seconds=300,
        now=NOW,
    )
    assert s.state is TokenState.REFRESH_NEEDED
    assert s.expires_in_seconds == 100
    assert s.has_refresh_token is True


def test_expired_at_or_past_expiry():
    s = classify_oauth2({"access_token": "a", "token_expires_at": NOW}, now=NOW)
    assert s.state is TokenState.EXPIRED
    assert s.expires_at == NOW
```

- [ ] **Step 2: Run it, confirm FAIL**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/lifecycle/test_status.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mountainash_auth_client.lifecycle'`.

- [ ] **Step 3: Create the package + module**

Create empty `src/mountainash_auth_client/lifecycle/__init__.py`:
```python
```
Create `src/mountainash_auth_client/lifecycle/status.py`:
```python
"""Typed OAuth token status model + OAuth2 expiry classifier."""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass

__all__ = ["TokenState", "TokenStatus", "classify_oauth2"]


class TokenState(str, enum.Enum):
    VALID = "valid"                    # present, outside the refresh buffer
    REFRESH_NEEDED = "refresh_needed"  # present, inside the buffer, not past expiry
    EXPIRED = "expired"                # present, at/past expiry
    MISSING = "missing"                # no record
    CLEARED = "cleared"                # explicitly revoked (tombstone)
    PRESENT = "present"                # OAuth1 only — non-expiring pair exists


@dataclass(frozen=True)
class TokenStatus:
    state: TokenState
    expires_at: int | None = None
    expires_in_seconds: int | None = None
    has_refresh_token: bool = False


def classify_oauth2(
    record: dict | None,
    *,
    buffer_seconds: int = 300,
    now: float | None = None,
) -> TokenStatus:
    """Classify an OAuth2 token record. `now` is injectable for tests.

    Buffer-aligned with the flow's is_expired(buffer=300) so status() and the
    flow's refresh decision agree at the boundary.
    """
    if record is None:
        return TokenStatus(TokenState.MISSING)
    has_refresh = bool(record.get("refresh_token"))
    expires_at = record.get("token_expires_at")
    if expires_at is None:
        return TokenStatus(TokenState.VALID, expires_at=None, has_refresh_token=has_refresh)
    current = time.time() if now is None else now
    if current >= expires_at:
        return TokenStatus(
            TokenState.EXPIRED, expires_at=expires_at, has_refresh_token=has_refresh
        )
    expires_in = int(expires_at - current)
    if current >= expires_at - buffer_seconds:
        return TokenStatus(
            TokenState.REFRESH_NEEDED,
            expires_at=expires_at,
            expires_in_seconds=expires_in,
            has_refresh_token=has_refresh,
        )
    return TokenStatus(
        TokenState.VALID,
        expires_at=expires_at,
        expires_in_seconds=expires_in,
        has_refresh_token=has_refresh,
    )
```

- [ ] **Step 4: Run it, confirm PASS**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/lifecycle/test_status.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/lifecycle/__init__.py src/mountainash_auth_client/lifecycle/status.py tests/lifecycle/test_status.py
git commit -m "$(cat <<'EOF'
feat: TokenState/TokenStatus model + OAuth2 expiry classifier

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `lifecycle/oauth2.py` — `OAuth2TokenManager`

**Files:**
- Create: `src/mountainash_auth_client/lifecycle/oauth2.py`
- Test: `tests/lifecycle/test_oauth2_manager.py`

- [ ] **Step 1: Write the failing test**

Create `tests/lifecycle/test_oauth2_manager.py`:
```python
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from mountainash_auth_client.lifecycle.oauth2 import OAuth2TokenManager
from mountainash_auth_client.lifecycle.status import TokenState
from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
from mountainash_auth_client.connections.server.manual import ManualCallbackServer
from mountainash_secrets import InMemoryStore, NamespacedStore, RegistryResolver
from mountainash_secrets.stores.filesystem import FilesystemStore


def _provider():
    return OAuth2ProviderProfile(
        NAME="testprovider",
        AUTHORIZE_URL="https://auth.example.com/authorize",
        TOKEN_URL="https://auth.example.com/token",
        BASE_URL="https://api.example.com",
    )


class _Auth:
    CLIENT_ID = "cid"
    CLIENT_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "csec"})()
    )
    SCOPE = "read"
    SETTINGS_SOURCE_SECRETS_PROVIDER = "mem"

    def persist_key(self) -> str:
        return "testprovider.default"


def _env():
    store = InMemoryStore()
    return (
        OAuth2TokenManager(_provider(), _Auth(), resolver=RegistryResolver({"mem": store})),
        NamespacedStore(store, "oauth"),  # the "oauth"-namespaced view to seed/read
    )


def test_status_missing():
    mgr, _ = _env()
    assert mgr.status().state is TokenState.MISSING


def test_status_valid_and_expired_and_refresh_needed():
    mgr, tokens = _env()
    tokens.set("testprovider.default", {"access_token": "a", "token_expires_at": int(time.time()) + 4000})
    assert mgr.status().state is TokenState.VALID
    tokens.set("testprovider.default", {"access_token": "a", "token_expires_at": int(time.time()) - 10})
    assert mgr.status().state is TokenState.EXPIRED
    tokens.set("testprovider.default", {"access_token": "a", "refresh_token": "r", "token_expires_at": int(time.time()) + 100})
    assert mgr.status().state is TokenState.REFRESH_NEEDED


def test_revoke_then_status_cleared():
    mgr, tokens = _env()
    tokens.set("testprovider.default", {"access_token": "a"})
    mgr.revoke()
    assert mgr.status().state is TokenState.CLEARED


def test_access_token_returns_seeded():
    mgr, tokens = _env()
    tokens.set("testprovider.default", {"access_token": "tok", "token_expires_at": int(time.time()) + 4000})
    assert mgr.access_token() == "tok"


def test_refresh_raises_when_nothing_to_refresh():
    from mountainash_auth_client.errors import AuthorizationRequired

    mgr, _ = _env()
    with pytest.raises(AuthorizationRequired):
        mgr.refresh()


def test_authorize_persists_and_returns_valid():
    mgr, tokens = _env()
    with patch.object(
        type(mgr)._flow_cls(), "authorize",
        return_value={"access_token": "new", "refresh_token": "r", "token_expires_at": int(time.time()) + 3600},
    ):
        status = mgr.authorize()
    assert status.state is TokenState.VALID
    assert tokens.get("testprovider.default")["access_token"] == "new"


def test_revoke_then_authorize_returns_valid():
    mgr, tokens = _env()
    tokens.set("testprovider.default", {"access_token": "old"})
    mgr.revoke()
    with patch.object(
        type(mgr)._flow_cls(), "authorize",
        return_value={"access_token": "fresh", "token_expires_at": int(time.time()) + 3600},
    ):
        status = mgr.authorize()
    assert status.state is TokenState.VALID  # set() cleared the tombstone


def test_authorize_manual_mode_uses_manual_callback_server():
    mgr, _ = _env()
    captured = {}

    def fake_authorize(self, **kwargs):
        captured["callback_server"] = kwargs["callback_server"]
        return {"access_token": "a", "token_expires_at": int(time.time()) + 3600}

    with patch.object(type(mgr)._flow_cls(), "authorize", new=fake_authorize):
        mgr.authorize(mode="manual")
    assert isinstance(captured["callback_server"](), ManualCallbackServer)


@pytest.mark.parametrize("bad_key", ["bad/key", "a..b"])
def test_bad_persist_key_is_rejected_by_filesystem(tmp_path, bad_key):
    # "/" (illegal char) and ".." (empty segment) both violate the §4 grammar;
    # FilesystemStore._key_to_paths validates each segment and raises ValueError.
    class _BadAuth(_Auth):
        SETTINGS_SOURCE_SECRETS_PROVIDER = "fs"

        def persist_key(self) -> str:
            return bad_key

    resolver = RegistryResolver({"fs": FilesystemStore(base_dir=tmp_path)})
    mgr = OAuth2TokenManager(_provider(), _BadAuth(), resolver=resolver)
    with pytest.raises(ValueError):
        mgr.status()  # opens transaction(key) -> _key_to_paths validates the segment
```

(Reserved-namespace avoidance — no leading `oauth`/`cred` segment — is a documented *convention* per spec §4 and mountainash-secrets §10, not enforced in `token_store()`; no test asserts it.)

(`type(mgr)._flow_cls()` returns the `OAuthFlow` class the manager constructs — exposed as a small classmethod so tests patch the exact symbol the manager uses, regardless of import aliasing. Defined in Step 3.)

- [ ] **Step 2: Run it, confirm FAIL**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/lifecycle/test_oauth2_manager.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mountainash_auth_client.lifecycle.oauth2'`.

- [ ] **Step 3: Create the manager**

Create `src/mountainash_auth_client/lifecycle/oauth2.py`:
```python
"""OAuth2 token-lifecycle manager — authorize / refresh / status / revoke."""
from __future__ import annotations

import typing as t

from mountainash_auth_client.connections.oauth2.flow import OAuthFlow
from mountainash_auth_client.connections.server.factory import resolve_callback_factory
from mountainash_auth_client.lifecycle.status import TokenState, TokenStatus, classify_oauth2
from mountainash_auth_client.persistence import token_store

if t.TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver
    from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
    from mountainash_auth_client.persistence import PersistableAuthProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory

__all__ = ["OAuth2TokenManager"]


class OAuth2TokenManager:
    """Full OAuth2 token lifecycle over an injected resolver.

    Manages *tokens* (persisted under the "oauth" namespace by persist_key());
    for an authed httpx client use OAuth2Connection instead. Every mutation is
    serialized through the per-key transaction (design spec §5.1).
    """

    def __init__(
        self,
        provider: OAuth2ProviderProfile,
        auth_profile: PersistableAuthProfile,
        *,
        resolver: SecretStoreResolver,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._auth = auth_profile
        self._resolver = resolver
        self._callback_server = callback_server

    @classmethod
    def _flow_cls(cls) -> type[OAuthFlow]:
        """The flow class this manager constructs (a test seam for patching)."""
        return OAuthFlow

    def _store(self):
        return token_store(self._resolver, self._auth)

    def authorize(self, *, mode: str = "local_server", manual_redirect_uri: str | None = None) -> TokenStatus:
        factory = resolve_callback_factory(
            redirect_mode=mode,
            callback_server=None,
            instance_default=self._callback_server,
            callback_port=self._provider.CALLBACK_PORT,
            manual_redirect_uri=manual_redirect_uri,
        )
        # Interactive dance runs OUTSIDE any lock (can take minutes).
        tokens = self._flow_cls()(self._provider, resolver=self._resolver).authorize(
            client_id=self._auth.CLIENT_ID,
            client_secret=self._auth.CLIENT_SECRET.get_secret_value(),
            scope=self._auth.SCOPE,
            callback_server=factory,
        )
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):  # short serialized write
            backend.set(key, tokens)
        return self.status()

    def refresh(self) -> TokenStatus:
        self._flow_cls()(self._provider, resolver=self._resolver).resolve_access_token(self._auth)
        return self.status()

    def access_token(self) -> str:
        return self._flow_cls()(self._provider, resolver=self._resolver).resolve_access_token(self._auth)

    def status(self) -> TokenStatus:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):  # consistent is_cleared + get snapshot
            cleared = backend.is_cleared(key)
            record = backend.get(key)
        if cleared:
            return TokenStatus(TokenState.CLEARED)
        return classify_oauth2(record)

    def revoke(self) -> None:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            backend.delete(key)
```

- [ ] **Step 4: Run it, confirm PASS**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/lifecycle/test_oauth2_manager.py -v`
Expected: PASS (10 passed — the parametrized bad-key test counts as 2).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/lifecycle/oauth2.py tests/lifecycle/test_oauth2_manager.py
git commit -m "$(cat <<'EOF'
feat: OAuth2TokenManager — authorize/refresh/access_token/status/revoke

Mutations serialized through the per-key transaction; status() is a consistent
is_cleared+get snapshot; authorize() persists wholesale and clears any tombstone.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `lifecycle/oauth1.py` — `OAuth1TokenManager`

**Files:**
- Create: `src/mountainash_auth_client/lifecycle/oauth1.py`
- Test: `tests/lifecycle/test_oauth1_manager.py`

- [ ] **Step 1: Write the failing test**

Create `tests/lifecycle/test_oauth1_manager.py`:
```python
from __future__ import annotations

from unittest.mock import patch

import pytest

from mountainash_auth_client.lifecycle.oauth1 import OAuth1TokenManager
from mountainash_auth_client.lifecycle.status import TokenState
from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
from mountainash_secrets import InMemoryStore, NamespacedStore, RegistryResolver


def _provider():
    return OAuth1ProviderProfile(
        NAME="garmin",
        REQUEST_TOKEN_URL="https://auth.example.com/request_token",
        AUTHORIZE_URL="https://auth.example.com/authorize",
        ACCESS_TOKEN_URL="https://auth.example.com/access_token",
        BASE_URL="https://api.example.com",
    )


class _Auth:
    CONSUMER_KEY = "ck"
    CONSUMER_SECRET = property(
        lambda self: type("S", (), {"get_secret_value": lambda s: "cs"})()
    )
    SETTINGS_SOURCE_SECRETS_PROVIDER = "mem"

    def persist_key(self) -> str:
        return "garmin.default"


def _env():
    store = InMemoryStore()
    return (
        OAuth1TokenManager(_provider(), _Auth(), resolver=RegistryResolver({"mem": store})),
        NamespacedStore(store, "oauth"),
    )


def test_status_missing_then_present_then_cleared():
    mgr, tokens = _env()
    assert mgr.status().state is TokenState.MISSING
    tokens.set("garmin.default", {"oauth_token": "AT", "oauth_token_secret": "ATS"})
    s = mgr.status()
    assert s.state is TokenState.PRESENT
    # OAuth1 invariants:
    assert s.expires_at is None and s.expires_in_seconds is None and s.has_refresh_token is False
    mgr.revoke()
    assert mgr.status().state is TokenState.CLEARED


def test_token_pair_returns_seeded():
    mgr, tokens = _env()
    tokens.set("garmin.default", {"oauth_token": "AT", "oauth_token_secret": "ATS"})
    assert mgr.token_pair() == ("AT", "ATS")


def test_token_pair_raises_when_missing():
    from mountainash_auth_client.errors import AuthorizationRequired

    mgr, _ = _env()
    with pytest.raises(AuthorizationRequired):
        mgr.token_pair()


def test_authorize_persists_and_returns_present():
    mgr, tokens = _env()
    with patch.object(
        type(mgr)._flow_cls(), "authorize",
        return_value={"oauth_token": "newAT", "oauth_token_secret": "newATS"},
    ):
        status = mgr.authorize()
    assert status.state is TokenState.PRESENT
    assert tokens.get("garmin.default")["oauth_token"] == "newAT"
```

- [ ] **Step 2: Run it, confirm FAIL**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/lifecycle/test_oauth1_manager.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mountainash_auth_client.lifecycle.oauth1'`.

- [ ] **Step 3: Create the manager**

Create `src/mountainash_auth_client/lifecycle/oauth1.py`:
```python
"""OAuth1 token-lifecycle manager — authorize / token_pair / status / revoke.

OAuth1 tokens are long-lived (no refresh/expiry), so the surface is smaller than
OAuth2's and status() is PRESENT/MISSING/CLEARED only.
"""
from __future__ import annotations

import typing as t

from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow
from mountainash_auth_client.connections.server.factory import resolve_callback_factory
from mountainash_auth_client.lifecycle.status import TokenState, TokenStatus
from mountainash_auth_client.persistence import token_store

if t.TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver
    from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
    from mountainash_auth_client.persistence import PersistableAuthProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory

__all__ = ["OAuth1TokenManager"]


class OAuth1TokenManager:
    def __init__(
        self,
        provider: OAuth1ProviderProfile,
        auth_profile: PersistableAuthProfile,
        *,
        resolver: SecretStoreResolver,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._auth = auth_profile
        self._resolver = resolver
        self._callback_server = callback_server

    @classmethod
    def _flow_cls(cls) -> type[OAuth1Flow]:
        return OAuth1Flow

    def _store(self):
        return token_store(self._resolver, self._auth)

    def authorize(self, *, mode: str = "local_server", manual_redirect_uri: str | None = None) -> TokenStatus:
        factory = resolve_callback_factory(
            redirect_mode=mode,
            callback_server=None,
            instance_default=self._callback_server,
            callback_port=self._provider.CALLBACK_PORT,
            manual_redirect_uri=manual_redirect_uri or "oob",
        )
        tokens = self._flow_cls()(self._provider, resolver=self._resolver).authorize(
            consumer_key=self._auth.CONSUMER_KEY,
            consumer_secret=self._auth.CONSUMER_SECRET.get_secret_value(),
            callback_server=factory,
        )
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            backend.set(key, tokens)
        return self.status()

    def token_pair(self) -> tuple[str, str]:
        return self._flow_cls()(self._provider, resolver=self._resolver).resolve_token_pair(self._auth)

    def status(self) -> TokenStatus:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            cleared = backend.is_cleared(key)
            record = backend.get(key)
        if cleared:
            return TokenStatus(TokenState.CLEARED)
        if record is None:
            return TokenStatus(TokenState.MISSING)
        return TokenStatus(TokenState.PRESENT)

    def revoke(self) -> None:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            backend.delete(key)
```

- [ ] **Step 4: Run it, confirm PASS**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/lifecycle/test_oauth1_manager.py -v`
Expected: PASS (4 passed). No authlib required (the interactive `authorize` is patched).

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/lifecycle/oauth1.py tests/lifecycle/test_oauth1_manager.py
git commit -m "$(cat <<'EOF'
feat: OAuth1TokenManager — authorize/token_pair/status/revoke

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Public API exports

**Files:**
- Modify: `src/mountainash_auth_client/lifecycle/__init__.py`
- Modify: `src/mountainash_auth_client/__init__.py`
- Test: `tests/test_lifecycle_exports.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_lifecycle_exports.py`:
```python
from __future__ import annotations

import mountainash_auth_client as ac


def test_lifecycle_symbols_exported_at_top_level():
    from mountainash_auth_client import (
        OAuth1TokenManager,
        OAuth2TokenManager,
        PersistableAuthProfile,
        TokenState,
        TokenStatus,
    )

    # Imports are load-bearing: each must be the SAME object on the package and
    # listed in __all__ (so ruff F401 is satisfied and the export is real).
    exported = {
        "OAuth1TokenManager": OAuth1TokenManager,
        "OAuth2TokenManager": OAuth2TokenManager,
        "PersistableAuthProfile": PersistableAuthProfile,
        "TokenState": TokenState,
        "TokenStatus": TokenStatus,
    }
    for name, obj in exported.items():
        assert name in ac.__all__
        assert getattr(ac, name) is obj
```

- [ ] **Step 2: Run it, confirm FAIL**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_lifecycle_exports.py -v`
Expected: FAIL — `ImportError: cannot import name 'OAuth2TokenManager'`.

- [ ] **Step 3: Fill `lifecycle/__init__.py`**

Replace `src/mountainash_auth_client/lifecycle/__init__.py` contents with:
```python
"""OAuth token-lifecycle managers + status model."""
from mountainash_auth_client.lifecycle.oauth1 import OAuth1TokenManager
from mountainash_auth_client.lifecycle.oauth2 import OAuth2TokenManager
from mountainash_auth_client.lifecycle.status import (
    TokenState,
    TokenStatus,
    classify_oauth2,
)

__all__ = [
    "OAuth1TokenManager",
    "OAuth2TokenManager",
    "TokenState",
    "TokenStatus",
    "classify_oauth2",
]
```

- [ ] **Step 4: Add the top-level re-exports**

In `src/mountainash_auth_client/__init__.py`:
- After the existing `from mountainash_auth_client.connections.server.manual import ManualCallbackServer` line, add:
  ```python
  from mountainash_auth_client.persistence import PersistableAuthProfile
  from mountainash_auth_client.lifecycle import (
      OAuth1TokenManager,
      OAuth2TokenManager,
      TokenState,
      TokenStatus,
  )
  ```
- Add these five names to the `__all__` list, preserving alphabetical order:
  `"OAuth1TokenManager"`, `"OAuth2TokenManager"`, `"PersistableAuthProfile"`, `"TokenState"`, `"TokenStatus"`.

- [ ] **Step 5: Run it, confirm PASS**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_lifecycle_exports.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/mountainash_auth_client/lifecycle/__init__.py src/mountainash_auth_client/__init__.py tests/test_lifecycle_exports.py
git commit -m "$(cat <<'EOF'
feat: export token-lifecycle managers + PersistableAuthProfile at package root

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Full suite, lint, PR

**Files:** none (verification + PR).

- [ ] **Step 1: Full test suite**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest -q`
Expected: PASS — the prior green count (293) plus the new tests (3 + 5 + 10 + 4 + 1 = 23), so ~316 passed, 2 skipped. No regressions in the existing connection/flow suites.

- [ ] **Step 2: Lint gate (scoped — avoids the pre-existing E402 baseline)**

`ruff check src tests` on the whole tree is NOT clean on `develop`: `tests/connections/test_oauth1_flow.py`, `test_oauth2_flow.py`, and `test_callback_servers.py` carry pre-existing `E402` (deliberate mid-file imports — verified identical on `develop`, out of scope, do NOT "fix"). So lint `src` plus only this PR's new test files:

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/ruff check src tests/test_persistence.py tests/lifecycle/ tests/test_lifecycle_exports.py`
Expected: `All checks passed!`. (If ruff flags anything under `src/mountainash_auth_client/persistence.py`, `lifecycle/*`, the touched flow files, or the new test files, fix that.)

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin feature/oauth-token-lifecycle
gh pr create --base develop --title "feat: generic OAuth token-lifecycle capability (OAuth2/OAuth1 managers)" --body "$(cat <<'EOF'
Adds a reusable OAuth token-lifecycle capability to auth-client so consumers
(wearables first, others next) stop hand-rolling it.

- `PersistableAuthProfile` (typed identity contract) + `token_store()` (single
  home for the "oauth"-namespaced store resolution). Flows refactored onto it.
- `lifecycle/`: `TokenStatus`/`TokenState` + `classify_oauth2`; `OAuth2TokenManager`
  (authorize/refresh/access_token/status/revoke) and `OAuth1TokenManager`
  (authorize/token_pair/status/revoke).
- Every mutation serialized through the per-key `transaction(key)`; `status()` is a
  consistent `is_cleared`+`get` snapshot; `authorize()` persists wholesale and
  clears any tombstone (revoke→authorize → VALID).

Design spec: `docs/superpowers/specs/2026-06-14-oauth-token-lifecycle-design.md`
(Codex-reviewed; 2 blockers + 6 importants folded). Unblocks the wearables
consumer migration (separate PR).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Out of scope (later)

- **Wearables consumer migration** (separate PR): descriptors → `ProviderProfile`; `config.py` composition root (build `RegistryResolver` + register a `mountainash_secrets.FilesystemStore`); auth profiles made to satisfy `PersistableAuthProfile`; `mw.authorize/auth_status/refresh/deauthorize` reduced to thin delegations to the managers; delete `OAuth2ConnectionMixin`/`get_store`/`OAuthFlow(spec)` code.
- Exporting `FilesystemStore` at the `mountainash_secrets` top level (a wearables-PR concern; this plan imports it from the submodule only in one test).
- Promoting `persist_key`/`SETTINGS_SOURCE_SECRETS_PROVIDER` to `ParameterSpec` fields on the auth schemas (the contract is typed via the Protocol; values stay consumer-supplied).
```

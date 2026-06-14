# OAuth `ProviderProfile` (auth-client) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a typed, validated `OAuth2ProviderProfile`/`OAuth1ProviderProfile` carrying a provider's coordinates, refactor `OAuthFlow`/`OAuth1Flow` to read those coordinates off the profile's fields, and parameterise `OAuth2Connection`/`OAuth1Connection` so they take `(provider, auth_profile, …)` and run the unified two-stage `emit()` — retiring the `ClassVar` subclass-per-provider design.

**Architecture:** A `ProviderProfile` is a `mountainash_settings.Profile` whose `ProfileSpec` declares the provider's URLs/flags as `ParameterSpec` fields, with an `__adapters__[HTTP]` that emits `{base_url: …}`. The flows stop reading `spec.metadata` and read typed fields instead. The connections compose two HTTP emissions — `provider.emit(HTTP)` (base_url) then `<credential>.emit(HTTP, base=…)` (Authorization header / authlib signer) — and build `httpx.Client(**merged)`. auth-client ships the *schema*; clients own *values*; no provider registry in auth-client.

**Tech Stack:** Python 3.12, `mountainash-settings` (`ParameterSpec`/`Profile`/`ProfileSpec`, `Profile.emit`), `httpx`, `authlib` (optional, OAuth1 signing), pytest.

**Scope boundary:** This plan is **PR 1 of 3** (auth-client only). PR 2 (transport: delete its unwired OAuth connections) and PR 3 (wearables: migrate descriptors → `ProviderProfile`, wire token persistence) are separate plans. The settings filesystem-`SecretsBackend` dependency gates **PR 3**, not this PR — out of scope here.

**Spec:** `docs/superpowers/specs/2026-06-13-oauth-provider-profile-design.md`

**Repo / branch:** `mountainash-auth-client`, branch `feature/oauth-provider-profile` (already checked out; spec already committed as `f10548f`).

**Test runner:** the shared dev venv python:
```
PY=/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python
```
Run tests with `$PY -m pytest …`. (This is the interpreter that resolves `mountainash_settings` + `mountainash_auth_client` in this workspace; `hatch run test:test` is the CI equivalent.)

**Baseline (verified before planning):** `tests/connections/test_oauth2_flow.py` + `tests/connections/test_callback_factory.py` → 37 passed.

---

## File Structure

**New files:**
- `src/mountainash_auth_client/providers/__init__.py` — re-exports the two provider profiles.
- `src/mountainash_auth_client/providers/oauth2.py` — `OAuth2ProviderProfile` + `OAUTH2_PROVIDER_PARAMS`/`OAUTH2_PROVIDER_SPEC` + `_provider_http_kwargs`.
- `src/mountainash_auth_client/providers/oauth1.py` — `OAuth1ProviderProfile` + `OAUTH1_PROVIDER_PARAMS`/`OAUTH1_PROVIDER_SPEC` (reuses `_provider_http_kwargs`).
- `tests/providers/__init__.py`
- `tests/providers/test_provider_profiles.py` — validation, emit golden, extension mechanism.

**Modified files:**
- `src/mountainash_auth_client/connections/server/factory.py` — `metadata: dict` param → `callback_port: int | None`.
- `src/mountainash_auth_client/connections/oauth2/flow.py` — `__init__(provider, …)`; properties read provider fields; `authorize()` passes `callback_port`.
- `src/mountainash_auth_client/connections/oauth1/flow.py` — same shape, OAuth1 fields.
- `src/mountainash_auth_client/connections/oauth2/connection.py` — parameterised `__init__`; `connect()` is the two-stage emit.
- `src/mountainash_auth_client/connections/oauth1/connection.py` — same, authlib signer via `OAuth1AuthProfile.emit`.
- `src/mountainash_auth_client/connections/__init__.py` + `oauth1/__init__.py` + `oauth2/__init__.py` — exports.
- `src/mountainash_auth_client/__init__.py` — top-level exports (provider profiles, `OAuth1Flow`, `OAuth1Connection`).
- `src/mountainash_auth_client/__version__.py` — `26.6.0` → `26.6.1`.
- `tests/connections/test_callback_factory.py`, `test_oauth2_flow.py`, `test_oauth1_flow.py`, `test_oauth2_connection.py`, `test_oauth1_connection.py` — migrate `FakeSpec`(metadata) → `ProviderProfile`(fields); migrate connection construction.

---

## Task 1: `ProviderProfile` schema (new `providers/` package)

**Files:**
- Create: `src/mountainash_auth_client/providers/__init__.py`
- Create: `src/mountainash_auth_client/providers/oauth2.py`
- Create: `src/mountainash_auth_client/providers/oauth1.py`
- Create: `tests/providers/__init__.py`
- Test: `tests/providers/test_provider_profiles.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/providers/__init__.py` (empty) and `tests/providers/test_provider_profiles.py`:

```python
"""ProviderProfile: validation, emit golden, extension mechanism."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from mountainash_settings import ParameterSpec, ProfileSpec
from mountainash_auth_client.targets import TargetFamily
from mountainash_auth_client.providers.oauth2 import (
    OAUTH2_PROVIDER_PARAMS,
    OAuth2ProviderProfile,
)
from mountainash_auth_client.providers.oauth1 import (
    OAUTH1_PROVIDER_PARAMS,
    OAuth1ProviderProfile,
)


def _oauth2(**overrides):
    base = dict(
        NAME="strava",
        AUTHORIZE_URL="https://www.strava.com/oauth/authorize",
        TOKEN_URL="https://www.strava.com/oauth/token",
        BASE_URL="https://www.strava.com/api/v3",
    )
    base.update(overrides)
    return OAuth2ProviderProfile(**base)


def _oauth1(**overrides):
    base = dict(
        NAME="garmin",
        REQUEST_TOKEN_URL="https://connectapi.garmin.com/oauth-service/oauth/request_token",
        AUTHORIZE_URL="https://connect.garmin.com/oauthConfirm",
        ACCESS_TOKEN_URL="https://connectapi.garmin.com/oauth-service/oauth/access_token",
        BASE_URL="https://apis.garmin.com",
    )
    base.update(overrides)
    return OAuth1ProviderProfile(**base)


class TestOAuth2ProviderProfile:
    def test_fields_round_trip(self):
        p = _oauth2(DEFAULT_SCOPE="read", USE_PKCE=True, CALLBACK_PORT=8923)
        assert p.NAME == "strava"
        assert p.AUTHORIZE_URL == "https://www.strava.com/oauth/authorize"
        assert p.TOKEN_URL == "https://www.strava.com/oauth/token"
        assert p.DEFAULT_SCOPE == "read"
        assert p.USE_PKCE is True
        assert p.CALLBACK_PORT == 8923

    def test_advanced_defaults(self):
        p = _oauth2()
        assert p.DEFAULT_SCOPE is None
        assert p.USE_PKCE is False
        assert p.CALLBACK_PORT is None

    def test_emit_http_is_base_url_only(self):
        # The provider emits resource-client config; auth-server URLs are NOT
        # client kwargs and must not leak into the emitted dict.
        assert _oauth2().emit(TargetFamily.HTTP) == {"base_url": "https://www.strava.com/api/v3"}

    def test_emit_without_target_fails_closed(self):
        # Targeted profile (has __adapters__) → emit() with no target raises.
        with pytest.raises(ValueError):
            _oauth2().emit()

    def test_missing_required_field_fails_at_construction(self):
        # The headline correctness win: a missing AUTHORIZE_URL is a construction
        # error, not a runtime KeyError deep in the flow.
        with pytest.raises(ValidationError):
            OAuth2ProviderProfile(NAME="x", TOKEN_URL="t", BASE_URL="b")

    def test_not_registered_in_auth_registry(self):
        # A provider is not an auth mode; it must not populate AUTH_REGISTRY.
        from mountainash_auth_client.schemas.registry import AUTH_REGISTRY
        assert "oauth2_provider" not in AUTH_REGISTRY
        assert "oauth1_provider" not in AUTH_REGISTRY


class TestOAuth1ProviderProfile:
    def test_fields_round_trip(self):
        p = _oauth1(CALLBACK_PORT=7000)
        assert p.NAME == "garmin"
        assert p.REQUEST_TOKEN_URL.endswith("/request_token")
        assert p.AUTHORIZE_URL == "https://connect.garmin.com/oauthConfirm"
        assert p.ACCESS_TOKEN_URL.endswith("/access_token")
        assert p.CALLBACK_PORT == 7000

    def test_emit_http_is_base_url_only(self):
        assert _oauth1().emit(TargetFamily.HTTP) == {"base_url": "https://apis.garmin.com"}

    def test_missing_required_field_fails_at_construction(self):
        with pytest.raises(ValidationError):
            OAuth1ProviderProfile(NAME="x", AUTHORIZE_URL="a", BASE_URL="b")


class TestExtension:
    """Esoteric providers extend the base param list + subclass the base."""

    def test_subclass_adds_field_and_keeps_base(self):
        from mountainash_settings import Profile

        EXT_SPEC = ProfileSpec(
            name="garmin_health_provider",
            provider_type="garmin_health_provider",
            parameters=[*OAUTH1_PROVIDER_PARAMS, ParameterSpec(name="USER_INFO_URL", type=str)],
        )

        class GarminHealthProvider(OAuth1ProviderProfile):
            __spec__ = EXT_SPEC

        p = GarminHealthProvider(
            NAME="garmin",
            REQUEST_TOKEN_URL="https://g/request_token",
            AUTHORIZE_URL="https://g/authorize",
            ACCESS_TOKEN_URL="https://g/access_token",
            BASE_URL="https://apis.garmin.com",
            USER_INFO_URL="https://apis.garmin.com/wellness-api/rest/user/id",
        )
        # Extended field is present...
        assert p.USER_INFO_URL.endswith("/user/id")
        # ...base fields still present and emit still works (inherited adapter).
        assert p.REQUEST_TOKEN_URL == "https://g/request_token"
        assert p.emit(TargetFamily.HTTP) == {"base_url": "https://apis.garmin.com"}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/providers/test_provider_profiles.py -q`
Expected: collection/import error — `ModuleNotFoundError: No module named 'mountainash_auth_client.providers'`.

- [ ] **Step 3: Implement the provider profiles**

Create `src/mountainash_auth_client/providers/oauth2.py`:

```python
"""OAuth2 provider coordinates — a typed, validated Profile (not an auth mode).

auth-client ships this *schema*; clients instantiate it with their provider's
*values*. There is no provider registry: there are infinitely many providers,
so provider data lives with the client, not here.
"""
from __future__ import annotations

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily

__all__ = ["OAuth2ProviderProfile", "OAUTH2_PROVIDER_PARAMS", "OAUTH2_PROVIDER_SPEC"]


OAUTH2_PROVIDER_PARAMS = [
    ParameterSpec(name="NAME", type=str, tier="core"),            # provider identity for error labels/logging
    ParameterSpec(name="AUTHORIZE_URL", type=str, tier="core"),
    ParameterSpec(name="TOKEN_URL", type=str, tier="core"),
    ParameterSpec(name="BASE_URL", type=str, tier="core"),        # resource API root
    ParameterSpec(name="DEFAULT_SCOPE", type=str | None, tier="advanced", default=None),
    ParameterSpec(name="USE_PKCE", type=bool, tier="advanced", default=False),
    ParameterSpec(name="CALLBACK_PORT", type=int | None, tier="advanced", default=None),
]


def _provider_http_kwargs(profile, kw):
    """Emit the resource-client config (base_url + future httpx knobs)."""
    return {**kw, "base_url": profile.BASE_URL}


OAUTH2_PROVIDER_SPEC = ProfileSpec(
    name="oauth2_provider",
    provider_type="oauth2_provider",
    parameters=OAUTH2_PROVIDER_PARAMS,
)


class OAuth2ProviderProfile(Profile):
    __spec__ = OAUTH2_PROVIDER_SPEC
    __adapters__ = {TargetFamily.HTTP: _provider_http_kwargs}
```

Create `src/mountainash_auth_client/providers/oauth1.py`:

```python
"""OAuth1 provider coordinates — typed, validated Profile (not an auth mode)."""
from __future__ import annotations

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .oauth2 import _provider_http_kwargs

__all__ = ["OAuth1ProviderProfile", "OAUTH1_PROVIDER_PARAMS", "OAUTH1_PROVIDER_SPEC"]


OAUTH1_PROVIDER_PARAMS = [
    ParameterSpec(name="NAME", type=str, tier="core"),
    ParameterSpec(name="REQUEST_TOKEN_URL", type=str, tier="core"),
    ParameterSpec(name="AUTHORIZE_URL", type=str, tier="core"),
    ParameterSpec(name="ACCESS_TOKEN_URL", type=str, tier="core"),
    ParameterSpec(name="BASE_URL", type=str, tier="core"),
    ParameterSpec(name="CALLBACK_PORT", type=int | None, tier="advanced", default=None),
]


OAUTH1_PROVIDER_SPEC = ProfileSpec(
    name="oauth1_provider",
    provider_type="oauth1_provider",
    parameters=OAUTH1_PROVIDER_PARAMS,
)


class OAuth1ProviderProfile(Profile):
    __spec__ = OAUTH1_PROVIDER_SPEC
    __adapters__ = {TargetFamily.HTTP: _provider_http_kwargs}
```

Create `src/mountainash_auth_client/providers/__init__.py`:

```python
"""Provider coordinate profiles (OAuth2 / OAuth1). Schema only — no values, no registry."""
from __future__ import annotations

from .oauth1 import OAuth1ProviderProfile
from .oauth2 import OAuth2ProviderProfile

__all__ = ["OAuth1ProviderProfile", "OAuth2ProviderProfile"]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `$PY -m pytest tests/providers/test_provider_profiles.py -q`
Expected: PASS (all green).

(`AUTH_REGISTRY` supports the `in` operator over registered names — verified: `"token" in AUTH_REGISTRY` is `True`, `"oauth2_provider" in AUTH_REGISTRY` is `False`. Registered names today: windows, azure_ad, certificate, iam, kerberos, none, oauth1, oauth2, oauth2_authcode, password, service_account, token, jwt.)

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/providers tests/providers
git commit -m "feat: OAuth2/OAuth1 ProviderProfile (typed provider coordinates)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `resolve_callback_factory` takes `callback_port` (not `metadata`)

The flows will no longer carry a `metadata` dict, so the factory must accept the fixed callback port directly. This is the one shared dependency both flow refactors need, so it lands first.

**Files:**
- Modify: `src/mountainash_auth_client/connections/server/factory.py`
- Test: `tests/connections/test_callback_factory.py`

- [ ] **Step 1: Update the failing tests first**

Open `tests/connections/test_callback_factory.py`. Every call to `resolve_callback_factory(...)` currently passes `metadata={...}` (or `metadata={"callback_port": N}`). Replace the `metadata=` keyword argument as follows at every call site:
- `metadata={}` or `metadata={"...non-port keys..."}` → `callback_port=None`
- `metadata={"callback_port": N}` (possibly with other keys) → `callback_port=N`

Add (or adjust) these two explicit cases so the new contract is pinned:

```python
def test_default_local_server_uses_callback_port():
    import mountainash_auth_client.connections.server.factory as f
    captured = {}

    def fake_local(port=0):
        captured["port"] = port
        return object()

    import unittest.mock as m
    with m.patch.object(f, "LocalCallbackServer", fake_local):
        factory = f.resolve_callback_factory(
            redirect_mode="local_server",
            callback_server=None,
            instance_default=None,
            callback_port=8923,
        )
        factory()
    assert captured["port"] == 8923


def test_default_local_server_port_zero_when_none():
    import mountainash_auth_client.connections.server.factory as f
    captured = {}

    def fake_local(port=0):
        captured["port"] = port
        return object()

    import unittest.mock as m
    with m.patch.object(f, "LocalCallbackServer", fake_local):
        f.resolve_callback_factory(
            redirect_mode="local_server",
            callback_server=None,
            instance_default=None,
            callback_port=None,
        )()
    assert captured["port"] == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/connections/test_callback_factory.py -q`
Expected: FAIL — `TypeError: resolve_callback_factory() got an unexpected keyword argument 'callback_port'` (and/or missing `metadata`).

- [ ] **Step 3: Implement the signature change**

In `src/mountainash_auth_client/connections/server/factory.py`, replace the `metadata: dict` parameter and its use:

```python
def resolve_callback_factory(
    *,
    redirect_mode: str,
    callback_server: CallbackServerFactory | None,
    instance_default: CallbackServerFactory | None,
    callback_port: int | None = None,
    manual_redirect_uri: str | None = None,
) -> CallbackServerFactory:
    """Resolve the callback-server factory to use for one authorize() call.

    Precedence: explicit per-call ``callback_server`` -> flow ``instance_default``
    -> built-in selected by ``redirect_mode``. A ``callback_server`` (per-call or
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
    port = callback_port or 0
    return lambda: LocalCallbackServer(port=port)
```

(Update the module docstring's `metadata` mention if present.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `$PY -m pytest tests/connections/test_callback_factory.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/server/factory.py tests/connections/test_callback_factory.py
git commit -m "refactor: callback factory takes callback_port, not metadata bag

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `OAuthFlow` reads coordinates off the `ProviderProfile`

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth2/flow.py`
- Test: `tests/connections/test_oauth2_flow.py`

- [ ] **Step 1: Migrate the tests to construct a `ProviderProfile`**

In `tests/connections/test_oauth2_flow.py`:

1. Add this import + helper near the top (after existing imports):

```python
from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile


def _provider(**overrides):
    base = dict(
        NAME="testprovider",
        AUTHORIZE_URL="https://auth.example.com/authorize",
        TOKEN_URL="https://auth.example.com/token",
        BASE_URL="https://api.example.com",
    )
    base.update(overrides)
    return OAuth2ProviderProfile(**base)
```

2. Delete the `class FakeSpec:` definition.

3. Replace every `OAuthFlow(FakeSpec())` → `OAuthFlow(_provider())`.

4. Replace the two PKCE constructions
   `OAuthFlow(FakeSpec(metadata={... "use_pkce": True}))` → `OAuthFlow(_provider(USE_PKCE=True))`
   (in `test_pkce_adds_code_challenge_and_s256` and `test_pkce_verifier_keyed_by_state_survives_second_authorize`).

5. Replace the two construction-default cases
   `OAuthFlow(FakeSpec(), callback_server=…)` → `OAuthFlow(_provider(), callback_server=…)`.

6. In the resolver section, delete `class _Spec:` and replace `OAuthFlow(_Spec())` → `OAuthFlow(_provider())` (the helper's `NAME="testprovider"` matches the existing `assert exc.value.provider == "testprovider"`).

(Assertions are unchanged — only the flow's construction argument moves from a metadata bag to a typed profile.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/connections/test_oauth2_flow.py -q`
Expected: FAIL — `OAuthFlow.__init__` still expects `spec` and reads `spec.metadata` / `spec.name`; an `OAuth2ProviderProfile` has neither `.metadata` nor `.name`, so property access (`AttributeError`) or `__init__` blows up.

- [ ] **Step 3: Refactor `OAuthFlow` to read provider fields**

In `src/mountainash_auth_client/connections/oauth2/flow.py`:

Replace the `TYPE_CHECKING` import of `ProfileSpec` with the provider profile:

```python
if TYPE_CHECKING:
    from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory
```

Replace `__init__` and the four properties:

```python
    def __init__(
        self,
        provider: OAuth2ProviderProfile,
        *,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._pending_verifiers: dict[str, str] = {}
        self._last_state: str | None = None
        self._callback_server = callback_server

    @property
    def authorize_url(self) -> str:
        return self._provider.AUTHORIZE_URL

    @property
    def token_url(self) -> str:
        return self._provider.TOKEN_URL

    @property
    def use_pkce(self) -> bool:
        return self._provider.USE_PKCE

    @property
    def default_scope(self) -> str | None:
        return self._provider.DEFAULT_SCOPE
```

In `resolve_access_token`, change the provider-name source:

```python
        provider = self._provider.NAME
```

In `authorize`, replace the `metadata=self._metadata` argument with the typed callback port:

```python
        factory = resolve_callback_factory(
            redirect_mode=redirect_mode,
            callback_server=callback_server,
            instance_default=self._callback_server,
            callback_port=self._provider.CALLBACK_PORT,
        )
```

(`build_authorize_url` / `exchange_code` / `refresh` / `resolve_access_token` bodies are otherwise unchanged.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `$PY -m pytest tests/connections/test_oauth2_flow.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth2/flow.py tests/connections/test_oauth2_flow.py
git commit -m "refactor: OAuthFlow reads coordinates off OAuth2ProviderProfile

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `OAuth1Flow` reads coordinates off the `ProviderProfile`

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth1/flow.py`
- Test: `tests/connections/test_oauth1_flow.py`

- [ ] **Step 1: Migrate the tests to construct a `ProviderProfile`**

In `tests/connections/test_oauth1_flow.py`:

1. Add import + helper near the top:

```python
from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile


def _provider(**overrides):
    base = dict(
        NAME="testprovider_oauth1",
        REQUEST_TOKEN_URL="https://auth.example.com/oauth/request_token",
        AUTHORIZE_URL="https://auth.example.com/oauth/authorize",
        ACCESS_TOKEN_URL="https://auth.example.com/oauth/access_token",
        BASE_URL="https://api.example.com",
    )
    base.update(overrides)
    return OAuth1ProviderProfile(**base)
```

2. Delete `class FakeSpec:` and `class _Spec1:`.

3. Replace every `OAuth1Flow(FakeSpec())` → `OAuth1Flow(_provider())`.

4. Replace every `OAuth1Flow(_Spec1())` → `OAuth1Flow(_provider())`. The helper's `NAME="testprovider_oauth1"` matches the existing `assert exc.value.provider == "testprovider_oauth1"`.

5. In `test_properties_read_from_metadata`, the asserted URLs must match the helper's values. Update the expected strings to:
   - `request_token_url == "https://auth.example.com/oauth/request_token"`
   - `authorize_url == "https://auth.example.com/oauth/authorize"`
   - `access_token_url == "https://auth.example.com/oauth/access_token"`
   (These already match the helper; rename the test to `test_properties_read_from_provider` for clarity.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/connections/test_oauth1_flow.py -q`
Expected: FAIL — `OAuth1Flow.__init__` reads `spec.metadata`; a provider profile has no `.metadata`.

- [ ] **Step 3: Refactor `OAuth1Flow` to read provider fields**

In `src/mountainash_auth_client/connections/oauth1/flow.py`:

Replace the `TYPE_CHECKING` import:

```python
if TYPE_CHECKING:
    from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory
```

Replace `__init__` and the three properties:

```python
    def __init__(
        self,
        provider: OAuth1ProviderProfile,
        *,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._callback_server = callback_server

    @property
    def request_token_url(self) -> str:
        return self._provider.REQUEST_TOKEN_URL

    @property
    def authorize_url(self) -> str:
        return self._provider.AUTHORIZE_URL

    @property
    def access_token_url(self) -> str:
        return self._provider.ACCESS_TOKEN_URL
```

In `resolve_token_pair`, change the provider-name source:

```python
        provider = self._provider.NAME
```

In `authorize`, replace `metadata=self._metadata` with `callback_port`:

```python
        factory = resolve_callback_factory(
            redirect_mode=redirect_mode,
            callback_server=callback_server,
            instance_default=self._callback_server,
            callback_port=self._provider.CALLBACK_PORT,
            manual_redirect_uri="oob",
        )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `$PY -m pytest tests/connections/test_oauth1_flow.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth1/flow.py tests/connections/test_oauth1_flow.py
git commit -m "refactor: OAuth1Flow reads coordinates off OAuth1ProviderProfile

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Parameterise `OAuth2Connection` (two-stage emit)

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth2/connection.py`
- Test: `tests/connections/test_oauth2_connection.py`

- [ ] **Step 1: Rewrite the connection tests for the parameterised API**

Replace the whole body of `tests/connections/test_oauth2_connection.py` with:

```python
"""Tests for the parameterised OAuth2Connection."""
from __future__ import annotations

import time
import typing as t
from contextlib import contextmanager
from unittest.mock import patch

import httpx
import pytest

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.connections.oauth2.connection import OAuth2Connection
from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
from mountainash_settings.secrets.registry import (
    clear_secrets_registry,
    register_secrets_backend,
)


class _InMemoryBackend:
    def __init__(self):
        self._store: dict[str, dict[str, t.Any]] = {}

    def get(self, key):
        return self._store.get(key)

    def set(self, key, data):
        self._store[key] = data

    def delete(self, key):
        self._store.pop(key, None)

    @contextmanager
    def transaction(self, key):
        yield


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


@pytest.fixture(autouse=True)
def clean():
    clear_secrets_registry()
    yield
    clear_secrets_registry()


@pytest.fixture
def backend():
    b = _InMemoryBackend()
    register_secrets_backend("test_mem", b)
    return b


class TestNoToken:
    def test_raises_authorization_required_when_no_token(self, backend):
        conn = OAuth2Connection(_provider(), FakeAuth())
        with pytest.raises(AuthorizationRequired) as exc_info:
            conn.connect()
        assert exc_info.value.provider == "testprovider"


class TestWithToken:
    def _seed(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })

    def test_connect_returns_self(self, backend):
        self._seed(backend)
        conn = OAuth2Connection(_provider(), FakeAuth())
        assert conn.connect() is conn

    def test_client_set_after_connect(self, backend):
        self._seed(backend)
        conn = OAuth2Connection(_provider(), FakeAuth())
        conn.connect()
        assert conn.client is not None

    def test_client_has_bearer_header(self, backend):
        self._seed(backend)
        conn = OAuth2Connection(_provider(), FakeAuth())
        conn.connect()
        assert "Bearer tok_abc" in conn.client.headers.get("authorization", "")

    def test_client_base_url_from_provider(self, backend):
        self._seed(backend)
        conn = OAuth2Connection(_provider(), FakeAuth())
        conn.connect()
        assert str(conn.client.base_url) == "https://api.example.com"


class TestExpiredToken:
    def test_raises_when_expired_and_no_refresh(self, backend):
        backend.set("test.oauth2", {
            "access_token": "old_tok",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        conn = OAuth2Connection(_provider(), FakeAuth())
        with pytest.raises(AuthorizationRequired):
            conn.connect()


class TestResolverSeam:
    def test_uses_resolved_token_for_bearer_header(self, backend):
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "resolved_tok"
            conn = OAuth2Connection(_provider(), FakeAuth())
            conn.connect()
        assert "Bearer resolved_tok" in conn.client.headers.get("authorization", "")

    def test_forwards_auto_authorize_and_callback_server(self, backend):
        sentinel = object()
        with patch(
            "mountainash_auth_client.connections.oauth2.connection.OAuthFlow"
        ) as flow_cls:
            flow_cls.return_value.resolve_access_token.return_value = "tok"
            conn = OAuth2Connection(
                _provider(), FakeAuth(), auto_authorize=True, callback_server=sentinel)
            conn.connect()
            _, kwargs = flow_cls.return_value.resolve_access_token.call_args
        assert kwargs["auto_authorize"] is True
        assert kwargs["callback_server"] is sentinel


class TestClientProperty:
    def test_client_none_before_connect(self):
        conn = OAuth2Connection(_provider(), FakeAuth())
        assert conn.client is None

    def test_context_manager_closes_client(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc", "refresh_token": "r",
            "token_expires_at": int(time.time()) + 3600,
        })
        with OAuth2Connection(_provider(), FakeAuth()).connect() as conn:
            assert conn.client is not None
        assert conn.client is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/connections/test_oauth2_connection.py -q`
Expected: FAIL — current `OAuth2Connection.__init__` takes no args (ClassVar design) and `connect()` requires `auth_profile`; `OAuth2Connection(_provider(), FakeAuth())` is a `TypeError`.

- [ ] **Step 3: Rewrite `OAuth2Connection` as parameterised**

Replace the whole body of `src/mountainash_auth_client/connections/oauth2/connection.py`:

```python
"""OAuth2Connection — parameterised connect for any OAuth2 provider.

Composes the unified two-stage HTTP emission: the provider emits its resource
config (base_url), then a TokenAuthProfile emits the Bearer header onto it.
No ClassVars, no subclass-per-provider.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Self

import httpx

from mountainash_auth_client.targets import TargetFamily
from mountainash_auth_client.connections.oauth2.flow import OAuthFlow
from mountainash_auth_client.schemas.token import TokenAuthProfile

if TYPE_CHECKING:
    from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
    from mountainash_auth_client.schemas.oauth2 import OAuth2AuthProfile
    from mountainash_auth_client.schemas.oauth2_authcode import OAuth2AuthCodeAuthProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory


class OAuth2Connection:
    def __init__(
        self,
        provider: OAuth2ProviderProfile,
        auth_profile: OAuth2AuthProfile | OAuth2AuthCodeAuthProfile,
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._auth = auth_profile
        self._auto_authorize = auto_authorize
        self._callback_server = callback_server
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client | None:
        return self._client

    def connect(self) -> Self:
        token = OAuthFlow(self._provider).resolve_access_token(
            self._auth,
            auto_authorize=self._auto_authorize,
            callback_server=self._callback_server,
        )
        base = self._provider.emit(TargetFamily.HTTP)
        merged = TokenAuthProfile(TOKEN=token).emit(TargetFamily.HTTP, base=base)
        self._client = httpx.Client(timeout=30.0, **merged)
        return self

    def disconnect(self) -> None:
        if self._client is not None:
            self._client.close()
        self._client = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `$PY -m pytest tests/connections/test_oauth2_connection.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth2/connection.py tests/connections/test_oauth2_connection.py
git commit -m "refactor: parameterise OAuth2Connection via two-stage emit

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Parameterise `OAuth1Connection` (authlib signer via emit)

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth1/connection.py`
- Test: `tests/connections/test_oauth1_connection.py`

- [ ] **Step 1: Rewrite the connection tests for the parameterised API**

Replace the whole body of `tests/connections/test_oauth1_connection.py` with:

```python
"""Tests for the parameterised OAuth1Connection."""
from __future__ import annotations

import typing as t
from contextlib import contextmanager

import pytest

from mountainash_auth_client.connections.oauth1.connection import OAuth1Connection
from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
from mountainash_settings.secrets.registry import (
    clear_secrets_registry,
    register_secrets_backend,
)


class _InMemoryBackend:
    def __init__(self):
        self._store: dict[str, dict[str, t.Any]] = {}

    def get(self, key):
        return self._store.get(key)

    def set(self, key, data):
        self._store[key] = data

    def delete(self, key):
        self._store.pop(key, None)

    @contextmanager
    def transaction(self, key):
        yield


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


@pytest.fixture(autouse=True)
def clean():
    clear_secrets_registry()
    yield
    clear_secrets_registry()


@pytest.fixture
def backend():
    b = _InMemoryBackend()
    register_secrets_backend("test_mem_oauth1", b)
    return b


import httpx


class _StubSigner(httpx.Auth):
    """A valid httpx auth object standing in for authlib's OAuth1Auth.

    authlib is an OPTIONAL `[oauth1]` extra and is NOT installed in the local
    dev venv, so the connection's real emit path (which calls
    `require_authlib("OAuth1Auth")` inside `_oauth1_signer`) would raise
    ImportError rather than build a client. Patching the `require_authlib`
    seam to return this stub lets the wiring (resolved pair → emit → client
    with provider base_url + an `auth` signer) be verified green in any env,
    while still exercising the genuine two-stage emit.
    """

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def auth_flow(self, request):
        yield request


class TestConnect:
    def test_connect_builds_signed_client_from_resolved_pair(self, monkeypatch, backend):
        captured = {}

        def fake_resolve(self, auth_profile, *, auto_authorize=False, callback_server=None):
            captured["auto_authorize"] = auto_authorize
            captured["callback_server"] = callback_server
            return ("AT", "ATS")

        monkeypatch.setattr(
            "mountainash_auth_client.connections.oauth1.flow.OAuth1Flow.resolve_token_pair",
            fake_resolve,
        )
        # Stand in for authlib's OAuth1Auth (optional extra, absent locally).
        monkeypatch.setattr(
            "mountainash_auth_client.schemas.oauth1.require_authlib",
            lambda name: _StubSigner,
        )
        sentinel = object()
        conn = OAuth1Connection(
            _provider(), FakeAuth(), auto_authorize=True, callback_server=sentinel)
        conn.connect()

        assert captured["auto_authorize"] is True
        assert captured["callback_server"] is sentinel
        # base_url comes from the provider; the signer is attached via emit.
        assert str(conn.client.base_url) == "https://api.example.com"
        assert isinstance(conn.client.auth, _StubSigner)
        # The signer received the resolved pair, not the auth_profile's (None) fields.
        assert conn.client.auth.kwargs["token"] == "AT"
        assert conn.client.auth.kwargs["token_secret"] == "ATS"

    def test_client_none_before_connect(self):
        conn = OAuth1Connection(_provider(), FakeAuth())
        assert conn.client is None
```

(This exercises the real `emit` path while keeping `authlib` optional: `_oauth1_signer` resolves its `OAuth1Auth` through the patched `require_authlib` seam, so the test is green whether or not the `[oauth1]` extra is installed. The `kwargs["token"]/["token_secret"]` assertions prove the connection injects the *resolved* pair — Task 6's correctness point.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$PY -m pytest tests/connections/test_oauth1_connection.py -q`
Expected: FAIL — current `OAuth1Connection` is ClassVar-based; `OAuth1Connection(_provider(), FakeAuth())` is a `TypeError`, and there is no `client` property.

- [ ] **Step 3: Rewrite `OAuth1Connection` as parameterised**

Replace the whole body of `src/mountainash_auth_client/connections/oauth1/connection.py`:

```python
"""OAuth1Connection — parameterised connect for any OAuth1 provider.

Resolves the access token pair, then dogfoods the unified emission: a fresh
OAuth1AuthProfile populated with the resolved pair emits the authlib signer
onto the provider's base_url.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Self

import httpx

from mountainash_auth_client.targets import TargetFamily
from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow
from mountainash_auth_client.schemas.oauth1 import OAuth1AuthProfile

if TYPE_CHECKING:
    from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
    from mountainash_auth_client.schemas.oauth1 import OAuth1AuthProfile as _OAuth1AuthProfile
    from mountainash_auth_client.connections.protocols import CallbackServerFactory


class OAuth1Connection:
    def __init__(
        self,
        provider: OAuth1ProviderProfile,
        auth_profile: "_OAuth1AuthProfile",
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> None:
        self._provider = provider
        self._auth = auth_profile
        self._auto_authorize = auto_authorize
        self._callback_server = callback_server
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client | None:
        return self._client

    def connect(self) -> Self:
        oauth_token, oauth_token_secret = OAuth1Flow(self._provider).resolve_token_pair(
            self._auth,
            auto_authorize=self._auto_authorize,
            callback_server=self._callback_server,
        )
        base = self._provider.emit(TargetFamily.HTTP)
        signed = OAuth1AuthProfile(
            CONSUMER_KEY=self._auth.CONSUMER_KEY,
            CONSUMER_SECRET=self._auth.CONSUMER_SECRET.get_secret_value(),
            ACCESS_TOKEN=oauth_token,
            ACCESS_TOKEN_SECRET=oauth_token_secret,
        )
        merged = signed.emit(TargetFamily.HTTP, base=base)
        self._client = httpx.Client(timeout=30.0, **merged)
        return self

    def disconnect(self) -> None:
        if self._client is not None:
            self._client.close()
        self._client = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()
```

Note on the `OAuth1AuthProfile` import: it is imported at module top (not lazily) because `connect()` always needs it. `OAuth1AuthProfile.emit(HTTP)` calls `require_authlib` internally, so authlib stays an optional runtime dependency surfaced only at `connect()` time — module import does not require authlib.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `$PY -m pytest tests/connections/test_oauth1_connection.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_auth_client/connections/oauth1/connection.py tests/connections/test_oauth1_connection.py
git commit -m "refactor: parameterise OAuth1Connection via emit (authlib signer)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Exports, version bump, and org-wide importer sweep

**Files:**
- Modify: `src/mountainash_auth_client/connections/oauth2/__init__.py`
- Modify: `src/mountainash_auth_client/connections/oauth1/__init__.py`
- Modify: `src/mountainash_auth_client/connections/__init__.py`
- Modify: `src/mountainash_auth_client/__init__.py`
- Modify: `src/mountainash_auth_client/__version__.py`
- Test: `tests/connections/test_exports.py`

- [ ] **Step 1: Add the export assertions (failing test)**

Append to `tests/connections/test_exports.py`:

```python
def test_provider_profiles_and_oauth1_exported_at_root():
    import mountainash_auth_client as pkg

    for name in (
        "OAuth2ProviderProfile",
        "OAuth1ProviderProfile",
        "OAuth1Connection",
        "OAuth1Flow",
    ):
        assert name in pkg.__all__, name
        assert hasattr(pkg, name), name
```

- [ ] **Step 2: Run to verify it fails**

Run: `$PY -m pytest tests/connections/test_exports.py -q`
Expected: FAIL — `OAuth2ProviderProfile` (etc.) not in `pkg.__all__`.

- [ ] **Step 3: Wire the exports**

`src/mountainash_auth_client/connections/oauth2/__init__.py` — unchanged (already exports `OAuthFlow`, `OAuth2Connection`).

`src/mountainash_auth_client/connections/oauth1/__init__.py` — unchanged (already exports `OAuth1Flow`, `OAuth1Connection`).

In `src/mountainash_auth_client/connections/__init__.py`, add the OAuth1 surface and re-export. Replace the import block + `__all__`:

```python
from .oauth1.flow import OAuth1Flow
from .oauth1.connection import OAuth1Connection
from .oauth2.flow import OAuthFlow
from .oauth2.connection import OAuth2Connection
from .protocols import CallbackServerFactory, CallbackServerProtocol
from .server.callback import LocalCallbackServer
from .server.manual import ManualCallbackServer, extract_code_from_input, prompt_for_code

__all__ = [
    "CallbackServerFactory",
    "CallbackServerProtocol",
    "LocalCallbackServer",
    "ManualCallbackServer",
    "OAuth1Connection",
    "OAuth1Flow",
    "OAuth2Connection",
    "OAuthFlow",
    "extract_code_from_input",
    "prompt_for_code",
]
```

In `src/mountainash_auth_client/__init__.py`, add imports after the existing `OAuth2Connection` import:

```python
from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow
from mountainash_auth_client.connections.oauth1.connection import OAuth1Connection
from mountainash_auth_client.providers import (
    OAuth1ProviderProfile,
    OAuth2ProviderProfile,
)
```

and add these names to `__all__` (keep it alphabetically sorted as it currently is):
`"OAuth1Connection"`, `"OAuth1Flow"`, `"OAuth1ProviderProfile"`, `"OAuth2ProviderProfile"`.

- [ ] **Step 4: Bump the version**

Set `src/mountainash_auth_client/__version__.py`:

```python
__version__ = "26.6.1"
```

- [ ] **Step 5: Run the export test + full connections suite**

Run: `$PY -m pytest tests/connections/test_exports.py -q`
Expected: PASS.

Run: `$PY -m pytest tests/ -q`
Expected: PASS (full suite green).

- [ ] **Step 6: Org-wide importer sweep (safety net for the breaking change)**

The flow input changed from `spec` to `ProviderProfile`. Confirm no in-repo caller still constructs `OAuthFlow(...)`/`OAuth1Flow(...)` with a `spec`/metadata bag, and document the cross-repo callers (handled in PR 2/PR 3):

Run:
```bash
grep -rn "OAuthFlow(\|OAuth1Flow(\|\.metadata\b\|mixins\.oauth\|store\.filesystem" \
  /home/nathanielramm/git/mountainash-io/mountainash --include='*.py' \
  | grep -v "/mountainash-auth-client/tests/" | grep -v "/.venv/"
```
Expected findings (record them in the commit message body, do NOT fix here — they are PR 2/PR 3 scope):
- `mountainash-utils-files` (transport) OAuth connection classes calling `OAuthFlow(self._spec)` → **PR 2** deletes these.
- `mountainash-wearables` descriptors / `mixins.oauth2` / `store.filesystem` imports → **PR 3** migrates these (already broken against current auth-client develop, per spec).
- Inside auth-client itself: only the refactored flows/connections + the migrated tests should match. There are **no** `mixins/` or `store/` packages in auth-client (verified absent), so the spec's "retire old surface" is a no-op here beyond this confirmation.

- [ ] **Step 7: Commit**

```bash
git add src/mountainash_auth_client/__init__.py \
        src/mountainash_auth_client/connections/__init__.py \
        src/mountainash_auth_client/__version__.py \
        tests/connections/test_exports.py
git commit -m "feat: export ProviderProfiles + OAuth1 surface; bump 26.6.1

BREAKING: OAuthFlow/OAuth1Flow now take an OAuth2/OAuth1ProviderProfile
instead of a ProfileSpec metadata bag. Cross-repo callers handled in the
same versioned cycle (transport delete = PR2, wearables migrate = PR3).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Type check + final review gate

**Files:** none (verification only)

- [ ] **Step 1: Lint the changed surface**

auth-client has no mypy environment or dependency (verified: `mypy` is not installed and `pyproject.toml` defines no mypy env). The repo's configured static gate is **ruff** (`[tool.ruff]` in `pyproject.toml`; `ruff 0.3.7` is in the venv). Run:

Run: `$PY -m ruff check src/mountainash_auth_client/providers src/mountainash_auth_client/connections tests/providers tests/connections`
Expected: no errors (clean). If ruff flags an issue in the new/changed files, fix it at root cause (do not add blanket `# noqa`). Pre-existing findings elsewhere are out of scope.

- [ ] **Step 2: Full suite, final green**

Run: `$PY -m pytest tests/ -q`
Expected: PASS.

- [ ] **Step 3: Fresh-eyes Codex adversarial review (pre-PR)**

Before opening the PR, run a fresh-eyes review of the branch diff via `codex:codex-rescue` (per repo workflow). Focus text: "Review the OAuth ProviderProfile auth-client implementation against its spec (`docs/superpowers/specs/2026-06-13-oauth-provider-profile-design.md`) — flow-reads-off-provider correctness, two-stage emit shape, callback_port threading, fail-closed emit, and the breaking-change handling. This IS implemented; review the code, not the design." Address any DO-NOT-SHIP findings before the PR.

- [ ] **Step 4: Open the PR (targets `develop`)**

```bash
git push -u origin feature/oauth-provider-profile
gh pr create --base develop \
  --title "feat: OAuth ProviderProfile + parameterised OAuth connections" \
  --body "$(cat <<'EOF'
## Summary
- Adds typed `OAuth2ProviderProfile` / `OAuth1ProviderProfile` (provider coordinates as validated `ParameterSpec` fields; schema only, no registry).
- `OAuthFlow` / `OAuth1Flow` read coordinates off the provider profile's fields (was `spec.metadata`).
- Parameterises `OAuth2Connection` / `OAuth1Connection`: `(provider, auth_profile, …)` + unified two-stage `emit(HTTP)`. Retires the `ClassVar` subclass-per-provider design.
- `resolve_callback_factory` takes `callback_port` instead of a `metadata` bag.

## Breaking change
`OAuthFlow`/`OAuth1Flow` no longer accept a `ProfileSpec`. Cross-repo callers land in the same versioned cycle: transport deletes its unwired OAuth connections (PR 2); wearables migrates descriptors → `ProviderProfile` (PR 3). Version bumped to 26.6.1.

## Out of scope
Settings filesystem-`SecretsBackend` dependency (gates wearables token persistence) — resolved in PR 3.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review (controller checklist — completed during planning)

- **Spec coverage:** ProviderProfile schema + extension (Task 1); flow-reads-off-provider for OAuth2 (Task 3) and OAuth1 (Task 4); `callback_port` threading (Task 2 + 3/4); parameterised connections + two-stage emit (Task 5/6); exports + version bump + breaking-change sweep (Task 7); review/PR gate (Task 8). The "retire mixins/store/*Auth" item is confirmed a no-op (those packages are absent) and verified by the Task 7 grep. The secrets-backend dependency is correctly deferred to PR 3.
- **Placeholder scan:** none — every code step carries complete code; every run step has an exact command + expected outcome.
- **Type consistency:** `OAuth2ProviderProfile` field names (`NAME`/`AUTHORIZE_URL`/`TOKEN_URL`/`BASE_URL`/`DEFAULT_SCOPE`/`USE_PKCE`/`CALLBACK_PORT`) used identically in the schema, the flow properties, and the tests. `emit(TargetFamily.HTTP)` golden shape `{"base_url": …}` (verified live), and `TokenAuthProfile(TOKEN=…).emit(HTTP, base=…)` → `{"base_url": …, "headers": {"Authorization": "Bearer …"}}` (verified live). `resolve_callback_factory(callback_port=…)` keyword consistent across factory, both flows, and the callback-factory tests.
```

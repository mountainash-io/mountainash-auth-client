# Unified Emission — Phase 2 (Auth-Client Adapters) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each auth profile in `mountainash-auth-client` a target-aware emission shape — corrected target-scoped `driver_key`s plus small `__adapters__` functions — so `profile.emit(TargetFamily.X)` produces exactly the SDK kwargs each family needs, replacing the auth half of transport's `_core/auth` strategies.

**Architecture:** Phase 2 of the design spec at `docs/superpowers/specs/2026-06-12-unified-profile-kwargs-emission-design.md`. It builds on Phase 1 (settings `emit()`/`__adapters__`/target-aware `driver_key`, landed in mountainash-settings #46). This phase introduces the `TargetFamily` enum (auth-client owns it), rewrites the eight auth profiles named in the spec's "What each auth profile becomes" table to emit per target, and adds the rule-4 invariant. No transport changes (that is Phase 3); auth-client still exports the same profile classes.

**Tech Stack:** Python 3.12, pydantic v2, mountainash-settings (Profile/emit), hatch, ruff, pytest. Optional deps: authlib (`[oauth1]`), paramiko (new `[sftp]`).

---

## Preconditions (controller verifies before dispatching Task 1)

1. **Settings substrate present in the test env.** Phase 2 uses `Profile.emit`, `__adapters__`, `Adapter`, and dict `driver_key`s, which only exist in mountainash-settings after #46. The auth-client `test` env installs settings via a path dependency that uv caches **by version**; the version did not change (26.5.0), so the env may hold a stale build. The controller has already force-installed a fresh settings wheel into the env this session. If any task hits `ImportError: cannot import name 'Adapter' from 'mountainash_settings'`, refresh per memory `auth_client_settings_env_staleness`:
   - `rm -f ../mountainash-settings/dist/*.whl`
   - from settings repo: `python3 -m pip wheel --no-deps --no-cache-dir --wheel-dir /tmp/ms-wheel .`
   - `~/.local/bin/uv pip install --python <env-venv>/bin/python --reinstall --no-cache --no-deps /tmp/ms-wheel/mountainash_settings-*.whl`
   - env venv path comes from any `hatch run test:` banner/traceback under `~/.local/share/hatch/env/virtual/mountainash-auth-client/<hash>/test.py3.12/`.

2. **Branch:** `feature/unified-emission-phase2` off auth-client `develop` (already created). PRs target `develop`.

---

## Design decisions locked for Phase 2 (read before any task)

These resolve ambiguities in the spec; each is justified so the Codex review can challenge them:

- **D1 — `TargetFamily` lives in a new top-level module** `src/mountainash_auth_client/targets.py` and is re-exported from the package root. The spec mandates auth-client own it; a dedicated module keeps it importable by every schema adapter without import cycles (schemas import `from mountainash_auth_client.targets import TargetFamily`, never from the package root).
- **D2 — Adapters are co-located with their profile** in each `schemas/*.py` file (the spec: "co-located with the profile in auth-client"). Optional deps (authlib, paramiko) are imported **inside** the adapter function via `connections/_optional.py` (`require_authlib`, new `require_paramiko`), so importing a schema module never imports an optional dep.
- **D3 — Rule-4 invariant is an auth-client-local test over `AUTH_REGISTRY`**, not an addition to settings' `spec_invariants_for`. The spec's prose says "in `spec_invariants_for(AUTH_REGISTRY)`", but its Ownership section also states Phase 1 is "the only change to the substrate." Implementing rule-4 in auth-client (iterating `AUTH_REGISTRY.get_settings_class(name).__adapters__`) honors that boundary and avoids a second settings release. Same enforcement, auth-client-owned.
- **D4 — IAM scopes its three credential keys to `{BOTO: aws_*}` and drops `ROLE_ARN`'s `driver_key`.** The old `IAMCredentialStrategy` emitted only `aws_access_key_id` / `aws_secret_access_key` / `aws_session_token`; `iam_role_arn` is **not** a valid `boto3.client()` kwarg, and the spec's "BOTO credential layering" section makes `role_arn` config owned by the storage profile, not the IAM auth credential. So `ROLE_ARN` keeps its field (construction unaffected) but `driver_key=None` (not emitted). `PROFILE_NAME` stays `None`.
- **D5 — Phase 2 rewrites existing `tests/test_schemas.py` assertions that encode the OLD bare-`driver_key` behavior** (e.g. `PasswordAuth._default_kwargs()["user"]`, `TokenAuth._default_kwargs()["token"]`, `IAMAuth._default_kwargs()["iam_role_arn"]`). These change because the underlying contract changes deliberately (the spec calls those driver_keys "dead and inconsistent"). New per-profile/per-target golden tests live in a new `tests/test_emission.py`; the now-wrong `*_default_kwargs` tests in `test_schemas.py` are updated to assert the new target-aware output (or construction-only where emission moved to an adapter). This is a spec-driven behavior change, not test-silencing.
- **D6 — `paramiko` and `authlib` are added to the `test` env** (hatch.toml) so the certificate/kerberos (paramiko) and oauth1 (authlib) adapters can be golden-tested. A new `[sftp]` packaging extra (`paramiko`) is added to `pyproject.toml`, mirroring transport's extra name so the missing-extra error message is consistent cross-repo. The `[oauth1]` extra already exists.
- **D7 — Plain `OAuth2AuthProfile` gets a `{HTTP: bearer}` adapter (from `TOKEN`) and sheds its bare driver_keys.** Surfaced by review: the current transport resolver maps `OAuth2Auth` with a `TOKEN` to `BearerTokenStrategy` (resolver lines 80-84). If Phase 2 left plain oauth2 untouched, Phase 3's deletion of `_core/auth` would silently drop its HTTP Bearer behavior. So plain oauth2 is folded into Phase 2 (Task 10): a Bearer-from-`TOKEN` adapter (guarding empty/None, matching the resolver's truthiness), with `CLIENT_ID`/`CLIENT_SECRET`/`TOKEN` bare driver_keys removed (client-credentials *acquisition* is flow territory, not emission). `CertificateAuthProfile` keeps the old `SSHKeyStrategy` **fail-fast**: emitting PARAMIKO with no `PRIVATE_KEY_PATH`/`PRIVATE_KEY` raises `ValueError` rather than silently connecting keyless.
- **Truthiness parity.** All Bearer adapters (token/jwt/oauth2_authcode/plain-oauth2) reproduce the old resolver's behavior of emitting **no** header when the unwrapped token is falsy (`""`/`None`), not a blank `Authorization: Bearer ` header. IAM tier-1 emission skips `None` (the accepted Phase 1 settings behavior) rather than the old strategy's full truthiness — realistic credentials are non-empty, so the golden outputs match; the plan does not claim empty-string parity for IAM.

### Golden output reference (from transport `_core/auth/strategies.py`, to be deleted in Phase 3)

| Profile | `emit(family)` | Exact output |
|---------|----------------|--------------|
| `TokenAuthProfile` / `JWTAuthProfile` | HTTP | `{"headers": {"Authorization": f"Bearer {TOKEN}"}}` |
| `OAuth2AuthProfile` (plain) | HTTP | `{"headers": {"Authorization": f"Bearer {TOKEN}"}}` when `TOKEN` set; `{}` otherwise (resolver-parity, D7) |
| `PasswordAuthProfile` | HTTP | `{"headers": {"Authorization": "Basic " + b64(f"{USERNAME}:{PASSWORD}")}}` |
| `PasswordAuthProfile` | PARAMIKO | `{"username": USERNAME, "password": PASSWORD}` (tier-1 rename; **restores username** the old `SSHPasswordStrategy` dropped) |
| `IAMAuthProfile` | BOTO | `{"aws_access_key_id":…, "aws_secret_access_key":…, "aws_session_token":…}` (only keys that are set) |
| `OAuth2AuthCodeAuthProfile` | HTTP | `{"headers": {"Authorization": f"Bearer {ACCESS_TOKEN}"}}` when `ACCESS_TOKEN` set; `{}` otherwise |
| `OAuth1AuthProfile` | HTTP | `{"auth": OAuth1Auth(client_id=CONSUMER_KEY, client_secret=CONSUMER_SECRET, token=ACCESS_TOKEN, token_secret=ACCESS_TOKEN_SECRET)}` |
| `CertificateAuthProfile` | PARAMIKO | path → `{"key_filename": str(PRIVATE_KEY_PATH)[, "passphrase": …]}`; raw PEM → `{"pkey": <paramiko PKey>}` |
| `KerberosAuthProfile` | PARAMIKO | `{"gss_auth": True, "gss_host": SERVICE_NAME}` (mirrors `SSHKerberosStrategy(gss_host=SERVICE_NAME)`; `gss_kex` stays default-off) |
| `NoAuthProfile` | any | `{}` |

All adapters **copy-on-write** nested containers (`kw["headers"] = {**kw.get("headers", {}), …}`) per emission safety rule 1. Secret fields are `SecretStr`; unwrap with `.get_secret_value()` (guard `None` for optional secrets).

### Commands (auth-client repo)

- One test file: `hatch run test:test-quick tests/test_emission.py -q`
- One test: `hatch run test:test-quick tests/test_emission.py::TestBearer::test_http -q`
- Full suite (with coverage): `hatch run test:test`
- Lint: `hatch run ruff:check` (checks `./src` only — this repo does not lint `tests/`)

> Use `test-quick` for fast iteration (no coverage); the final gate uses `test`.

---

## File Structure

- **Create** `src/mountainash_auth_client/targets.py` — `TargetFamily` enum.
- **Modify** `src/mountainash_auth_client/__init__.py` — export `TargetFamily`.
- **Modify** `src/mountainash_auth_client/connections/_optional.py` — add `require_paramiko`.
- **Modify** `pyproject.toml` — add `[sftp]` extra (`paramiko`).
- **Modify** `hatch.toml` — add `authlib`, `paramiko` to the `test` env deps.
- **Modify** schema files: `token.py`, `password.py`, `iam.py`, `oauth2_authcode.py`, `oauth1.py`, `certificate.py`, `kerberos.py`, `oauth2.py` (plain) — target-scoped `driver_key`s + `__adapters__`.
- **Create** `tests/test_emission.py` — per-profile/per-target golden tests.
- **Create** `tests/test_emission_invariants.py` — rule-4 (no bare driver_key behind an adapter) over `AUTH_REGISTRY`.
- **Modify** `tests/test_schemas.py` — update the `*_default_kwargs` assertions that encoded the old contract (D5).

`none.py` needs **no change** (no params, no adapter → `emit(any)` returns `{}`). `azure.py` and `service_account.py` are untouched: they have no adapters, so rule-4 permits their (absent) `driver_key`s. Plain `oauth2.py` **is** modified (D7): the old resolver mapped its `TOKEN` to a Bearer strategy, so it gains a `{HTTP: bearer}` adapter and sheds its now-dead bare driver_keys.

---

### Task 1: `TargetFamily` enum + package export

**Files:**
- Create: `src/mountainash_auth_client/targets.py`
- Modify: `src/mountainash_auth_client/__init__.py`
- Test: `tests/test_emission.py`

- [ ] **Step 1: Write the failing test** — create `tests/test_emission.py`:

```python
"""Per-profile, per-target golden emission tests (Phase 2)."""
from __future__ import annotations

import base64

import pytest

from mountainash_auth_client.targets import TargetFamily


@pytest.mark.unit
class TestTargetFamily:
    def test_members_and_values(self):
        assert TargetFamily.HTTP == "http"
        assert TargetFamily.BOTO == "boto"
        assert TargetFamily.PARAMIKO == "paramiko"

    def test_is_str_enum(self):
        # str-Enum so it doubles as an opaque Hashable settings key.
        assert isinstance(TargetFamily.HTTP, str)

    def test_exported_from_package_root(self):
        from mountainash_auth_client import TargetFamily as Exported
        assert Exported is TargetFamily
```

- [ ] **Step 2: Run to verify it fails**

Run: `hatch run test:test-quick tests/test_emission.py::TestTargetFamily -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'mountainash_auth_client.targets'`.

- [ ] **Step 3: Create `src/mountainash_auth_client/targets.py`:**

```python
"""Emission target families — the SDK-client axis that selects an auth shape.

Owned by auth-client (the spec keeps mountainash-settings domain-agnostic: it
stores adapters under an opaque ``Hashable`` key and never imports this enum).
A connection declares its family; ``profile.emit(family)`` renders the kwargs
that family's SDK client expects.
"""
from __future__ import annotations

from enum import Enum

__all__ = ["TargetFamily"]


class TargetFamily(str, Enum):
    """The SDK client family an emission targets."""

    HTTP = "http"        # httpx
    BOTO = "boto"        # boto3
    PARAMIKO = "paramiko"  # ssh / sftp
```

- [ ] **Step 4: Export from the package root.** In `src/mountainash_auth_client/__init__.py`, add an import and an `__all__` entry.

After the `from mountainash_auth_client.constants import CONST_AUTH_PROFILES` line, add:
```python
from mountainash_auth_client.targets import TargetFamily
```
In `__all__`, add `"TargetFamily",` (keep alphabetical-ish; place after `"TokenExchangeError"` or near the T entries).

- [ ] **Step 5: Run to verify it passes**

Run: `hatch run test:test-quick tests/test_emission.py::TestTargetFamily -q`
Expected: PASS (3 passed).

- [ ] **Step 6: Lint**

Run: `hatch run ruff:check`
Expected: `All checks passed!` (auto-fix: `hatch run ruff:fix`).

- [ ] **Step 7: Commit**

```bash
git add src/mountainash_auth_client/targets.py src/mountainash_auth_client/__init__.py tests/test_emission.py
git commit -m "feat(auth): add TargetFamily emission-target enum

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `[sftp]` extra + `require_paramiko` + test-env deps

**Files:**
- Modify: `pyproject.toml` (`[project.optional-dependencies]`)
- Modify: `hatch.toml` (`[envs.test]` deps)
- Modify: `src/mountainash_auth_client/connections/_optional.py`
- Test: `tests/test_emission.py`

- [ ] **Step 1: Write the failing test** — append to `tests/test_emission.py`:

```python
@pytest.mark.unit
class TestRequireParamiko:
    def test_returns_module(self):
        # paramiko is in the test env (added in this task); require returns it.
        from mountainash_auth_client.connections._optional import require_paramiko
        paramiko = require_paramiko()
        assert hasattr(paramiko, "RSAKey")

    def test_returns_named_attr(self):
        from mountainash_auth_client.connections._optional import require_paramiko
        RSAKey = require_paramiko("RSAKey")
        assert RSAKey.__name__ == "RSAKey"

    def test_missing_extra_message(self, monkeypatch):
        # Simulate paramiko not installed → consistent install hint.
        # Patch importlib.import_module directly (the seam `require` uses),
        # mirroring the existing tests/connections/test_optional.py pattern.
        # This avoids sys.modules-cache fragility: paramiko may already be
        # imported by other tests, so patching builtins.__import__ would not
        # reach import_module's cached return.
        import importlib

        from mountainash_auth_client.connections._optional import require_paramiko

        def boom(name):
            raise ImportError("simulated missing paramiko")

        monkeypatch.setattr(importlib, "import_module", boom)
        with pytest.raises(ImportError) as exc_info:
            require_paramiko("RSAKey")
        msg = str(exc_info.value)
        assert "SSH key/Kerberos auth requires paramiko" in msg
        assert "pip install mountainash-auth-client[sftp]" in msg
```

- [ ] **Step 2: Run to verify it fails**

Run: `hatch run test:test-quick tests/test_emission.py::TestRequireParamiko -q`
Expected: FAIL — `ImportError: cannot import name 'require_paramiko'` (and/or paramiko not installed yet).

- [ ] **Step 3: Add the `[sftp]` extra.** In `pyproject.toml`, under `[project.optional-dependencies]`, add a line after `oauth1 = [...]`:

```toml
sftp = ["paramiko>=3.0.0"]
```

- [ ] **Step 4: Add `authlib` + `paramiko` to the test env.** In `hatch.toml`, in `[envs.test]` `dependencies = [...]`, add two entries after the `mountainash-settings @ …` line:

```toml
    "authlib>=1.3.0",
    "paramiko>=3.0.0",
```

(These let the oauth1/certificate/kerberos adapter golden tests run. The env will reinstall on next `hatch run test:` invocation since its dependency set changed.)

- [ ] **Step 5: Add `require_paramiko`.** In `src/mountainash_auth_client/connections/_optional.py`, append after `require_authlib`:

```python
def require_paramiko(*attrs: str) -> Any:
    """Load paramiko (or named attributes), behind the ``[sftp]`` extra."""
    return require(
        "paramiko",
        *attrs,
        extra="sftp",
        feature="SSH key/Kerberos auth",
    )
```

- [ ] **Step 6: Run to verify it passes** (the env reinstalls deps on first invocation)

Run: `hatch run test:test-quick tests/test_emission.py::TestRequireParamiko -q`
Expected: PASS (3 passed). If paramiko still missing, the env did not re-sync — run `hatch env prune` is too broad; instead confirm hatch.toml saved and re-run; if needed `~/.local/bin/uv pip install --python <env-venv>/bin/python paramiko authlib`.

- [ ] **Step 7: Lint**

Run: `hatch run ruff:check`
Expected: `All checks passed!`

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml hatch.toml src/mountainash_auth_client/connections/_optional.py tests/test_emission.py
git commit -m "feat(auth): add [sftp] extra and require_paramiko optional loader

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Bearer adapter — Token + JWT (HTTP)

**Files:**
- Modify: `src/mountainash_auth_client/schemas/token.py`
- Test: `tests/test_emission.py`
- Modify: `tests/test_schemas.py` (rewrite `TestTokenAuth.test_default_kwargs`, `TestJWTAuth.test_default_kwargs`)

- [ ] **Step 1: Write the failing test** — append to `tests/test_emission.py`:

```python
@pytest.mark.unit
class TestBearer:
    def test_token_http(self):
        from mountainash_auth_client import TokenAuthProfile
        out = TokenAuthProfile(TOKEN="abc").emit(TargetFamily.HTTP)
        assert out == {"headers": {"Authorization": "Bearer abc"}}

    def test_jwt_http(self):
        from mountainash_auth_client import JWTAuthProfile
        out = JWTAuthProfile(TOKEN="eyJ").emit(TargetFamily.HTTP)
        assert out == {"headers": {"Authorization": "Bearer eyJ"}}

    def test_layers_onto_base_headers_copy_on_write(self):
        from mountainash_auth_client import TokenAuthProfile
        base = {"headers": {"X-Trace": "1"}, "timeout": 5}
        out = TokenAuthProfile(TOKEN="abc").emit(TargetFamily.HTTP, base=base)
        assert out["headers"] == {"X-Trace": "1", "Authorization": "Bearer abc"}
        assert out["timeout"] == 5
        # base untouched (copy-on-write).
        assert base["headers"] == {"X-Trace": "1"}

    def test_targeted_no_target_raises(self):
        from mountainash_auth_client import TokenAuthProfile
        with pytest.raises(ValueError, match="target-scoped"):
            TokenAuthProfile(TOKEN="abc").emit()

    def test_empty_token_emits_nothing(self):
        # Matches the old resolver truthiness: a falsy token yields no header.
        from mountainash_auth_client import TokenAuthProfile
        assert TokenAuthProfile(TOKEN="").emit(TargetFamily.HTTP) == {}
```

- [ ] **Step 2: Run to verify it fails**

Run: `hatch run test:test-quick tests/test_emission.py::TestBearer -q`
Expected: FAIL — current `TokenAuthProfile` has a bare `driver_key="token"`, no adapter; `emit(HTTP)` returns `{"token": "abc"}` (or, since not targeted, does not raise). Assertions mismatch.

- [ ] **Step 3: Rewrite `src/mountainash_auth_client/schemas/token.py`:**

```python
"""Bearer-token and JWT authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["TokenAuthProfile", "JWTAuthProfile", "TOKEN_SPEC", "JWT_SPEC"]


def _bearer_header(profile, kw):
    """Render the token as an HTTP ``Authorization: Bearer`` header.

    Matches the old ``resolve_auth_strategy`` truthiness: an empty token yields
    no header (the resolver fell through to NoAuth when the token was falsy).
    """
    token = profile.TOKEN.get_secret_value()
    if not token:
        return kw
    headers = {**kw.get("headers", {}), "Authorization": f"Bearer {token}"}
    return {**kw, "headers": headers}


TOKEN_SPEC = ProfileSpec(
    name="token",
    provider_type="token",
    parameters=[
        ParameterSpec(name="TOKEN", type=str, tier="core", secret=True),
    ],
)


@register
class TokenAuthProfile(Profile):
    __spec__ = TOKEN_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_header}


JWT_SPEC = ProfileSpec(
    name="jwt",
    provider_type="jwt",
    parameters=[
        ParameterSpec(name="TOKEN", type=str, tier="core", secret=True),
    ],
)


@register
class JWTAuthProfile(Profile):
    __spec__ = JWT_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_header}
```

(Note: `driver_key="token"` removed — rule 4 forbids a bare driver_key on an adapter-bearing profile. `TOKEN` is `secret=True`, so it is a `SecretStr`; `.get_secret_value()` unwraps it.)

- [ ] **Step 4: Run to verify it passes**

Run: `hatch run test:test-quick tests/test_emission.py::TestBearer -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Update the now-stale tests in `tests/test_schemas.py`.** Replace `TestTokenAuth.test_default_kwargs` and `TestJWTAuth.test_default_kwargs` with target-aware assertions:

```python
    def test_default_kwargs(self):
        # token is now adapter-only (HTTP Bearer); no bare driver_key.
        cls = AUTH_REGISTRY.get_settings_class("token")
        instance = cls(TOKEN="my-bearer-token")
        assert instance._default_kwargs() == {}
```

and for JWT:

```python
    def test_default_kwargs(self):
        cls = AUTH_REGISTRY.get_settings_class("jwt")
        instance = cls(TOKEN="eyJhbGciOi...")
        assert instance._default_kwargs() == {}
```

- [ ] **Step 6: Run the schema tests**

Run: `hatch run test:test-quick tests/test_schemas.py -q`
Expected: PASS (TokenAuth/JWT updated; all others still green).

- [ ] **Step 7: Lint + Commit**

```bash
hatch run ruff:check
git add src/mountainash_auth_client/schemas/token.py tests/test_emission.py tests/test_schemas.py
git commit -m "feat(auth): Token/JWT emit HTTP Bearer header via adapter

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Password — PARAMIKO rename + HTTP Basic adapter

**Files:**
- Modify: `src/mountainash_auth_client/schemas/password.py`
- Test: `tests/test_emission.py`
- Modify: `tests/test_schemas.py` (`TestPasswordAuth.test_default_kwargs`)

- [ ] **Step 1: Write the failing test** — append to `tests/test_emission.py`:

```python
@pytest.mark.unit
class TestPassword:
    def test_http_basic_header(self):
        from mountainash_auth_client import PasswordAuthProfile
        out = PasswordAuthProfile(USERNAME="alice", PASSWORD="hunter2").emit(
            TargetFamily.HTTP
        )
        expected = base64.b64encode(b"alice:hunter2").decode()
        assert out == {"headers": {"Authorization": f"Basic {expected}"}}

    def test_paramiko_username_and_password(self):
        from mountainash_auth_client import PasswordAuthProfile
        out = PasswordAuthProfile(USERNAME="alice", PASSWORD="hunter2").emit(
            TargetFamily.PARAMIKO
        )
        # Restores username the old SSHPasswordStrategy dropped.
        assert out == {"username": "alice", "password": "hunter2"}

    def test_http_no_stray_username_password(self):
        from mountainash_auth_client import PasswordAuthProfile
        out = PasswordAuthProfile(USERNAME="alice", PASSWORD="hunter2").emit(
            TargetFamily.HTTP
        )
        assert "username" not in out and "password" not in out and "user" not in out

    def test_unknown_target_raises(self):
        from mountainash_auth_client import PasswordAuthProfile
        with pytest.raises(ValueError, match="no emission for target"):
            PasswordAuthProfile(USERNAME="a", PASSWORD="b").emit(TargetFamily.BOTO)
```

- [ ] **Step 2: Run to verify it fails**

Run: `hatch run test:test-quick tests/test_emission.py::TestPassword -q`
Expected: FAIL — current password has bare `driver_key="user"/"password"`, no adapter.

- [ ] **Step 3: Rewrite `src/mountainash_auth_client/schemas/password.py`:**

```python
"""Classic username + password authentication."""
import base64

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["PasswordAuthProfile", "PASSWORD_SPEC"]


def _basic_header(profile, kw):
    """Render USERNAME/PASSWORD as an HTTP Basic ``Authorization`` header."""
    raw = f"{profile.USERNAME}:{profile.PASSWORD.get_secret_value()}".encode()
    token = base64.b64encode(raw).decode()
    headers = {**kw.get("headers", {}), "Authorization": f"Basic {token}"}
    return {**kw, "headers": headers}


PASSWORD_SPEC = ProfileSpec(
    name="password",
    provider_type="password",
    parameters=[
        ParameterSpec(
            name="USERNAME",
            type=str,
            tier="core",
            driver_key={TargetFamily.PARAMIKO: "username"},
        ),
        ParameterSpec(
            name="PASSWORD",
            type=str,
            tier="core",
            secret=True,
            driver_key={TargetFamily.PARAMIKO: "password"},
        ),
    ],
)


@register
class PasswordAuthProfile(Profile):
    __spec__ = PASSWORD_SPEC
    __adapters__ = {TargetFamily.HTTP: _basic_header}
```

(`USERNAME`/`PASSWORD` emit at tier 1 only for PARAMIKO, so the HTTP `base` never carries a stray `password=`/`user=`; the Basic adapter is the sole HTTP producer — the field-leak resolution from the spec.)

- [ ] **Step 4: Run to verify it passes**

Run: `hatch run test:test-quick tests/test_emission.py::TestPassword -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Update `tests/test_schemas.py`.** Replace `TestPasswordAuth.test_default_kwargs`:

```python
    def test_default_kwargs(self):
        # USERNAME/PASSWORD are PARAMIKO-scoped now; untargeted emit is empty.
        cls = AUTH_REGISTRY.get_settings_class("password")
        instance = cls(USERNAME="alice", PASSWORD="hunter2")
        assert instance._default_kwargs() == {}
        assert instance._default_kwargs("paramiko") == {
            "username": "alice",
            "password": "hunter2",
        }
```

- [ ] **Step 6: Run the schema tests**

Run: `hatch run test:test-quick tests/test_schemas.py -q`
Expected: PASS.

- [ ] **Step 7: Lint + Commit**

```bash
hatch run ruff:check
git add src/mountainash_auth_client/schemas/password.py tests/test_emission.py tests/test_schemas.py
git commit -m "feat(auth): Password emits PARAMIKO username/password and HTTP Basic header

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: IAM — BOTO-scoped credentials

**Files:**
- Modify: `src/mountainash_auth_client/schemas/iam.py`
- Test: `tests/test_emission.py`
- Modify: `tests/test_schemas.py` (`TestIAMAuth.test_construction_with_role`, `test_construction_with_keys`)

- [ ] **Step 1: Write the failing test** — append to `tests/test_emission.py`:

```python
@pytest.mark.unit
class TestIAM:
    def test_boto_full_credentials(self):
        from mountainash_auth_client import IAMAuthProfile
        out = IAMAuthProfile(
            ACCESS_KEY_ID="AKID", SECRET_ACCESS_KEY="secret", SESSION_TOKEN="tok"
        ).emit(TargetFamily.BOTO)
        assert out == {
            "aws_access_key_id": "AKID",
            "aws_secret_access_key": "secret",
            "aws_session_token": "tok",
        }

    def test_boto_skips_unset(self):
        from mountainash_auth_client import IAMAuthProfile
        out = IAMAuthProfile(ACCESS_KEY_ID="AKID").emit(TargetFamily.BOTO)
        assert out == {"aws_access_key_id": "AKID"}

    def test_boto_ambient_is_empty(self):
        from mountainash_auth_client import IAMAuthProfile
        assert IAMAuthProfile().emit(TargetFamily.BOTO) == {}

    def test_role_arn_not_emitted(self):
        from mountainash_auth_client import IAMAuthProfile
        # role_arn is config (storage-profile owned), not a boto3.client kwarg.
        out = IAMAuthProfile(
            ROLE_ARN="arn:aws:iam::123:role/r", ACCESS_KEY_ID="AKID"
        ).emit(TargetFamily.BOTO)
        assert "iam_role_arn" not in out
        assert out == {"aws_access_key_id": "AKID"}

    def test_layers_onto_base(self):
        from mountainash_auth_client import IAMAuthProfile
        out = IAMAuthProfile(ACCESS_KEY_ID="AKID").emit(
            TargetFamily.BOTO, base={"region_name": "us-east-1"}
        )
        assert out == {"region_name": "us-east-1", "aws_access_key_id": "AKID"}
```

- [ ] **Step 2: Run to verify it fails**

Run: `hatch run test:test-quick tests/test_emission.py::TestIAM -q`
Expected: FAIL — IAM currently has bare driver_keys (incl. `iam_role_arn`); `emit(BOTO)` is not yet target-scoped and `test_role_arn_not_emitted` fails.

- [ ] **Step 3: Rewrite `src/mountainash_auth_client/schemas/iam.py`:**

```python
"""AWS IAM authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["IAMAuthProfile", "IAM_SPEC"]

IAM_SPEC = ProfileSpec(
    name="iam",
    provider_type="iam",
    parameters=[
        # ROLE_ARN is config consumed by the storage profile's assume-role
        # shape, not a boto3.client() kwarg — kept as a field, never emitted.
        ParameterSpec(name="ROLE_ARN", type=str | None, tier="core", default=None),
        ParameterSpec(name="ACCESS_KEY_ID", type=str | None, tier="core",
                      driver_key={TargetFamily.BOTO: "aws_access_key_id"}, default=None),
        ParameterSpec(name="SECRET_ACCESS_KEY", type=str | None, tier="core",
                      driver_key={TargetFamily.BOTO: "aws_secret_access_key"}, default=None, secret=True),
        ParameterSpec(name="SESSION_TOKEN", type=str | None, tier="advanced",
                      driver_key={TargetFamily.BOTO: "aws_session_token"}, default=None, secret=True),
        ParameterSpec(name="PROFILE_NAME", type=str | None, tier="advanced", default=None),
    ],
)


@register
class IAMAuthProfile(Profile):
    __spec__ = IAM_SPEC
```

(IAM has **no** adapter — pure tier-1 data. Dict driver_keys make it target-scoped, so `emit(BOTO)` works and `emit()`/`emit(HTTP)` fail closed, which is correct: IAM is only ever emitted on a BOTO leaf.)

- [ ] **Step 4: Run to verify it passes**

Run: `hatch run test:test-quick tests/test_emission.py::TestIAM -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Update `tests/test_schemas.py`.** Replace `TestIAMAuth.test_construction_with_role` and `test_construction_with_keys`:

```python
    def test_construction_with_role(self):
        # ROLE_ARN is stored as a field but no longer emitted (config, not a
        # boto3.client kwarg).
        cls = AUTH_REGISTRY.get_settings_class("iam")
        instance = cls(ROLE_ARN="arn:aws:iam::123:role/myrole")
        assert instance.ROLE_ARN == "arn:aws:iam::123:role/myrole"
        assert instance._default_kwargs("boto") == {}

    def test_construction_with_keys(self):
        cls = AUTH_REGISTRY.get_settings_class("iam")
        instance = cls(
            ACCESS_KEY_ID="AKID",
            SECRET_ACCESS_KEY="secret",
            SESSION_TOKEN="tok",
        )
        result = instance._default_kwargs("boto")
        assert result["aws_access_key_id"] == "AKID"
        assert result["aws_secret_access_key"] == "secret"
        assert result["aws_session_token"] == "tok"
```

Also update `TestIAMAuth.test_construction_ambient` if it calls `_default_kwargs()` with no target — change to `instance._default_kwargs("boto") == {}` (untargeted on a now-targeted profile is still `{}` from `_default_kwargs`, but be explicit):

```python
    def test_construction_ambient(self):
        cls = AUTH_REGISTRY.get_settings_class("iam")
        instance = cls()
        assert instance._default_kwargs("boto") == {}
```

- [ ] **Step 6: Run the schema tests**

Run: `hatch run test:test-quick tests/test_schemas.py -q`
Expected: PASS.

- [ ] **Step 7: Lint + Commit**

```bash
hatch run ruff:check
git add src/mountainash_auth_client/schemas/iam.py tests/test_emission.py tests/test_schemas.py
git commit -m "feat(auth): IAM credentials scoped to BOTO target; role_arn no longer emitted

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: OAuth2 Authorization-Code — Bearer-from-access-token (HTTP)

**Files:**
- Modify: `src/mountainash_auth_client/schemas/oauth2_authcode.py`
- Test: `tests/test_emission.py`

- [ ] **Step 1: Write the failing test** — append to `tests/test_emission.py`:

```python
@pytest.mark.unit
class TestOAuth2AuthCode:
    def test_http_bearer_from_access_token(self):
        from mountainash_auth_client import OAuth2AuthCodeAuthProfile
        out = OAuth2AuthCodeAuthProfile(
            CLIENT_ID="cid", CLIENT_SECRET="csec", ACCESS_TOKEN="at"
        ).emit(TargetFamily.HTTP)
        assert out == {"headers": {"Authorization": "Bearer at"}}

    def test_http_no_token_is_empty(self):
        from mountainash_auth_client import OAuth2AuthCodeAuthProfile
        # No access token in hand → nothing static to render (flow acquires it).
        out = OAuth2AuthCodeAuthProfile(CLIENT_ID="cid", CLIENT_SECRET="csec").emit(
            TargetFamily.HTTP
        )
        assert out == {}

    def test_no_stray_client_fields(self):
        from mountainash_auth_client import OAuth2AuthCodeAuthProfile
        out = OAuth2AuthCodeAuthProfile(
            CLIENT_ID="cid", CLIENT_SECRET="csec", ACCESS_TOKEN="at"
        ).emit(TargetFamily.HTTP)
        assert "client_id" not in out and "access_token" not in out
```

- [ ] **Step 2: Run to verify it fails**

Run: `hatch run test:test-quick tests/test_emission.py::TestOAuth2AuthCode -q`
Expected: FAIL — current oauth2_authcode has bare driver_keys (client_id/client_secret/access_token/refresh_token), no adapter.

- [ ] **Step 3: Rewrite `src/mountainash_auth_client/schemas/oauth2_authcode.py`:**

```python
"""OAuth 2.0 Authorization Code grant authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["OAuth2AuthCodeAuthProfile", "OAUTH2_AUTHCODE_SPEC"]


def _bearer_from_access_token(profile, kw):
    """Render the *current* access token as a Bearer header (have-a-token case).

    Token acquisition/refresh is the flow's job, not emission; when no access
    token is present (None or empty) this renders nothing — matching the old
    resolver's truthiness on the unwrapped token.
    """
    token = profile.ACCESS_TOKEN.get_secret_value() if profile.ACCESS_TOKEN else None
    if not token:
        return kw
    headers = {**kw.get("headers", {}), "Authorization": f"Bearer {token}"}
    return {**kw, "headers": headers}


OAUTH2_AUTHCODE_SPEC = ProfileSpec(
    name="oauth2_authcode",
    provider_type="oauth2_authcode",
    parameters=[
        ParameterSpec(name="CLIENT_ID", type=str, tier="core"),
        ParameterSpec(name="CLIENT_SECRET", type=str, tier="core", secret=True),
        ParameterSpec(name="ACCESS_TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="TOKEN_EXPIRES_AT", type=int | None, tier="advanced", default=None),
        ParameterSpec(name="SCOPE", type=str | None, tier="advanced", default=None),
    ],
)


@register
class OAuth2AuthCodeAuthProfile(Profile):
    __spec__ = OAUTH2_AUTHCODE_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_from_access_token}
```

(All bare driver_keys removed per rule 4; `ACCESS_TOKEN` is `secret=True` → `SecretStr`.)

- [ ] **Step 4: Run to verify it passes**

Run: `hatch run test:test-quick tests/test_emission.py::TestOAuth2AuthCode -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Confirm `test_schemas.py::TestOAuth2AuthCodeAuth` still passes** (it only tests construction/field storage, not `_default_kwargs`, so it should be unaffected):

Run: `hatch run test:test-quick "tests/test_schemas.py::TestOAuth2AuthCodeAuth" -q`
Expected: PASS. If any assertion reads `_default_kwargs()`, update it to expect `{}` (no bare driver_keys remain).

- [ ] **Step 6: Lint + Commit**

```bash
hatch run ruff:check
git add src/mountainash_auth_client/schemas/oauth2_authcode.py tests/test_emission.py
git commit -m "feat(auth): OAuth2 auth-code emits HTTP Bearer from current access token

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: OAuth1 — authlib signer object (HTTP)

**Files:**
- Modify: `src/mountainash_auth_client/schemas/oauth1.py`
- Test: `tests/test_emission.py`

- [ ] **Step 1: Write the failing test** — append to `tests/test_emission.py`:

```python
@pytest.mark.unit
class TestOAuth1:
    def test_http_installs_authlib_signer(self):
        from mountainash_auth_client import OAuth1AuthProfile
        OAuth1Auth = pytest.importorskip(
            "authlib.integrations.httpx_client"
        ).OAuth1Auth
        out = OAuth1AuthProfile(
            CONSUMER_KEY="ck", CONSUMER_SECRET="cs",
            ACCESS_TOKEN="at", ACCESS_TOKEN_SECRET="ats",
        ).emit(TargetFamily.HTTP)
        assert set(out) == {"auth"}
        assert isinstance(out["auth"], OAuth1Auth)
        # authlib stores the consumer key as client_id.
        assert out["auth"].client_id == "ck"

    def test_no_stray_consumer_fields(self):
        from mountainash_auth_client import OAuth1AuthProfile
        pytest.importorskip("authlib.integrations.httpx_client")
        out = OAuth1AuthProfile(
            CONSUMER_KEY="ck", CONSUMER_SECRET="cs",
            ACCESS_TOKEN="at", ACCESS_TOKEN_SECRET="ats",
        ).emit(TargetFamily.HTTP)
        assert "consumer_key" not in out and "consumer_secret" not in out
```

- [ ] **Step 2: Run to verify it fails**

Run: `hatch run test:test-quick tests/test_emission.py::TestOAuth1 -q`
Expected: FAIL — current oauth1 has bare `consumer_key`/`consumer_secret` driver_keys, no adapter.

- [ ] **Step 3: Rewrite `src/mountainash_auth_client/schemas/oauth1.py`:**

```python
"""OAuth 1.0a authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..connections._optional import require_authlib
from ..targets import TargetFamily
from .registry import register

__all__ = ["OAuth1AuthProfile", "OAUTH1_SPEC"]


def _oauth1_signer(profile, kw):
    """Build an authlib ``OAuth1Auth`` signer under httpx's ``auth=`` kwarg."""
    OAuth1Auth = require_authlib("OAuth1Auth")
    return {
        **kw,
        "auth": OAuth1Auth(
            client_id=profile.CONSUMER_KEY,
            client_secret=profile.CONSUMER_SECRET.get_secret_value(),
            token=profile.ACCESS_TOKEN.get_secret_value() if profile.ACCESS_TOKEN else None,
            token_secret=profile.ACCESS_TOKEN_SECRET.get_secret_value() if profile.ACCESS_TOKEN_SECRET else None,
        ),
    }


OAUTH1_SPEC = ProfileSpec(
    name="oauth1",
    provider_type="oauth1",
    parameters=[
        ParameterSpec(name="CONSUMER_KEY", type=str, tier="core"),
        ParameterSpec(name="CONSUMER_SECRET", type=str, tier="core", secret=True),
        ParameterSpec(name="ACCESS_TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="ACCESS_TOKEN_SECRET", type=str | None, tier="core", default=None, secret=True),
    ],
)


@register
class OAuth1AuthProfile(Profile):
    __spec__ = OAUTH1_SPEC
    __adapters__ = {TargetFamily.HTTP: _oauth1_signer}
```

(`CONSUMER_KEY` is not secret in the current spec, so it is a plain `str` — no unwrap. `CONSUMER_SECRET`/`ACCESS_TOKEN`/`ACCESS_TOKEN_SECRET` are `SecretStr`.)

- [ ] **Step 4: Run to verify it passes**

Run: `hatch run test:test-quick tests/test_emission.py::TestOAuth1 -q`
Expected: PASS (2 passed; skips if authlib absent — but the test env installs it in Task 2).

- [ ] **Step 5: Confirm `test_schemas.py::TestOAuth1Auth` still passes** (construction-only):

Run: `hatch run test:test-quick "tests/test_schemas.py::TestOAuth1Auth" -q`
Expected: PASS.

- [ ] **Step 6: Lint + Commit**

```bash
hatch run ruff:check
git add src/mountainash_auth_client/schemas/oauth1.py tests/test_emission.py
git commit -m "feat(auth): OAuth1 emits authlib signer object for HTTP

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Certificate — SSH key (PARAMIKO)

**Files:**
- Modify: `src/mountainash_auth_client/schemas/certificate.py`
- Test: `tests/test_emission.py`

- [ ] **Step 1: Write the failing test** — append to `tests/test_emission.py`:

```python
@pytest.mark.unit
class TestCertificate:
    def test_paramiko_key_path(self):
        from mountainash_auth_client import CertificateAuthProfile
        out = CertificateAuthProfile(
            PRIVATE_KEY_PATH="/home/u/.ssh/id_rsa", PASSPHRASE="pp"
        ).emit(TargetFamily.PARAMIKO)
        assert out == {"key_filename": "/home/u/.ssh/id_rsa", "passphrase": "pp"}

    def test_paramiko_key_path_no_passphrase(self):
        from mountainash_auth_client import CertificateAuthProfile
        out = CertificateAuthProfile(
            PRIVATE_KEY_PATH="/home/u/.ssh/id_rsa"
        ).emit(TargetFamily.PARAMIKO)
        assert out == {"key_filename": "/home/u/.ssh/id_rsa"}

    def test_paramiko_raw_pem_parsed_to_pkey(self):
        paramiko = pytest.importorskip("paramiko")
        from mountainash_auth_client import CertificateAuthProfile
        key = paramiko.RSAKey.generate(2048)
        import io
        buf = io.StringIO()
        key.write_private_key(buf)
        pem = buf.getvalue()
        out = CertificateAuthProfile(PRIVATE_KEY=pem).emit(TargetFamily.PARAMIKO)
        assert set(out) == {"pkey"}
        assert isinstance(out["pkey"], paramiko.PKey)
        assert out["pkey"].get_fingerprint() == key.get_fingerprint()

    def test_no_key_material_raises(self):
        # Fail-fast (matches old SSHKeyStrategy): no key path or PEM → error,
        # not a silent keyless connect.
        from mountainash_auth_client import CertificateAuthProfile
        with pytest.raises(ValueError, match="PRIVATE_KEY_PATH or PRIVATE_KEY"):
            CertificateAuthProfile().emit(TargetFamily.PARAMIKO)
```

- [ ] **Step 2: Run to verify it fails**

Run: `hatch run test:test-quick tests/test_emission.py::TestCertificate -q`
Expected: FAIL — certificate has no driver_keys and no adapter.

- [ ] **Step 3: Rewrite `src/mountainash_auth_client/schemas/certificate.py`:**

```python
"""Private-key / certificate authentication (Snowflake JWT, SSH keys)."""
import io
from pathlib import Path

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..connections._optional import require_paramiko
from ..targets import TargetFamily
from .registry import register

__all__ = ["CertificateAuthProfile", "CERTIFICATE_SPEC"]


def _parse_private_key(key_string: str, passphrase: str | None):
    """Parse a PEM/OpenSSH private key string into a paramiko PKey.

    Tries RSA, Ed25519, ECDSA, DSS in order; raises ``ValueError`` if none match.
    """
    paramiko = require_paramiko()
    for cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
        try:
            return cls.from_private_key(io.StringIO(key_string), password=passphrase)
        except paramiko.SSHException:
            continue
    raise ValueError("Could not parse private key: no supported key type matched.")


def _ssh_key(profile, kw):
    """Render PRIVATE_KEY_PATH (key_filename) or PRIVATE_KEY (parsed pkey).

    Fail-fast when neither is set, matching the old ``SSHKeyStrategy`` (which
    raised on construction with no key material). A certificate profile with no
    key would otherwise connect with no key auth silently.
    """
    passphrase = profile.PASSPHRASE.get_secret_value() if profile.PASSPHRASE else None
    if profile.PRIVATE_KEY_PATH is not None:
        out = {**kw, "key_filename": str(profile.PRIVATE_KEY_PATH)}
        if passphrase is not None:
            out["passphrase"] = passphrase
        return out
    if profile.PRIVATE_KEY is not None:
        pem = profile.PRIVATE_KEY.get_secret_value()
        return {**kw, "pkey": _parse_private_key(pem, passphrase)}
    raise ValueError(
        "CertificateAuthProfile requires PRIVATE_KEY_PATH or PRIVATE_KEY "
        "to emit PARAMIKO key auth."
    )


CERTIFICATE_SPEC = ProfileSpec(
    name="certificate",
    provider_type="certificate",
    parameters=[
        ParameterSpec(name="PRIVATE_KEY", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="PRIVATE_KEY_PATH", type=Path | None, tier="core", default=None),
        ParameterSpec(name="PASSPHRASE", type=str | None, tier="advanced", default=None, secret=True),
    ],
)


@register
class CertificateAuthProfile(Profile):
    __spec__ = CERTIFICATE_SPEC
    __adapters__ = {TargetFamily.PARAMIKO: _ssh_key}
```

- [ ] **Step 4: Run to verify it passes**

Run: `hatch run test:test-quick tests/test_emission.py::TestCertificate -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Confirm `test_schemas.py::TestCertificateAuth` still passes** (construction-only). If it asserts `_default_kwargs()`, update to `{}`.

Run: `hatch run test:test-quick "tests/test_schemas.py::TestCertificateAuth" -q`
Expected: PASS.

- [ ] **Step 6: Lint + Commit**

```bash
hatch run ruff:check
git add src/mountainash_auth_client/schemas/certificate.py tests/test_emission.py
git commit -m "feat(auth): Certificate emits paramiko key_filename/pkey for PARAMIKO

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Kerberos — GSS flags (PARAMIKO)

**Files:**
- Modify: `src/mountainash_auth_client/schemas/kerberos.py`
- Test: `tests/test_emission.py`

- [ ] **Step 1: Write the failing test** — append to `tests/test_emission.py`:

```python
@pytest.mark.unit
class TestKerberos:
    def test_paramiko_gss_flags_default_service(self):
        from mountainash_auth_client import KerberosAuthProfile
        out = KerberosAuthProfile().emit(TargetFamily.PARAMIKO)
        # SERVICE_NAME defaults to "postgres"; mirrors SSHKerberosStrategy(gss_host=SERVICE_NAME).
        assert out == {"gss_auth": True, "gss_host": "postgres"}

    def test_paramiko_gss_flags_custom_service(self):
        from mountainash_auth_client import KerberosAuthProfile
        out = KerberosAuthProfile(SERVICE_NAME="trino").emit(TargetFamily.PARAMIKO)
        assert out == {"gss_auth": True, "gss_host": "trino"}

    def test_layers_onto_base(self):
        from mountainash_auth_client import KerberosAuthProfile
        out = KerberosAuthProfile(SERVICE_NAME="trino").emit(
            TargetFamily.PARAMIKO, base={"hostname": "h"}
        )
        assert out == {"hostname": "h", "gss_auth": True, "gss_host": "trino"}
```

- [ ] **Step 2: Run to verify it fails**

Run: `hatch run test:test-quick tests/test_emission.py::TestKerberos -q`
Expected: FAIL — kerberos has no driver_keys and no adapter.

- [ ] **Step 3: Rewrite `src/mountainash_auth_client/schemas/kerberos.py`:**

```python
"""Kerberos / GSSAPI authentication."""
from pathlib import Path

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["KerberosAuthProfile", "KERBEROS_SPEC"]


def _gss_flags(profile, kw):
    """Render paramiko GSS/Kerberos connect flags.

    Mirrors the old ``SSHKerberosStrategy(gss_host=SERVICE_NAME)``: enable
    ``gss_auth`` and set ``gss_host`` from SERVICE_NAME (gss_kex stays off).
    """
    out = {**kw, "gss_auth": True}
    if profile.SERVICE_NAME is not None:
        out["gss_host"] = profile.SERVICE_NAME
    return out


KERBEROS_SPEC = ProfileSpec(
    name="kerberos",
    provider_type="kerberos",
    parameters=[
        ParameterSpec(name="SERVICE_NAME", type=str, tier="core", default="postgres"),
        ParameterSpec(name="PRINCIPAL", type=str | None, tier="core", default=None),
        ParameterSpec(name="KEYTAB", type=Path | None, tier="advanced", default=None),
    ],
)


@register
class KerberosAuthProfile(Profile):
    __spec__ = KERBEROS_SPEC
    __adapters__ = {TargetFamily.PARAMIKO: _gss_flags}
```

- [ ] **Step 4: Run to verify it passes**

Run: `hatch run test:test-quick tests/test_emission.py::TestKerberos -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Confirm `test_schemas.py::TestKerberosAuth` still passes** (construction-only).

Run: `hatch run test:test-quick "tests/test_schemas.py::TestKerberosAuth" -q`
Expected: PASS.

- [ ] **Step 6: Lint + Commit**

```bash
hatch run ruff:check
git add src/mountainash_auth_client/schemas/kerberos.py tests/test_emission.py
git commit -m "feat(auth): Kerberos emits paramiko GSS flags for PARAMIKO

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: Plain OAuth2 — Bearer from TOKEN (HTTP)

**Files:**
- Modify: `src/mountainash_auth_client/schemas/oauth2.py`
- Test: `tests/test_emission.py`
- Modify: `tests/test_schemas.py` (rewrite `TestOAuth2Auth` `_default_kwargs` tests)

This closes the gap the review found (D7): the old resolver gave plain
`OAuth2Auth` an HTTP Bearer from `TOKEN`. Without this, Phase 3's deletion of
`_core/auth` would drop that behavior.

- [ ] **Step 1: Write the failing test** — append to `tests/test_emission.py`:

```python
@pytest.mark.unit
class TestPlainOAuth2:
    def test_http_bearer_from_token(self):
        from mountainash_auth_client import OAuth2AuthProfile
        out = OAuth2AuthProfile(TOKEN="access-tok").emit(TargetFamily.HTTP)
        assert out == {"headers": {"Authorization": "Bearer access-tok"}}

    def test_http_no_token_is_empty(self):
        from mountainash_auth_client import OAuth2AuthProfile
        # client-credentials-only (no token yet) → nothing to render statically.
        out = OAuth2AuthProfile(CLIENT_ID="cid", CLIENT_SECRET="csec").emit(
            TargetFamily.HTTP
        )
        assert out == {}

    def test_no_stray_client_fields(self):
        from mountainash_auth_client import OAuth2AuthProfile
        out = OAuth2AuthProfile(TOKEN="access-tok").emit(TargetFamily.HTTP)
        assert "client_id" not in out and "token" not in out
```

- [ ] **Step 2: Run to verify it fails**

Run: `hatch run test:test-quick tests/test_emission.py::TestPlainOAuth2 -q`
Expected: FAIL — plain oauth2 has bare driver_keys (`client_id`/`client_secret`/`token`), no adapter.

- [ ] **Step 3: Rewrite `src/mountainash_auth_client/schemas/oauth2.py`:**

```python
"""OAuth2 client-credentials / token authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["OAuth2AuthProfile", "OAUTH2_SPEC"]


def _bearer_from_token(profile, kw):
    """Render the current ``TOKEN`` as an HTTP Bearer header (have-a-token case).

    Token acquisition via client credentials is the flow's job; an empty/None
    token renders nothing (matches the old resolver's truthiness).
    """
    token = profile.TOKEN.get_secret_value() if profile.TOKEN else None
    if not token:
        return kw
    headers = {**kw.get("headers", {}), "Authorization": f"Bearer {token}"}
    return {**kw, "headers": headers}


OAUTH2_SPEC = ProfileSpec(
    name="oauth2",
    provider_type="oauth2",
    parameters=[
        ParameterSpec(name="CLIENT_ID", type=str | None, tier="core", default=None),
        ParameterSpec(name="CLIENT_SECRET", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="advanced", default=None, secret=True),
        ParameterSpec(name="SERVER_URI", type=str | None, tier="advanced", default=None),
        ParameterSpec(name="SCOPE", type=str | None, tier="advanced", default=None),
    ],
)


@register
class OAuth2AuthProfile(Profile):
    __spec__ = OAUTH2_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_from_token}
```

(Bare `client_id`/`client_secret`/`token` driver_keys removed per rule 4.)

- [ ] **Step 4: Run to verify it passes**

Run: `hatch run test:test-quick tests/test_emission.py::TestPlainOAuth2 -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Update `tests/test_schemas.py::TestOAuth2Auth`.** Replace the three `_default_kwargs` tests (token / client-credentials / all-optional) with target-aware versions:

```python
    def test_default_kwargs_token(self):
        # TOKEN now renders via the HTTP Bearer adapter, not a bare driver_key.
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls(TOKEN="access-tok")
        assert instance._default_kwargs() == {}

    def test_default_kwargs_client_credentials(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls(CLIENT_ID="cid", CLIENT_SECRET="csec")
        # client-credentials are flow inputs, not emitted kwargs.
        assert instance._default_kwargs() == {}

    def test_all_fields_optional(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls()
        assert instance._default_kwargs() == {}
```

- [ ] **Step 6: Run the schema tests**

Run: `hatch run test:test-quick tests/test_schemas.py -q`
Expected: PASS.

- [ ] **Step 7: Lint + Commit**

```bash
hatch run ruff:check
git add src/mountainash_auth_client/schemas/oauth2.py tests/test_emission.py tests/test_schemas.py
git commit -m "feat(auth): plain OAuth2 emits HTTP Bearer from current token

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Rule-4 invariant — no bare driver_key behind an adapter

**Files:**
- Create: `tests/test_emission_invariants.py`

This enforces emission-safety rule 4 over the whole registry: any profile that
registers `__adapters__` must declare only `None`/`dict` (target-scoped)
driver_keys — never a bare `str` that would leak into every target's `base`.

- [ ] **Step 1: Write the test** — create `tests/test_emission_invariants.py`:

```python
"""Rule 4 (emission safety): no bare driver_key behind an adapter.

A profile that registers any __adapters__ must not declare a bare-string
driver_key on any field — bare keys emit for every target and would leak into
an adapter target's base. Target-scoped (dict) or absent (None) only.
"""
from __future__ import annotations

import pytest

from mountainash_auth_client.schemas.registry import AUTH_REGISTRY


def _adapter_bearing_profiles():
    out = []
    for name in AUTH_REGISTRY.descriptors:
        cls = AUTH_REGISTRY.get_settings_class(name)
        if getattr(cls, "__adapters__", {}):
            out.append((name, cls))
    return out


@pytest.mark.unit
class TestNoBareDriverKeyBehindAdapter:
    def test_registry_compliant(self):
        offenders = []
        for name, cls in _adapter_bearing_profiles():
            for param in cls.__spec__.parameters:
                if isinstance(param.driver_key, str):  # bare string
                    offenders.append(f"{name}.{param.name} -> {param.driver_key!r}")
        assert not offenders, (
            "adapter-bearing profiles must not declare bare driver_keys: "
            + ", ".join(offenders)
        )

    def test_at_least_one_adapter_profile_exists(self):
        # Guard against the invariant silently passing because nothing registers
        # an adapter (e.g. a future import regression).
        assert _adapter_bearing_profiles(), "expected adapter-bearing profiles"

    def test_detects_a_bad_profile(self):
        # A constructed profile that violates rule 4 is caught by the same check.
        from mountainash_settings import ParameterSpec, Profile, ProfileSpec

        from mountainash_auth_client.targets import TargetFamily

        bad_spec = ProfileSpec(
            name="bad_rule4", provider_type="bad_rule4",
            parameters=[
                ParameterSpec(name="TOKEN", type=str, tier="core", driver_key="token"),
            ],
        )

        def _adapter(profile, kw):
            return kw

        class BadProfile(Profile):
            __spec__ = bad_spec
            __adapters__ = {TargetFamily.HTTP: _adapter}

        offenders = [
            p.name for p in BadProfile.__spec__.parameters
            if isinstance(p.driver_key, str)
        ]
        assert offenders == ["TOKEN"]
```

- [ ] **Step 2: Run to verify it passes**

Run: `hatch run test:test-quick tests/test_emission_invariants.py -q`
Expected: PASS (3 passed). If `test_registry_compliant` fails, a Task 3–10 profile still has a bare driver_key behind its adapter — fix that profile, do not weaken the test.

- [ ] **Step 3: Lint + Commit**

```bash
hatch run ruff:check
git add tests/test_emission_invariants.py
git commit -m "test(auth): enforce rule-4 (no bare driver_key behind an adapter)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Full-suite + lint gate

**Files:** none (verification only)

- [ ] **Step 1: Full suite with coverage**

Run: `hatch run test:test`
Expected: PASS — entire suite green, including `tests/test_emission.py`, `tests/test_emission_invariants.py`, the updated `tests/test_schemas.py`, and `tests/test_invariants.py` (the existing `spec_invariants_for(AUTH_REGISTRY)` — its per-target `test_driver_keys_unique` now exercises the dict driver_keys and must stay green). If any pre-existing test fails for a reason not covered by D5, STOP and report — do not silence it.

- [ ] **Step 2: Lint**

Run: `hatch run ruff:check`
Expected: `All checks passed!`

- [ ] **Step 3: Final commit (only if ruff:fix changed anything)**

```bash
git add -A
git commit -m "chore(auth): ruff clean for unified-emission phase 2

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage** (against "What each auth profile becomes" + safety contract + phasing):
- `TargetFamily` enum owned by auth-client → Task 1. ✅
- Token/JWT `{HTTP: bearer_header}` → Task 3. ✅
- Password `{PARAMIKO: username/password}` + `{HTTP: basic_header}` (field-leak fix; username restored) → Task 4. ✅
- IAM `{BOTO: aws_*}`, no adapter → Task 5 (D4 on ROLE_ARN). ✅
- OAuth2 auth-code `{HTTP: bearer_from_access_token}` (current-token only; flow owns refresh) → Task 6. ✅
- OAuth1 `{HTTP: oauth1_authlib_object}` → Task 7. ✅
- Certificate `{PARAMIKO: ssh_key}` (key-path or parse PEM; fail-fast on no key material per D7) → Task 8. ✅
- Kerberos `{PARAMIKO: gss_flags}` → Task 9. ✅
- Plain OAuth2 `{HTTP: bearer_from_token}` (resolver-parity, D7) → Task 10. ✅
- NoAuth empty emit → no change needed (verified by `emit` returning `{}`; covered indirectly). ✅
- Optional deps imported inside adapters via `_optional` (`require_authlib`/`require_paramiko`) → Tasks 2,7,8. ✅
- Rule 4 (no bare driver_key behind adapter) enforced over `AUTH_REGISTRY` → Task 11 (D3). ✅
- Copy-on-write nested containers (rule 1) → Tasks 3,4 (header CoW tests); object/flat adapters return fresh dicts. ✅
- Fail-closed targeting (rule 3) → Tasks 3,4 (no-target/unknown-target raise tests). ✅
- Bearer truthiness parity (empty/None token → no header) → Tasks 3,6,10 (D7). ✅
- Per-profile/per-target golden tests asserting exact kwargs, no count assertions → `tests/test_emission.py`. ✅
- **Deliberately out of Phase 2:** transport `family`/factory/`_core/auth` deletion (Phase 3); storage `to_handler_kwargs` (Phase 4); `azure`/`service_account`/`windows` profiles unchanged (no adapters, no driver_keys → rule-4 compliant; resolver fell through to NoAuth for them, so no emission behavior is lost).

**2. Placeholder scan:** every code step shows complete code; every command has expected output; no TBD/TODO. ✅

**3. Type/name consistency:** adapters are 2-arg `(profile, kw)` matching settings' `Adapter`; `__adapters__` keyed by `TargetFamily`; `require_paramiko` signature matches `require_authlib`; `_parse_private_key` and `_ssh_key` names match between def and use; `TargetFamily.{HTTP,BOTO,PARAMIKO}` string values (`"http"/"boto"/"paramiko"`) match the `_default_kwargs` target lookups and the golden-test target args. ✅

**4. Behavior-change honesty (D5):** the existing `test_schemas.py` assertions that encoded dead bare-driver_key output are rewritten to the new target-aware contract in Tasks 3/4/5/10; this is a spec-mandated change, surfaced explicitly, not silent test-weakening. ✅

---

## Execution Handoff

Phase 2 leaves auth profiles emitting correctly per target with the old transport strategies still present (unused by this phase). **Phase 3** wires transport connections to `emit()` and deletes `_core/auth`; it gets its own plan once this lands on `develop`. The `TargetFamily` enum and the adapters are the contract Phase 3 consumes.

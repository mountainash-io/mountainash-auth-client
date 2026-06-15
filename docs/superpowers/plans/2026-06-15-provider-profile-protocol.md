# ProviderProfileProtocol (Layer A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a runtime-checkable `ProviderProfileProtocol` (+ OAuth2/OAuth1 refinements) to auth-client and retype the OAuth connections/flows/managers against it, so consumers type against the contract instead of the concrete OAuth provider classes — behaviour-identical.

**Architecture:** A new leaf `providers/protocols.py` defines three runtime-checkable Protocols. The concrete `OAuth2ProviderProfile`/`OAuth1ProviderProfile` satisfy them structurally (unchanged). Six consumer files swap their `provider:` annotation (under `TYPE_CHECKING`, so annotation-only) from the concrete to the protocol. Exports are added at `providers/__init__.py` and the package root.

**Tech Stack:** Python ≥3.10, `typing.Protocol`/`runtime_checkable`, pydantic-backed `mountainash_settings.Profile`, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-06-15-provider-profile-protocol-design.md` (read it first).

**Conventions for every task:**
- **Repo root (CWD):** `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client`
- **Branch:** `feature/provider-profile-protocol` (already checked out, off `develop` @ `7b82dca`; the spec + Layer B backlog are already committed at `f846110`). Do NOT create/switch branches.
- **Test runner (PY):** `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest`
- **Lint:** `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/ruff check <paths>`
- Commit messages end with the `Co-Authored-By` trailer shown in Task 1.

**Pinned facts (verified against the tree — do not change, rely on them):**
- `Profile.emit(self, target: Hashable = <sentinel>, *, base: dict | None = None) -> dict` (from `mountainash_settings`).
- `OAuth2ProviderProfile` fields: `NAME`, `AUTHORIZE_URL`, `TOKEN_URL`, `BASE_URL`, `DEFAULT_SCOPE` (default None), `USE_PKCE` (default False), `CALLBACK_PORT` (default None). `__adapters__={TargetFamily.HTTP: lambda profile, kw: {**kw, "base_url": profile.BASE_URL}}`.
- `OAuth1ProviderProfile` fields: `NAME`, `REQUEST_TOKEN_URL`, `AUTHORIZE_URL`, `ACCESS_TOKEN_URL`, `BASE_URL`, `CALLBACK_PORT` (default None). Same HTTP adapter.
- Every `provider.*` read across the six consumer files (audited): OAuth2 side reads `AUTHORIZE_URL`, `TOKEN_URL`, `USE_PKCE`, `DEFAULT_SCOPE`, `NAME`, `CALLBACK_PORT`, `emit`; OAuth1 side reads `REQUEST_TOKEN_URL`, `AUTHORIZE_URL`, `ACCESS_TOKEN_URL`, `NAME`, `CALLBACK_PORT`, `emit`. All are declared on the respective protocol below.
- All six consumer files have `from __future__ import annotations` and a `TYPE_CHECKING` block importing the concrete provider — so the retype is import + annotation only.
- Baseline suite: **317 passed, 2 skipped**. Behaviour must not change.

---

## File Structure

```
src/mountainash_auth_client/
  providers/protocols.py          # Task 1 — the 3 protocols (NEW)
  connections/oauth2/connection.py # Task 2 — retype provider param
  connections/oauth1/connection.py # Task 2 — retype
  connections/oauth2/flow.py       # Task 2 — retype
  connections/oauth1/flow.py       # Task 2 — retype
  lifecycle/oauth2.py              # Task 2 — retype
  lifecycle/oauth1.py              # Task 2 — retype
  providers/__init__.py            # Task 3 — export protocols
  __init__.py                      # Task 3 — re-export at root
tests/
  providers/test_provider_protocols.py  # Task 1 (conformance) + Task 3 (exports)
```

---

## Task 1: `providers/protocols.py` + conformance tests

**Files:**
- Create: `src/mountainash_auth_client/providers/protocols.py`
- Create: `tests/providers/test_provider_protocols.py`

- [ ] **Step 1: Write the failing test**

Create the directory `tests/providers/` if absent, then create `tests/providers/test_provider_protocols.py`:
```python
from __future__ import annotations

from mountainash_auth_client.providers.protocols import (
    OAuth1ProviderProfileProtocol,
    OAuth2ProviderProfileProtocol,
    ProviderProfileProtocol,
)
from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
from mountainash_auth_client.targets import TargetFamily


def _oauth2():
    return OAuth2ProviderProfile(
        NAME="p",
        AUTHORIZE_URL="https://auth/authorize",
        TOKEN_URL="https://auth/token",
        BASE_URL="https://api",
    )


def _oauth1():
    return OAuth1ProviderProfile(
        NAME="p",
        REQUEST_TOKEN_URL="https://auth/request",
        AUTHORIZE_URL="https://auth/authorize",
        ACCESS_TOKEN_URL="https://auth/access",
        BASE_URL="https://api",
    )


def test_oauth2_concrete_satisfies_refinement_and_base():
    p = _oauth2()
    assert isinstance(p, OAuth2ProviderProfileProtocol)
    assert isinstance(p, ProviderProfileProtocol)


def test_oauth1_concrete_satisfies_refinement_and_base():
    p = _oauth1()
    assert isinstance(p, OAuth1ProviderProfileProtocol)
    assert isinstance(p, ProviderProfileProtocol)


def test_base_protocol_is_minimal():
    # A provider with only NAME + emit satisfies the base but NOT the OAuth
    # refinements — proving the base is genuinely auth-method-agnostic.
    class _Dummy:
        NAME = "d"

        def emit(self, target, *, base=None):
            return {}

    d = _Dummy()
    assert isinstance(d, ProviderProfileProtocol)
    assert not isinstance(d, OAuth2ProviderProfileProtocol)
    assert not isinstance(d, OAuth1ProviderProfileProtocol)


def test_emit_http_returns_base_url():
    # Locks the resource-emit contract the connection relies on.
    assert _oauth2().emit(TargetFamily.HTTP) == {"base_url": "https://api"}
    assert _oauth1().emit(TargetFamily.HTTP) == {"base_url": "https://api"}
```

- [ ] **Step 2: Run it, confirm it FAILS**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/providers/test_provider_protocols.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mountainash_auth_client.providers.protocols'`.

- [ ] **Step 3: Create the protocols module**

Create `src/mountainash_auth_client/providers/protocols.py`:
```python
"""Runtime-checkable provider-profile contracts.

`ProviderProfileProtocol` is the structural minimum every provider profile
satisfies regardless of auth method: a `NAME` (for labels/logging) and a
target-parametric `emit`. It does NOT promise that `emit(TargetFamily.HTTP)`
returns HTTP-ready kwargs — that is a per-target precondition a connection states
of the providers it accepts (which is why `BASE_URL` lives on the HTTP-provider
refinements, not the base).

`runtime_checkable` checks member *presence* only (names, not types/signatures),
matching the ecosystem convention (the secrets capability protocols, the storage
protocols): structural conformance is asserted by tests, not promised by
`isinstance`.
"""
from __future__ import annotations

import typing as t

__all__ = [
    "ProviderProfileProtocol",
    "OAuth2ProviderProfileProtocol",
    "OAuth1ProviderProfileProtocol",
]


@t.runtime_checkable
class ProviderProfileProtocol(t.Protocol):
    """Resource-coordinate contract shared by every provider profile."""

    NAME: str

    # `target` is required at the protocol level; the concrete `Profile.emit`
    # supplies a default for internal convenience. Callers always pass a target.
    def emit(
        self, target: t.Hashable, *, base: dict[str, t.Any] | None = None
    ) -> dict[str, t.Any]: ...


@t.runtime_checkable
class OAuth2ProviderProfileProtocol(ProviderProfileProtocol, t.Protocol):
    """An OAuth2 authorization-code provider: base contract + auth-server URLs."""

    AUTHORIZE_URL: str
    TOKEN_URL: str
    BASE_URL: str
    DEFAULT_SCOPE: str | None
    USE_PKCE: bool
    CALLBACK_PORT: int | None


@t.runtime_checkable
class OAuth1ProviderProfileProtocol(ProviderProfileProtocol, t.Protocol):
    """An OAuth1 provider: base contract + the three-legged handshake URLs."""

    REQUEST_TOKEN_URL: str
    AUTHORIZE_URL: str
    ACCESS_TOKEN_URL: str
    BASE_URL: str
    CALLBACK_PORT: int | None
```

- [ ] **Step 4: Run it, confirm PASS**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/providers/test_provider_protocols.py -v`
Expected: PASS (4 passed). If `test_base_protocol_is_minimal` fails because `_Dummy` unexpectedly matches an OAuth refinement, that is a real `runtime_checkable` surprise — STOP and report, do not weaken the test.

- [ ] **Step 5: Lint**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/ruff check src/mountainash_auth_client/providers/protocols.py tests/providers/test_provider_protocols.py`
Expected: `All checks passed!`.

- [ ] **Step 6: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/providers/protocols.py tests/providers/test_provider_protocols.py
git commit -m "$(cat <<'EOF'
feat: ProviderProfileProtocol + OAuth2/OAuth1 refinements

Runtime-checkable structural contracts for provider profiles: a base
(NAME + emit) plus per-family OAuth refinements carrying the auth-server URLs.
The concrete OAuth2/OAuth1ProviderProfile satisfy them structurally.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Retype the six consumers against the protocols (annotation-only)

**Files (each: swap the `TYPE_CHECKING` import + the `provider:` annotation):**
- Modify: `src/mountainash_auth_client/connections/oauth2/connection.py`
- Modify: `src/mountainash_auth_client/connections/oauth1/connection.py`
- Modify: `src/mountainash_auth_client/connections/oauth2/flow.py`
- Modify: `src/mountainash_auth_client/connections/oauth1/flow.py`
- Modify: `src/mountainash_auth_client/lifecycle/oauth2.py`
- Modify: `src/mountainash_auth_client/lifecycle/oauth1.py`

These are annotation-only changes (every file has `from __future__ import annotations`; the imports are under `TYPE_CHECKING`). The concrete profiles satisfy the protocols, so every existing test stays green.

- [ ] **Step 1: Confirm the full suite is green BEFORE the change**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest -q`
Expected: 317 passed, 2 skipped (plus the 4 from Task 1 = 321 passed, 2 skipped). Note the count.

- [ ] **Step 2: Retype the three OAuth2 consumers**

In each of `connections/oauth2/connection.py`, `connections/oauth2/flow.py`, `lifecycle/oauth2.py`:
- In the `TYPE_CHECKING` block, replace the line
  ```python
  from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
  ```
  with
  ```python
  from mountainash_auth_client.providers.protocols import OAuth2ProviderProfileProtocol
  ```
- Replace the parameter annotation
  ```python
          provider: OAuth2ProviderProfile,
  ```
  with
  ```python
          provider: OAuth2ProviderProfileProtocol,
  ```

- [ ] **Step 3: Retype the three OAuth1 consumers**

In each of `connections/oauth1/connection.py`, `connections/oauth1/flow.py`, `lifecycle/oauth1.py`:
- In the `TYPE_CHECKING` block, replace
  ```python
  from mountainash_auth_client.providers.oauth1 import OAuth1ProviderProfile
  ```
  with
  ```python
  from mountainash_auth_client.providers.protocols import OAuth1ProviderProfileProtocol
  ```
- Replace the parameter annotation
  ```python
          provider: OAuth1ProviderProfile,
  ```
  with
  ```python
          provider: OAuth1ProviderProfileProtocol,
  ```

- [ ] **Step 4: Run the full suite, confirm UNCHANGED count**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest -q`
Expected: identical to Step 1 (321 passed, 2 skipped). Annotation-only — any change in behaviour means an import was moved out of `TYPE_CHECKING` or an annotation typo; fix it.

- [ ] **Step 5: Lint the six files**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/ruff check src/mountainash_auth_client/connections/oauth2/connection.py src/mountainash_auth_client/connections/oauth1/connection.py src/mountainash_auth_client/connections/oauth2/flow.py src/mountainash_auth_client/connections/oauth1/flow.py src/mountainash_auth_client/lifecycle/oauth2.py src/mountainash_auth_client/lifecycle/oauth1.py`
Expected: `All checks passed!` (the old concrete import is fully replaced in each, so no unused-import warning).

- [ ] **Step 6: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/connections/oauth2/connection.py src/mountainash_auth_client/connections/oauth1/connection.py src/mountainash_auth_client/connections/oauth2/flow.py src/mountainash_auth_client/connections/oauth1/flow.py src/mountainash_auth_client/lifecycle/oauth2.py src/mountainash_auth_client/lifecycle/oauth1.py
git commit -m "$(cat <<'EOF'
refactor: type OAuth connections/flows/managers against ProviderProfileProtocol

Annotation-only: the six consumers now type their `provider` param against the
OAuth2/OAuth1 provider protocols instead of the concrete classes. The concretes
satisfy the protocols structurally; behaviour and the full suite are unchanged.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Exports + load-bearing export test

**Files:**
- Modify: `src/mountainash_auth_client/providers/__init__.py`
- Modify: `src/mountainash_auth_client/__init__.py`
- Modify: `tests/providers/test_provider_protocols.py` (append the export test)

- [ ] **Step 1: Write the failing export test**

Append to `tests/providers/test_provider_protocols.py`:
```python
def test_protocols_exported_at_package_root():
    import mountainash_auth_client as ac
    from mountainash_auth_client import (
        OAuth1ProviderProfileProtocol,
        OAuth2ProviderProfileProtocol,
        ProviderProfileProtocol,
    )

    exported = {
        "ProviderProfileProtocol": ProviderProfileProtocol,
        "OAuth2ProviderProfileProtocol": OAuth2ProviderProfileProtocol,
        "OAuth1ProviderProfileProtocol": OAuth1ProviderProfileProtocol,
    }
    for name, obj in exported.items():
        assert name in ac.__all__
        assert getattr(ac, name) is obj
```

- [ ] **Step 2: Run it, confirm FAIL**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/providers/test_provider_protocols.py::test_protocols_exported_at_package_root -v`
Expected: FAIL — `ImportError: cannot import name 'ProviderProfileProtocol'`.

- [ ] **Step 3: Export from `providers/__init__.py`**

Replace the contents of `src/mountainash_auth_client/providers/__init__.py` with:
```python
"""Provider coordinate profiles (OAuth2 / OAuth1). Schema only — no values, no registry."""
from __future__ import annotations

from .oauth1 import OAuth1ProviderProfile
from .oauth2 import OAuth2ProviderProfile
from .protocols import (
    OAuth1ProviderProfileProtocol,
    OAuth2ProviderProfileProtocol,
    ProviderProfileProtocol,
)

__all__ = [
    "OAuth1ProviderProfile",
    "OAuth1ProviderProfileProtocol",
    "OAuth2ProviderProfile",
    "OAuth2ProviderProfileProtocol",
    "ProviderProfileProtocol",
]
```

- [ ] **Step 4: Re-export at the package root**

In `src/mountainash_auth_client/__init__.py`:
- Extend the existing providers import block (currently
  `from mountainash_auth_client.providers import (OAuth1ProviderProfile, OAuth2ProviderProfile,)`)
  to:
  ```python
  from mountainash_auth_client.providers import (
      OAuth1ProviderProfile,
      OAuth1ProviderProfileProtocol,
      OAuth2ProviderProfile,
      OAuth2ProviderProfileProtocol,
      ProviderProfileProtocol,
  )
  ```
- Add the three names to the `__all__` list at their alphabetical positions:
  `"OAuth1ProviderProfileProtocol"` immediately after `"OAuth1ProviderProfile"`;
  `"OAuth2ProviderProfileProtocol"` immediately after `"OAuth2ProviderProfile"`;
  `"ProviderProfileProtocol"` at its alphabetical spot among the `P…` entries
  (e.g. after `"PersistableAuthProfile"`).

- [ ] **Step 5: Run it, confirm PASS**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/providers/test_provider_protocols.py -v`
Expected: PASS (5 passed).

- [ ] **Step 6: Lint**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/ruff check src/mountainash_auth_client/providers/__init__.py src/mountainash_auth_client/__init__.py tests/providers/test_provider_protocols.py`
Expected: `All checks passed!`.

- [ ] **Step 7: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/providers/__init__.py src/mountainash_auth_client/__init__.py tests/providers/test_provider_protocols.py
git commit -m "$(cat <<'EOF'
feat: export provider profile protocols at package root

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Full suite, lint, PR

**Files:** none (verification + PR).

- [ ] **Step 1: Full test suite**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest -q`
Expected: 322 passed, 2 skipped (baseline 317 + the 5 new protocol tests). No regressions.

- [ ] **Step 2: Lint the touched scope**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/ruff check src tests/providers/test_provider_protocols.py`
Expected: `All checks passed!`. (If `ruff check src tests` on the whole tree reports pre-existing `E402` in `tests/connections/test_oauth1_flow.py`/`test_oauth2_flow.py`/`test_callback_servers.py`, those are out of scope — deliberate mid-file imports, verified identical on `develop`. Do NOT touch them.)

- [ ] **Step 3: Push and open the PR**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git push -u origin feature/provider-profile-protocol
gh pr create --base develop --title "feat: ProviderProfileProtocol — generalise the provider-profile pattern (Layer A)" --body "$(cat <<'EOF'
Generalises the OAuth-only provider-profile concretes into a runtime-checkable
`ProviderProfileProtocol` (base: `NAME` + `emit`) with `OAuth2ProviderProfileProtocol`
/`OAuth1ProviderProfileProtocol` refinements, and retypes the OAuth connections,
flows, and token managers against the protocol instead of the concrete classes.

- **Annotation-only / behaviour-identical** — the concretes satisfy the protocols
  structurally; the full suite is unchanged (322 passed, 2 skipped).
- Mirrors the `ProfileProtocol → StorageProfileProtocol` precedent in transport.
- The base is structural, not target-semantic (`emit(HTTP)→base_url` is a per-target
  precondition), so non-HTTP/non-OAuth providers fit — the foundation Layer B builds on.

Design: `docs/superpowers/specs/2026-06-15-provider-profile-protocol-design.md`
(Codex-reviewed). Layer B (generic non-OAuth HTTP connection, transport-driven) is
captured in `docs/superpowers/backlog/2026-06-15-generic-nonoauth-http-connection.md`.
Unblocks the wearables consumer collapse typing against the protocol.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Out of scope (later)

- **Layer B** — the generic non-OAuth HTTP connection (provider profile + non-lifecycle auth profile → authed client); transport-driven; see the backlog doc.
- Adding/renaming any field on the concrete provider profiles.
- Unifying the cross-family universal verb (`emit` vs transport's `to_handler_kwargs`).
- Moving the protocol into `mountainash-settings` as a shared base.

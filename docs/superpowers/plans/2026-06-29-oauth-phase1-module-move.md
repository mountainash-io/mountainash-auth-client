# OAuth Split Phase 1: Module Move — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Relocate the OAuth ops code into a new `oauth/` package and make the package
root import lazily, so that importing credential *data* (`schemas/`) or the package root
never pulls in `httpx`/`authlib`/`paramiko`/`oauth` — with zero change to runtime auth
behaviour and an identical public API.

**Architecture:** A pure code move. `connections/`, `lifecycle/`, `providers/`, and
`persistence.py` move under a new `oauth/` package; the only `schemas/ → connections/`
edge (`_optional.py`) is severed by relocating that file to the package root. The package
root `__init__.py` keeps every exported name but resolves the OAuth-side names lazily via
PEP 562 `__getattr__`, while schema/constant/error names stay eager. A subprocess
boundary test proves the isolation.

**Tech Stack:** Python 3.12, hatch (uv installer), pydantic v2, pytest. OAuth deps:
`httpx` (core), `authlib` (`[oauth1]` extra), `paramiko` (`[sftp]` extra).

## Global Constraints

- **No runtime auth-behaviour change.** This is a move, not a rewrite. Schema fields,
  class shapes, `OAuth2Connection`/`OAuth1Connection` (incl. `.client`), and the
  `__adapters__`/`emit(target)` rendering on schemas all stay intact (Phase 2/3 territory).
- **Public API names unchanged.** Every name in `__init__.py`'s `__all__` stays exported
  and importable; `__all__` itself is byte-for-byte unchanged.
- **Internal imports use the absolute `mountainash_auth_client.<...>` form** wherever they
  cross a subpackage (existing convention); relative imports only within a subpackage.
- **`from __future__ import annotations`** at the top of every module (existing convention).
- **Tests:** fast iteration `hatch run test:test-quick <args>`; full coverage gate
  `hatch run test:test`. Lint: `hatch run ruff:check` (runs `ruff check ./src`); autofix
  `hatch run ruff:fix`. The `test` env already installs `authlib` and `paramiko`, so the
  boundary test's absence-assertions are meaningful.
- **Commit after every task.** Run all commands from the repo root
  (`mountainash-auth-client/`).
- **Branch:** all work on `feature/oauth-phase1-module-move` (seeded from `develop` — see
  Branch Setup); PR targets `develop` (mountainash three-tier flow). Never push to
  `develop`/`main`.

---

## Branch Setup (do once, before Task 1)

- [ ] **Confirm clean baseline and seed the branch from `develop`.**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git fetch origin
git switch develop && git pull --ff-only
git switch -c feature/oauth-phase1-module-move
```

- [ ] **Establish the green baseline (the regression net for the whole move).**

Run: `hatch run test:test-quick -q`
Expected: all tests pass (this is the suite that must stay green through every task).

> The working tree carries unrelated uncommitted edits (`CLAUDE.md`, `docs/INTEGRATION.md`,
> `docs/superpowers/`). Leave them; this plan only stages the files it names in each
> commit, so they will not be swept into these commits.

---

## Task 1: Relocate `_optional.py` to the package root

Severs the only `schemas/ → connections/` import edges (`require_paramiko`,
`require_authlib`) by moving the optional-dep guard to a package-neutral home. After this
task `schemas/` no longer references `connections/`, so the later move cannot create a
`schemas/ → oauth/` edge. Behaviour is unchanged — `_optional.py` depends on nothing in
`schemas/` or `connections/`.

**Files:**
- Move: `src/mountainash_auth_client/connections/_optional.py` → `src/mountainash_auth_client/_optional.py`
- Modify: `src/mountainash_auth_client/schemas/oauth1.py:4`
- Modify: `src/mountainash_auth_client/schemas/certificate.py:7`
- Modify: `src/mountainash_auth_client/connections/oauth1/flow.py:14`
- Modify: `tests/connections/test_optional.py:9`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `mountainash_auth_client._optional` exposing `require`, `require_authlib`,
  `require_paramiko` (signatures unchanged). No remaining reference to
  `mountainash_auth_client.connections._optional` anywhere.

- [ ] **Step 1: Move the file with history preserved**

```bash
git mv src/mountainash_auth_client/connections/_optional.py \
       src/mountainash_auth_client/_optional.py
```

- [ ] **Step 2: Repoint the two `schemas/` importers (relative form)**

In `src/mountainash_auth_client/schemas/oauth1.py` line 4, change:

```python
from ..connections._optional import require_authlib
```
to:
```python
from .._optional import require_authlib
```

In `src/mountainash_auth_client/schemas/certificate.py` line 7, change:

```python
from ..connections._optional import require_paramiko
```
to:
```python
from .._optional import require_paramiko
```

- [ ] **Step 3: Repoint the OAuth-side importer (absolute form)**

In `src/mountainash_auth_client/connections/oauth1/flow.py` line 14, change:

```python
from mountainash_auth_client.connections._optional import require_authlib
```
to:
```python
from mountainash_auth_client._optional import require_authlib
```

- [ ] **Step 4: Repoint the test**

In `tests/connections/test_optional.py` line 9, change:

```python
from mountainash_auth_client.connections._optional import require, require_authlib
```
to:
```python
from mountainash_auth_client._optional import require, require_authlib
```

- [ ] **Step 5: Verify no stale reference remains**

Run: `grep -rn "connections._optional" src tests`
Expected: no output (exit code 1).

- [ ] **Step 6: Run the suite**

Run: `hatch run test:test-quick -q`
Expected: all tests pass (unchanged behaviour).

- [ ] **Step 7: Lint**

Run: `hatch run ruff:check`
Expected: no findings.

- [ ] **Step 8: Commit**

```bash
git add src/mountainash_auth_client/_optional.py \
        src/mountainash_auth_client/schemas/oauth1.py \
        src/mountainash_auth_client/schemas/certificate.py \
        src/mountainash_auth_client/connections/oauth1/flow.py \
        tests/connections/test_optional.py
git commit -m "refactor: relocate _optional.py to package root (sever schemas->connections edge)"
```

---

## Task 2: Move the OAuth ops tree into `oauth/` and rewrite imports

Relocate `connections/`, `lifecycle/`, `providers/`, and `persistence.py` under a new
`oauth/` package (git history preserved), then rewrite every absolute import path and fix
the two relative imports whose depth changed. The package root `__init__.py` is **not**
touched here (it still eager-imports, now via `oauth/` paths) — laziness is Task 3. The
suite stays green because only import paths change.

**Files:**
- Move: `connections/` → `oauth/`; `lifecycle/` → `oauth/lifecycle/`; `providers/` → `oauth/providers/`; `persistence.py` → `oauth/persistence.py` (all under `src/mountainash_auth_client/`)
- Modify (bulk): every `.py` under `src/` and `tests/` referencing `mountainash_auth_client.{connections,lifecycle,providers,persistence}`
- Modify: `src/mountainash_auth_client/__init__.py` lines 13-16, 40-52 (re-export source paths only — still eager)
- Modify: `src/mountainash_auth_client/oauth/providers/oauth1.py`, `oauth/providers/oauth2.py` (the two `from ..targets` relative imports)

**Interfaces:**
- Consumes: `mountainash_auth_client._optional` (Task 1).
- Produces: the OAuth ops live at `mountainash_auth_client.oauth.*` —
  `oauth.oauth1.flow.OAuth1Flow`, `oauth.oauth1.connection.OAuth1Connection`,
  `oauth.oauth2.flow.OAuthFlow`, `oauth.oauth2.connection.OAuth2Connection`,
  `oauth.server.callback.LocalCallbackServer`, `oauth.server.manual.ManualCallbackServer`,
  `oauth.protocols.{CallbackServerFactory,CallbackServerProtocol}`,
  `oauth.providers.*`, `oauth.lifecycle.*`, `oauth.persistence.{PersistableAuthProfile,token_store}`.
  The package root still re-exports every existing name (eager for now).

- [ ] **Step 1: Move the four trees (history preserved, order matters)**

```bash
git mv src/mountainash_auth_client/connections src/mountainash_auth_client/oauth
git mv src/mountainash_auth_client/lifecycle   src/mountainash_auth_client/oauth/lifecycle
git mv src/mountainash_auth_client/providers    src/mountainash_auth_client/oauth/providers
git mv src/mountainash_auth_client/persistence.py src/mountainash_auth_client/oauth/persistence.py
```

- [ ] **Step 2: Rewrite all absolute import paths across `src/` and `tests/`**

Each `-e` is applied in order, per line; the four target segments are distinct so there is
no double-substitution. (Task 1 already removed every `connections._optional` reference, so
the first rule cannot mis-rewrite the relocated guard.)

```bash
files=$(grep -rl "mountainash_auth_client\.\(connections\|lifecycle\|providers\|persistence\)" src tests)
sed -i \
  -e 's/mountainash_auth_client\.connections/mountainash_auth_client.oauth/g' \
  -e 's/mountainash_auth_client\.lifecycle/mountainash_auth_client.oauth.lifecycle/g' \
  -e 's/mountainash_auth_client\.providers/mountainash_auth_client.oauth.providers/g' \
  -e 's/mountainash_auth_client\.persistence/mountainash_auth_client.oauth.persistence/g' \
  $files
```

- [ ] **Step 3: Fix the two relative imports whose depth changed**

`providers/` moved one level deeper (into `oauth/`), so its `from ..targets` now resolves
to the non-existent `oauth.targets`. Convert both to absolute:

```bash
sed -i 's/from \.\.targets import TargetFamily/from mountainash_auth_client.targets import TargetFamily/' \
  src/mountainash_auth_client/oauth/providers/oauth1.py \
  src/mountainash_auth_client/oauth/providers/oauth2.py
```

> No other relative import changes depth: `connections/ → oauth/` is a same-level rename
> (its internal `.oauth1`, `..protocols`, `.server` relatives stay valid), `lifecycle/` and
> `persistence.py` use only absolute cross-package imports, and `providers/`'s internal
> `.oauth2`/`.protocols` relatives stay within the moved subtree.

- [ ] **Step 4: Verify no stale paths remain in source**

```bash
grep -rn "mountainash_auth_client\.connections\|from \.\.connections\|mountainash_auth_client\.lifecycle[^.]\|mountainash_auth_client\.providers[^.]\|mountainash_auth_client\.persistence" src
grep -rn "from \.\.targets" src/mountainash_auth_client/oauth/providers
```
Expected: both produce no output (exit code 1). (`mountainash_auth_client.oauth.lifecycle`
etc. are the intended new paths and correctly do not match the `[^.]`-anchored patterns.)

- [ ] **Step 5: Confirm Python can import the moved tree**

Run: `hatch run test:test-quick -q tests/connections/test_oauth2_flow.py tests/lifecycle/test_oauth2_manager.py tests/providers/test_provider_profiles.py tests/test_persistence.py`
Expected: all pass — proves the OAuth flow, lifecycle, providers, and persistence imports
resolve at their new `oauth/` paths.

- [ ] **Step 6: Run the full suite**

Run: `hatch run test:test-quick -q`
Expected: all tests pass. (Test directories are still named `tests/connections` etc.; that
cosmetic mismatch is fixed in Task 4. Their imports already point at `oauth/`.)

- [ ] **Step 7: Lint**

Run: `hatch run ruff:check`
Expected: no findings. If ruff reports import-sorting (`I001`) in `__init__.py` or moved
modules, run `hatch run ruff:fix` and re-run `hatch run ruff:check`.

- [ ] **Step 8: Commit**

```bash
git add -A src tests
git commit -m "refactor: move connections/lifecycle/providers/persistence under oauth/ (code move, no behaviour change)"
```

---

## Task 3: Establish the `schemas/ ⊥ oauth/` import boundary

Today the package root `__init__.py` eagerly imports the OAuth names, so
`import mountainash_auth_client` (and therefore `import …schemas`, which runs the package
`__init__` first) pulls in `httpx`. Write the boundary test first to capture that as a
failure, then make the OAuth-side re-exports lazy (PEP 562 `__getattr__`) so the names stay
exported but resolve only on first access. Schema/constant/error names stay eager (cheap,
boundary-free).

**Files:**
- Create: `tests/test_boundary.py`
- Create: `tests/test_public_api.py`
- Modify: `src/mountainash_auth_client/__init__.py` (full rewrite of the import section;
  `__all__` and the `AuthProfile` union unchanged)

**Interfaces:**
- Consumes: `mountainash_auth_client.oauth.*` re-export targets (Task 2).
- Produces: a package root where `from mountainash_auth_client import OAuthFlow` (and every
  other `__all__` name) still works, but `import mountainash_auth_client` does not import
  `oauth`/`httpx`. The lazy name→module map is `_LAZY`; `__getattr__`/`__dir__` honour it.

- [ ] **Step 1: Write the boundary test (the failing test)**

Create `tests/test_boundary.py`:

```python
"""The schemas/ ⊥ oauth/ import boundary.

Importing only credential *data* (``schemas/``) — or the package root — must not pull in
the OAuth ops machinery or its heavy deps (httpx/authlib/paramiko/oauth). Enforced in a
clean subprocess because other tests import ``oauth/`` and would pollute this process's
``sys.modules``.
"""
from __future__ import annotations

import subprocess
import sys

_HEAVY = ("httpx", "authlib", "paramiko", "mountainash_auth_client.oauth")


def _assert_clean(import_line: str) -> None:
    code = (
        f"{import_line}\n"
        "import sys\n"
        f"heavy = {_HEAVY!r}\n"
        "leaked = [m for m in heavy if m in sys.modules]\n"
        "assert not leaked, f'boundary leak: {leaked}'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_importing_package_root_is_clean():
    _assert_clean("import mountainash_auth_client")


def test_importing_schemas_package_is_clean():
    _assert_clean("import mountainash_auth_client.schemas")


def test_importing_each_schema_module_is_clean():
    for module in ("certificate", "oauth1", "oauth2", "token", "password", "iam"):
        _assert_clean(f"import mountainash_auth_client.schemas.{module}")
```

- [ ] **Step 2: Run the boundary test — verify it FAILS**

Run: `hatch run test:test-quick -q tests/test_boundary.py`
Expected: FAIL. `test_importing_package_root_is_clean` and
`test_importing_schemas_package_is_clean` fail with a `boundary leak` mentioning `httpx`
and `mountainash_auth_client.oauth`, because the eager `__init__.py` imports the OAuth
modules.

- [ ] **Step 3: Make the OAuth-side re-exports lazy**

Replace the entire import section of `src/mountainash_auth_client/__init__.py` with the
following. The eager imports (constants, targets, errors, schemas) and the `AuthProfile`
union and `__all__` list are preserved exactly; only the OAuth/provider/lifecycle/
persistence/callback names move into the lazy `_LAZY` map.

```python
"""mountainash-auth-client — client-side authentication for the mountainash ecosystem."""
from __future__ import annotations

import importlib

from mountainash_auth_client.constants import CONST_AUTH_PROFILES
from mountainash_auth_client.targets import TargetFamily
from mountainash_auth_client.errors import (
    AuthorizationDeniedError,
    AuthorizationRequired,
    CallbackError,
    CallbackTimeoutError,
    MalformedCallbackError,
    TokenExchangeError,
    TokenRefreshError,
)
from mountainash_auth_client.schemas import (
    AUTH_REGISTRY,
    AzureADAuthProfile,
    CertificateAuthProfile,
    IAMAuthProfile,
    JWTAuthProfile,
    KerberosAuthProfile,
    NoAuthProfile,
    OAuth1AuthProfile,
    OAuth2AuthCodeAuthProfile,
    OAuth2AuthProfile,
    PasswordAuthProfile,
    ServiceAccountAuthProfile,
    TokenAuthProfile,
    WindowsAuthProfile,
)

# Lazy (PEP 562) re-exports for the OAuth ops layer. These names stay exported but resolve
# on first attribute access, so `import mountainash_auth_client` / `import …schemas` never
# pulls in httpx/authlib/paramiko/oauth. Keep this map and __all__ in sync.
_LAZY = {
    "OAuthFlow": "mountainash_auth_client.oauth.oauth2.flow",
    "OAuth2Connection": "mountainash_auth_client.oauth.oauth2.connection",
    "OAuth1Flow": "mountainash_auth_client.oauth.oauth1.flow",
    "OAuth1Connection": "mountainash_auth_client.oauth.oauth1.connection",
    "LocalCallbackServer": "mountainash_auth_client.oauth.server.callback",
    "ManualCallbackServer": "mountainash_auth_client.oauth.server.manual",
    "CallbackServerFactory": "mountainash_auth_client.oauth.protocols",
    "CallbackServerProtocol": "mountainash_auth_client.oauth.protocols",
    "PersistableAuthProfile": "mountainash_auth_client.oauth.persistence",
    "OAuth1ProviderProfile": "mountainash_auth_client.oauth.providers",
    "OAuth1ProviderProfileProtocol": "mountainash_auth_client.oauth.providers",
    "OAuth2ProviderProfile": "mountainash_auth_client.oauth.providers",
    "OAuth2ProviderProfileProtocol": "mountainash_auth_client.oauth.providers",
    "ProviderProfileProtocol": "mountainash_auth_client.oauth.providers",
    "OAuth1TokenManager": "mountainash_auth_client.oauth.lifecycle",
    "OAuth2TokenManager": "mountainash_auth_client.oauth.lifecycle",
    "TokenState": "mountainash_auth_client.oauth.lifecycle",
    "TokenStatus": "mountainash_auth_client.oauth.lifecycle",
}


def __getattr__(name: str):
    """Resolve OAuth-side public names lazily (PEP 562)."""
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)


def __dir__() -> list[str]:
    return sorted(__all__)


AuthProfile = (
    NoAuthProfile | PasswordAuthProfile | TokenAuthProfile | JWTAuthProfile
    | OAuth1AuthProfile | OAuth2AuthProfile | OAuth2AuthCodeAuthProfile
    | IAMAuthProfile | WindowsAuthProfile | AzureADAuthProfile
    | KerberosAuthProfile | CertificateAuthProfile | ServiceAccountAuthProfile
)

__all__ = [
    "AUTH_REGISTRY",
    "AuthProfile",
    "AuthorizationDeniedError",
    "AuthorizationRequired",
    "AzureADAuthProfile",
    "CONST_AUTH_PROFILES",
    "CallbackError",
    "CallbackServerFactory",
    "CallbackServerProtocol",
    "CallbackTimeoutError",
    "CertificateAuthProfile",
    "IAMAuthProfile",
    "JWTAuthProfile",
    "KerberosAuthProfile",
    "LocalCallbackServer",
    "MalformedCallbackError",
    "ManualCallbackServer",
    "NoAuthProfile",
    "OAuth1AuthProfile",
    "OAuth1Connection",
    "OAuth1Flow",
    "OAuth1ProviderProfile",
    "OAuth1ProviderProfileProtocol",
    "OAuth1TokenManager",
    "OAuth2AuthCodeAuthProfile",
    "OAuth2AuthProfile",
    "OAuth2Connection",
    "OAuth2ProviderProfile",
    "OAuth2ProviderProfileProtocol",
    "OAuth2TokenManager",
    "OAuthFlow",
    "PasswordAuthProfile",
    "PersistableAuthProfile",
    "ProviderProfileProtocol",
    "ServiceAccountAuthProfile",
    "TargetFamily",
    "TokenAuthProfile",
    "TokenExchangeError",
    "TokenRefreshError",
    "TokenState",
    "TokenStatus",
    "WindowsAuthProfile",
]
```

- [ ] **Step 4: Write the public-API importability test**

Create `tests/test_public_api.py`:

```python
"""Every public name stays importable through the lazy package root."""
from __future__ import annotations

import mountainash_auth_client as pkg


def test_every_public_name_resolves():
    missing = [name for name in pkg.__all__ if not hasattr(pkg, name)]
    assert not missing, missing


def test_lazy_map_and_all_agree():
    # Every lazily-mapped name must be advertised in __all__ (no orphan lazies).
    assert set(pkg._LAZY).issubset(set(pkg.__all__))
```

- [ ] **Step 5: Run the boundary test — verify it now PASSES**

Run: `hatch run test:test-quick -q tests/test_boundary.py tests/test_public_api.py`
Expected: PASS. The boundary is clean and every public name still resolves.

- [ ] **Step 6: Run the full suite (catches export-shape regressions)**

Run: `hatch run test:test-quick -q`
Expected: all pass — including the existing `tests/connections/test_exports.py` and
`tests/test_lifecycle_exports.py`, which exercise `hasattr(pkg, name)` / `getattr(pkg,
name) is obj` and therefore drive the lazy `__getattr__`.

- [ ] **Step 7: Lint**

Run: `hatch run ruff:check`
Expected: no findings. (`importlib` is used by `__getattr__`; no unused imports.)

- [ ] **Step 8: Commit**

```bash
git add src/mountainash_auth_client/__init__.py tests/test_boundary.py tests/test_public_api.py
git commit -m "feat: lazy package-root re-exports establish schemas/ vs oauth/ import boundary"
```

---

## Task 4: Mirror the test directories to the new tree

The test layout still says `tests/connections`, `tests/lifecycle`, `tests/providers`. Move
them under `tests/oauth/` to mirror the package, and move the optional-dep test to the root
(its subject now lives at the package root). Imports already point at `oauth/` (Task 2), so
this is pure relocation.

**Files:**
- Move: `tests/connections/` → `tests/oauth/`; `tests/lifecycle/` → `tests/oauth/lifecycle/`; `tests/providers/` → `tests/oauth/providers/`
- Move: `tests/oauth/test_optional.py` → `tests/test_optional.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `tests/oauth/…` mirroring `src/mountainash_auth_client/oauth/…`; the suite
  collects the same test count as before.

- [ ] **Step 1: Record the current test count (baseline for "same set")**

Run: `hatch run test:test-quick -q --collect-only | tail -1`
Expected: a line like `N tests collected`. Note N.

- [ ] **Step 2: Move the directories (history preserved)**

```bash
git mv tests/connections tests/oauth
git mv tests/lifecycle   tests/oauth/lifecycle
git mv tests/providers    tests/oauth/providers
git mv tests/oauth/test_optional.py tests/test_optional.py
```

- [ ] **Step 3: Ensure package `__init__` files exist where needed**

`tests/oauth/lifecycle` and `tests/oauth/providers` came from `tests/providers` (which had
`__init__.py`) and `tests/lifecycle` (which did not). Match the existing convention — the
old `tests/connections`/`tests/lifecycle` had no `__init__.py` and collected fine via
pytest rootdir config, so add none. Verify collection in Step 4 instead.

- [ ] **Step 4: Verify the same test set collects**

Run: `hatch run test:test-quick -q --collect-only | tail -1`
Expected: `N tests collected` — the same N from Step 1.

- [ ] **Step 5: Run the full suite**

Run: `hatch run test:test-quick -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add -A tests
git commit -m "test: mirror test tree to oauth/ layout"
```

---

## Task 5: Update in-repo docs, run the final gates, and open the PR

Fix the one stale deep-import path in `INTEGRATION.md`, run the full coverage suite plus the
boundary `grep` gates from the spec, then open the PR to `develop`.

**Files:**
- Modify: `docs/INTEGRATION.md:149`

**Interfaces:**
- Consumes: everything above.
- Produces: a green Phase-1 PR against `develop`.

- [ ] **Step 1: Fix the stale deep import in `INTEGRATION.md`**

At `docs/INTEGRATION.md` line 149, change:

```python
from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow
```
to:
```python
from mountainash_auth_client.oauth.oauth1.flow import OAuth1Flow
```

> `docs/INTEGRATION.md` already has unrelated uncommitted edits from earlier work. Stage
> only this file for the Phase-1 doc commit; its other pending edits ride along in the same
> file and are acceptable to include, but do not stage `CLAUDE.md` or `docs/superpowers/`.

- [ ] **Step 2: Spec-mandated `grep` gates (no stale internal paths)**

```bash
grep -rn "mountainash_auth_client\.connections\|from \.\.connections" src tests
grep -rn "mountainash_auth_client\.lifecycle[^.]\|mountainash_auth_client\.providers[^.]\|mountainash_auth_client\.persistence" src tests
```
Expected: both produce no output (exit code 1).

- [ ] **Step 3: Full coverage suite (the real gate)**

Run: `hatch run test:test`
Expected: all tests pass; coverage report prints. Pre-existing green tests stay green.

- [ ] **Step 4: Lint**

Run: `hatch run ruff:check`
Expected: no findings.

- [ ] **Step 5: Commit the doc fix**

```bash
git add docs/INTEGRATION.md
git commit -m "docs: repoint INTEGRATION.md OAuth1Flow import to oauth/ path"
```

- [ ] **Step 6: Push and open the PR (target `develop`)**

```bash
git push -u origin feature/oauth-phase1-module-move
gh pr create --base develop \
  --title "OAuth split Phase 1: module move (schemas/ vs oauth/ boundary)" \
  --body "Relocates connections/lifecycle/providers/persistence under \`oauth/\`, severs the schemas->connections edge via package-root \`_optional.py\`, and makes package-root OAuth re-exports lazy (PEP 562) so importing \`schemas\`/the package root no longer pulls httpx/authlib/paramiko/oauth. Pure code move — no auth-behaviour change; public API names unchanged. New \`tests/test_boundary.py\` enforces the boundary in a subprocess.

See \`docs/superpowers/specs/2026-06-29-oauth-phase1-module-move-design.md\`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Task 6: Cross-repo follow-up — repoint mountainash-transport (separate PR)

`mountainash-transport` deep-imports the old `connections/` paths. The package root API is
otherwise stable, so transport only breaks on these deep paths. This lands as its **own**
branch and PR **in the transport repo** (mountainash three-tier flow), coordinated to merge
when transport next builds against this auth-client version — **not** in the auth-client PR.

**Files (in `../mountainash-transport`):**
- Modify: `src/mountainash_transport/connections/__init__.py:17-20`

- [ ] **Step 1: Branch transport from its `develop`**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-transport
git fetch origin && git switch develop && git pull --ff-only
git switch -c feature/auth-client-oauth-paths
```

- [ ] **Step 2: Repoint the deep imports**

In `src/mountainash_transport/connections/__init__.py`, change lines 17-20:

```python
from mountainash_auth_client.connections.oauth2.flow import OAuthFlow
from mountainash_auth_client.connections.oauth1.flow import OAuth1Flow
from mountainash_auth_client.connections.server.callback import LocalCallbackServer
from mountainash_auth_client.connections.server.manual import (
```
to:
```python
from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.oauth.oauth1.flow import OAuth1Flow
from mountainash_auth_client.oauth.server.callback import LocalCallbackServer
from mountainash_auth_client.oauth.server.manual import (
```

- [ ] **Step 3: Verify no other auth-client deep paths remain in transport**

Run: `grep -rn "mountainash_auth_client\.connections" src`
Expected: no output (exit code 1).

- [ ] **Step 4: Run transport's test suite**

Run transport's configured test command (e.g. `hatch run test:test-quick -q`).
Expected: all pass against the new auth-client paths.

- [ ] **Step 5: Commit, push, PR to transport `develop`**

```bash
git add src/mountainash_transport/connections/__init__.py
git commit -m "fix: repoint auth-client OAuth imports to oauth/ submodule paths"
git push -u origin feature/auth-client-oauth-paths
gh pr create --base develop \
  --title "Repoint auth-client OAuth imports to oauth/ paths (Phase 1)" \
  --body "Follows mountainash-auth-client OAuth split Phase 1: connections/ -> oauth/. Deep-import-only change.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**1. Spec coverage** (against `2026-06-29-oauth-phase1-module-move-design.md`):
- §3.1 target tree (move connections/lifecycle/providers/persistence → `oauth/`) → Task 2.
- §3.2 relocate `_optional.py` + repoint 3 importers → Task 1.
- §3.3 lazy `__getattr__` re-exports, schemas eager, `__all__` unchanged → Task 3 Step 3.
- §3.4 subprocess boundary test (schemas + package root clean) → Task 3 Steps 1-2, 5.
- §3.5 update intra-package imports + mirror test tree → Task 2 Steps 2-3, Task 4.
- §4 file-level change list → Tasks 1-4 cover every row (git mv, edits, `__init__` rewrite,
  `tests/test_boundary.py`, test dir moves).
- §5 consumer impact (transport ~3 imports + INTEGRATION.md:149) → Task 5 Step 1, Task 6.
- §6 risks: `__all__` completeness + every-name-importable test → Task 3 Step 4
  (`test_public_api.py`); `__dir__` added so `dir()`/tooling enumerate lazy names.
- §7 verification (suite, boundary test, ruff, grep) → Task 5 Steps 2-4.
- §8 rollout (branch off develop, PR to develop, coordinated transport) → Branch Setup,
  Task 5 Step 6, Task 6.

**2. Placeholder scan:** No TBD/TODO; every code/command step shows exact content. ✓

**3. Type/name consistency:** `_LAZY` keys are exactly the OAuth-side `__all__` names;
`test_lazy_map_and_all_agree` asserts `set(_LAZY) ⊆ set(__all__)`. Module targets match the
Task 2 "Produces" interface (`oauth.oauth2.flow`, `oauth.providers`, `oauth.lifecycle`,
`oauth.persistence`, `oauth.protocols`, `oauth.server.{callback,manual}`). The eager names
(`CONST_AUTH_PROFILES`, `TargetFamily`, errors, schema classes, `AuthProfile`) are **not** in
`_LAZY`, matching the boundary requirement. ✓

## Execution Note (open design forks — Phases 2 & 3 are NOT yet plannable)

Phase 1 is fully resolved and has no open decisions. Phases 2 and 3 still carry design
forks that must be settled before they can become plans:
- **Phase 2:** SCOPE override mechanism (acquisition-param A [lean] vs provider-instance B);
  `TOKEN → ACCESS_TOKEN` is already DECIDED as a hard rename (no alias).
- **Phase 3:** refresh contract (consumer re-acquires [lean i] vs http-client seam vs
  reactive-only); ops return type (`TokenCredential` [lean] vs enriched `TokenAuthProfile`).

Do not extend this plan into Phases 2/3 until those are decided.

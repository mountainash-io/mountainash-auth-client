# Design — OAuth Split Phase 1: Module Move

**Date:** 2026-06-29
**Repo:** mountainash-auth-client
**Status:** Design — implementation-ready
**Phase:** 1 of 3 (see `mountainash-central/.../a.backlog/2026-06-28-oauth-split-phased-landing.md`)
**Companion phases:** `2026-06-29-oauth-phase2-credential-deweave-design.md`,
`2026-06-29-oauth-phase3-l4-purity-design.md`

---

## 1. Goal

Establish the `schemas/ ⊥ oauth/` module boundary by **relocating** the OAuth ops code
into a new `oauth/` package, with **no change to runtime auth behaviour** and a **stable
public API** (identical exported names). This is a code move, not a rewrite.

After Phase 1: a consumer that only reads credential *data* imports `schemas/` and
never transitively pulls in the OAuth flow machinery; everything that imports `httpx`,
`authlib`, or `mountainash-secrets` lives under `oauth/`.

> **Import timing is not "behaviour" but it does change.** Today `__init__.py` eagerly
> imports the connection modules (`:13-16`), so `import mountainash_auth_client` pulls in
> `httpx`. The boundary requires the oauth-side re-exports to load **lazily** (§3.3) —
> the exported *names* are unchanged, but they resolve on first access, not at package
> import. This is essential to the boundary, not incidental.

## 2. Non-goals (explicitly deferred)

- **No schema field changes / no class collapse** (Phase 2).
- **No `OAuth2Connection`/`OAuth1Connection` retirement** — they move intact and keep
  building their `httpx.Client` and exposing `.client` (Phase 3).
- **No adapter removal** — `__adapters__`/`emit(target)` rendering stays inline on the
  schemas (sanctioned 1:M reuse; architect ruling 2026-06-28).
- **No packaging/extras changes** (dev/hatch env).

## 3. Design

### 3.1 Target tree

```
src/mountainash_auth_client/
├── __init__.py        public API — re-export names unchanged, source paths updated
├── _optional.py       NEW neutral home for require_authlib / require_paramiko  ← see 3.2
├── constants.py       unchanged
├── errors.py          unchanged
├── targets.py         unchanged
├── schemas/           unchanged except the two _optional import lines (3.2)
└── oauth/             NEW — all OAuth ops (was connections/ + lifecycle/ + providers/ + persistence.py)
    ├── oauth1/        flow.py, connection.py        (from connections/oauth1/)
    ├── oauth2/        flow.py, connection.py        (from connections/oauth2/)
    ├── server/        callback.py, factory.py, manual.py
    ├── protocols/     prtcl_callback.py
    ├── providers/     oauth1.py, oauth2.py, protocols.py   (from providers/)
    ├── lifecycle/     oauth1.py, oauth2.py, status.py      (from lifecycle/)
    └── persistence.py                                       (from persistence.py)
```

Relocations (`git mv`, preserve history): `connections/* → oauth/*`, `lifecycle/ →
oauth/lifecycle/`, `providers/ → oauth/providers/`, `persistence.py →
oauth/persistence.py`. Internal sub-layout of `oauth/` keeps the existing
`oauth1/`/`oauth2/` split to minimise churn (no file merges this phase).

### 3.2 The one forced detangle — relocate `_optional.py`

The **only** `schemas/ → connections/` import edges today:
- `schemas/certificate.py:7` — `from ..connections._optional import require_paramiko`
- `schemas/oauth1.py:4` — `from ..connections._optional import require_authlib`

After the move these would become `schemas/ → oauth/` edges, breaking the boundary.
Fix: move `connections/_optional.py` to a **package-neutral** `src/mountainash_auth_client/_optional.py`
(it depends on nothing in `oauth/` or `schemas/` — it is the optional-dep guard).
Repoint its three importers:
- `schemas/certificate.py` → `from .._optional import require_paramiko`
- `schemas/oauth1.py` → `from .._optional import require_authlib`
- `oauth/oauth1/flow.py` → `from mountainash_auth_client._optional import require_authlib`

`require_authlib`/`require_paramiko` import their SDK **lazily** (only when called), so
importing `schemas/` triggers no `authlib`/`paramiko`/`httpx` import. The `__adapters__`
(including OAuth1's `_oauth1_signer`) **stay inline on the schemas** — the boundary
holds *with adapters kept*, because the adapters only reach the SDK at `emit()` time,
invoked by the consumer that owns the relevant extra.

### 3.3 Public API stability — via LAZY re-exports (resolves the boundary/eager conflict)

**The trap:** Python runs `__init__.py` before any submodule, so a subprocess doing
`import mountainash_auth_client.schemas` first executes `__init__.py`. If `__init__.py`
eagerly imports the oauth names (as it does today, `:13-16`), `httpx`/`oauth` load and
the §3.4 boundary test fails. Eager root re-exports and the boundary test are mutually
exclusive.

**Fix:** the oauth-side names (`OAuthFlow`, `OAuth2Connection`, `OAuth1Flow`,
`OAuth1Connection`, `LocalCallbackServer`, `ManualCallbackServer`,
`PersistableAuthProfile`, callback protocols) re-export **lazily** via a module-level
`__getattr__` (PEP 562) in `__init__.py`. The schema/constant/error/target names stay
**eager** (pydantic-only, cheap, no boundary cost). Result:
- `from mountainash_auth_client import OAuthFlow` still works — resolves on first access.
- `import mountainash_auth_client` / `…schemas` does **not** load `oauth/`/`httpx`.
- exported names and `__all__` are unchanged; `__all__` drives the lazy-name set.

```python
# __init__.py sketch
_LAZY = {
    "OAuthFlow": "mountainash_auth_client.oauth.oauth2.flow",
    "OAuth2Connection": "mountainash_auth_client.oauth.oauth2.connection",
    # … OAuth1Flow, OAuth1Connection, LocalCallbackServer, ManualCallbackServer,
    #    PersistableAuthProfile, callback protocols
}
def __getattr__(name: str):
    if name in _LAZY:
        import importlib
        return getattr(importlib.import_module(_LAZY[name]), name)
    raise AttributeError(name)
```

### 3.4 Boundary enforcement test

Add `tests/test_boundary.py`: in a clean subprocess, `import
mountainash_auth_client.schemas` (and each schema submodule), then assert `httpx`,
`authlib`, `paramiko`, and `mountainash_auth_client.oauth` are **absent** from
`sys.modules`. Add a second case asserting `import mountainash_auth_client` (the package
root) is also clean — this is what proves the lazy `__init__` (§3.3) works. Subprocess
isolation is required (other tests import `oauth/`, polluting in-process `sys.modules`).

### 3.5 Internal imports & tests

- Update all intra-package imports to the `oauth/` paths.
- Move `tests/connections/ → tests/oauth/` (and `tests/lifecycle/`, etc.) to mirror.

## 4. File-level change list

| Action | Path |
|---|---|
| `git mv` | `connections/` → `oauth/` (oauth1, oauth2, server, protocols) |
| `git mv` | `lifecycle/` → `oauth/lifecycle/`; `providers/` → `oauth/providers/`; `persistence.py` → `oauth/persistence.py` |
| `git mv` | `connections/_optional.py` → `_optional.py` (package root) |
| edit | `schemas/certificate.py:7`, `schemas/oauth1.py:4` — repoint `_optional` import |
| edit | `oauth/oauth1/flow.py:14` — repoint `_optional` import |
| rewrite | `__init__.py` — oauth names re-exported **lazily** via `__getattr__` (§3.3); schema names stay eager; `__all__` unchanged |
| edit | all internal `from …connections/lifecycle/providers/persistence import …` |
| add | `tests/test_boundary.py` |
| `git mv` | `tests/connections/ → tests/oauth/` (+ lifecycle) |

## 5. Consumer impact (downstream)

Only **deep-path importers** break (root re-exports are stable):
- **mountainash-transport** — `connections/__init__.py` deep-imports
  `connections.oauth2.flow.OAuthFlow`, `connections.oauth1.flow.OAuth1Flow`,
  `connections.server.callback.LocalCallbackServer`. Repoint to `oauth/…`.
- **INTEGRATION.md** line 149 (`from …connections.oauth1.flow import OAuth1Flow`) — update.

**Decision:** update transport's ~3 imports in the coordinated change, **or** leave a
thin `connections/` re-export shim for one release. Recommended: update transport — it
is small and avoids a lingering shim.

## 6. Risks

- **Low.** No runtime auth-behaviour changes; the boundary test + the existing suite
  (`hatch run test:test`) are the safety net. Pre-existing green tests must stay green.
- **Lazy `__init__` (§3.3) edge:** `from x import Y` and attribute access are unaffected,
  but `dir(mountainash_auth_client)` / star-imports / static analysers that don't honour
  PEP 562 may not see lazy names until accessed. Keep `__all__` complete so star-import
  and tooling still enumerate them; add a test that every `__all__` name is importable.
- Import-cycle risk during the move; mitigated by the neutral `_optional.py` and keeping
  the `oauth1/`/`oauth2/` sub-structure intact.

## 7. Verification

- `hatch run test:test` green (unchanged behaviour).
- New boundary test green.
- `hatch run ruff:check src tests` green (incl. TCH import rules).
- `grep` confirms no `from …connections` / `from …\.lifecycle` / `from …providers`
  remain outside `oauth/`.

## 8. Rollout

Branch `feature/oauth-phase1-module-move` off `develop` → PR to `develop`. Transport's
import repoint lands coordinated (same set) since the root API is otherwise stable.

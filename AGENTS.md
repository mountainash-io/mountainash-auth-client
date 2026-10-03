# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Design Principles — READ FIRST

Durable architectural decisions for this package live in **mountainash-central**:

```
mountainash-central/01.principles/mountainash-auth-client/
├── PRINCIPLES.md   # governance: categories, status markers, how to add a principle
├── README.md       # index of principles
└── a.architecture/
    └── connections-single-source-of-truth.md   # ADOPTED
```


The implementation backlog also lives in `mountainash-central`:
[`04.planning/mountainash-auth-client/a.backlog/INDEX.md`](../mountainash-central/04.planning/mountainash-auth-client/a.backlog/INDEX.md)
— prioritized items; see that directory's `CHANGELOG.md` for update history. Save new
design specs/plans to `../mountainash-central/04.planning/mountainash-auth-client/superpowers/{specs,plans}/`,
not under `docs/superpowers/` in this repo.

## Project Overview

**mountainash-auth-client** provides client-side authentication for the mountainash
ecosystem. Two concerns:

1. **Auth profiles** (`schemas/`) — a typed discriminated union of `*AuthProfile`
   classes (`IAMAuthProfile`, `TokenAuthProfile`, `PasswordAuthProfile`,
   `OAuth1AuthProfile`, `OAuth2AuthProfile`, `NoAuthProfile`, …) registered in
   `AUTH_REGISTRY`. These are consumed by downstream packages (e.g. transport's
   storage backends) to describe credentials.
2. **The connection layer** (`connections/`) — OAuth authorization flows, connection
   classes, and pluggable callback servers (see the principle above).

## Package Structure

```
src/mountainash_auth_client/
├── __init__.py          # public API surface (+ __all__)
├── constants.py         # CONST_AUTH_PROFILES
├── errors.py            # exception hierarchy (TokenExchangeError, TokenRefreshError,
│                        #   AuthorizationRequired; CallbackError taxonomy:
│                        #   AuthorizationDeniedError / MalformedCallbackError /
│                        #   CallbackTimeoutError)
├── schemas/             # *AuthProfile discriminated union + AUTH_REGISTRY
└── connections/
    ├── _optional.py     # require()/require_authlib() — centralised optional-dep loading
    ├── oauth1/          # OAuth1Flow + OAuth1Connection (flow.py / connection.py)
    ├── oauth2/          # OAuthFlow (OAuth2) + OAuth2Connection (flow.py / connection.py)
    ├── protocols/       # CallbackServerProtocol (+ CallbackServerFactory alias)
    └── server/          # LocalCallbackServer, ManualCallbackServer, prompt_for_code,
                         #   resolve_callback_factory (factory.py)
```

Callback servers are injectable behind `CallbackServerProtocol`; flows resolve a factory
via `resolve_callback_factory` (per-call override → flow construction default →
`redirect_mode` builtin). `LocalCallbackServer` is the default.

## Build / Test / Lint

This package uses **hatch** (with `uv` as the installer).

- Tests: `hatch run test:test` (single file/test: `hatch run test:test <path>::<test> -v`)
- Lint: `hatch run ruff:check src tests` (auto-fix: `hatch run ruff:fix`)
- Tests live under `tests/`, mirroring the package (`tests/connections/…`).
- No mypy environment is configured; type-correctness is enforced via ruff (incl. TCH
  rules — keep type-only imports under `if TYPE_CHECKING:`).

## Conventions

- **Optional dependencies:** import required deps directly; guard only optional extras,
  and do it through `connections/_optional.py::require_authlib()` rather than inline
  `try/except ImportError` blocks.
- **Code style:** ruff formatting, Google-style docstrings, `from __future__ import
  annotations` in modules, typing annotations on public functions.

## Git Branch Flow (mountainash three-tier)

```
feature/* | bugfix/* | hotfix/*  →  develop  →  release/*  →  main + tag
```

Feature/bugfix/hotfix PRs **always target `develop`**. Never push directly to `develop`
or `main`. CalVer `YY.MM.MICRO` for releases.

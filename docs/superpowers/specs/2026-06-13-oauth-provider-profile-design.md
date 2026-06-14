# OAuth `ProviderProfile` — standardised provider coordinates + parameterised OAuth connection

**Status:** Draft for review (fresh spec; not yet planned). Spans **two repos**:
`mountainash-auth-client` (primary) and `mountainash-wearables` (first adopter).

**Date:** 2026-06-13

**Related:** completes the OAuth side of the unified-emission work. Builds on the
connections-dedup (`OAuthFlow.resolve_access_token` / `OAuth1Flow.resolve_token_pair`,
auth-client 26.6.0) and Phase 4's `__adapters__[HTTP]` storage-emission pattern. Transport's
OAuth connection classes are explicitly **out of scope** (unwired scaffolding; see transport
`docs/BACKLOG.md`).

---

## Problem

OAuth providers that ship **no SDK** (the wearables use case — Garmin, Oura, Strava, Whoop,
Google Health) force the integrator to supply the provider's coordinates by hand. Two things
are wrong with how that's expressed today:

1. **Provider coordinates are an untyped `metadata` dict.** Wearables proves the need but each
   provider's `descriptor.py` stuffs `{"authorize_url": ..., "token_url": ...}` into a metadata
   bag fed to `OAuthFlow(descriptor)`. No validation, no standard shape — a missing
   `authorize_url` surfaces as a runtime `KeyError`, not a construction error. (The same class of
   bug made transport's OAuth path theatrical.)
2. **The connection fuses two concerns and demands a subclass per provider.** auth-client's
   OAuth connection (and the old `mixins.oauth2.OAuth2ConnectionMixin` wearables is on) carries
   `_spec`/`_base_url` as `ClassVar`s — so every provider needs a subclass, and the
   **auth-server URLs** (`authorize_url`/`token_url`, which are 1:1 with the credential) are
   welded to the **resource `base_url`** (1:many with the credential — one token can be spent at
   several resource hosts).

There are infinitely many providers, so provider data **cannot** live inside auth-client — but
it also shouldn't be an ad-hoc dict each client reinvents. The resolution: **auth-client ships a
standardised `ProviderProfile` *schema*; clients instantiate it with their provider's *values*.**

## Goal

A typed, validated `ProviderProfile` (a `Profile` with a real `ProfileSpec` of `ParameterSpec`
fields, with a base esoteric providers extend) that carries a provider's coordinates; a
**parameterised** `OAuth2Connection`/`OAuth1Connection` taking `(provider_profile, auth_profile,
…)` — no `ClassVar`s, no subclass-per-provider, no provider registry in auth-client. The
connection runs the same two-stage `emit()` the rest of the stack uses. Wearables migrates to it
first, replacing its descriptor dicts + `OAuth2ConnectionMixin` subclasses.

## Non-goals

- Shipping provider **data** or a provider **registry** in auth-client (schema only; clients own instances).
- Changing the resolver lifecycle — `resolve_access_token` / `resolve_token_pair` are unchanged.
- Transport's OAuth connections (separate, unwired; deletable later).
- A 1:many "one token → many resource hosts" override mechanism (YAGNI — see Architecture).

---

## Architecture

### `ProviderProfile` — standardised, typed, extendable (new in auth-client)

A `Profile` whose `ProfileSpec` declares the provider's coordinates as `ParameterSpec` fields,
following the exact pattern of the auth schemas (`from mountainash_settings import ParameterSpec,
Profile, ProfileSpec`). **Two base variants**, mirroring the per-mode auth profiles:

```python
# mountainash_auth_client/providers/oauth2.py
OAUTH2_PROVIDER_PARAMS = [
    ParameterSpec(name="NAME",          type=str, tier="core"),   # provider identity ("strava") — error labels/logging (Codex-b)
    ParameterSpec(name="AUTHORIZE_URL", type=str, tier="core"),
    ParameterSpec(name="TOKEN_URL",     type=str, tier="core"),
    ParameterSpec(name="BASE_URL",      type=str, tier="core"),
    ParameterSpec(name="DEFAULT_SCOPE", type=str | None, tier="advanced", default=None),  # provider default; the credential's per-request SCOPE overrides (Codex-c)
    ParameterSpec(name="USE_PKCE",      type=bool, tier="advanced", default=False),
    ParameterSpec(name="CALLBACK_PORT", type=int | None, tier="advanced", default=None),  # fixed local callback port, e.g. Whoop (Codex-a)
]

def _provider_http_kwargs(profile, kw):
    """Emit the resource client config (base_url + future httpx knobs)."""
    return {**kw, "base_url": profile.BASE_URL}

OAUTH2_PROVIDER_SPEC = ProfileSpec(
    name="oauth2_provider", provider_type="oauth2_provider",
    parameters=OAUTH2_PROVIDER_PARAMS,
)

class OAuth2ProviderProfile(Profile):
    __spec__ = OAUTH2_PROVIDER_SPEC
    __adapters__ = {TargetFamily.HTTP: _provider_http_kwargs}
```

```python
# mountainash_auth_client/providers/oauth1.py
OAUTH1_PROVIDER_PARAMS = [
    ParameterSpec(name="NAME",              type=str, tier="core"),
    ParameterSpec(name="REQUEST_TOKEN_URL", type=str, tier="core"),
    ParameterSpec(name="AUTHORIZE_URL",     type=str, tier="core"),
    ParameterSpec(name="ACCESS_TOKEN_URL",  type=str, tier="core"),
    ParameterSpec(name="BASE_URL",          type=str, tier="core"),
    ParameterSpec(name="CALLBACK_PORT",     type=int | None, tier="advanced", default=None),
]
# OAUTH1_PROVIDER_SPEC + OAuth1ProviderProfile analogous, same _provider_http_kwargs adapter.
```

**Extension (the "base esoteric providers extend" requirement):** a provider needing
non-standard fields composes the base param list and subclasses the base. This is exactly how
provider-specific *resource* endpoints are modelled — e.g. Oura's and Garmin Health's
`user_info_url` (consumed by Garmin's verifier), which do **not** belong on the standard base
(Codex-d):

```python
GARMIN_PROVIDER_SPEC = ProfileSpec(
    name="garmin_health_provider", provider_type="garmin_health_provider",
    parameters=[*OAUTH1_PROVIDER_PARAMS, ParameterSpec(name="USER_INFO_URL", type=str)],
)
class GarminHealthProvider(OAuth1ProviderProfile):
    __spec__ = GARMIN_PROVIDER_SPEC
```

Standard providers need **no** subclass — they instantiate the base directly with values:
`OAuth2ProviderProfile(NAME="strava", AUTHORIZE_URL="https://www.strava.com/oauth/authorize", TOKEN_URL=..., BASE_URL=..., DEFAULT_SCOPE=...)`.
Providers with extra coordinates (`USER_INFO_URL`, custom callback ports beyond `CALLBACK_PORT`,
API-version fields) extend via a one-line subclass. This is the load-bearing reason the base is a
real `ProfileSpec` rather than a fixed dict: extension is typed and validated, not bolted on.

**Not registered** in `AUTH_REGISTRY` (it is not an auth mode). No provider registry at all —
clients construct instances. Validation comes for free from the `ProfileSpec` (a missing
required URL fails at construction, killing the runtime-`KeyError` bug class).

### `OAuthFlow` / `OAuth1Flow` read URLs off the `ProviderProfile`

The flows currently take a `spec` and read **everything** off `spec.metadata` — not only URLs:
`authorize_url`/`token_url`/`use_pkce`/`default_scope` (OAuth2) and the URL trio (OAuth1), **and**
the full metadata bag is forwarded into callback resolution, where the callback factory reads
`callback_port` (Codex-a — Whoop sets this today). The refactor therefore moves **all** of that
onto typed `ProviderProfile` fields, not just the URLs:

- `provider.AUTHORIZE_URL` / `TOKEN_URL` (OAuth2); `REQUEST_TOKEN_URL`/`AUTHORIZE_URL`/`ACCESS_TOKEN_URL` (OAuth1)
- `provider.USE_PKCE`
- `provider.DEFAULT_SCOPE` — used as the *default*; the credential's per-request `auth_profile.SCOPE`
  still takes precedence in `build_authorize_url` (existing behaviour, now with unambiguous names — Codex-c)
- `provider.CALLBACK_PORT` — threaded into the callback factory (replacing the metadata-bag read — Codex-a)
- `provider.NAME` — used for `AuthorizationRequired(provider=...)` (was `self._spec.name`; base
  instances would otherwise all report `"oauth2_provider"` — Codex-b)

`build_authorize_url` / `exchange_code` / `refresh` / `resolve_access_token` / `resolve_token_pair`
bodies are otherwise unchanged — only the *source* of these values moves from `metadata[...]` to
typed fields.

Clean break: the old `spec.metadata` input is dropped. See **Compatibility & version boundary**
below for the (non-wearables) consumers this affects.

### Parameterised connections

```python
# mountainash_auth_client/connections/oauth2/connection.py
class OAuth2Connection:
    def __init__(self, provider, auth_profile, *, auto_authorize=False, callback_server=None):
        self._provider = provider          # OAuth2ProviderProfile (URLs + base_url)
        self._auth = auth_profile          # OAuth2AuthCodeAuthProfile (credentials)
        ...

    def connect(self) -> Self:
        token  = OAuthFlow(self._provider).resolve_access_token(
            self._auth, auto_authorize=self._auto_authorize, callback_server=self._callback_server)
        base   = self._provider.emit(TargetFamily.HTTP)                 # {base_url: ...}
        merged = TokenAuthProfile(TOKEN=token).emit(TargetFamily.HTTP, base=base)
        self._client = httpx.Client(**merged)
        return self
```

OAuth1 analog: `resolve_token_pair` → `OAuth1AuthProfile(CONSUMER_KEY=…, CONSUMER_SECRET=…,
ACCESS_TOKEN=…, ACCESS_TOKEN_SECRET=…).emit(HTTP, base=provider.emit(HTTP))`. The
subclass-per-provider `ClassVar` design (and the old `mixins.oauth2.OAuth2ConnectionMixin`) is
**retired**.

**`base_url` and the 1:many case.** `BASE_URL` lives on the `ProviderProfile` (provider
coordinates), emitted via its `__adapters__[HTTP]`. The auth-server-URLs-1:1 /
resource-base_url-1:many distinction is real, but every wearables provider is one auth server +
one resource API, so we keep `BASE_URL` on the provider. The rare 1:many case (one credential,
several resource hosts) is expressed by **constructing separate `ProviderProfile` instances** (or
a future endpoint-profile split) — not built now (YAGNI). Documented so it isn't mistaken for an
oversight.

### Data flow (after)

```
OAuth2Connection(provider_profile, auth_profile).connect()
  → token  = OAuthFlow(provider_profile).resolve_access_token(auth_profile, ...)   # URLs from provider fields
  → base   = provider_profile.emit(HTTP)                                           # {base_url, …}
  → merged = TokenAuthProfile(TOKEN=token).emit(HTTP, base=base)                    # + Authorization: Bearer
  → httpx.Client(**merged)
```

One emission machinery, two stages on `TargetFamily.HTTP`; provider = *where*, credential = *who*
— the same separation wearables already draws between its descriptor and its auth object.

## Error handling

- `ProviderProfile(...)` construction validates required fields (missing `AUTHORIZE_URL` →
  validation error at construction, not a runtime `KeyError`). This is the headline correctness win.
- `resolve_*` raises `AuthorizationRequired` exactly as today.
- Callback errors (`CallbackTimeoutError`/`AuthorizationDeniedError`/`MalformedCallbackError`)
  unchanged.

## Testing

- **`ProviderProfile`:** required-field validation; `emit(HTTP)` golden (`{base_url: …}` + any
  knobs); extension test (a subclass adds a `ParameterSpec`; base params still present and emit).
- **Flow:** `OAuthFlow`/`OAuth1Flow` read URLs off the provider instance (unit, no HTTP);
  `resolve_*` still cached/refresh/authorize/raise paths green against a `ProviderProfile`.
- **Connection:** `connect()` resolves → emits → builds a client; `Authorization: Bearer` present;
  `base_url` taken from the provider; OAuth1 analog attaches the authlib signer.
- **Wearables (first adopter):** its existing per-provider tests (Garmin OAuth1; Oura/Strava/
  Whoop/Google OAuth2) pass against `ProviderProfile` instances — the migration's golden net.

## Scope & sequencing

1. **auth-client PR** — add `OAuth2ProviderProfile`/`OAuth1ProviderProfile` (+ extension support),
   refactor `OAuthFlow`/`OAuth1Flow` to read off the provider, parameterise the OAuth connections,
   retire the old `mixins`/`store`/`*Auth` (non-`Profile`) surface. Version bump. (If settings lacks
   a filesystem `SecretsBackend`, that lands here — see Dependencies.)
2. **transport PR** — delete (or stub) transport's OAuth connection classes, which call the old
   `OAuthFlow(self._spec)` signature, so nothing is left on the broken input (version-boundary
   section). Refresh transport's env to the new auth-client version.
3. **wearables PR (first adopter)** — convert each `descriptor.py` → a `ProviderProfile` instance
   (or a small subclass for esoteric ones); delete the `OAuth2ConnectionMixin` subclasses; point at
   the parameterised connection; migrate token persistence from `store.filesystem.FilesystemStore`
   to the settings secrets backend named by its existing `secrets_provider` string. Refresh the
   wearables env to the new auth-client version (uv version-cache gotcha).

Sequencing rationale: the auth-client break must land first (version bump); transport and wearables
then update against the new version. Transport before/with wearables so no repo is left calling the
old flow signature.

## Dependencies (design-time, not plan-time — Codex-e)

**Token-persistence backend.** The resolvers persist/read tokens through a settings secrets
backend resolved from `auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER` (`get_secrets_backend(name)`),
and `get_secrets_backend(None)` returns `None`. Wearables today persists tokens via a **separate**
`store.filesystem.FilesystemStore` (under `config_dir/.tokens`), while its `secrets_provider` string
currently feeds only profile *loading* — so there is a genuine gap, not a detail: the new flow has
nowhere to read/write tokens for wearables until this is wired. **Resolution (must be settled before
the wearables plan):**
1. Confirm whether `mountainash-settings` ships a filesystem-backed `SecretsBackend`. If yes,
   wearables registers it under its `secrets_provider` name and sets each auth profile's
   `SETTINGS_SOURCE_SECRETS_PROVIDER` to it.
2. If not, providing that filesystem `SecretsBackend` (in settings, or wearables-local + registered)
   is **in scope** for this work — the migration cannot complete without it.

## Compatibility & version boundary (Codex-f)

Changing the flow input from `spec` to `ProviderProfile` is a **breaking public-API change** —
`OAuthFlow`/`OAuth1Flow` are exported from auth-client's top-level `__init__`, and they have a
consumer beyond wearables: **transport** calls `OAuthFlow(self._spec)` / `OAuth1Flow(self._spec)`
directly in its (unwired) OAuth connections. The break must be handled, not just declared
out-of-scope:

- **Chosen approach — coordinated removal, no shim.** Transport's OAuth connection classes are
  already slated for deletion (unwired scaffolding; transport `BACKLOG.md`). Delete (or stub) them
  in the **same versioned cycle** as this auth-client change, so no caller is left calling the old
  `OAuthFlow(spec)` signature. The auth-client PR bumps the version; transport + wearables update
  against the new version in lock-step. (Rejected: a transitional `OAuthFlow.from_spec(metadata)`
  shim — it would preserve the exact `metadata`-bag pattern we're removing, for one already-dead path.)
- **Note:** wearables already imports `mixins/oauth2.py` and `store/filesystem.py`, which **do not
  exist** in current auth-client `develop` — so wearables is *already* broken against current
  auth-client. Migration is mandatory, not optional; there is no working state to preserve.
- The plan must `grep` the org for any other importer of `OAuthFlow`/`OAuth1Flow`/the old
  `mixins`/`store`/`*Auth` names before deletion.

## Open questions / to confirm at plan time

- **OAuth1/OAuth2 split:** two `ProviderProfile` classes (proposed) vs one discriminated class.
  *Proposed: two*, mirroring `OAuth2AuthCodeAuthProfile` / `OAuth1AuthProfile`.
- **Module home:** `mountainash_auth_client/providers/` (proposed) vs folding into `schemas/`.
  Providers are not auth modes, so a sibling `providers/` package is cleaner.

## Risks

- **Clean break of the flow input** — addressed by the version-boundary section: auth-client →
  transport (delete OAuth connections) → wearables, landing in order with a version bump + env refresh.
- **Secrets-backend gap** — the headline dependency above; if settings has no filesystem backend,
  building one is in scope.
- **`emit(HTTP)` base_url shape** must match what `httpx.Client(**kwargs)` expects (`base_url=`),
  and compose cleanly with the bearer-header emit — covered by the connection golden test.

# OAuth Token-Lifecycle Capability — Design

**Status:** Draft (pre-implementation)
**Repo:** mountainash-auth-client
**Date:** 2026-06-14
**Supersedes (for consumers):** wearables' `2026-06-08-auth-client-migration-design.md` (obsolete — two generations stale).

---

## 1. Context & motivation

§7.4 (PR #9) moved OAuth token *persistence* **inside** `OAuthFlow`/`OAuth1Flow`, behind an
injected `mountainash_secrets.SecretStoreResolver`: a flow resolves a `ClearableStore` by name,
wraps it in `NamespacedStore(store, "oauth")`, keys it by `auth_profile.persist_key()`, and does
the cached → refresh → authorize → persist dance there.

What §7.4 did **not** provide is the rest of an OAuth token *lifecycle* that every consumer needs:

- **first-time interactive authorization** with a chosen redirect mode (local server vs. manual),
- **non-mutating status inspection** (is the token valid / about to expire / expired / missing /
  revoked?),
- **explicit refresh**, and
- **revocation** (delete/tombstone the stored tokens).

Today the only OAuth consumer, **mountainash-wearables**, hand-rolls all of this in
`connections/auth.py` against the *deleted* multi-arg auth-client `FilesystemStore` API and the
*deleted* `OAuthFlow(spec)` signature. That code is broken and is a legacy smell: it re-implements
persistence parallel to the flow and hard-codes auth-client's `"oauth"` namespace + key + expiry
contract inside a consumer.

**Decision (user):** wearables is **not** our only OAuth consumer. The full token lifecycle is a
generic, reusable capability and must live in **auth-client**, with consumers reduced to a thin
facade. This spec designs that capability.

## 2. Goals / non-goals

**Goals**
- A reusable, family-symmetric token-lifecycle surface in auth-client: `authorize`, `status`,
  `refresh` (OAuth2), `access_token`/`token_pair`, `revoke`.
- **One** place that owns the §7.4 storage contract (the `"oauth"` namespace, `persist_key`, the
  token-record shape, the expiry windows). The flow and the managers share it; no consumer ever
  hard-codes it.
- Promote the currently-undefined dynamic attributes `persist_key()` /
  `SETTINGS_SOURCE_SECRETS_PROVIDER` to a **typed, discoverable contract**
  (`PersistableAuthProfile`) that both the flow and the managers depend on. (Closes the §7.4
  deferral.)
- Typed status results (`TokenStatus`/`TokenState`), not loose dicts.
- Consumers (starting with wearables) collapse to: composition root + provider registry + a thin
  name-binding facade.

**Non-goals**
- Building HTTP clients. That is the connections' job (`OAuth2Connection`/`OAuth1Connection`); a
  manager manages *tokens*, a connection produces an authed *client*. Both share the flow + the
  storage contract.
- Changing the OAuth wire protocol, the provider profiles, or the secrets package.
- Promoting `persist_key`/`SETTINGS_SOURCE_SECRETS_PROVIDER` to `ParameterSpec` *fields* on the
  auth-profile classes (they remain consumer-supplied; we only make the *contract* typed — see §4).

## 3. Architecture overview

New + changed modules:

```
src/mountainash_auth_client/
  persistence.py                 # NEW — PersistableAuthProfile contract + token_store() helper
  lifecycle/                     # NEW package
    __init__.py                  # exports the managers + status types
    status.py                    # TokenState (enum) + TokenStatus (frozen dataclass) + classify()
    oauth2.py                    # OAuth2TokenManager
    oauth1.py                    # OAuth1TokenManager
  connections/
    oauth2/flow.py               # CHANGED — acquisition refactored onto token_store(); typed param
    oauth1/flow.py               # CHANGED — same
  __init__.py                    # CHANGED — re-export the new public surface
```

**Dependency direction (acyclic):**
`persistence.py` depends only on `mountainash_secrets`. `connections/*/flow.py` and `lifecycle/*`
both depend on `persistence.py`. `lifecycle/*` additionally composes the flows and the callback
factory. Nothing depends back upward.

## 4. The identity contract — `PersistableAuthProfile`

The flow already reads two attributes off the auth profile that are defined on *no* auth-profile
class today (`OAuth2AuthCodeAuthProfile`/`OAuth1AuthProfile` carry neither): a per-record key and
the name of the store to resolve. We make this a named, runtime-checkable contract in
`persistence.py`:

```python
import typing as t

@t.runtime_checkable
class PersistableAuthProfile(t.Protocol):
    """An auth profile that knows WHERE its tokens persist and under WHAT key.

    `SETTINGS_SOURCE_SECRETS_PROVIDER` names the store registered in the consumer's
    SecretStoreResolver. `persist_key()` returns a per-(provider, account) key, unique within
    that store. Both are consumer-supplied — auth-client defines the contract, not the values.
    """

    SETTINGS_SOURCE_SECRETS_PROVIDER: str

    def persist_key(self) -> str: ...
```

- `runtime_checkable` checks method/attr **names** only (consistent with mountainash-secrets'
  protocol philosophy); semantics are the consumer's responsibility.
- The flow's `resolve_access_token`/`resolve_token_pair` and both managers type their
  `auth_profile` parameter against `PersistableAuthProfile` (in `TYPE_CHECKING`), making the
  requirement explicit and tooling-visible instead of a magic dynamic attribute.
- auth-client does **not** make `OAuth2AuthCodeAuthProfile` satisfy it by default (the values are
  consumer-specific). Consumers attach `SETTINGS_SOURCE_SECRETS_PROVIDER` + `persist_key()` to the
  auth profiles they materialise (wearables does this in `config.py` — see §10).

**Key grammar (required of `persist_key()` output).** Because the key is dot-prefixed by
`NamespacedStore` and mapped to a filesystem path by `FilesystemStore._key_to_paths` (which splits
on `.` and validates each segment against `[a-z0-9_]+`), `persist_key()` MUST return one or more
`[a-z0-9_]+` segments joined by `.` — no `/`, `\`, `..`, empty segments, leading/trailing dots, or a
leading `oauth`/`cred` reserved-namespace segment (the manager already namespaces under `oauth`).
`FilesystemStore` enforces the per-segment charset and raises `ValueError` on violation (fails loud,
not silent); `InMemoryStore` does not, so the contract is documented here and asserted in the
managers' tests. The wearables example `f"{provider}.{user}"` is conformant only when `provider` and
`user` are themselves `[a-z0-9_]+` — consumers are responsible for slugifying.

## 5. The storage-contract helper — `token_store()`

The single owner of the `"oauth"` namespace + resolve-as-capability step, in `persistence.py`:

```python
from mountainash_secrets import ClearableStore, NamespacedStore

if t.TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver

def token_store(
    resolver: SecretStoreResolver,
    auth_profile: PersistableAuthProfile,
) -> NamespacedStore:
    """Resolve the OAuth token store for an auth profile.

    Centralises the §7.4 contract: resolve the named store as a ClearableStore, then namespace it
    under "oauth". Every read/write of OAuth tokens — by the flow OR a manager — goes through this,
    so the namespace/capability decision lives in exactly one place.
    """
    store = resolver.resolve_as(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER, ClearableStore)
    return NamespacedStore(store, "oauth")
```

The §7.4 acquisition lines in `oauth2/flow.py` and `oauth1/flow.py` are **refactored** to call this
helper (DRY), e.g. `backend = token_store(self._resolver, auth_profile)` after the existing
`self._resolver is None` guard. Behaviour is unchanged; the only difference is the namespace string
and `resolve_as` call now live in one function. The flow keeps `key = auth_profile.persist_key()`.

`token_store()` owns **addressing** (which store, which namespace, which key) — *not* mutation
ordering. Ordering is owned by the transaction discipline in §5.1.

### 5.1 Mutation serialization (the single write discipline)

The token record for a key is mutated by three call sites — the flow's refresh (inside
`resolve_access_token`), the manager's `authorize()` persist, and the manager's `revoke()`. To close
the dual-writer and revoke races, **every mutation of a key runs inside that key's
`token_store(...).transaction(key)`** (the mountainash-secrets per-key lock: an in-process `RLock`
for `InMemoryStore`, `fcntl.flock` for `FilesystemStore`). Concretely:

- **Flow refresh** already does this (§7.4: `with backend.transaction(key): re-get; refresh; set`),
  and critically *re-reads inside the lock* — so a refresh that began before a concurrent `revoke()`
  sees `get()→None` after acquiring the lock and does **not** resurrect the credential.
- **`revoke()`** runs `with backend.transaction(key): backend.delete(key)`.
- **`authorize()` persist** runs `with backend.transaction(key): backend.set(key, tokens)`.

**Long interactive auth is held *outside* the lock.** `authorize()` performs the browser/redirect
dance first (which can take minutes — never hold `flock` across it), then takes the per-key
transaction only for the short `set`. A completed interactive authorization is therefore
**last-writer-wins by design**: if it lands after a concurrent `revoke()`, the freshly-consented
token is persisted (and clears the tombstone, §5.2) — this reflects explicit user intent and is the
correct outcome. The race window that matters (a *stale* writer resurrecting a revoked credential)
is closed because the only other writer, refresh, re-reads under the lock.

`FilesystemStore`'s `flock` is atomic on a local filesystem only (not NFS/CIFS) and is cooperative
(direct `get`/`set`/`delete` outside a `transaction` do not take it) — acceptable here because all
**mutations** are funnelled through `transaction(key)`. This is the same concurrency envelope §7.4
already operates under.

### 5.2 Tombstone contract (relied upon)

`revoke()` calls `delete(key)`, which writes a tombstone so `is_cleared(key)` is true and `get(key)`
returns `None`. The managers rely on the mountainash-secrets contract that **`set(key, …)` clears
any existing tombstone** — verified in both stores: `FilesystemStore.set` unlinks the
`.{stem}.cleared` file; `InMemoryStore.set` does `self._cleared.discard(key)`. Therefore
revoke-then-authorize persists the new token *and* clears the tombstone, so `status()` returns
`VALID`/`PRESENT`, not `CLEARED`. (If this secrets contract ever changes, these managers break — it
is asserted in the managers' tests, not just assumed.)

## 6. Status model — `TokenStatus` / `TokenState`

In `lifecycle/status.py`:

```python
import enum, time
from dataclasses import dataclass

class TokenState(str, enum.Enum):
    VALID = "valid"                  # present, not within the refresh buffer
    REFRESH_NEEDED = "refresh_needed"  # present, inside the buffer window, not yet past expiry
    EXPIRED = "expired"              # present, past expiry
    MISSING = "missing"             # no record stored
    CLEARED = "cleared"             # explicitly revoked (tombstone present)
    PRESENT = "present"             # OAuth1 only — a non-expiring token pair exists

@dataclass(frozen=True)
class TokenStatus:
    state: TokenState
    expires_at: int | None = None
    expires_in_seconds: int | None = None
    has_refresh_token: bool = False
```

**OAuth2 classification** (`classify_oauth2(record, *, buffer_seconds=300, now=None)`), matching the
flow's existing `is_expired` buffer so status and refresh agree:

- record is `None` → `MISSING`.
- `token_expires_at` is `None` → `VALID` (non-expiring), `expires_at=None`.
- `now >= expires_at` → `EXPIRED` (+ `has_refresh_token`).
- `expires_at - buffer <= now < expires_at` → `REFRESH_NEEDED` (+ `expires_in_seconds`,
  `has_refresh_token`).
- else → `VALID` (+ `expires_in_seconds`).

`CLEARED` is decided *before* classification by the manager (a `ClearableStore.is_cleared` check),
because a tombstone and "no record" both make `get()` return `None`; `is_cleared` disambiguates.

`now` is injectable for testability (no `time.time()` at import). OAuth1 has no expiry concept, so
its manager returns `PRESENT`/`MISSING`/`CLEARED` only.

## 7. `OAuth2TokenManager`

`lifecycle/oauth2.py`. Construction takes the provider profile, a `PersistableAuthProfile`, and the
resolver (the same trio the connection takes), plus an optional default callback factory:

```python
class OAuth2TokenManager:
    def __init__(
        self,
        provider: OAuth2ProviderProfile,
        auth_profile: PersistableAuthProfile,   # also an OAuth2 auth profile (CLIENT_ID/SECRET/SCOPE)
        *,
        resolver: SecretStoreResolver,
        callback_server: CallbackServerFactory | None = None,
    ) -> None: ...
```

**Methods**

- `authorize(*, mode="local_server", manual_redirect_uri=None) -> TokenStatus`
  Forces a fresh interactive authorization (does **not** return a cached token). The manager owns
  the `mode`→factory mapping deterministically: `effective = self._callback_server if set else
  resolve_callback_factory(mode, manual_redirect_uri=manual_redirect_uri)` (a construction
  `callback_server` shadows `mode`, mirroring the flow/factory precedence). It then calls the flow's
  **pinned** `authorize` signature
  `OAuthFlow(provider, resolver=resolver).authorize(client_id=auth.CLIENT_ID,
  client_secret=auth.CLIENT_SECRET.get_secret_value(), scope=auth.SCOPE, callback_server=effective)`
  — passing an explicit `callback_server` so the flow's internal `redirect_mode` handling is bypassed
  and resolution is deterministic. The **interactive dance runs outside any lock**; the returned
  token dict is then persisted under the per-key transaction (§5.1):
  `with token_store(resolver, auth_profile).transaction(key): backend.set(key, tokens)`. Returns
  `status()`.
  **Clobber policy:** `authorize()` replaces the record **wholesale** — a completed
  authorization-code grant is the new source of truth (contrast `refresh()`, where the flow already
  *preserves* a prior `refresh_token` via `token_data.get("refresh_token", refresh_token)`). A full
  grant normally returns a `refresh_token`; if a provider omits it on re-consent, that is reflected
  as-is. This wholesale-vs-preserve asymmetry is intentional and documented.

- `refresh() -> TokenStatus`
  Delegates to `OAuthFlow(provider, resolver=resolver).resolve_access_token(auth_profile)` with
  `auto_authorize=False`. This fires when the flow's **300s-buffered** `is_expired` is true — i.e. at
  the `REFRESH_NEEDED` boundary, not only at hard wall-clock expiry — refreshing in place under the
  flow's transaction when a `refresh_token` exists, and raising `AuthorizationRequired` when there is
  nothing to refresh. Returns `status()`.

- `access_token() -> str`
  `OAuthFlow(...).resolve_access_token(auth_profile, auto_authorize=False)` — the usable-token
  accessor; raises `AuthorizationRequired` when none. (For an authed *client*, use
  `OAuth2Connection`; the manager intentionally does not build clients.)

- `status() -> TokenStatus`
  Non-mutating, **point-in-time snapshot** — explicitly *not* a guarantee about the next call. To
  avoid a `is_cleared`/`get` TOCTOU (a concurrent `revoke()`/`authorize()` between two reads), both
  reads happen under one per-key transaction: `with token_store(resolver, auth_profile).transaction(key):
  cleared = t.is_cleared(key); rec = t.get(key)`. Then `CLEARED` if `cleared` else
  `classify_oauth2(rec)`. Because `status()` and a later `access_token()` are separate calls with
  separate clocks, a token near the 300s buffer edge can legitimately report `VALID` here yet trigger
  a refresh on the next `access_token()` — this is acceptable and documented, not a bug.

- `revoke() -> None`
  `with token_store(resolver, auth_profile).transaction(key): backend.delete(key)` (serialized per
  §5.1) — deletes the record and writes the tombstone, so a subsequent `status()` is `CLEARED`, not
  `MISSING`. Idempotent (delete on an absent/already-cleared key does not raise).

## 8. `OAuth1TokenManager`

`lifecycle/oauth1.py`. Same constructor trio. OAuth1 tokens (a `(token, secret)` pair) are
long-lived — no refresh/expiry — so the surface is smaller:

- `authorize(*, mode="local_server", manual_redirect_uri=None) -> TokenStatus`
  Interactive dance outside the lock via `OAuth1Flow(provider, resolver=resolver).authorize(...)`
  (callback factory resolved as in §7), then `with token_store(...).transaction(key):
  backend.set(key, {"oauth_token": ..., "oauth_token_secret": ...})`. Returns `status()`. Wholesale
  replacement (same policy as §7).
- `token_pair() -> tuple[str, str]`
  `OAuth1Flow(provider, resolver=resolver).resolve_token_pair(auth_profile)` (raises
  `AuthorizationRequired` if missing).
- `status() -> TokenStatus` — point-in-time snapshot; reads `is_cleared`+`get` under one transaction
  (§7): `CLEARED` if tombstoned, else `PRESENT` if a record exists, else `MISSING`. **OAuth1
  invariant:** the returned `TokenStatus` always has `expires_at=None`, `expires_in_seconds=None`,
  `has_refresh_token=False` (OAuth1 has no expiry/refresh); consumers must not read those as
  meaningful for OAuth1.
- `revoke() -> None` — `with token_store(...).transaction(key): backend.delete(key)` (serialized,
  idempotent).

**authlib note:** the OAuth1 *interactive* path ultimately needs the `[oauth1]` extra (authlib),
which is **not** installed in the shared dev venv. Tests for `authorize()` mock the flow's
`authorize`/`resolve_token_pair`; `status`/`revoke` use only the resolver + store and need no
authlib. (No test should require authlib to be installed.)

## 9. Error handling

- **No resolver:** the flow already raises `RuntimeError` when its resolver is `None`; the managers
  take a *required* resolver, so the None case cannot arise through a manager.
- **Capability mismatch:** `resolver.resolve_as(name, ClearableStore)` raises `CapabilityError` at
  call time if the registered store cannot clear — surfaced unchanged.
- **No usable token:** `access_token()`/`refresh()`/`token_pair()` raise `AuthorizationRequired`
  (the flow's existing exception).
- **Refresh transport failure:** the flow's existing behaviour is preserved (delete the record;
  re-raise as `AuthorizationRequired` when not auto-authorizing). The manager does not add a second
  failure path.
- `status()` and `revoke()` never raise on a missing/tombstoned record (`get` returns `None`,
  `delete` is idempotent).

## 10. Consumer migration (wearables — illustrative, lands in a separate PR)

Wearables collapses to three responsibilities:

1. **Composition root** (`config.py`): build one
   `RegistryResolver({secrets_provider: mountainash_secrets.FilesystemStore(base_dir=.../.tokens)})`.
2. **Provider registry + profile refactor**: descriptors → typed `ProviderProfile` instances; the
   materialised auth profile is given `SETTINGS_SOURCE_SECRETS_PROVIDER = secrets_provider` and
   `persist_key() -> f"{provider}.{user}"` so it satisfies `PersistableAuthProfile`.
3. **Thin facade** (`auth.py`): the public `mw.authorize/auth_status/refresh/deauthorize` **stay**
   but become ~3-line delegations — load profiles for `(provider, user)`, construct the matching
   `*TokenManager`, call `authorize(mode=...)` / `status()` / `refresh()` / `revoke()`. The deleted
   `get_store`, the `OAuthFlow(spec)` calls, and the parallel persistence are removed.

`mw.authorize(...)` returns `TokenStatus` (was the raw tokens dict) — an intentional, documented
public-API change. The store is the single source of truth for tokens; the auth profile's
`ACCESS_TOKEN`/`REFRESH_TOKEN` fields are not loaded as a token source (avoids split-brain).

## 11. Testing strategy

- **`token_store`/`PersistableAuthProfile`:** a fake auth profile + `RegistryResolver({name:
  InMemoryStore()})`; assert the returned store namespaces under `oauth.` and raises
  `CapabilityError` for a read-only store.
- **`classify_oauth2`:** table test over the five states with injected `now` and `buffer_seconds`
  (no real clock).
- **`OAuth2TokenManager`:** `RegistryResolver({name: InMemoryStore()})`; seed via
  `NamespacedStore(store, "oauth")`. Cover: `status()` across valid/refresh_needed/expired/missing/
  cleared; `revoke()` → `CLEARED`; **`revoke()` then `authorize()` → `VALID`** (asserts the §5.2
  set-clears-tombstone contract end-to-end, with `OAuthFlow.authorize` patched to return a token
  dict); `refresh()` raising when no refresh token; `access_token()` returning a seeded token;
  `authorize(mode="manual")` mapping to `ManualCallbackServer` (assert via the resolved factory, with
  `OAuthFlow.authorize` patched) and persisting through the namespace; a `persist_key()` containing
  `/` or `..` is rejected by `FilesystemStore` (assert the `ValueError`, locking the §4 key grammar).
- **`OAuth1TokenManager`:** present/missing/cleared `status()`; `revoke()`; `token_pair()` with the
  flow's `resolve_token_pair` patched; `authorize()` with the flow patched (no authlib).
- **Flow refactor:** existing §7.4 flow tests stay green unchanged (behaviour is identical; only the
  acquisition lines move into `token_store`).
- Runner: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest`;
  lint gate: `ruff` (no mypy env).

## 12. Public API

`mountainash_auth_client/__init__.py` re-exports: `OAuth2TokenManager`, `OAuth1TokenManager`,
`TokenStatus`, `TokenState`, `PersistableAuthProfile`. `token_store` stays internal (not exported).

## 13. Out of scope

- Wearables' own migration (separate PR; this spec only illustrates the consumer collapse in §10).
- Promoting `persist_key`/`SETTINGS_SOURCE_SECRETS_PROVIDER` to `ParameterSpec` fields on the auth
  schemas (the contract is typed via the Protocol; values stay consumer-supplied).
- A client-building convenience on the managers (use the connections).
- OAuth1 token rotation / refresh (the protocol has none).

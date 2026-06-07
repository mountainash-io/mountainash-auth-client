# Secrets Backend Write-Back

## Problem

mountainash-auth-client has a hand-rolled `SecretStore` protocol and
`FilesystemStore` implementation for persisting OAuth tokens. Now that auth
modes are Profile subclasses inheriting MountainAshBaseSettings, the read path
for credentials is already handled by mountainash-settings (config files, env
vars, secrets providers). But the write path (persisting tokens after OAuth
authorization or refresh) and the current `SecretsResolver` in
mountainash-settings are misaligned:

1. **`SecretsResolver` is read-only** — `Callable[[str], str]` with no write
   capability.
2. **auth-client reinvents persistence** — `FilesystemStore` duplicates what
   mountainash-settings should provide: secure file I/O, atomic writes,
   locking, namespaced storage.
3. **No path to cloud backends** — the `SecretStore` protocol is auth-client
   specific. Vault, AWS Secrets Manager, etc. would need separate integrations
   in each consuming package instead of one implementation in
   mountainash-settings.

## Scope

Two packages are in scope:

- **mountainash-settings** — replace `SecretsResolver` callable with a
  `SecretsBackend` protocol (read+write+delete+transaction), add
  `FilesystemBackend` implementation, add `persist()` method to
  `MountainAshBaseSettings`.
- **mountainash-auth-client** — delete `store/` directory, update mixins to
  use `persist()`.

Downstream package fixes (mountainash-wearables) are separate follow-up work.

## Design

### SecretsBackend protocol

Replaces `SecretsResolver = Callable[[str], str]` in mountainash-settings.

```python
@runtime_checkable
class SecretsBackend(Protocol):
    def get(self, key: str) -> dict[str, Any] | None: ...
    def set(self, key: str, data: dict[str, Any]) -> None: ...
    def delete(self, key: str) -> None: ...
    def transaction(self, key: str) -> AbstractContextManager[None]: ...
```

**Values are structured** — one key maps to one credential set (e.g. all OAuth
tokens for a provider+user). `get()` returns the full dict, `set()` writes the
full dict atomically.

**Key format:** Flat dot-separated string encoding `{domain}.{provider}.{user}`
(e.g. `"wearables.strava.default"`). The backend doesn't parse or enforce
structure, but the convention preserves multi-user support and backwards
compatibility with the current on-disk layout.

**Transactions:** `transaction(key)` is a context manager for read-modify-write
operations. The OAuth mixin acquires a transaction before reading, conditionally
refreshes, and writes — all under the same lock. Backends implement this
appropriately: filesystem uses `fcntl.flock`, cloud backends may use optimistic
concurrency or no-op if the backend provides its own atomic operations.

**`is_cleared()` is an optional extension**, not part of the core protocol.
Backends that support the "never set" vs. "explicitly cleared" distinction
implement a `ClearableBackend` protocol:

```python
@runtime_checkable
class ClearableBackend(SecretsBackend, Protocol):
    def is_cleared(self, key: str) -> bool: ...
```

Consumers that need this distinction (e.g. wearables `auth_status()`)
check `isinstance(backend, ClearableBackend)`. `delete()` on the core
protocol removes the value; whether that's tracked as "cleared" is a
backend concern.

### Scalar field resolution (backwards compatibility with resolve.py)

The existing `resolve.py` resolves `secret:some/path` references in config
files by calling `resolver(key) -> str`. This scalar resolution path is
preserved.

When a `SecretsBackend` is registered, `resolve.py` calls
`backend.get(key)` and receives a dict. For single-value secrets, the
dict contains one entry. For structured credential sets, it contains
multiple fields.

For field-level resolution (`secret:wearables.strava.default.access_token`),
`resolve.py` splits on the last dot: backend key = `"wearables.strava.default"`,
field = `"access_token"`. It calls `backend.get(key)` and plucks the field
from the returned dict.

### Registry API migration

The secrets registry migrates from callable-based to backend-based:

- `register_secrets_backend(provider, backend)` — replaces
  `register_secrets_resolver()`
- `get_secrets_backend(provider)` — replaces `get_secrets_resolver()`
- `replace_secrets_backend(provider, backend)` — replaces
  `replace_secrets_resolver()`
- `clear_secrets_registry()` — unchanged

**No deprecation shims.** The old callable-based API
(`register_secrets_resolver`, `get_secrets_resolver`,
`replace_secrets_resolver`) and `SecretsResolver` type alias are removed.
Consumers migrate to the new backend-based API directly.

### FilesystemBackend

Ported from auth-client's `FilesystemStore`, adapted to the `SecretsBackend`
protocol. Implements `ClearableBackend` (tombstone support).

**Key → path mapping:** Dot-separated keys map to filesystem paths.
`"wearables.strava.default"` → `{base_dir}/wearables/strava-default.yaml`.
The last dot-segment is the leaf, preceding segments form the directory
hierarchy. Preserves the current on-disk layout so existing credential files
aren't orphaned.

**Security:**
- Directories: 0o700
- Files: 0o600
- Symlink rejection on read
- Atomic writes via temp file + `os.replace()`

**Transactions:** `transaction(key)` acquires an exclusive `fcntl.flock` on a
`.lock` file adjacent to the credential file. The lock is held for the
duration of the context manager, covering the entire read-modify-write
sequence.

**Tombstones:** `delete()` removes the YAML file and creates a `.cleared`
marker. `is_cleared()` checks for the marker. `set()` removes it. Same
semantics as the current `FilesystemStore`.

**Storage format:** YAML (matching current behavior). The structured dict is
written as a YAML document.

### MountainAshBaseSettings.persist()

Settings instances gain a `persist()` method for writing field values back to
the registered secrets backend.

```python
def persist(self, data: dict[str, Any], *, key: str | None = None) -> None:
    """Write data to the registered secrets backend.

    Args:
        data: Dict of field names to values to persist.
        key: Backend key. If None, derived from SettingsParameters.
    """
```

**Caller specifies fields explicitly** — no default "persist everything".
The caller passes exactly the fields and values to write. This avoids
accidentally persisting non-secret configuration and keeps the API explicit.

**Key derivation:** When `key` is None, derived from the instance's stored
meta-fields: `SETTINGS_SOURCE_ENV_PREFIX` (stripped of trailing underscore,
lowercased) + `SETTINGS_CLASS_NAME` (lowercased), joined with a dot. For
example, env_prefix `"STRAVA_"` + class `OAuth2AuthCodeAuth` → key
`"strava.oauth2authcodeauth"`. Callers can override with an explicit key for
custom namespacing (e.g. `"wearables.strava.default"`).

**Backend resolution:** Uses `SETTINGS_SOURCE_SECRETS_PROVIDER` from the
instance's stored meta-fields to look up the registered `SecretsBackend`.
Raises `ValueError` if no secrets_provider is configured.

**In-memory update:** After writing to the backend, `persist()` also updates
the in-memory instance fields via `update_settings_from_dict()`. This ensures
the live instance reflects the persisted values without requiring cache
invalidation or re-construction.

### auth-client changes

**Delete `store/` directory.** `SecretStore` protocol, `FilesystemStore`, and
`store/__init__.py` are removed. The capability now lives in
mountainash-settings.

**Update mixins.** OAuth2ConnectionMixin and OAuth1ConnectionMixin drop the
`store`, `domain`, and `user` parameters. The auth settings instance knows its
identity via `SettingsParameters` and its backend via `secrets_provider`.

Before:
```python
def connect(self, profile, *, user, store, domain, auto_authorize=False):
    tokens = store.load(domain, provider, user)
    ...
    with store.lock(domain, provider, user):
        tokens = store.load(domain, provider, user)
        ...
        store.save(domain, provider, user, new_tokens)
```

After:
```python
def connect(self, profile, *, auto_authorize=False):
    auth = profile.auth
    backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
    key = auth.persist_key()  # derived from SettingsParameters
    # Tokens loaded from backend during settings construction
    ...
    with backend.transaction(key):
        current = backend.get(key)
        ...
        backend.set(key, new_tokens)
        auth.persist(new_tokens, key=key)
```

**Update public API.** Remove `FilesystemStore` and `SecretStore` from
`__init__.py` exports.

### Downstream impact (out of scope)

**mountainash-wearables:** Currently calls `store.load()`, `store.save()`,
`store.is_cleared()` directly. Migrates to using `get_secrets_backend()`
for direct backend access, or settings instances with `persist()`. The
`auth_status()` function uses `is_cleared()` which requires checking
`isinstance(backend, ClearableBackend)`.

## Migration order

1. mountainash-settings: replace `SecretsResolver` with `SecretsBackend` and
   `ClearableBackend` protocols, add `FilesystemBackend`, migrate registry API,
   remove old callable-based API, update `resolve.py` for structured values.
2. mountainash-settings: add `persist()` and `persist_key()` to
   `MountainAshBaseSettings`.
3. mountainash-auth-client: delete `store/` directory, update mixins, update
   exports, update tests.
4. (Follow-up) mountainash-wearables: migrate store usage.

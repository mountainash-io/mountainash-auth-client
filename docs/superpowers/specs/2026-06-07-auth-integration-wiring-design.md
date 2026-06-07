# Auth Integration Wiring

## Problem

The auth modes are now Profile subclasses with full mountainash-settings
capabilities (config loading, env vars, secrets providers, caching, persist).
The secrets backend is implemented. But nothing actually wires it together:

1. **No SettingsParameters created for auth modes.** Auth instances are still
   constructed with raw keyword arguments, bypassing mountainash-settings.
2. **Mixins still expect `profile.auth` nesting.** But nested pydantic models
   don't get full settings services (no `__init__` call, no secrets_provider,
   no persist). This is a pydantic-settings architectural limitation, not a
   bug.
3. **No example of how consumers load auth from config files.**

## Key Insight: Don't Nest — Separate Concerns

Pydantic constructs nested models via its validator pipeline, bypassing
`MountainAshBaseSettings.__init__`. Nested settings models lose config loading,
secret resolution, caching, and persist. Rather than fighting pydantic with
propagation hacks, **profile and auth should be separate top-level settings
instances**, each with their own `SettingsParameters`.

Both can load from the same config file (each picks its own fields via
`extra="ignore"`) or from separate files. The caller composes
`SettingsParameters` as appropriate for their deployment.

## Scope

- **mountainash-auth-client** — update mixins to receive auth as a separate
  settings instance (not `profile.auth`). Update tests.

Downstream consumer updates (mountainash-wearables `config.py`,
mountainash-data connection profiles) are separate follow-up work, but this
spec documents the intended pattern.

## Design

### Mixin signature change

Mixins currently take `profile` and access `profile.auth`. They change to
take `auth` directly as a separate parameter — a top-level Profile subclass
with full settings services.

Before:
```python
def connect(self, profile, *, auto_authorize=False):
    auth = profile.auth
    backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
    ...
```

After:
```python
def connect(self, auth, *, auto_authorize=False):
    backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
    key = auth.persist_key()
    tokens = backend.get(key)
    ...
    auth.persist({"ACCESS_TOKEN": ...})
```

The mixin no longer knows about profiles. It receives an auth settings
instance and works with it directly.

### Intended consumer pattern

This is how downstream packages (wearables, mountainash-data) create and
use profile + auth. This is documented here for reference — implementation
is out of scope for this spec.

```python
# wearables/connections/config.py

def load_connection(provider, user="default", *, config_dir=None,
                    secrets_provider=None, **kwargs):
    base = config_dir or _config.config_dir
    config_file = str(base / f"{provider}-{user}.yaml")
    secrets = secrets_provider or _config.secrets_provider

    profile_cls = WEARABLES.get_settings_class(provider)
    auth_cls = get_auth_class(provider)  # from AUTH_REGISTRY or descriptor

    profile_params = SettingsParameters.create(
        settings_class=profile_cls,
        config_files=[config_file],
        secrets_provider=secrets,
    )
    auth_params = SettingsParameters.create(
        settings_class=auth_cls,
        config_files=[config_file],
        secrets_provider=secrets,
    )

    profile = get_settings(settings_parameters=profile_params)
    auth = get_settings(settings_parameters=auth_params)
    return profile, auth
```

Both profile and auth load from the same YAML file. Each takes the fields
it knows about. Unknown fields are ignored (`extra="ignore"` on
MountainAshBaseSettings).

Example YAML (`~/.config/mountainash/wearables/strava-default.yaml`):
```yaml
# Profile fields
BASE_URL: https://www.strava.com/api/v3

# Auth fields (OAuth2AuthCodeAuth)
CLIENT_ID: "12345"
CLIENT_SECRET: "secret:wearables.strava.default.client_secret"
SCOPE: "read,activity:read_all"
```

### Auth mode lookup

The AUTH_REGISTRY in auth-client enables dynamic lookup of auth classes by
name via `AUTH_REGISTRY.get_settings_class(name)`. The `get_auth_class()`
helper shown in the consumer pattern is domain-defined — each domain
determines how to map a provider name to an auth class (e.g. from profile
spec metadata, a domain-specific registry, or a hardcoded mapping).

### What changes in auth-client

**Mixins:** `OAuth2ConnectionMixin.connect()` and
`OAuth1ConnectionMixin.connect()` change signature from
`connect(self, profile, ...)` to `connect(self, auth, ...)`.

`OAuth1ConnectionMixin._build_client(tokens, profile)` also changes to
`_build_client(tokens, auth)` — it currently accesses `profile.auth` to
get consumer key/secret, which becomes just `auth` directly.

Note: both mixins still access `self._spec.name` for provider name in
error messages. `_spec` is a ClassVar on the concrete connection class
(e.g. `StravaConnection`), not on the auth model. This dependency is
unchanged.

**Tests:** Mixin tests update to pass auth directly instead of wrapping in
a FakeProfile.

**No other changes.** The schemas, registry, and public API are unchanged.

## Migration order

1. mountainash-auth-client: update mixin signatures and tests.
2. (Follow-up) mountainash-wearables: update `config.py` and connection
   classes to create separate profile + auth SettingsParameters.
3. (Follow-up) mountainash-data: same pattern for connection profiles.

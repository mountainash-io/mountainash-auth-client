# SettingsParameters Pattern: Flow Depth and Materialisation

> Discussion paper — not a spec. Captures the architectural pattern for how
> `SettingsParameters` should be used with auth modes, and addresses the
> central design question: how deep should the parameters flow, and when
> should settings be materialised?

## Context

mountainash-auth-client's auth modes are now Profile subclasses backed by
mountainash-settings. The mixins receive `auth` as a top-level settings
instance — not nested inside a profile. But the specs don't address how
that `auth` instance gets created, or what flows through the system to
create it.

This paper documents the intended pattern, drawing from how
SettingsParameters is already used in mountainash-data, mountainash-utils-secrets,
and mountainash-utils-files.

## The Two Objects

**SettingsParameters** — a frozen dataclass that describes *how* to load
settings. It carries: `settings_class`, `config_files`, `env_prefix`,
`secrets_provider`, and runtime `kwargs`. It's hashable (excluding kwargs)
so the settings cache can deduplicate.

**The materialised settings instance** — the actual MountainAshBaseSettings
subclass, created by `get_settings(settings_parameters=params)`. This is
the live object with resolved values, secret references expanded, config
files merged, environment variables applied.

```
SettingsParameters  ──get_settings()──►  MountainAshBaseSettings instance
   (recipe)                                    (the meal)
```

## The Central Question: Flow vs Materialise

There are two strategies for getting settings to where they're needed:

### Strategy A: Flow parameters, materialise late

Pass `SettingsParameters` down the call chain. Each layer that needs the
settings calls `get_settings()` itself. The caller controls *what* gets
loaded; the callee controls *when*.

```python
# Entry point creates the recipe
auth_params = SettingsParameters.create(
    settings_class=OAuth2AuthCodeAuth,
    config_files=[config_file],
    secrets_provider="filesystem",
)

# Passes the recipe down
connection = StravaConnection(auth_params=auth_params)

# Connection materialises when it needs the values
class StravaConnection(OAuth2ConnectionMixin):
    def connect(self, auth_params, *, auto_authorize=False):
        auth = get_settings(settings_parameters=auth_params)
        backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
        ...
```

**Advantages:**
- Caller doesn't need to know when settings are needed
- Settings are always fresh at point of use (cache handles dedup)
- Easy to serialise/pass across boundaries (SettingsParameters is a simple dataclass)
- Consistent with mountainash-data's `BaseDBConnection(db_auth_settings_parameters=...)`

**Disadvantages:**
- Every layer needs to import `get_settings`
- The callee needs to understand SettingsParameters, not just the settings values
- Harder to test — need to set up config files/env/backends even in unit tests

### Strategy B: Materialise early, flow the instance

The entry point calls `get_settings()` and passes the live settings object.
Downstream code just uses the values.

```python
# Entry point creates AND materialises
auth_params = SettingsParameters.create(
    settings_class=OAuth2AuthCodeAuth,
    config_files=[config_file],
    secrets_provider="filesystem",
)
auth = get_settings(settings_parameters=auth_params)

# Passes the live instance
connection = StravaConnection()
connection.connect(auth=auth, auto_authorize=True)

# Connection just uses values
class StravaConnection(OAuth2ConnectionMixin):
    def connect(self, auth, *, auto_authorize=False):
        backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
        ...
```

**Advantages:**
- Downstream code is simpler — it receives values, not recipes
- Easy to test — just construct the settings object directly with kwargs
- Library code (auth-client) stays ignorant of SettingsParameters
- Clear separation: application code creates settings, library code uses them

**Disadvantages:**
- Caller must materialise at the right time
- If settings need refreshing, the caller must handle it
- Passing mutable objects deep into the stack can make data flow harder to trace

### Strategy C: Accept both (mountainash-data pattern)

Some mountainash-data components accept either form:

```python
class IbisBackend:
    def __init__(self, settings_params_or_url, **kwargs):
        if isinstance(settings_params_or_url, SettingsParameters):
            self._init_from_settings(settings_params_or_url)
        elif isinstance(settings_params_or_url, str):
            self._init_from_url(settings_params_or_url)
        else:
            self._init_from_kwargs(**kwargs)
```

This adds flexibility at the cost of complexity. It suits gateway
components that serve multiple audiences (deployment, testing, scripting).

## Recommendation for Auth

**Strategy B: materialise early, flow the instance.** Here's why:

### Auth-client is a library, not an application

Auth-client defines schemas (Profile subclasses) and mixins
(OAuth2ConnectionMixin, OAuth1ConnectionMixin). It doesn't know about
deployment topology, config file locations, or which secrets provider
is in use. That's application-level concern.

The mixins should receive a materialised auth settings instance and
work with its values. They shouldn't need to understand *how* the
instance was created.

### The materialisation boundary is the consumer's entry point

Each consumer (mountainash-wearables, mountainash-data) has its own
entry point where connections are created. This is where
SettingsParameters lives:

```python
# mountainash-wearables/connections/config.py

def load_connection(provider, user="default", *, config_dir=None,
                    secrets_provider=None):
    base = config_dir or _config.config_dir
    config_file = str(base / f"{provider}-{user}.yaml")
    secrets = secrets_provider or _config.secrets_provider

    profile_cls = WEARABLES_REGISTRY.get_settings_class(provider)
    auth_cls = AUTH_REGISTRY.get_settings_class(provider)

    profile_params = SettingsParameters.create(
        settings_class=profile_cls,
        config_files=[config_file],
        secrets_provider=secrets,
    )
    auth_params = SettingsParameters.create(
        settings_class=auth_cls,
        config_files=[config_file],  # same file, each picks its own fields
        secrets_provider=secrets,
    )

    profile = get_settings(settings_parameters=profile_params)
    auth = get_settings(settings_parameters=auth_params)
    return profile, auth
```

Then downstream:

```python
profile, auth = load_connection("strava")
connection = StravaConnection()
connection.connect(auth=auth, auto_authorize=True)
```

### Testing stays simple

Unit tests construct auth directly without config files:

```python
def test_connect_with_valid_token(backend):
    auth = FakeAuth()  # or OAuth2AuthCodeAuth(CLIENT_ID="x", ...)
    provider = FakeProvider()
    provider.connect(auth)
```

Integration tests use SettingsParameters:

```python
def test_connect_from_config(tmp_path):
    config = tmp_path / "strava-default.yaml"
    config.write_text("CLIENT_ID: '12345'\nSCOPE: 'read'\n")

    params = SettingsParameters.create(
        settings_class=OAuth2AuthCodeAuth,
        config_files=[str(config)],
        secrets_provider="filesystem",
    )
    auth = get_settings(settings_parameters=params)
    # ... test with real settings loading
```

### persist() works because the instance carries its own backend reference

A materialised MountainAshBaseSettings instance knows its own
`SETTINGS_SOURCE_SECRETS_PROVIDER`. When the mixin calls
`auth.persist(data)` or `get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)`,
the instance already has everything it needs. No SettingsParameters
required at that point.

## When Strategy A (late materialisation) IS right

Late materialisation suits components that:

- **Hold long-lived references** where settings might change between uses
  (e.g., a connection pool that reconnects with refreshed credentials)
- **Cross serialisation boundaries** (e.g., passing config to a subprocess
  or remote worker — SettingsParameters serialises cleanly, live objects don't)
- **Serve as gateway objects** that need to support multiple creation patterns
  (the IbisBackend case)

Auth connections don't fit these patterns. A `connect()` call is a
point-in-time operation that uses the settings once.

## Summary

| Concern | Owner | Object |
|---|---|---|
| Which auth class to use | Consumer (wearables, data) | Registry lookup |
| Where config files live | Consumer entry point | SettingsParameters |
| Which secrets provider | Consumer entry point | SettingsParameters |
| Creating the settings instance | Consumer entry point | `get_settings()` |
| Using auth values | Auth-client mixins | Materialised instance |
| Persisting tokens | Auth-client mixins | `auth.persist()` / backend |

The SettingsParameters pattern flows exactly one layer deep in auth's
case: from the consumer's configuration layer to `get_settings()`. After
that, the materialised instance flows to the mixins. Auth-client never
sees SettingsParameters.

## Example: Full Stack

```yaml
# ~/.config/mountainash/wearables/strava-default.yaml

# Profile fields (picked up by StravaProfile)
BASE_URL: https://www.strava.com/api/v3

# Auth fields (picked up by OAuth2AuthCodeAuth)
CLIENT_ID: "12345"
CLIENT_SECRET: "secret:wearables.strava.client_secret"
SCOPE: "read,activity:read_all"
```

```python
# Consumer entry point — creates SettingsParameters, materialises settings
profile, auth = load_connection("strava", user="default")

# Auth-client mixin — receives materialised instance, uses values
with StravaConnection() as conn:
    conn.connect(auth=auth, auto_authorize=True)
    activities = conn.get_activities()
```

```python
# Under the hood: mixin uses auth values and persist
class StravaConnection(OAuth2ConnectionMixin):
    # connect() receives `auth` — a live settings instance
    # It reads auth.CLIENT_ID, auth.CLIENT_SECRET, auth.SCOPE
    # It calls get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
    # It calls auth.persist_key() for token storage key
    # It calls backend.set(key, tokens) to persist refreshed tokens
    pass
```

SettingsParameters exists only in `load_connection()`. Everything
downstream works with materialised values.

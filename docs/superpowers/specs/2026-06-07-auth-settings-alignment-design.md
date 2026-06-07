# Auth-Client Alignment with mountainash-settings

## Problem

mountainash-auth-client was extracted from mountainash-settings as a straight
copy of raw pydantic BaseModel subclasses. The extraction missed the opportunity
to align with the ProfileSpec/Profile/Registry patterns that mountainash-settings
provides. As a result:

1. **AuthSpec subclasses raw `pydantic.BaseModel`** instead of using Profile with
   ParameterSpec-driven field installation.
2. **`dispatch.py` reinvents `_default_kwargs()`** — manually mapping auth fields
   to driver kwargs with per-type handler functions, duplicating what
   `ParameterSpec.driver_key` + `Profile._default_kwargs()` do automatically.
3. **No config-file, env-var, or secrets-provider support** — auth credentials
   can only be passed programmatically, bypassing the caching and configuration
   first principles of mountainash-settings.
4. **No Registry** — auth modes cannot be looked up dynamically by name.
5. **`ProfileSpec.auth_modes` is domain-specific coupling** baked into the
   generic Profile base. Auth is a domain concern (connections), not a generic
   profile concern. The `provider_type` field already serves the identification
   purpose.

Additionally, mountainash-data's imports from the deleted
`mountainash_settings.auth` module are broken on develop.

## Scope

Two packages are in scope for this spec:

- **mountainash-settings** — remove `auth_modes` from ProfileSpec and the auth
  union assembly from `Profile.__pydantic_init_subclass__`.
- **mountainash-auth-client** — migrate auth modes to Profile subclasses with
  ProfileSpecs, registered in an AUTH_REGISTRY.

Downstream package fixes (mountainash-data, mountainash-utils-files,
mountainash-wearables) are separate follow-up work.

## Design

### mountainash-settings changes

#### Remove `auth_modes` from ProfileSpec

`ProfileSpec.auth_modes: list[type]` is removed. It was domain-specific coupling
that assumed every profile needs auth modes. Domains that need auth (connections)
handle it as their own concern — e.g. a `ConnectionSpec` subclass of ProfileSpec
that adds an auth field, or a separate field on their Profile subclasses.

**File:** `src/mountainash_settings/profiles/spec.py`

Before:
```python
@dataclass(frozen=True, kw_only=True)
class ProfileSpec:
    name: str
    provider_type: t.Any
    parameters: list[ParameterSpec]
    auth_modes: list[type]
    metadata: dict[str, t.Any] = field(default_factory=dict)
```

After:
```python
@dataclass(frozen=True, kw_only=True)
class ProfileSpec:
    name: str
    provider_type: t.Any
    parameters: list[ParameterSpec]
    metadata: dict[str, t.Any] = field(default_factory=dict)
```

#### Remove auth union assembly from Profile

`Profile.__pydantic_init_subclass__` currently reads `spec.auth_modes` and
builds a discriminated union `auth` field (lines 114-127 of `profile.py`). This
block is removed entirely. Profile becomes purely about ParameterSpec-driven
field installation.

**File:** `src/mountainash_settings/profiles/profile.py`

Remove the block:
```python
# 2. auth field as discriminated union of spec.auth_modes
if spec.auth_modes:
    auth_union: t.Any
    if len(spec.auth_modes) == 1:
        auth_union = spec.auth_modes[0]
        auth_info = FieldInfo(annotation=auth_union, default=...)
    else:
        auth_union = t.Union[tuple(spec.auth_modes)]
        auth_info = FieldInfo(
            annotation=auth_union,
            default=...,
            discriminator="kind",
        )
    new_fields["auth"] = (auth_union, auth_info)
```

#### Update invariants

`spec_invariants_for()` in `profiles/invariants.py` currently checks that
`auth_modes` is non-empty. This invariant is removed along with any other
`auth_modes` references.

#### No other changes needed

Registry, ParameterSpec, `_default_kwargs()`, config loading, caching,
`MountainAshBaseSettings` — all already work and are reused as-is.

### mountainash-auth-client changes

#### Add mountainash-settings dependency

`pyproject.toml` gains `mountainash-settings` as a dependency.

#### AUTH_REGISTRY

A `Registry("auth")` instance in auth-client. All auth mode Profile subclasses
are registered here, enabling dynamic lookup by name.

```python
from mountainash_settings import Registry

AUTH_REGISTRY = Registry("auth")
register = AUTH_REGISTRY.decorator()
```

#### Auth modes become Profile subclasses with ProfileSpecs

Each auth mode declares a ProfileSpec with ParameterSpecs and a Profile subclass
registered in the AUTH_REGISTRY. Fields are installed automatically by
`Profile.__pydantic_init_subclass__`. Driver-kwargs mapping is handled by
`_default_kwargs()` via `ParameterSpec.driver_key`.

Example — NoAuth:

```python
from mountainash_settings import Profile, ProfileSpec

NOAUTH_SPEC = ProfileSpec(
    name="none",
    provider_type="none",
    parameters=[],
)

@register
class NoAuth(Profile):
    __spec__ = NOAUTH_SPEC
```

Example — PasswordAuth:

```python
from mountainash_settings import Profile, ProfileSpec, ParameterSpec

PASSWORD_SPEC = ProfileSpec(
    name="password",
    provider_type="password",
    parameters=[
        ParameterSpec(
            name="USERNAME", type=str, tier="core",
            driver_key="user",
        ),
        ParameterSpec(
            name="PASSWORD", type=str, tier="core",
            driver_key="password", secret=True,
        ),
    ],
)

@register
class PasswordAuth(Profile):
    __spec__ = PASSWORD_SPEC
```

Example — OAuth2Auth:

```python
from mountainash_settings import Profile, ProfileSpec, ParameterSpec

OAUTH2_SPEC = ProfileSpec(
    name="oauth2",
    provider_type="oauth2",
    parameters=[
        ParameterSpec(name="CLIENT_ID",     type=str | None, tier="core",     driver_key="client_id",     default=None),
        ParameterSpec(name="CLIENT_SECRET", type=str | None, tier="core",     driver_key="client_secret", default=None, secret=True),
        ParameterSpec(name="TOKEN",         type=str | None, tier="core",     driver_key="token",         default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="advanced",                             default=None, secret=True),
        ParameterSpec(name="SERVER_URI",    type=str | None, tier="advanced",                             default=None),
        ParameterSpec(name="SCOPE",         type=str | None, tier="advanced",                             default=None),
    ],
)

@register
class OAuth2Auth(Profile):
    __spec__ = OAUTH2_SPEC
```

All 13 auth modes follow this pattern:
NoAuth, PasswordAuth, TokenAuth, JWTAuth, OAuth1Auth, OAuth2Auth,
OAuth2AuthCodeAuth, IAMAuth, WindowsAuth, AzureADAuth, KerberosAuth,
CertificateAuth, ServiceAccountAuth.

#### Delete dispatch.py

`AUTH_TO_DRIVER_KWARGS`, `auth_to_driver_kwargs()`, and `auth_kwargs()` are
deleted. `Profile._default_kwargs()` handles driver-key mapping, SecretStr
unwrapping, and transforms — all driven by ParameterSpec metadata.

#### Delete schemas/base.py

The `AuthSpec(BaseModel)` base class is removed. Auth modes are Profile
subclasses, not BaseModel subclasses.

#### Restructure schemas directory

Each auth mode file declares its ProfileSpec + Profile subclass.
`schemas/__init__.py` exports from the Registry and re-exports the classes.

#### Model config considerations

The current AuthSpec uses `ConfigDict(extra="forbid", frozen=True)` —
immutable instances that reject unknown fields. MountainAshBaseSettings uses
`ConfigDict(extra="ignore", validate_assignment=True)` — tolerant of extra
fields from config sources, mutable with revalidation.

Auth mode Profile subclasses inherit the looser MountainAshBaseSettings
defaults. This is correct: config files often serve multiple purposes and may
contain fields not relevant to auth, so `extra="ignore"` is appropriate.
The `frozen` constraint is unnecessary — mountainash-settings loads just in
time and runtime kwargs override via `model_copy()`, not mutation.

#### Runtime behavior unchanged

These modules stay as-is (they consume auth mode instances, which are now
Profile subclasses but expose the same fields):

- **Mixins:** `OAuth2ConnectionMixin`, `OAuth1ConnectionMixin`
- **Flows:** `OAuthFlow`, `OAuth1Flow`
- **Storage:** `SecretStore` (protocol), `FilesystemStore`
- **Server:** `LocalCallbackServer`
- **Errors:** `AuthorizationRequired`, `TokenExchangeError`, `TokenRefreshError`

The mixins access fields like `auth.client_id`, `auth.client_secret` etc.
These fields still exist — they're just installed by ParameterSpec now instead
of being hand-coded. Field names change from lowercase (`client_id`) to
uppercase (`CLIENT_ID`) per mountainash-settings convention. Mixins update
their attribute access accordingly.

#### Tests

- `spec_invariants_for(AUTH_REGISTRY)` provides automatic structural validation
  for all registered auth modes.
- Existing behavioral tests (flows, mixins, storage, server, errors) adapt to
  the new field names (uppercase).
- Schema tests rewritten to test Profile subclass construction and
  `_default_kwargs()` output.

### Downstream impact (out of scope, noted for context)

**mountainash-data:** Broken on develop (imports from deleted
`mountainash_settings.auth`). Needs to import auth types from
`mountainash_auth_client`, remove `auth_modes` from its BackendSpec, and handle
auth as a domain concern.

**mountainash-utils-files:** Same pattern — imports move to
`mountainash_auth_client`, auth field becomes a domain concern.

**mountainash-wearables:** Already imports from `mountainash_auth_client`. Adapts
to uppercase field names.

## Migration order

1. mountainash-settings: remove `auth_modes` from ProfileSpec, remove auth union
   assembly from Profile, update invariants.
2. mountainash-auth-client: add mountainash-settings dependency, migrate all auth
   modes to Profile subclasses with ProfileSpecs, create AUTH_REGISTRY, delete
   dispatch.py and base.py, update tests.
3. (Follow-up) Downstream packages: fix broken imports, handle auth as domain
   concern.

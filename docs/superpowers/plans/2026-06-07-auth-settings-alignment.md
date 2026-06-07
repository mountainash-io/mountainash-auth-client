# Auth-Client Settings Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate mountainash-auth-client from raw pydantic BaseModel subclasses to mountainash-settings Profile/ProfileSpec/Registry patterns, and remove domain-specific `auth_modes` coupling from mountainash-settings.

**Architecture:** Two packages change. mountainash-settings loses `auth_modes` from ProfileSpec and the auth union assembly from Profile. mountainash-auth-client gains a mountainash-settings dependency, replaces all AuthSpec subclasses with Profile subclasses backed by ProfileSpecs, creates an AUTH_REGISTRY, and deletes the manual dispatch layer.

**Tech Stack:** Python 3.11+, pydantic v2, mountainash-settings (ProfileSpec, ParameterSpec, Profile, Registry, spec_invariants_for)

---

### Task 1: Remove `auth_modes` from mountainash-settings ProfileSpec

This task modifies mountainash-settings to remove the domain-specific `auth_modes` field from ProfileSpec, the auth union assembly from Profile, and the auth invariant from spec_invariants_for.

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/profiles/spec.py:82-102`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/profiles/profile.py:86-133`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/profiles/invariants.py:75-84`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/fixtures/auth_stubs.py` (delete file)
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/profiles/test_spec.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/profiles/test_profile.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/profiles/test_registry.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/profiles/test_invariants.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/profiles/test_deprecation.py`

- [ ] **Step 1: Remove `auth_modes` from ProfileSpec dataclass**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/profiles/spec.py`, remove the `auth_modes` field and its docstring reference:

```python
@dataclass(frozen=True, kw_only=True)
class ProfileSpec:
    """Immutable specification of a single settings profile.

    Attributes:
        name: Short name (conventionally lowercase, e.g. ``"postgresql"``).
        provider_type: Canonical provider identifier (domain-specific enum).
        parameters: Ordered list of :class:`ParameterSpec`.
        metadata: Bag of domain-specific metadata (e.g. port, URL scheme,
            dialect name). Domains wanting strong typing may subclass
            ``ProfileSpec`` and add typed fields instead.

    Public from 26.5.0. Previously named ``ProfileDescriptor``.
    """

    name: str
    provider_type: t.Any
    parameters: list[ParameterSpec]
    metadata: dict[str, t.Any] = field(default_factory=dict)
```

- [ ] **Step 2: Remove auth union assembly from Profile.__pydantic_init_subclass__**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/profiles/profile.py`, remove lines 114-127 (the `# 2. auth field as discriminated union` block). The method should go from installing spec parameters straight to writing `new_fields` into `model_fields`:

```python
@classmethod
def __pydantic_init_subclass__(cls, **kwargs: t.Any) -> None:
    """Install fields described by ``__spec__`` on the subclass."""
    super().__pydantic_init_subclass__(**kwargs)
    spec = _resolve_spec(cls)
    if spec is None:
        return  # intermediate subclass without its own spec

    new_fields: dict[str, tuple[t.Any, FieldInfo]] = {}

    # Spec parameters -> pydantic fields
    for param in spec.parameters:
        ptype: t.Any = SecretStr if param.secret else param.type
        if param.validator is not None:
            ptype = t.Annotated[ptype, AfterValidator(param.validator)]
        if param.default is MISSING:
            info = FieldInfo(
                annotation=ptype,
                default=...,
                description=param.description,
            )
        else:
            info = FieldInfo(
                annotation=ptype,
                default=param.default,
                description=param.description,
            )
        new_fields[param.name] = (ptype, info)

    for name, (annotation, info) in new_fields.items():
        cls.model_fields[name] = info
        cls.__annotations__[name] = annotation

    cls.model_rebuild(force=True)
```

Also update the module docstring at the top of profile.py to remove the auth-union reference. Replace:
```
pydantic v2's ``__pydantic_init_subclass__`` hook to materialize the spec
into pydantic fields and compose the :class:`AuthSpec` union into the
``auth`` field.
```
With:
```
pydantic v2's ``__pydantic_init_subclass__`` hook to materialize the spec
into pydantic fields.
```

Also remove from the class docstring:
```
        - :meth:`_auth_kwargs` — default auth dispatch (consumers may override).
```

- [ ] **Step 3: Remove auth invariant from spec_invariants_for**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/profiles/invariants.py`, delete the `test_auth_modes_nonempty` method (lines 75-78) and the commented-out `test_auth_modes_are_authspec` method (lines 80-84).

- [ ] **Step 4: Delete auth_stubs.py**

Delete `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/fixtures/auth_stubs.py` — these stubs exist only to provide fake auth types for `auth_modes`; they're no longer needed.

- [ ] **Step 5: Update mountainash-settings tests — remove all `auth_modes=` arguments**

Every ProfileSpec construction in the test files passes `auth_modes=[NoAuth]` or `auth_modes=[NoAuth, PasswordAuth]`. Remove all `auth_modes=` keyword arguments and any imports of `NoAuth`/`PasswordAuth`/`StubNoAuth`/`StubPasswordAuth` from auth_stubs.

Files to update (search and remove `auth_modes=...` from each ProfileSpec construction):
- `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/profiles/test_spec.py`
- `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/profiles/test_profile.py`
- `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/profiles/test_registry.py`
- `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/profiles/test_invariants.py`
- `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/profiles/test_deprecation.py`

Also in test_profile.py, remove any test that specifically tests auth field assembly (e.g. tests that assert `auth` is a field on the Profile, or tests that construct a Profile with `auth=StubNoAuth()`). The profile tests for parameter installation, templates, and _default_kwargs should still work — they don't depend on auth.

Also in test_spec.py, remove the assertion `assert spec.auth_modes == [NoAuth]`.

- [ ] **Step 6: Run mountainash-settings tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick`
Expected: All tests pass. Any test that referenced auth_modes should have been cleaned up in step 5.

- [ ] **Step 7: Commit mountainash-settings changes**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings
git add src/mountainash_settings/profiles/spec.py \
        src/mountainash_settings/profiles/profile.py \
        src/mountainash_settings/profiles/invariants.py \
        tests/
git commit -m "refactor: remove auth_modes from ProfileSpec

auth_modes was domain-specific coupling baked into the generic Profile
base. Auth is a domain concern (connections), not a generic profile
concern. The provider_type field already serves identification.

Downstream packages handle auth as their own domain concern."
```

---

### Task 2: Add mountainash-settings dependency to auth-client

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/pyproject.toml:27-31`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/hatch.toml:37-42`

- [ ] **Step 1: Add mountainash-settings to pyproject.toml dependencies**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/pyproject.toml`, add mountainash-settings to the dependencies list:

```python
dependencies = [
    "pydantic>=2.9.0",
    "httpx>=0.27.0",
    "pyaml",
    "mountainash-settings",
]
```

- [ ] **Step 2: Add mountainash-settings to hatch test dependencies**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/hatch.toml`, add mountainash-settings to the test env dependencies. Since mountainash-settings is a local sibling package, add a direct reference:

```toml
[envs.test]
type = "virtual"
installer = "uv"
dependencies = [
    "coverage[toml]>=6.5",
    "pytest>=8.0",
    "pytest-cov>=4.1.0",
    "pytest-timeout>=2.1.0",
    "mountainash-settings @ {root:uri}/../mountainash-settings",
]
```

- [ ] **Step 3: Verify import works**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:python -c "from mountainash_settings import Profile, ProfileSpec, ParameterSpec, Registry, spec_invariants_for; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add pyproject.toml hatch.toml
git commit -m "chore: add mountainash-settings dependency"
```

---

### Task 3: Create AUTH_REGISTRY and migrate NoAuth + PasswordAuth

Start with the two simplest auth modes to establish the pattern. Create the registry module and rewrite the first two auth modes as Profile subclasses with ProfileSpecs.

**Files:**
- Create: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/registry.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/none.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/password.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`

- [ ] **Step 1: Write test for AUTH_REGISTRY and NoAuth Profile**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`, replace the existing test content with:

```python
"""Tests for auth mode Profile subclasses."""
from __future__ import annotations

from mountainash_auth_client.schemas.registry import AUTH_REGISTRY


class TestAuthRegistry:
    def test_noauth_registered(self):
        assert "none" in AUTH_REGISTRY

    def test_noauth_lookup_by_name(self):
        cls = AUTH_REGISTRY.get_settings_class("none")
        instance = cls()
        assert instance.profile_name == "none"

    def test_noauth_default_kwargs_empty(self):
        cls = AUTH_REGISTRY.get_settings_class("none")
        instance = cls()
        assert instance._default_kwargs() == {}


class TestPasswordAuth:
    def test_registered(self):
        assert "password" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("password")
        instance = cls(USERNAME="alice", PASSWORD="hunter2")
        assert instance.USERNAME == "alice"
        assert instance.profile_name == "password"

    def test_default_kwargs(self):
        cls = AUTH_REGISTRY.get_settings_class("password")
        instance = cls(USERNAME="alice", PASSWORD="hunter2")
        result = instance._default_kwargs()
        assert result["user"] == "alice"
        assert result["password"] == "hunter2"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py -v`
Expected: FAIL — `mountainash_auth_client.schemas.registry` does not exist yet.

- [ ] **Step 3: Create registry.py**

Create `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/registry.py`:

```python
"""Auth mode registry — all auth Profile subclasses register here."""
from mountainash_settings import Registry

AUTH_REGISTRY = Registry("auth")
register = AUTH_REGISTRY.decorator()
```

- [ ] **Step 4: Rewrite none.py as Profile subclass**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/none.py`:

```python
"""The 'no authentication' variant."""
from mountainash_settings import Profile, ProfileSpec

from .registry import register

__all__ = ["NoAuth", "NOAUTH_SPEC"]

NOAUTH_SPEC = ProfileSpec(
    name="none",
    provider_type="none",
    parameters=[],
)


@register
class NoAuth(Profile):
    __spec__ = NOAUTH_SPEC
```

- [ ] **Step 5: Rewrite password.py as Profile subclass**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/password.py`:

```python
"""Classic username + password authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["PasswordAuth", "PASSWORD_SPEC"]

PASSWORD_SPEC = ProfileSpec(
    name="password",
    provider_type="password",
    parameters=[
        ParameterSpec(
            name="USERNAME",
            type=str,
            tier="core",
            driver_key="user",
        ),
        ParameterSpec(
            name="PASSWORD",
            type=str,
            tier="core",
            driver_key="password",
            secret=True,
        ),
    ],
)


@register
class PasswordAuth(Profile):
    __spec__ = PASSWORD_SPEC
```

- [ ] **Step 6: Run tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py -v`
Expected: All tests in TestAuthRegistry and TestPasswordAuth pass.

- [ ] **Step 7: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/schemas/registry.py \
        src/mountainash_auth_client/schemas/none.py \
        src/mountainash_auth_client/schemas/password.py \
        tests/test_schemas.py
git commit -m "feat: AUTH_REGISTRY + NoAuth/PasswordAuth as Profile subclasses"
```

---

### Task 4: Migrate TokenAuth and JWTAuth

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/token.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`

- [ ] **Step 1: Add tests for TokenAuth and JWTAuth**

Append to `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`:

```python
class TestTokenAuth:
    def test_registered(self):
        assert "token" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("token")
        instance = cls(TOKEN="my-bearer-token")
        assert instance.profile_name == "token"

    def test_default_kwargs(self):
        cls = AUTH_REGISTRY.get_settings_class("token")
        instance = cls(TOKEN="my-bearer-token")
        result = instance._default_kwargs()
        assert result["token"] == "my-bearer-token"


class TestJWTAuth:
    def test_registered(self):
        assert "jwt" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("jwt")
        instance = cls(TOKEN="eyJhbGciOi...")
        assert instance.profile_name == "jwt"

    def test_default_kwargs(self):
        cls = AUTH_REGISTRY.get_settings_class("jwt")
        instance = cls(TOKEN="eyJhbGciOi...")
        result = instance._default_kwargs()
        assert result["token"] == "eyJhbGciOi..."
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py::TestTokenAuth -v`
Expected: FAIL — "token" not in AUTH_REGISTRY.

- [ ] **Step 3: Rewrite token.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/token.py`:

```python
"""Bearer-token and JWT authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["TokenAuth", "JWTAuth", "TOKEN_SPEC", "JWT_SPEC"]

TOKEN_SPEC = ProfileSpec(
    name="token",
    provider_type="token",
    parameters=[
        ParameterSpec(
            name="TOKEN",
            type=str,
            tier="core",
            driver_key="token",
            secret=True,
        ),
    ],
)


@register
class TokenAuth(Profile):
    __spec__ = TOKEN_SPEC


JWT_SPEC = ProfileSpec(
    name="jwt",
    provider_type="jwt",
    parameters=[
        ParameterSpec(
            name="TOKEN",
            type=str,
            tier="core",
            driver_key="token",
            secret=True,
        ),
    ],
)


@register
class JWTAuth(Profile):
    __spec__ = JWT_SPEC
```

- [ ] **Step 4: Run tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/schemas/token.py tests/test_schemas.py
git commit -m "feat: migrate TokenAuth/JWTAuth to Profile subclasses"
```

---

### Task 5: Migrate OAuth2Auth and OAuth2AuthCodeAuth

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/oauth2.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/oauth2_authcode.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`

- [ ] **Step 1: Add tests for OAuth2Auth and OAuth2AuthCodeAuth**

Append to `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`:

```python
class TestOAuth2Auth:
    def test_registered(self):
        assert "oauth2" in AUTH_REGISTRY

    def test_construction_with_token(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls(TOKEN="access-tok")
        assert instance.profile_name == "oauth2"

    def test_default_kwargs_token(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls(TOKEN="access-tok")
        result = instance._default_kwargs()
        assert result["token"] == "access-tok"

    def test_default_kwargs_client_credentials(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls(CLIENT_ID="cid", CLIENT_SECRET="csec")
        result = instance._default_kwargs()
        assert result["client_id"] == "cid"
        assert result["client_secret"] == "csec"

    def test_all_fields_optional(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls()
        assert instance._default_kwargs() == {}


class TestOAuth2AuthCodeAuth:
    def test_registered(self):
        assert "oauth2_authcode" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2_authcode")
        instance = cls(CLIENT_ID="cid", CLIENT_SECRET="csec")
        assert instance.profile_name == "oauth2_authcode"

    def test_with_tokens(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2_authcode")
        instance = cls(
            CLIENT_ID="cid",
            CLIENT_SECRET="csec",
            ACCESS_TOKEN="at",
            REFRESH_TOKEN="rt",
            TOKEN_EXPIRES_AT=9999,
            SCOPE="read write",
        )
        assert instance.SCOPE == "read write"
        assert instance.TOKEN_EXPIRES_AT == 9999
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py::TestOAuth2Auth -v`
Expected: FAIL — "oauth2" not in AUTH_REGISTRY.

- [ ] **Step 3: Rewrite oauth2.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/oauth2.py`:

```python
"""OAuth2 client-credentials / token authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["OAuth2Auth", "OAUTH2_SPEC"]

OAUTH2_SPEC = ProfileSpec(
    name="oauth2",
    provider_type="oauth2",
    parameters=[
        ParameterSpec(name="CLIENT_ID", type=str | None, tier="core", driver_key="client_id", default=None),
        ParameterSpec(name="CLIENT_SECRET", type=str | None, tier="core", driver_key="client_secret", default=None, secret=True),
        ParameterSpec(name="TOKEN", type=str | None, tier="core", driver_key="token", default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="advanced", default=None, secret=True),
        ParameterSpec(name="SERVER_URI", type=str | None, tier="advanced", default=None),
        ParameterSpec(name="SCOPE", type=str | None, tier="advanced", default=None),
    ],
)


@register
class OAuth2Auth(Profile):
    __spec__ = OAUTH2_SPEC
```

- [ ] **Step 4: Rewrite oauth2_authcode.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/oauth2_authcode.py`:

```python
"""OAuth 2.0 Authorization Code grant authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["OAuth2AuthCodeAuth", "OAUTH2_AUTHCODE_SPEC"]

OAUTH2_AUTHCODE_SPEC = ProfileSpec(
    name="oauth2_authcode",
    provider_type="oauth2_authcode",
    parameters=[
        ParameterSpec(name="CLIENT_ID", type=str, tier="core", driver_key="client_id"),
        ParameterSpec(name="CLIENT_SECRET", type=str, tier="core", driver_key="client_secret", secret=True),
        ParameterSpec(name="ACCESS_TOKEN", type=str | None, tier="core", driver_key="access_token", default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="core", driver_key="refresh_token", default=None, secret=True),
        ParameterSpec(name="TOKEN_EXPIRES_AT", type=int | None, tier="advanced", default=None),
        ParameterSpec(name="SCOPE", type=str | None, tier="advanced", default=None),
    ],
)


@register
class OAuth2AuthCodeAuth(Profile):
    __spec__ = OAUTH2_AUTHCODE_SPEC
```

- [ ] **Step 5: Run tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py -v`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/schemas/oauth2.py \
        src/mountainash_auth_client/schemas/oauth2_authcode.py \
        tests/test_schemas.py
git commit -m "feat: migrate OAuth2Auth/OAuth2AuthCodeAuth to Profile subclasses"
```

---

### Task 6: Migrate OAuth1Auth

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/oauth1.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`

- [ ] **Step 1: Add tests for OAuth1Auth**

Append to `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`:

```python
class TestOAuth1Auth:
    def test_registered(self):
        assert "oauth1" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth1")
        instance = cls(CONSUMER_KEY="key", CONSUMER_SECRET="secret")
        assert instance.profile_name == "oauth1"
        assert instance.ACCESS_TOKEN is None

    def test_with_tokens(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth1")
        instance = cls(
            CONSUMER_KEY="key",
            CONSUMER_SECRET="secret",
            ACCESS_TOKEN="at",
            ACCESS_TOKEN_SECRET="ats",
        )
        assert instance.ACCESS_TOKEN is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py::TestOAuth1Auth -v`
Expected: FAIL.

- [ ] **Step 3: Rewrite oauth1.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/oauth1.py`:

```python
"""OAuth 1.0a authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["OAuth1Auth", "OAUTH1_SPEC"]

OAUTH1_SPEC = ProfileSpec(
    name="oauth1",
    provider_type="oauth1",
    parameters=[
        ParameterSpec(name="CONSUMER_KEY", type=str, tier="core", driver_key="consumer_key"),
        ParameterSpec(name="CONSUMER_SECRET", type=str, tier="core", driver_key="consumer_secret", secret=True),
        ParameterSpec(name="ACCESS_TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="ACCESS_TOKEN_SECRET", type=str | None, tier="core", default=None, secret=True),
    ],
)


@register
class OAuth1Auth(Profile):
    __spec__ = OAUTH1_SPEC
```

- [ ] **Step 4: Run tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/schemas/oauth1.py tests/test_schemas.py
git commit -m "feat: migrate OAuth1Auth to Profile subclass"
```

---

### Task 7: Migrate IAMAuth

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/iam.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`

- [ ] **Step 1: Add tests for IAMAuth**

Append to `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`:

```python
class TestIAMAuth:
    def test_registered(self):
        assert "iam" in AUTH_REGISTRY

    def test_construction_ambient(self):
        cls = AUTH_REGISTRY.get_settings_class("iam")
        instance = cls()
        assert instance._default_kwargs() == {}

    def test_construction_with_role(self):
        cls = AUTH_REGISTRY.get_settings_class("iam")
        instance = cls(ROLE_ARN="arn:aws:iam::123:role/myrole")
        result = instance._default_kwargs()
        assert result["iam_role_arn"] == "arn:aws:iam::123:role/myrole"

    def test_construction_with_keys(self):
        cls = AUTH_REGISTRY.get_settings_class("iam")
        instance = cls(
            ACCESS_KEY_ID="AKID",
            SECRET_ACCESS_KEY="secret",
            SESSION_TOKEN="tok",
        )
        result = instance._default_kwargs()
        assert result["aws_access_key_id"] == "AKID"
        assert result["aws_secret_access_key"] == "secret"
        assert result["aws_session_token"] == "tok"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py::TestIAMAuth -v`
Expected: FAIL.

- [ ] **Step 3: Rewrite iam.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/iam.py`:

```python
"""AWS IAM authentication."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["IAMAuth", "IAM_SPEC"]

IAM_SPEC = ProfileSpec(
    name="iam",
    provider_type="iam",
    parameters=[
        ParameterSpec(name="ROLE_ARN", type=str | None, tier="core", driver_key="iam_role_arn", default=None),
        ParameterSpec(name="ACCESS_KEY_ID", type=str | None, tier="core", driver_key="aws_access_key_id", default=None),
        ParameterSpec(name="SECRET_ACCESS_KEY", type=str | None, tier="core", driver_key="aws_secret_access_key", default=None, secret=True),
        ParameterSpec(name="SESSION_TOKEN", type=str | None, tier="advanced", driver_key="aws_session_token", default=None, secret=True),
        ParameterSpec(name="PROFILE_NAME", type=str | None, tier="advanced", default=None),
    ],
)


@register
class IAMAuth(Profile):
    __spec__ = IAM_SPEC
```

- [ ] **Step 4: Run tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/schemas/iam.py tests/test_schemas.py
git commit -m "feat: migrate IAMAuth to Profile subclass"
```

---

### Task 8: Migrate remaining auth modes (azure, kerberos, certificate, service_account)

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/azure.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/kerberos.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/certificate.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/service_account.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`

- [ ] **Step 1: Add tests for all four**

Append to `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_schemas.py`:

```python
class TestWindowsAuth:
    def test_registered(self):
        assert "windows" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("windows")
        instance = cls(USERNAME="admin", DOMAIN="CORP")
        assert instance.USERNAME == "admin"
        assert instance.DOMAIN == "CORP"


class TestAzureADAuth:
    def test_registered(self):
        assert "azure_ad" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("azure_ad")
        instance = cls(TENANT_ID="tid", CLIENT_ID="cid")
        assert instance.TENANT_ID == "tid"

    def test_managed_identity(self):
        cls = AUTH_REGISTRY.get_settings_class("azure_ad")
        instance = cls(MANAGED_IDENTITY=True)
        assert instance.MANAGED_IDENTITY is True


class TestKerberosAuth:
    def test_registered(self):
        assert "kerberos" in AUTH_REGISTRY

    def test_construction_defaults(self):
        cls = AUTH_REGISTRY.get_settings_class("kerberos")
        instance = cls()
        assert instance.SERVICE_NAME == "postgres"

    def test_construction_custom(self):
        cls = AUTH_REGISTRY.get_settings_class("kerberos")
        instance = cls(SERVICE_NAME="trino", PRINCIPAL="user@REALM")
        assert instance.SERVICE_NAME == "trino"
        assert instance.PRINCIPAL == "user@REALM"


class TestCertificateAuth:
    def test_registered(self):
        assert "certificate" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("certificate")
        instance = cls(PRIVATE_KEY="key-data")
        assert instance.profile_name == "certificate"


class TestServiceAccountAuth:
    def test_registered(self):
        assert "service_account" in AUTH_REGISTRY

    def test_construction_with_file(self):
        cls = AUTH_REGISTRY.get_settings_class("service_account")
        instance = cls(FILE="/path/to/sa.json")
        assert instance.profile_name == "service_account"

    def test_construction_with_info(self):
        cls = AUTH_REGISTRY.get_settings_class("service_account")
        instance = cls(INFO={"type": "service_account", "project_id": "test"})
        assert instance.INFO["project_id"] == "test"
```

- [ ] **Step 2: Run test to verify they fail**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py::TestWindowsAuth -v`
Expected: FAIL.

- [ ] **Step 3: Rewrite azure.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/azure.py`:

```python
"""Microsoft-centric authentication: Windows integrated + Azure AD."""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["WindowsAuth", "AzureADAuth", "WINDOWS_SPEC", "AZURE_AD_SPEC"]

WINDOWS_SPEC = ProfileSpec(
    name="windows",
    provider_type="windows",
    parameters=[
        ParameterSpec(name="USERNAME", type=str | None, tier="core", default=None),
        ParameterSpec(name="DOMAIN", type=str | None, tier="core", default=None),
    ],
)


@register
class WindowsAuth(Profile):
    __spec__ = WINDOWS_SPEC


AZURE_AD_SPEC = ProfileSpec(
    name="azure_ad",
    provider_type="azure_ad",
    parameters=[
        ParameterSpec(name="TENANT_ID", type=str | None, tier="core", default=None),
        ParameterSpec(name="CLIENT_ID", type=str | None, tier="core", default=None),
        ParameterSpec(name="CLIENT_SECRET", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="MANAGED_IDENTITY", type=bool, tier="advanced", default=False),
        ParameterSpec(name="MSI_ENDPOINT", type=str | None, tier="advanced", default=None),
    ],
)


@register
class AzureADAuth(Profile):
    __spec__ = AZURE_AD_SPEC
```

- [ ] **Step 4: Rewrite kerberos.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/kerberos.py`:

```python
"""Kerberos / GSSAPI authentication."""
from pathlib import Path

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["KerberosAuth", "KERBEROS_SPEC"]

KERBEROS_SPEC = ProfileSpec(
    name="kerberos",
    provider_type="kerberos",
    parameters=[
        ParameterSpec(name="SERVICE_NAME", type=str, tier="core", default="postgres"),
        ParameterSpec(name="PRINCIPAL", type=str | None, tier="core", default=None),
        ParameterSpec(name="KEYTAB", type=Path | None, tier="advanced", default=None),
    ],
)


@register
class KerberosAuth(Profile):
    __spec__ = KERBEROS_SPEC
```

- [ ] **Step 5: Rewrite certificate.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/certificate.py`:

```python
"""Private-key / certificate authentication (Snowflake JWT)."""
from pathlib import Path

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["CertificateAuth", "CERTIFICATE_SPEC"]

CERTIFICATE_SPEC = ProfileSpec(
    name="certificate",
    provider_type="certificate",
    parameters=[
        ParameterSpec(name="PRIVATE_KEY", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="PRIVATE_KEY_PATH", type=Path | None, tier="core", default=None),
        ParameterSpec(name="PASSPHRASE", type=str | None, tier="advanced", default=None, secret=True),
    ],
)


@register
class CertificateAuth(Profile):
    __spec__ = CERTIFICATE_SPEC
```

- [ ] **Step 6: Rewrite service_account.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/service_account.py`:

```python
"""Google-style service-account authentication."""
from __future__ import annotations

import typing as t
from pathlib import Path

from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from .registry import register

__all__ = ["ServiceAccountAuth", "SERVICE_ACCOUNT_SPEC"]

SERVICE_ACCOUNT_SPEC = ProfileSpec(
    name="service_account",
    provider_type="service_account",
    parameters=[
        ParameterSpec(name="INFO", type=dict[str, t.Any] | None, tier="core", default=None),
        ParameterSpec(name="FILE", type=Path | None, tier="core", default=None),
    ],
)


@register
class ServiceAccountAuth(Profile):
    __spec__ = SERVICE_ACCOUNT_SPEC
```

- [ ] **Step 7: Run tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_schemas.py -v`
Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/schemas/azure.py \
        src/mountainash_auth_client/schemas/kerberos.py \
        src/mountainash_auth_client/schemas/certificate.py \
        src/mountainash_auth_client/schemas/service_account.py \
        tests/test_schemas.py
git commit -m "feat: migrate WindowsAuth/AzureADAuth/KerberosAuth/CertificateAuth/ServiceAccountAuth to Profile subclasses"
```

---

### Task 9: Delete base.py, dispatch.py, and add spec_invariants_for tests

**Files:**
- Delete: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/base.py`
- Delete: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/dispatch.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/__init__.py`
- Create: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_invariants.py`

- [ ] **Step 1: Add spec_invariants_for test**

Create `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_invariants.py`:

```python
"""Automatic structural invariant tests for all registered auth modes."""
from mountainash_settings import spec_invariants_for

from mountainash_auth_client.schemas.registry import AUTH_REGISTRY

TestAuthInvariants = spec_invariants_for(AUTH_REGISTRY)
```

- [ ] **Step 2: Run invariant tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_invariants.py -v`
Expected: All 13 auth modes pass all invariants (name_matches_registry_key, name_lowercase_nonempty, parameter_names_unique, parameter_names_uppercase, driver_keys_unique, parameter_tiers_valid, provider_type_not_none).

- [ ] **Step 3: Delete base.py and dispatch.py**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
rm src/mountainash_auth_client/schemas/base.py
rm src/mountainash_auth_client/schemas/dispatch.py
```

- [ ] **Step 4: Rewrite schemas/__init__.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/schemas/__init__.py`:

```python
"""Auth mode Profile subclasses — registered in AUTH_REGISTRY."""
from .registry import AUTH_REGISTRY, register
from .azure import AzureADAuth, WindowsAuth
from .certificate import CertificateAuth
from .iam import IAMAuth
from .kerberos import KerberosAuth
from .none import NoAuth
from .oauth1 import OAuth1Auth
from .oauth2 import OAuth2Auth
from .oauth2_authcode import OAuth2AuthCodeAuth
from .password import PasswordAuth
from .service_account import ServiceAccountAuth
from .token import JWTAuth, TokenAuth

__all__ = [
    "AUTH_REGISTRY",
    "AzureADAuth",
    "CertificateAuth",
    "IAMAuth",
    "JWTAuth",
    "KerberosAuth",
    "NoAuth",
    "OAuth1Auth",
    "OAuth2Auth",
    "OAuth2AuthCodeAuth",
    "PasswordAuth",
    "ServiceAccountAuth",
    "TokenAuth",
    "WindowsAuth",
    "register",
]
```

- [ ] **Step 5: Run all tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick -v`
Expected: All tests pass. Any test that imported from dispatch or base will fail — fix in next step.

- [ ] **Step 6: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add -A src/mountainash_auth_client/schemas/ tests/test_invariants.py
git commit -m "refactor: delete AuthSpec base and dispatch.py, add spec_invariants_for"
```

---

### Task 10: Update package __init__.py and mixins for uppercase fields

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/__init__.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth2.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth1.py`

- [ ] **Step 1: Update package __init__.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/__init__.py`:

```python
"""mountainash-auth-client — client-side authentication for the mountainash ecosystem."""
from mountainash_auth_client.errors import (
    AuthorizationRequired,
    TokenExchangeError,
    TokenRefreshError,
)
from mountainash_auth_client.flows.oauth2 import OAuthFlow
from mountainash_auth_client.mixins.oauth2 import OAuth2ConnectionMixin
from mountainash_auth_client.schemas import (
    AUTH_REGISTRY,
    AzureADAuth,
    CertificateAuth,
    IAMAuth,
    JWTAuth,
    KerberosAuth,
    NoAuth,
    OAuth1Auth,
    OAuth2Auth,
    OAuth2AuthCodeAuth,
    PasswordAuth,
    ServiceAccountAuth,
    TokenAuth,
    WindowsAuth,
)
from mountainash_auth_client.server.callback import LocalCallbackServer
from mountainash_auth_client.store.filesystem import FilesystemStore
from mountainash_auth_client.store.protocol import SecretStore

__all__ = [
    "AUTH_REGISTRY",
    "AuthorizationRequired",
    "AzureADAuth",
    "CertificateAuth",
    "FilesystemStore",
    "IAMAuth",
    "JWTAuth",
    "KerberosAuth",
    "LocalCallbackServer",
    "NoAuth",
    "OAuth1Auth",
    "OAuth2Auth",
    "OAuth2AuthCodeAuth",
    "OAuth2ConnectionMixin",
    "OAuthFlow",
    "PasswordAuth",
    "SecretStore",
    "ServiceAccountAuth",
    "TokenAuth",
    "TokenExchangeError",
    "TokenRefreshError",
    "WindowsAuth",
]
```

- [ ] **Step 2: Update OAuth2ConnectionMixin for uppercase fields**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth2.py`, update all field accesses from lowercase to uppercase. The mixin reads `profile.auth` which is now a Profile subclass with uppercase field names.

Change these attribute accesses throughout the file:
- `auth.access_token` → `auth.ACCESS_TOKEN`
- `auth.refresh_token` → `auth.REFRESH_TOKEN`
- `auth.token_expires_at` → `auth.TOKEN_EXPIRES_AT`
- `auth.client_id` → `auth.CLIENT_ID`
- `auth.client_secret` → `auth.CLIENT_SECRET`
- `auth.scope` → `auth.SCOPE`

For SecretStr fields, `.get_secret_value()` is still needed since ParameterSpec marks them as `secret=True` which wraps as SecretStr.

The full updated `connect` method:

```python
def connect(
    self,
    profile,
    *,
    user: str = "default",
    store: SecretStore,
    domain: str,
    auto_authorize: bool = False,
) -> Self:
    provider = self._spec.name
    flow = OAuthFlow(self._spec)

    tokens = store.load(domain, provider, user)

    if tokens is None and not store.is_cleared(domain, provider, user):
        auth = profile.auth
        if getattr(auth, "ACCESS_TOKEN", None) is not None:
            tokens = {
                "access_token": auth.ACCESS_TOKEN.get_secret_value(),
                "refresh_token": auth.REFRESH_TOKEN.get_secret_value() if auth.REFRESH_TOKEN else None,
                "token_expires_at": auth.TOKEN_EXPIRES_AT,
            }
            store.save(domain, provider, user, tokens)

    access_token: str | None = None

    if tokens and not flow.is_expired(tokens.get("token_expires_at")):
        access_token = tokens["access_token"]
    elif tokens and tokens.get("refresh_token"):
        with store.lock(domain, provider, user):
            tokens = store.load(domain, provider, user)
            if tokens and not flow.is_expired(tokens.get("token_expires_at")):
                access_token = tokens["access_token"]
            else:
                try:
                    auth = profile.auth
                    new_tokens = flow.refresh(
                        refresh_token=tokens["refresh_token"],
                        client_id=auth.CLIENT_ID,
                        client_secret=auth.CLIENT_SECRET.get_secret_value(),
                    )
                    store.save(domain, provider, user, new_tokens)
                    access_token = new_tokens["access_token"]
                except Exception:
                    store.clear(domain, provider, user)
                    if not auto_authorize:
                        raise AuthorizationRequired(provider=provider, user=user)

    if access_token is None:
        if auto_authorize:
            auth = profile.auth
            new_tokens = flow.authorize(
                client_id=auth.CLIENT_ID,
                client_secret=auth.CLIENT_SECRET.get_secret_value(),
                scope=auth.SCOPE,
            )
            store.save(domain, provider, user, new_tokens)
            access_token = new_tokens["access_token"]
        else:
            raise AuthorizationRequired(provider=provider, user=user)

    self._client = httpx.Client(
        base_url=self._base_url,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30.0,
    )
    return self
```

- [ ] **Step 3: Update OAuth1ConnectionMixin for uppercase fields**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth1.py`, update field accesses:

- `auth.access_token` → `auth.ACCESS_TOKEN`
- `auth.access_token_secret` → `auth.ACCESS_TOKEN_SECRET`
- `auth.consumer_key` → `auth.CONSUMER_KEY`
- `auth.consumer_secret` → `auth.CONSUMER_SECRET`

The full updated `connect` method:

```python
def connect(
    self,
    profile,
    *,
    user: str = "default",
    store: SecretStore,
    domain: str,
    auto_authorize: bool = False,
) -> Self:
    provider = self._spec.name
    tokens = store.load(domain, provider, user)

    if tokens is None and not store.is_cleared(domain, provider, user):
        auth = profile.auth
        if getattr(auth, "ACCESS_TOKEN", None) is not None:
            tokens = {
                "oauth_token": auth.ACCESS_TOKEN.get_secret_value(),
                "oauth_token_secret": (
                    auth.ACCESS_TOKEN_SECRET.get_secret_value()
                    if auth.ACCESS_TOKEN_SECRET
                    else None
                ),
            }
            store.save(domain, provider, user, tokens)

    if tokens and tokens.get("oauth_token"):
        self._build_client(tokens, profile)
        return self

    if auto_authorize:
        auth = profile.auth
        flow = OAuth1Flow(self._spec)
        new_tokens = flow.authorize(
            consumer_key=auth.CONSUMER_KEY,
            consumer_secret=auth.CONSUMER_SECRET.get_secret_value(),
        )
        store.save(domain, provider, user, new_tokens)
        self._build_client(new_tokens, profile)
        return self

    raise AuthorizationRequired(provider=provider, user=user)
```

And the updated `_build_client` method:

```python
def _build_client(self, tokens: dict, profile) -> None:
    try:
        from authlib.integrations.httpx_client import OAuth1Auth
    except ImportError as exc:
        raise ImportError(
            "OAuth1 requires authlib: pip install mountainash-auth-client[oauth1]"
        ) from exc

    auth = profile.auth
    self._client = httpx.Client(
        base_url=self._base_url,
        auth=OAuth1Auth(
            client_id=auth.CONSUMER_KEY,
            client_secret=auth.CONSUMER_SECRET.get_secret_value(),
            token=tokens["oauth_token"],
            token_secret=tokens["oauth_token_secret"],
        ),
        timeout=30.0,
    )
```

- [ ] **Step 4: Run all tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/__init__.py \
        src/mountainash_auth_client/mixins/oauth2.py \
        src/mountainash_auth_client/mixins/oauth1.py
git commit -m "refactor: update package exports and mixins for uppercase fields"
```

---

### Task 11: Update mixin tests for uppercase fields

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_oauth2_mixin.py`

- [ ] **Step 1: Read the existing test file to find all field references**

Read `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_oauth2_mixin.py` and update any construction of `OAuth2AuthCodeAuth` to use uppercase field names:

- `client_id="..."` → `CLIENT_ID="..."`
- `client_secret="..."` → `CLIENT_SECRET="..."`
- `access_token="..."` → `ACCESS_TOKEN="..."`
- `refresh_token="..."` → `REFRESH_TOKEN="..."`
- `token_expires_at=...` → `TOKEN_EXPIRES_AT=...`
- `scope="..."` → `SCOPE="..."`

Also update any assertions that read lowercase fields to read uppercase.

- [ ] **Step 2: Run mixin tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick tests/test_oauth2_mixin.py -v`
Expected: All tests pass.

- [ ] **Step 3: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add tests/test_oauth2_mixin.py
git commit -m "test: update mixin tests for uppercase field names"
```

---

### Task 12: Clean up __pycache__ and run full test suite

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/.gitignore` (if needed)

- [ ] **Step 1: Clean pycache files tracked by git**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
git rm -r --cached '**/__pycache__' 2>/dev/null || true
```

- [ ] **Step 2: Run the full test suite with coverage**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test`
Expected: All tests pass. Coverage report shows the new Profile-based schemas are tested.

- [ ] **Step 3: Run mountainash-settings tests to confirm nothing broke**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick`
Expected: All tests pass.

- [ ] **Step 4: Final commit if any cleanup needed**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add -A
git status
# Only commit if there are changes
git commit -m "chore: clean up pycache and verify full test suite"
```

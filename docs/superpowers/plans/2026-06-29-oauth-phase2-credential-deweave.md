# OAuth Split Phase 2: Credential De-weave — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an OAuth2 credential generic data again — collapse the two near-duplicate
OAuth2 classes into one `OAuth2AuthProfile`, hard-rename its token field `TOKEN → ACCESS_TOKEN`,
delete two dead fields (`SERVER_URI`, `TOKEN_EXPIRES_AT`), and keep `SCOPE` (per-user grant
data) — then repoint the three downstream consumers in one coordinated landing.

**Architecture:** The two classes differed only by a naming accident (`TOKEN` vs
`ACCESS_TOKEN`), two fields nothing reads, and the grant *flow* they were modeled around —
and the flow is selected by the provider profile, not the credential. So the unified
`OAuth2AuthProfile` carries `CLIENT_ID, CLIENT_SECRET, ACCESS_TOKEN, REFRESH_TOKEN, SCOPE`
and one HTTP Bearer renderer reading `ACCESS_TOKEN`. `SCOPE` stays because it co-varies
per-user (the flow already sources the per-user override from `auth_profile.SCOPE`, with
`provider.DEFAULT_SCOPE` as fallback — unchanged).

**Tech Stack:** Python 3.12, hatch (uv installer), pydantic v2 / `mountainash_settings`
`Profile`/`ProfileSpec`, pytest. Four repos in the sibling workspace (`mountainash-auth-client`,
`mountainash-data`, `mountainash-wearables`, `mountainash-transport`), each installing
auth-client as an editable sibling, so consumer suites see auth-client edits live.

## Global Constraints

- **Precondition: Phase 1 is merged.** OAuth ops live under `oauth/` — this plan edits
  `oauth/oauth2/connection.py`. (`schemas/` was not moved by Phase 1, so schema paths are
  unchanged.) If Phase 1 is *not* merged, substitute `connections/oauth2/connection.py` for
  `oauth/oauth2/connection.py` throughout.
- **Hard rename, no alias** (architect ruling): `TOKEN → ACCESS_TOKEN` on `OAuth2AuthProfile`.
  No compatibility field/alias. A consumer needing a different kwarg name writes an adapter.
- **Hard removal, no alias** (architect ruling): delete `OAuth2AuthCodeAuthProfile` and the
  `OAUTH2_AUTHCODE` discriminator outright; repoint consumers in the same coordinated set.
  Loud validation failure on an un-migrated persisted `oauth2_authcode` key is intended.
- **`SCOPE` stays** on `OAuth2AuthProfile`. Do **not** evict it; do **not** touch the flow's
  `authorize(scope=auth_profile.SCOPE)` reads (`oauth/oauth2/flow.py:325`,
  `oauth/lifecycle/oauth2.py:61`).
- **`TokenAuthProfile.TOKEN` is unchanged.** Only `OAuth2AuthProfile`'s token field is
  renamed. Most `.TOKEN` reads in `mountainash-data` are on `TokenAuthProfile` and must NOT
  change — only the snowflake `oauth2` adapter touches `OAuth2AuthProfile`.
- **Atomic multi-repo landing:** four branches, four PRs, each targeting its repo's `develop`
  (three-tier flow). They merge together; never push to `develop`/`main`. Develop and test
  in the shared sibling workspace so the consumer repos compile against the new auth-client.
- **Tests:** auth-client fast iteration `hatch run test:test-quick <args>`, full gate
  `hatch run test:test`, lint `hatch run ruff:check`. For data/wearables/transport use that
  repo's equivalent (`hatch run test:test-quick` where present).
- **Commit after every task.** Run auth-client commands from the auth-client repo root.

---

## Branch Setup (auth-client; seed from `develop`)

- [ ] **Seed the auth-client branch and confirm a green baseline.**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git fetch origin && git switch develop && git pull --ff-only
git switch -c feature/oauth-phase2-credential-deweave
hatch run test:test-quick -q
```
Expected: all tests pass (the regression net).

> Consumer-repo branches (data/wearables/transport) are seeded in Tasks 4-6, each from its
> own `develop`.

---

## Task 1: Unify on `OAuth2AuthProfile` (rename token, drop dead `SERVER_URI`, keep `SCOPE`)

Turn the client-credentials `schemas/oauth2.py` into the single canonical OAuth2 credential:
rename `TOKEN → ACCESS_TOKEN`, delete the dead `SERVER_URI`, keep `SCOPE`/`REFRESH_TOKEN`,
and point the Bearer renderer at `ACCESS_TOKEN`. (`OAuth2AuthCodeAuthProfile` is removed in
Task 2; after Task 1 it still exists and its tests still pass.)

**Files:**
- Modify: `src/mountainash_auth_client/schemas/oauth2.py`
- Modify: `tests/test_emission.py` (`TestPlainOAuth2`, ~lines 270-289)
- Modify: `tests/test_schemas.py` (`TestOAuth2Auth`, lines 74-98)

**Interfaces:**
- Produces: `OAuth2AuthProfile` with fields `CLIENT_ID, CLIENT_SECRET, ACCESS_TOKEN,
  REFRESH_TOKEN, SCOPE` (all `str | None`, `default=None`; secrets: `CLIENT_SECRET`,
  `ACCESS_TOKEN`, `REFRESH_TOKEN`). `__adapters__ = {TargetFamily.HTTP:
  _bearer_from_access_token}` rendering `Authorization: Bearer <ACCESS_TOKEN>`. Registry
  name `"oauth2"` unchanged.

- [ ] **Step 1: Update the emission tests to the target field name (failing test)**

In `tests/test_emission.py`, `TestPlainOAuth2`, change the two constructions:

Line ~274:
```python
        out = OAuth2AuthProfile(TOKEN="access-tok").emit(TargetFamily.HTTP)
```
→
```python
        out = OAuth2AuthProfile(ACCESS_TOKEN="access-tok").emit(TargetFamily.HTTP)
```

Line ~287:
```python
        out = OAuth2AuthProfile(TOKEN="access-tok").emit(TargetFamily.HTTP)
```
→
```python
        out = OAuth2AuthProfile(ACCESS_TOKEN="access-tok").emit(TargetFamily.HTTP)
```

- [ ] **Step 2: Update the schema tests to the target field name + add the round-trip**

In `tests/test_schemas.py`, `TestOAuth2Auth`, change lines 80 and 86 from
`instance = cls(TOKEN="access-tok")` to `instance = cls(ACCESS_TOKEN="access-tok")`.

Then append this test inside `TestOAuth2Auth` (preserves the field round-trip coverage that
the soon-deleted `TestOAuth2AuthCodeAuth` provided, minus the deleted `TOKEN_EXPIRES_AT`):

```python
    def test_construction_with_all_token_fields(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls(
            CLIENT_ID="cid",
            CLIENT_SECRET="csec",
            ACCESS_TOKEN="at",
            REFRESH_TOKEN="rt",
            SCOPE="read write",
        )
        assert instance.profile_name == "oauth2"
        assert instance.ACCESS_TOKEN.get_secret_value() == "at"
        assert instance.SCOPE == "read write"
```

- [ ] **Step 3: Run the updated tests — verify they FAIL**

Run: `hatch run test:test-quick -q tests/test_emission.py::TestPlainOAuth2 tests/test_schemas.py::TestOAuth2Auth`
Expected: FAIL — `OAuth2AuthProfile` has no `ACCESS_TOKEN` field yet (it's still `TOKEN`).

- [ ] **Step 4: Rewrite `schemas/oauth2.py` to the unified spec**

Replace the body of `src/mountainash_auth_client/schemas/oauth2.py` with:

```python
"""OAuth2 credential (client-credentials or authorization-code grant).

The grant flow is selected by the provider profile (oauth/providers/), not the
credential — so one credential class serves both. Carries client identity, the
access/refresh tokens, and the per-user requested SCOPE; the IdP coordinates
(AUTHORIZE_URL/TOKEN_URL/…) live on the provider profile.
"""
from mountainash_settings import ParameterSpec, Profile, ProfileSpec

from ..targets import TargetFamily
from .registry import register

__all__ = ["OAuth2AuthProfile", "OAUTH2_SPEC"]


def _bearer_from_access_token(profile, kw):
    """Render the current ``ACCESS_TOKEN`` as an HTTP Bearer header.

    Token acquisition/refresh is the flow's job; an empty/None token renders
    nothing (matches the resolver's truthiness on the unwrapped token).
    """
    token = profile.ACCESS_TOKEN.get_secret_value() if profile.ACCESS_TOKEN else None
    if not token:
        return kw
    headers = {**kw.get("headers", {}), "Authorization": f"Bearer {token}"}
    return {**kw, "headers": headers}


OAUTH2_SPEC = ProfileSpec(
    name="oauth2",
    provider_type="oauth2",
    parameters=[
        ParameterSpec(name="CLIENT_ID", type=str | None, tier="core", default=None),
        ParameterSpec(name="CLIENT_SECRET", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="ACCESS_TOKEN", type=str | None, tier="core", default=None, secret=True),
        ParameterSpec(name="REFRESH_TOKEN", type=str | None, tier="advanced", default=None, secret=True),
        ParameterSpec(name="SCOPE", type=str | None, tier="advanced", default=None),
    ],
)


@register
class OAuth2AuthProfile(Profile):
    __spec__ = OAUTH2_SPEC
    __adapters__ = {TargetFamily.HTTP: _bearer_from_access_token}
```

> Changes from the old file: `TOKEN → ACCESS_TOKEN`; `SERVER_URI` deleted; adapter renamed
> and reads `ACCESS_TOKEN`. `SCOPE`, `REFRESH_TOKEN`, `CLIENT_ID`, `CLIENT_SECRET` retained.

- [ ] **Step 5: Run the updated tests — verify they PASS**

Run: `hatch run test:test-quick -q tests/test_emission.py::TestPlainOAuth2 tests/test_schemas.py::TestOAuth2Auth`
Expected: PASS.

- [ ] **Step 6: Run the full auth-client suite**

Run: `hatch run test:test-quick -q`
Expected: all pass. (`OAuth2AuthCodeAuthProfile` and its tests are untouched and still
green; the flow's `auth_profile.SCOPE` reads are unchanged.)

- [ ] **Step 7: Lint**

Run: `hatch run ruff:check`
Expected: no findings.

- [ ] **Step 8: Commit**

```bash
git add src/mountainash_auth_client/schemas/oauth2.py tests/test_emission.py tests/test_schemas.py
git commit -m "refactor(schemas): rename OAuth2 TOKEN->ACCESS_TOKEN, drop dead SERVER_URI, keep SCOPE"
```

---

## Task 1B: Guard the OAuth2 `authorize()` path for an optional client secret

The unified `OAuth2AuthProfile` has `CLIENT_SECRET` optional (`str | None`) — correct,
because the `TOKEN_ENDPOINT_AUTH_METHOD="none"` public-client case has no secret, so
requiredness can't be a field constraint. But the collapse drops the old authcode schema's
required-secret guarantee, which newly exposes a latent bug: `OAuth2TokenManager.authorize()`
dereferences `self._auth.CLIENT_SECRET.get_secret_value()` **unconditionally**
(`oauth/lifecycle/oauth2.py`), so a `None` secret now raises `AttributeError` instead of
flowing through as `None`. `OAuthFlow.resolve_access_token()` already guards this via
`TOKEN_ENDPOINT_AUTH_METHOD`; make the manager consistent.

**Files:**
- Modify: `src/mountainash_auth_client/oauth/lifecycle/oauth2.py` (the `authorize()` method, the
  `self._flow_cls()(…).authorize(…)` call)
- Test: `tests/oauth/lifecycle/test_oauth2_manager.py` (append)

**Interfaces:**
- Consumes: the unified `OAuth2AuthProfile` (Task 1) with optional `CLIENT_ID`/`CLIENT_SECRET`.
- Produces: `OAuth2TokenManager.authorize()` passes `client_id=None, client_secret=None` when
  the provider's `TOKEN_ENDPOINT_AUTH_METHOD == "none"` or when the secret is absent — never
  dereferencing a `None` secret. Behaviour for present secrets is unchanged.

- [ ] **Step 1: Write the failing test**

Append to `tests/oauth/lifecycle/test_oauth2_manager.py` (reuses the file's `_provider` and
`_Auth` helpers):

```python
def test_authorize_tolerates_missing_client_secret():
    # After the OAuth2 class collapse CLIENT_SECRET is optional; the manager must
    # not dereference a None secret (it did unconditionally pre-collapse, because
    # the old authcode schema required it).
    class _NoSecretAuth(_Auth):
        CLIENT_SECRET = None

    mgr = OAuth2TokenManager(
        _provider(), _NoSecretAuth(),
        resolver=SecretRegistryResolver({"mem": InMemorySecretStore()}),
    )
    captured = {}

    def fake_authorize(self, **kwargs):
        captured.update(kwargs)
        return {"access_token": "a", "token_expires_at": int(time.time()) + 3600}

    with patch.object(type(mgr)._flow_cls(), "authorize", new=fake_authorize):
        mgr.authorize()
    assert captured["client_secret"] is None
```

- [ ] **Step 2: Run it — verify it FAILS**

Run: `hatch run test:test-quick -q "tests/oauth/lifecycle/test_oauth2_manager.py::test_authorize_tolerates_missing_client_secret"`
Expected: FAIL — `AttributeError: 'NoneType' object has no attribute 'get_secret_value'`
raised inside `authorize()` before the patched flow is reached.

- [ ] **Step 3: Guard the dereference (mirror `flow.py`)**

In `src/mountainash_auth_client/oauth/lifecycle/oauth2.py`, `authorize()`, replace the
flow-call block:

```python
        tokens = self._flow_cls()(self._provider, resolver=self._resolver).authorize(
            client_id=self._auth.CLIENT_ID,
            client_secret=self._auth.CLIENT_SECRET.get_secret_value(),
            scope=self._auth.SCOPE,
            callback_server=factory,
        )
```
with:
```python
        _method = getattr(self._provider, "TOKEN_ENDPOINT_AUTH_METHOD", "client_secret_post")
        if _method == "none":
            _cid = _csec = None
        else:
            _cid = self._auth.CLIENT_ID
            _csec = (
                self._auth.CLIENT_SECRET.get_secret_value()
                if self._auth.CLIENT_SECRET else None
            )
        tokens = self._flow_cls()(self._provider, resolver=self._resolver).authorize(
            client_id=_cid,
            client_secret=_csec,
            scope=self._auth.SCOPE,
            callback_server=factory,
        )
```

- [ ] **Step 4: Run it — verify it PASSES, then the manager suite**

Run: `hatch run test:test-quick -q tests/oauth/lifecycle/test_oauth2_manager.py`
Expected: PASS (new test green; the existing `test_authorize_*` cases — which use a present
secret — stay green).

- [ ] **Step 5: Lint + commit**

```bash
hatch run ruff:check
git add src/mountainash_auth_client/oauth/lifecycle/oauth2.py tests/oauth/lifecycle/test_oauth2_manager.py
git commit -m "fix(lifecycle): tolerate optional client_secret in OAuth2TokenManager.authorize()"
```

---

## Task 2: Remove `OAuth2AuthCodeAuthProfile` and the `OAUTH2_AUTHCODE` discriminator

Delete the redundant authorization-code class and every reference. Registration is via the
`@register` decorator at class-definition time, so deleting the module **and** its import in
`schemas/__init__.py` removes the `"oauth2_authcode"` registry entry — `registry.py` itself
needs no edit.

**Files:**
- Delete: `src/mountainash_auth_client/schemas/oauth2_authcode.py`
- Modify: `src/mountainash_auth_client/schemas/__init__.py:10,25`
- Modify: `src/mountainash_auth_client/__init__.py:33,56,86`
- Modify: `src/mountainash_auth_client/constants.py:19`
- Modify: `src/mountainash_auth_client/oauth/oauth2/connection.py:21,29`
- Modify: `tests/test_schemas.py` (delete `TestOAuth2AuthCodeAuth`, lines 101-121)
- Modify: `tests/test_emission.py` (delete `TestOAuth2AuthCode`, lines 161-183)

**Interfaces:**
- Produces: a registry with no `"oauth2_authcode"` entry; `OAuth2AuthCodeAuthProfile` and
  `CONST_AUTH_PROFILES.OAUTH2_AUTHCODE` no longer exist anywhere in auth-client.

- [ ] **Step 1: Delete the redundant tests first (so the suite tracks the removal)**

In `tests/test_schemas.py`, delete the entire `TestOAuth2AuthCodeAuth` class (lines
101-121, from `class TestOAuth2AuthCodeAuth:` through the `assert instance.TOKEN_EXPIRES_AT
== 9999` line). In `tests/test_emission.py`, delete the entire `TestOAuth2AuthCode` class
(lines 161-183, the `@pytest.mark.unit` decorator through `test_no_stray_client_fields`).

- [ ] **Step 2: Delete the module**

```bash
git rm src/mountainash_auth_client/schemas/oauth2_authcode.py
```

- [ ] **Step 3: Drop the schema-package export**

In `src/mountainash_auth_client/schemas/__init__.py`, remove line 10
(`from .oauth2_authcode import OAuth2AuthCodeAuthProfile`) and the `"OAuth2AuthCodeAuthProfile",`
entry from `__all__` (line 25).

- [ ] **Step 4: Drop the package-root export and union member**

In `src/mountainash_auth_client/__init__.py`:
- Remove `OAuth2AuthCodeAuthProfile,` from the `from mountainash_auth_client.schemas import (…)`
  block (line 33).
- In the `AuthProfile` union (line 56), change
  `| OAuth1AuthProfile | OAuth2AuthProfile | OAuth2AuthCodeAuthProfile` to
  `| OAuth1AuthProfile | OAuth2AuthProfile`.
- Remove the `"OAuth2AuthCodeAuthProfile",` entry from `__all__` (line 86).

- [ ] **Step 5: Drop the constant**

In `src/mountainash_auth_client/constants.py`, delete line 19
(`OAUTH2_AUTHCODE = "oauth2_authcode"`).

- [ ] **Step 6: Simplify the connection type hint**

In `src/mountainash_auth_client/oauth/oauth2/connection.py`:
- Remove the `TYPE_CHECKING` import line 21
  (`from mountainash_auth_client.schemas.oauth2_authcode import OAuth2AuthCodeAuthProfile`).
- Change the parameter annotation at line 29 from
  `auth_profile: OAuth2AuthProfile | OAuth2AuthCodeAuthProfile,` to
  `auth_profile: OAuth2AuthProfile,`.

- [ ] **Step 7: Verify no references remain**

Run: `grep -rn "OAuth2AuthCodeAuthProfile\|OAUTH2_AUTHCODE\|oauth2_authcode" src tests`
Expected: no output (exit code 1).

- [ ] **Step 8: Run the full suite + lint**

Run: `hatch run test:test-quick -q && hatch run ruff:check`
Expected: all tests pass; no lint findings. (Any test asserting `"oauth2_authcode" in
AUTH_REGISTRY` is gone; the unified `"oauth2"` tests cover the surviving behaviour.)

- [ ] **Step 9: Commit**

```bash
git add -A src tests
git commit -m "refactor(schemas): remove OAuth2AuthCodeAuthProfile + OAUTH2_AUTHCODE (collapsed into OAuth2AuthProfile)"
```

---

## Task 3: Update auth-client docs (`INTEGRATION.md`)

**Files:**
- Modify: `docs/INTEGRATION.md:129-130,136,187`

**Interfaces:** Docs only.

- [ ] **Step 0: Fix the `OAuth2Connection` example comment (line 187)**

In `docs/INTEGRATION.md` line 187, the `OAuth2Connection(...)` example annotates the
`auth_profile` argument with the removed class:
```
    auth_profile,         # OAuth2AuthProfile | OAuth2AuthCodeAuthProfile
```
Change the comment to:
```
    auth_profile,         # OAuth2AuthProfile
```

- [ ] **Step 1: Fix the OAuth2 catalogue row and delete the authcode row**

In `docs/INTEGRATION.md`, replace line 129:
```
| `OAuth2AuthProfile` | `CLIENT_ID`, `CLIENT_SECRET`, `TOKEN`, `SCOPE` | HTTP | `Authorization: Bearer …` (from `TOKEN`) |
```
with:
```
| `OAuth2AuthProfile` | `CLIENT_ID`, `CLIENT_SECRET`, `ACCESS_TOKEN`, `REFRESH_TOKEN`, `SCOPE` | HTTP | `Authorization: Bearer …` (from `ACCESS_TOKEN`) |
```
and delete line 130 entirely (the `| `OAuth2AuthCodeAuthProfile` | … |` row).

- [ ] **Step 2: Drop `OAUTH2_AUTHCODE` from the `CONST_AUTH_PROFILES` enumeration**

At line 136, change:
```
`NONE, PASSWORD, TOKEN, JWT, OAUTH1, OAUTH2, OAUTH2_AUTHCODE, IAM, AZURE_AD, WINDOWS, KERBEROS, CERTIFICATE, SERVICE_ACCOUNT`.
```
to:
```
`NONE, PASSWORD, TOKEN, JWT, OAUTH1, OAUTH2, IAM, AZURE_AD, WINDOWS, KERBEROS, CERTIFICATE, SERVICE_ACCOUNT`.
```

- [ ] **Step 3: Commit**

```bash
git add docs/INTEGRATION.md
git commit -m "docs: update INTEGRATION catalogue for unified OAuth2AuthProfile (ACCESS_TOKEN; no authcode)"
```

> Push + PR for auth-client happens in Task 7, after the consumer branches are ready, so the
> coordinated set lands together.

---

## Task 4: mountainash-data — point the snowflake `oauth2` adapter at `ACCESS_TOKEN`

Only the snowflake **`oauth2`** adapter reads `OAuth2AuthProfile.TOKEN`. The neighbouring
**`token`** adapter reads `TokenAuthProfile.TOKEN` (unchanged) — do not touch it, nor any
other `.TOKEN` reader (motherduck/databricks/trino/iceberg are all `TokenAuthProfile`).

**Files (in `../mountainash-data`):**
- Modify: `src/mountainash_data/core/settings/adapters/snowflake.py:26-28`
- Modify: `tests/test_unit/core/settings/adapters/test_auth_adapters.py:29`

- [ ] **Step 1: Seed the data branch**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-data
git fetch origin && git switch develop && git pull --ff-only
git switch -c feature/oauth2-access-token-rename
```

- [ ] **Step 2: Update the adapter test (failing test)**

In `tests/test_unit/core/settings/adapters/test_auth_adapters.py`, line 29, change:
```python
    assert _snow.oauth2(OAuth2AuthProfile(TOKEN="t"), {}) == {"authenticator": "oauth", "token": "t"}
```
to:
```python
    assert _snow.oauth2(OAuth2AuthProfile(ACCESS_TOKEN="t"), {}) == {"authenticator": "oauth", "token": "t"}
```
(Leave line 25 — `_snow.token(TokenAuthProfile(TOKEN="t"), …)` — unchanged.)

- [ ] **Step 3: Run it — verify it FAILS**

Run: `hatch run test:test-quick -q tests/test_unit/core/settings/adapters/test_auth_adapters.py::test_snowflake_oauth2_token_only`
Expected: FAIL — with the new auth-client installed, `OAuth2AuthProfile(TOKEN=…)` is invalid
and the adapter reads the now-missing `.TOKEN`. (The neighbouring `test_snowflake_token_oauth`,
which uses `TokenAuthProfile(TOKEN=…)`, must stay green — it's a different class.)

- [ ] **Step 4: Update the adapter**

In `src/mountainash_data/core/settings/adapters/snowflake.py`, change the `oauth2` function
(lines 26-28):
```python
def oauth2(auth, base):
    # token-only: never reads CLIENT_ID/SECRET/SCOPE (smell #1)
    return {**base, "authenticator": "oauth", "token": auth.ACCESS_TOKEN.get_secret_value()}
```
(`SERVER_URI` is dropped from the comment because the field no longer exists.)

- [ ] **Step 5: Run it — verify it PASSES, then the full file**

Run: `hatch run test:test-quick -q tests/test_unit/core/settings/adapters/test_auth_adapters.py`
Expected: PASS.

- [ ] **Step 6: Verify no other `OAuth2AuthProfile.TOKEN` reader remains in data**

Run: `grep -rn "OAuth2AuthProfile" src tests | grep -i token`
Expected: no `OAuth2AuthProfile(... TOKEN=...)` or `oauth2.*\.TOKEN` matches (only
`ACCESS_TOKEN`). The `TokenAuthProfile(TOKEN=…)` lines are a different class — fine.

- [ ] **Step 7: Run the data suite + commit**

```bash
hatch run test:test-quick -q
git add src/mountainash_data/core/settings/adapters/snowflake.py \
        tests/test_unit/core/settings/adapters/test_auth_adapters.py
git commit -m "fix: snowflake oauth2 adapter reads OAuth2AuthProfile.ACCESS_TOKEN (was .TOKEN)"
```

---

## Task 5: mountainash-wearables — repoint the base class; drop the dead-field assertion

`WearableOAuth2Auth` subclasses the removed `OAuth2AuthCodeAuthProfile`. Repoint it to
`OAuth2AuthProfile`. The per-user `SCOPE` override is unchanged (it stays on the credential);
only the `TOKEN_EXPIRES_AT` field-presence assertion needs dropping.

**Files (in `../mountainash-wearables`):**
- Modify: `src/mountainash_wearables/connections/auth_identity.py:3,10`
- Modify: `tests/connections/test_auth_identity.py:13`

- [ ] **Step 1: Seed the wearables branch**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-wearables
git fetch origin && git switch develop && git pull --ff-only
git switch -c feature/oauth2-collapse
```

- [ ] **Step 1B: Confirm the task opens on a broken import (red)**

With the new auth-client installed (editable sibling), `auth_identity.py:3` still imports the
removed `OAuth2AuthCodeAuthProfile`, so the wearables module — and any test importing it —
fails to import. Confirm this is the starting state:

Run: `hatch run test:test-quick -q tests/connections/test_auth_identity.py`
Expected: collection/import ERROR — `ImportError: cannot import name 'OAuth2AuthCodeAuthProfile'
from 'mountainash_auth_client'`. (This task opens on a broken import; the repoint in Step 2
is the first green step.)

- [ ] **Step 2: Repoint the base class**

In `src/mountainash_wearables/connections/auth_identity.py`:
- Line 3: `from mountainash_auth_client import OAuth2AuthCodeAuthProfile`
  → `from mountainash_auth_client import OAuth2AuthProfile`
- Line 10: `class WearableOAuth2Auth(OAuth2AuthCodeAuthProfile):`
  → `class WearableOAuth2Auth(OAuth2AuthProfile):`

- [ ] **Step 3: Drop `TOKEN_EXPIRES_AT` from the inherited-field assertion**

In `tests/connections/test_auth_identity.py`, line 13, change:
```python
    for field in ("CLIENT_ID", "CLIENT_SECRET", "ACCESS_TOKEN", "REFRESH_TOKEN", "TOKEN_EXPIRES_AT", "SCOPE"):
```
to:
```python
    for field in ("CLIENT_ID", "CLIENT_SECRET", "ACCESS_TOKEN", "REFRESH_TOKEN", "SCOPE"):
```
(`SCOPE` stays — the per-user override lives on the credential. `OuraProfile(… SCOPE="read")`
constructions in this file and in `tests/test_config.py:65` are unchanged.)

> Finding 9 (construction coverage) is already satisfied by the existing
> `test_oura_profile_is_persistable_identity` (constructs `OuraProfile(CLIENT_ID, CLIENT_SECRET,
> SCOPE)`, asserts `PersistableAuthProfile` identity + `persist_key()`) and
> `test_subclass_inherits_credential_fields` (inherited field-set) — no new test needed once
> the base is repointed and `TOKEN_EXPIRES_AT` is dropped from the tuple.

- [ ] **Step 4: Verify no removed-symbol references remain in wearables**

Run: `grep -rn "OAuth2AuthCodeAuthProfile\|TOKEN_EXPIRES_AT" src tests`
Expected: no output (exit code 1).

- [ ] **Step 5: Run the wearables suite + commit**

```bash
hatch run test:test-quick -q
git add src/mountainash_wearables/connections/auth_identity.py \
        tests/connections/test_auth_identity.py
git commit -m "fix: repoint WearableOAuth2Auth base to unified OAuth2AuthProfile; drop dead TOKEN_EXPIRES_AT assert"
```

---

## Task 6: mountainash-transport — drop `OAuth2AuthCodeAuthProfile` from the reject set

Transport imports `OAuth2AuthCodeAuthProfile` only to include it in an "unsupported auth"
reject tuple that already contains `OAuth2AuthProfile`. Remove the redundant member; the
reject behaviour is preserved (`OAuth2AuthProfile` is still rejected).

**Files (in `../mountainash-transport`):**
- Modify: `src/mountainash_transport/connections/__init__.py:157,163`
- Modify: `tests/connections/test_factory.py:107,109`
- Modify: `tests/connections/test_errors.py:129-130`

- [ ] **Step 1: Seed the transport branch**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-transport
git fetch origin && git switch develop && git pull --ff-only
git switch -c feature/oauth2-collapse
```

- [ ] **Step 2: Remove the import and the reject-tuple member**

In `src/mountainash_transport/connections/__init__.py`:
- Delete line 157 (`        OAuth2AuthCodeAuthProfile,`) from the auth-client import block.
- Line 163: change
  `        (OAuth2AuthProfile, OAuth2AuthCodeAuthProfile, OAuth1AuthProfile),`
  to
  `        (OAuth2AuthProfile, OAuth1AuthProfile),`.

- [ ] **Step 3: Update the factory test to the unified class**

In `tests/connections/test_factory.py`, `test_oauth2_auth_raises_unsupported` (lines
107-116):
- Line 107: `from mountainash_auth_client import OAuth2AuthCodeAuthProfile`
  → `from mountainash_auth_client import OAuth2AuthProfile`
- Line 109: `auth = OAuth2AuthCodeAuthProfile(` → `auth = OAuth2AuthProfile(`

The construction kwargs (`CLIENT_ID`, `CLIENT_SECRET`, `SCOPE`,
`SETTINGS_SOURCE_SECRETS_PROVIDER`) are all valid on `OAuth2AuthProfile`, and it is still in
the reject tuple, so the test still expects `UnsupportedAuthProfileError`.

- [ ] **Step 4: Update the stale label in the error test**

In `tests/connections/test_errors.py` lines 129-130, change the literal label
`"OAuth2AuthCodeAuthProfile"` to `"OAuth2AuthProfile"` (both occurrences). This is a plain
string passed to `UnsupportedAuthProfileError`; the change keeps the test representative of a
real profile name.

- [ ] **Step 5: Verify no references remain + run the suite**

```bash
grep -rn "OAuth2AuthCodeAuthProfile" src tests   # expect: no output
hatch run test:test-quick -q
```
Expected: grep silent (exit 1); all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/mountainash_transport/connections/__init__.py \
        tests/connections/test_factory.py tests/connections/test_errors.py
git commit -m "fix: drop removed OAuth2AuthCodeAuthProfile from transport reject set + tests"
```

---

## Task 7: Coordinated verification and the four PRs

Run the full suites across the workspace, assert the rename is total, then open one PR per
repo (each to its own `develop`) so the set lands together.

- [ ] **Step 1: Workspace-wide grep gates (run from the workspace root)**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash
grep -rn "OAuth2AuthCodeAuthProfile\|OAUTH2_AUTHCODE\|oauth2_authcode" \
  mountainash-auth-client/src mountainash-auth-client/tests mountainash-auth-client/docs \
  mountainash-data/src mountainash-data/tests \
  mountainash-wearables/src mountainash-wearables/tests \
  mountainash-transport/src mountainash-transport/tests
```
Expected: no output (exit code 1) — the collapsed type (and its mention in docs) is gone
everywhere.

- [ ] **Step 1B: Audit persisted config / secret stores for deleted keys**

Hard deletion of `TOKEN` (OAuth2), `SERVER_URI`, `TOKEN_EXPIRES_AT`, and the
`oauth2_authcode` discriminator means any persisted profile/secret/env keyed on those names
fails loudly on load. That is the intended behaviour — but it must be a *known*, audited
outcome, not a surprise in production. Search the non-repo config and secret surfaces the
workspace actually uses (filesystem secret stores, env files, deployment config), e.g.:

```bash
grep -rni "oauth2_authcode\|TOKEN_EXPIRES_AT\|SERVER_URI" \
  ~/.config 2>/dev/null
# plus any deployment/secret-store locations this workspace uses (filesystem secret
# store dirs, .env files, infra config repos) — enumerate them explicitly here.
```
For the OAuth2 `TOKEN → ACCESS_TOKEN` rename, also check stored token records: live tokens
live in the token-store *record* (`access_token`/`token_expires_at` keys — unaffected), but
any persisted *credential profile* that set the schema field `TOKEN` must be re-keyed to
`ACCESS_TOKEN`.
Expected outcome: either no hits, or an explicit migration note per hit. **Record the audit
result in the auth-client PR description** so the loud-failure risk is an accepted decision,
not an unverified gap. (If the workspace has no persisted profiles for these providers yet,
state that — it is the common case here and closes the finding.)

```bash
grep -rn "OAuth2AuthProfile(.*\bTOKEN=" \
  mountainash-auth-client mountainash-data mountainash-wearables mountainash-transport
```
Expected: no output — no construction still uses the old `TOKEN=` kwarg on `OAuth2AuthProfile`.

- [ ] **Step 2: Full suites, all four repos**

```bash
( cd mountainash-auth-client && hatch run test:test )
( cd mountainash-data        && hatch run test:test-quick -q )
( cd mountainash-wearables   && hatch run test:test-quick -q )
( cd mountainash-transport   && hatch run test:test-quick -q )
```
Expected: all green. (Use each repo's actual full-suite command if it differs.)

- [ ] **Step 3: Push and open the four PRs (each to its repo's `develop`)**

```bash
( cd mountainash-auth-client && git push -u origin feature/oauth-phase2-credential-deweave && \
  gh pr create --base develop \
    --title "OAuth split Phase 2: collapse OAuth2 classes, rename TOKEN->ACCESS_TOKEN" \
    --body "Unifies OAuth2AuthProfile (one class), hard-renames TOKEN->ACCESS_TOKEN (no alias), deletes dead SERVER_URI/TOKEN_EXPIRES_AT, removes OAuth2AuthCodeAuthProfile/OAUTH2_AUTHCODE. SCOPE stays on the credential (per-user grant data); the flow's auth_profile.SCOPE reads are unchanged. Coordinated with data/wearables/transport PRs — land together.

See docs/superpowers/specs/2026-06-29-oauth-phase2-credential-deweave-design.md.

🤖 Generated with [Claude Code](https://claude.com/claude-code)" )

( cd mountainash-data && git push -u origin feature/oauth2-access-token-rename && \
  gh pr create --base develop \
    --title "Snowflake oauth2 adapter: OAuth2AuthProfile.ACCESS_TOKEN" \
    --body "Follows auth-client OAuth Phase 2 TOKEN->ACCESS_TOKEN rename. Only the snowflake oauth2 adapter changes; TokenAuthProfile.TOKEN readers are untouched.

🤖 Generated with [Claude Code](https://claude.com/claude-code)" )

( cd mountainash-wearables && git push -u origin feature/oauth2-collapse && \
  gh pr create --base develop \
    --title "Repoint WearableOAuth2Auth to unified OAuth2AuthProfile" \
    --body "Follows auth-client OAuth Phase 2 class collapse. SCOPE override unchanged; drops dead TOKEN_EXPIRES_AT assertion.

🤖 Generated with [Claude Code](https://claude.com/claude-code)" )

( cd mountainash-transport && git push -u origin feature/oauth2-collapse && \
  gh pr create --base develop \
    --title "Drop removed OAuth2AuthCodeAuthProfile from reject set" \
    --body "Follows auth-client OAuth Phase 2 class collapse. OAuth2AuthProfile remains rejected; behaviour unchanged.

🤖 Generated with [Claude Code](https://claude.com/claude-code)" )
```

- [ ] **Step 4: Note the merge coordination in each PR**

Add a comment on each PR linking the other three and stating they must merge together
(auth-client first or simultaneously) so no consumer builds against a half-migrated
auth-client. `gh pr comment <url> --body "Coordinated landing — see #<n> (auth-client), #<n>
(data), #<n> (wearables), #<n> (transport). Merge together."`

---

## Self-Review

**1. Spec coverage** (against `2026-06-29-oauth-phase2-credential-deweave-design.md`):
- §2 / §2a SCOPE stays on credential, flow reads unchanged → Global Constraints + Task 1 (no
  flow edit); §2b SERVER_URI/TOKEN_EXPIRES_AT deleted as dead → Task 1 (SERVER_URI), Task 2
  removes the authcode module that held TOKEN_EXPIRES_AT.
- §3 collapse to one `OAuth2AuthProfile` (`…, SCOPE`) → Task 1 + Task 2.
- §4 hard rename `TOKEN → ACCESS_TOKEN`, no alias → Task 1; consumer rename → Task 4.
- §5 file-level list (merge into oauth2.py, delete oauth2_authcode.py, constants/__init__/
  connection edits, adapter→ACCESS_TOKEN, the `oauth/lifecycle/oauth2.py` optional-secret
  guard, INTEGRATION.md, tests) → Tasks 1, 1B, 2, 3 (registry needs no edit — registration
  is decorator-driven; noted in Task 2).
- §7 consumers: data `.TOKEN→.ACCESS_TOKEN` (Task 4), wearables base repoint + SCOPE
  unchanged + drop TOKEN_EXPIRES_AT assert (Task 5), transport reject-set drop (Task 6).
- §8 decisions: hard removal of the public type + atomic landing → Task 2 + Task 7;
  client-secret requiredness is flow-dependent/optional, guarded in the flow → Task 1B;
  persisted-config/secret-store audit for deleted keys → Task 7 Step 1B.
- §9 verification (collapsed class round-trips emit/registry; cross-repo green) → Task 1
  Step 2 round-trip test, Task 7 Steps 1-2.

**2. Placeholder scan:** No TBD/TODO; every code/command step shows exact content. ✓
(§6 doc-guide amendments in mountainash-central are intentionally out of scope for this
*code* plan — they are doc edits tracked in the spec, not implementation tasks here. Flagged
here so they are not forgotten: land them with the auth-client PR or a follow-up docs PR.)

**3. Type/name consistency:** The unified `OAuth2AuthProfile` field set
(`CLIENT_ID, CLIENT_SECRET, ACCESS_TOKEN, REFRESH_TOKEN, SCOPE`) defined in Task 1 Step 4 is
exactly what Tasks 4-6 construct/read (`ACCESS_TOKEN`, `SCOPE`). The adapter
`_bearer_from_access_token` reads `ACCESS_TOKEN`, matching the field. No reference to the
deleted `TOKEN`/`SERVER_URI`/`TOKEN_EXPIRES_AT`/`OAuth2AuthCodeAuthProfile`/`OAUTH2_AUTHCODE`
survives (Task 2 Step 7 + Task 7 Step 1 gates). ✓

## Open follow-up (not in this plan)

The spec's §6 guide amendments (`auth-connection-layering.md` smell #1 narrowing;
`oauth-settings-ops-split.md` wording; adapter-governance + OAuth1-exception notes) live in
`mountainash-central` docs. They are doc-only and should land with, or just after, this PR
set — track separately.

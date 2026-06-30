# Design — OAuth Split Phase 2: Credential De-weave

**Date:** 2026-06-29
**Repo:** mountainash-auth-client
**Status:** Design — decisions locked (token field hard-renamed; SCOPE stays on the
credential; collapsed type hard-removed). Ready for planning.
**Phase:** 2 of 3 (depends on Phase 1 landing first)
**Companion phases:** `2026-06-29-oauth-phase1-module-move-design.md`,
`2026-06-29-oauth-phase3-l4-purity-design.md`

---

## 1. Goal

Remove **OAuth protocol policy** from the credential schema so an OAuth2 credential is
generic data again — not "an HTTP-OAuth client." Two moves:

1. **Evict** provider coordinates and live token state off the schema.
2. **Collapse** the two near-duplicate OAuth2 classes into one.

The `__adapters__`/`emit(target)` rendering **stays** — that is reuse, not policy
(architect ruling 2026-06-28). Only *policy* fields and the redundant *flow split* move.

## 2. What is policy vs data (the dividing line)

| Field | Today | Verdict | Destination |
|---|---|---|---|
| `CLIENT_ID`, `CLIENT_SECRET`, `REFRESH_TOKEN` | both schemas | data | stays in `schemas/` |
| access token (`TOKEN` / `ACCESS_TOKEN`) | split name | data | stays, canonical `ACCESS_TOKEN` (§4) |
| `SCOPE` | `schemas/oauth2.py:32`, authcode `:33` | **per-grant data** | **stays in `schemas/`** — see §2a |
| `SERVER_URI` | `schemas/oauth2.py:31` | dead field | **DELETE** — read by nothing (see §2b) |
| `TOKEN_EXPIRES_AT` | `schemas/oauth2_authcode.py:32` | dead field | **DELETE** — read by nothing (see §2b) |
| authcode-vs-client-credentials *flow split* | two classes | flow policy | selected by `oauth/providers/` profile |

### 2a. SCOPE stays on the credential (DECISION — 2026-06-29)

`SCOPE` is **per-grant data**, not protocol machinery, and **stays on the credential**.
A credential is per-user; scope co-varies per-user/per-role; the access token was *granted
for* a particular scope. That makes scope the same category of fact as `CLIENT_ID` /
`REFRESH_TOKEN` (kept), not the same as `SERVER_URI` (an IdP coordinate). It decomposes
into two layers that the code **already** implements correctly:
- **provider default scope** → `OAuth2ProviderProfile.DEFAULT_SCOPE` (the fallback).
- **per-user requested/granted scope** → `OAuth2AuthProfile.SCOPE` on the credential (the
  override). In use today: wearables sets `OuraProfile(… SCOPE="read")`; each provider
  profile sets `DEFAULT_SCOPE` (e.g. Strava `"read,activity:read_all"`).

The flow already sources the override from the credential — `flow.py:325`
(`authorize(scope=auth_profile.SCOPE)`) and `lifecycle/oauth2.py:61`
(`authorize(scope=self._auth.SCOPE)`), with `provider.DEFAULT_SCOPE` as the fallback
(`flow.py:59`). **This is correct and unchanged in Phase 2.** The earlier A/B mechanism
fork and the "CRITICAL ordering fix" (rewiring those reads) are **withdrawn**: there is no
eviction, so nothing to rewire.

### 2b. SERVER_URI and TOKEN_EXPIRES_AT are dead — delete, don't relocate

Both fields are read by **nothing** (`grep` across auth-client / data / wearables /
transport `src`):
- `SERVER_URI` — the provider profile already carries the real endpoints
  (`AUTHORIZE_URL` / `TOKEN_URL`); the credential's `SERVER_URI` is vestigial. `mountainash-data`'s
  snowflake adapter even documents that it ignores it.
- `TOKEN_EXPIRES_AT` — live token expiry lives in the **token-store record**, managed by
  lifecycle; the credential field is never read.

So "evict" here means **delete the dead `ParameterSpec`**, not move it. A persisted config
that set either key fails loudly on load (acceptable, per §4's no-silent-survival ruling) —
but neither is expected in real configs (both `tier="advanced"`, `default=None`).

## 3. Collapse

`OAuth2AuthProfile` + `OAuth2AuthCodeAuthProfile` → **one** `OAuth2AuthProfile`:

```
OAuth2AuthProfile: CLIENT_ID, CLIENT_SECRET, ACCESS_TOKEN, REFRESH_TOKEN, SCOPE
__adapters__ = {TargetFamily.HTTP: _bearer_from_access_token}   # reads ACCESS_TOKEN
```

`SCOPE` stays (§2a, per-grant data). `SERVER_URI` and `TOKEN_EXPIRES_AT` are dropped
(§2b, dead fields). Name retained (`OAuth2AuthProfile`) — `mountainash-data` imports it by
name and keys its adapter registry on it. The flow difference (client-credentials vs
authorization-code) is selected by the provider profile in `oauth/providers/`, which
already carries `AUTHORIZE_URL`/`TOKEN_URL`/`USE_PKCE`/`BASE_URL`/`DEFAULT_SCOPE`/
`CALLBACK_PORT` (`OAuth2ProviderProfileProtocol`) — the credential carries none of it.

## 4. Token field — canonical `ACCESS_TOKEN`, hard rename (DECIDED)

`TOKEN` (client-credentials schema) and `ACCESS_TOKEN` (authcode schema) are the same
fact under two names — over-specification. Collapse to one canonical field,
`ACCESS_TOKEN` (RFC 6749).

**DECISION (architect, 2026-06-29): hard rename, no alias.** The credential carries one
canonical field. **No compatibility alias.** The governing principle:

> A consumer that needs a different **shape or name** for the emit kwargs creates an
> **adapter** — it does not push a compat field/alias onto the generic credential.

Aliasing would re-enshrine the two-name accident and smuggle consumer vocabulary back
onto the credential — the opposite of this phase's goal. Per-consumer naming (snowflake
`token=`) already lives where it belongs: `mountainash-data`'s L3 adapter.

**Execution consequence (not a reopening):** the rename breaks any reader of the old
name. Two kinds, both handled in the coordinated landing:
- **Code** — `mountainash-data` `adapters/snowflake.py:23,28` `.TOKEN → .ACCESS_TOKEN`;
  its test `OAuth2AuthProfile(TOKEN="t") → ACCESS_TOKEN`.
- **Persisted config/secrets** — audit for any store/env keyed on the literal `TOKEN`
  field; migrate the key to `ACCESS_TOKEN`. Loud validation failure on an un-migrated key
  is **acceptable and intended** (no silent survival).

## 5. File-level change list (auth-client)

| Action | Path |
|---|---|
| merge | `schemas/oauth2.py` + `schemas/oauth2_authcode.py` → single `schemas/oauth2.py` (`OAuth2AuthProfile`) |
| delete | `schemas/oauth2_authcode.py` (`OAuth2AuthCodeAuthProfile`) |
| none | `schemas/registry.py` — **no edit**: registration is `@register`-decorator-driven; deleting the module + its `schemas/__init__.py` import removes the `oauth2_authcode` entry |
| edit | `constants.py` — drop `OAUTH2_AUTHCODE` from `CONST_AUTH_PROFILES` |
| edit | `oauth/lifecycle/oauth2.py` — guard the `authorize()` call for an optional `CLIENT_SECRET` (mirror `flow.py`'s `TOKEN_ENDPOINT_AUTH_METHOD` handling); the collapse drops the old authcode required-secret guarantee |
| edit | `__init__.py` — drop (or alias) `OAuth2AuthCodeAuthProfile` export + `__all__` |
| none | `SCOPE` **stays** on `OAuth2AuthProfile`; `flow.py:325` / `lifecycle/oauth2.py:61` keep reading `auth_profile.SCOPE` **unchanged** (§2a) — no rewire |
| delete | `SERVER_URI` and `TOKEN_EXPIRES_AT` `ParameterSpec`s (§2b, dead fields) — provider/lifecycle already own the live equivalents; nothing to relocate |
| edit | adapter fn → read `ACCESS_TOKEN` (was `_bearer_from_token` on `TOKEN`) |
| edit | `docs/INTEGRATION.md` — catalogue rows 129–130, `CONST_AUTH_PROFILES` line 136 |
| update | tests asserting `OAuth2AuthCodeAuthProfile` / `TOKEN` / evicted fields |

## 6. Doc amendments (carried here)

- **`mountainash/docs/guides/auth-connection-layering.md` smell #1** — narrow to OAuth
  *protocol policy* only (`SERVER_URI`/`TOKEN_EXPIRES_AT`/flow-split — **not** `SCOPE`,
  which is per-grant credential data per §2a); state that generic
  `emit(target)`/`__adapters__` rendering is the sanctioned L3-reuse mechanism, not a smell.
- **`mountainash/docs/guides/oauth-settings-ops-split.md`** — replace "strip the
  `__adapters__` Bearer renderers" with "evict OAuth protocol policy; keep generic
  rendering."
- Add an **adapter-governance** note (Codex): which target families may live on generic
  schemas; provider/driver-specific renderers may **not**.
- **Name the OAuth1 exception explicitly** so "L4 purity" is not over-read: OAuth1's
  `_oauth1_signer` returns an HTTP-runtime `httpx.Auth`, not a pure dict — it is the one
  schema renderer that is HTTP-runtime-shaped (and the one relocated in Phase 1). The
  guide amendment must call this out as a scoped, contract-pinned exception
  (`mountainash-http-client/tests/.../test_oauth1_httpx_contract.py`).

## 7. Consumer impact (downstream — coordinated)

- **mountainash-data** — reads `.TOKEN` (`adapters/snowflake.py:23,28`); test builds
  `OAuth2AuthProfile(TOKEN="t")`. Change both to `ACCESS_TOKEN` (hard rename, no alias).
  Registry key `(SNOWFLAKE, OAuth2AuthProfile)` unchanged (name retained).
- **mountainash-wearables** — `WearableOAuth2Auth` subclasses `OAuth2AuthCodeAuthProfile`
  (`auth_identity.py:3,10`). Repoint base to `OAuth2AuthProfile`. The per-user `SCOPE`
  override is **unchanged** (it stays on the credential, §2a) — `OuraProfile(… SCOPE="read")`
  in `test_auth_identity.py:18` and `test_config.py:65` keeps working. Only one test edit:
  `test_auth_identity.py:13` asserts the inherited field-set includes `TOKEN_EXPIRES_AT` —
  drop that name from the tuple (the field is deleted; nothing reads it). `SCOPE` remains
  in the tuple. (Garmin's `ACCESS_TOKEN`/`ACCESS_TOKEN_SECRET` are a separate descriptor —
  unaffected.)
- **mountainash-transport** — imports `OAuth2AuthCodeAuthProfile` for an isinstance
  reject; drop to `OAuth2AuthProfile`.

## 8. Risks & decisions

- **Token-field migration** (§4) — DECIDED: hard rename `TOKEN → ACCESS_TOKEN`, no alias.
- **Collapse removes a public type** (`OAuth2AuthCodeAuthProfile`, `OAUTH2_AUTHCODE`) —
  serialized profile-name lookups and subclass imports break. **DECIDED (2026-06-29): hard
  removal, no deprecated alias** — consistent with the no-alias token-field ruling and the
  atomic multi-repo landing. Repoint data/wearables/transport in the same coordinated set;
  migrate any persisted `OAUTH2_AUTHCODE` discriminator to `oauth2`. Loud validation
  failure on an un-migrated key is intended (no silent survival).
- **`SCOPE` retained** (§2a) — the per-user override stays on the credential; no eviction,
  no A/B mechanism, no flow rewire. This removes the only previously-open design fork.
- **Client-credential requiredness is flow-dependent, so it stays optional on the
  credential** (DECISION 2026-06-29). The unified `OAuth2AuthProfile` serves both grants,
  and the `TOKEN_ENDPOINT_AUTH_METHOD="none"` (public-client) case legitimately has no
  `CLIENT_ID`/`CLIENT_SECRET` — so requiredness cannot be a static field constraint. It is
  enforced (where needed) by the **flow**. Collapsing the classes drops the old authcode
  schema's required-secret guarantee, which newly exposes `OAuth2TokenManager.authorize()`'s
  **unconditional** `self._auth.CLIENT_SECRET.get_secret_value()` (`oauth/lifecycle/oauth2.py`)
  to an `AttributeError` on a `None` secret. `OAuthFlow.resolve_access_token()` already
  guards this via `TOKEN_ENDPOINT_AUTH_METHOD`; the manager must be made consistent
  (guard + tests). This is in-scope for Phase 2 because the collapse introduces the
  exposure.
- **Persisted-config / secret-store audit** — hard deletion of `TOKEN`/`SERVER_URI`/
  `TOKEN_EXPIRES_AT` fields and the `oauth2_authcode` discriminator can fail loudly on any
  store/env/config keyed on the old names. Loud failure is intended (no silent survival),
  but the landing must **audit** the secret stores and config sources for those literal
  keys (not just repo `src`/`tests`) and migrate or accept the failure explicitly.

## 9. Verification

- auth-client suite green; the collapsed class round-trips (construct, `emit(HTTP)`
  renders Bearer from `ACCESS_TOKEN`, registry resolves).
- Cross-repo: data + wearables + transport suites green in the coordinated set.

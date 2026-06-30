# OAuth Split Phase 3: L4 Purity — Implementation Plan (auth-client)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make auth-client supply L2 data + token *acquisition* only — promote the lifecycle
manager to the public `acquire()`/`refresh()` seam returning a `TokenCredential`, and retire
the `httpx.Client`-building `OAuth2Connection`/`OAuth1Connection`. The consumer renders the
token (reusing the shipped `emit(HTTP)`); http-client builds the client (Phase 4 seam).

**Architecture:** This is the auth-client half of Phase 3. The capability stays here
(`acquire()`/`refresh()`); the *when* (proactive/reactive) is Phase 4; the *consumer rewire*
(wearables) is its own spec (§10 of the design). The three land **coordinated**.

**Tech Stack:** Python 3.12, hatch, pydantic v2, pytest. Depends on Phases 1+2 merged
(paths under `oauth/`; `ACCESS_TOKEN` field; lazy `__init__`).

## Global Constraints

- **Precondition:** Phases 1+2 merged (OAuth ops under `oauth/`, lazy `__init__`, unified
  `OAuth2AuthProfile` with `ACCESS_TOKEN`, the Task 1B optional-`CLIENT_SECRET` guard).
- **`acquire()` is non-interactive in the request path** (Codex #6): it resolves
  (refresh-if-stale) or **raises `AuthorizationRequired`**; it never launches the interactive
  authorize dance. Interactive `authorize()` stays the existing explicit, out-of-band method.
- **Single-flight preserved:** the per-key transaction + locked-record re-check in
  `resolve_access_token` (`oauth/oauth2/flow.py ~272-309`) is the refresh serialization — do
  not bypass it. `acquire()` reuses it.
- **`TokenCredential.token_type` is synthesized `"Bearer"`** (not stored — the record has no
  `token_type`; these flows are Bearer-only).
- **Inherited invariants:** the promoted seam preserves the per-user `SCOPE` reads and the
  guarded optional-`CLIENT_SECRET` call (Phase 2 Task 1B) — do not revert.
- **Coordinated landing (3 efforts):** this auth-client PR + Phase 4 (http-client seam) + the
  wearables rewire (separate spec). The connection retirement (Task 2) **breaks wearables**
  until its rewire lands — they merge together. Never push to `develop`/`main`.
- **Tests:** `hatch run test:test-quick` (fast), `hatch run test:test` (full), `hatch run
  ruff:check`. Commit after every task.
- **Branch:** `feature/oauth-phase3-l4-purity` off `develop`; PR to `develop`.

---

## Branch Setup

- [ ] **Seed off `develop`, green baseline.**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git fetch origin && git switch develop && git pull --ff-only
git switch -c feature/oauth-phase3-l4-purity
hatch run test:test-quick -q
```
Expected: all tests pass.

---

## Task 1: Add `TokenCredential` + the `acquire()`/`refresh()` seam (OAuth2)

Introduce the frozen ops-output value object and promote `OAuth2TokenManager` to return it.
`acquire()` resolves non-interactively and reads the persisted record; `refresh()` forces a
refresh then returns the credential.

**Files:**
- Create: `src/mountainash_auth_client/oauth/lifecycle/credential.py` (`TokenCredential`)
- Modify: `src/mountainash_auth_client/oauth/lifecycle/oauth2.py` (`acquire()`/`refresh()`)
- Test: `tests/oauth/lifecycle/test_token_credential.py`
- Test: `tests/oauth/lifecycle/test_oauth2_manager.py` (append `acquire`/`refresh` cases)

**Interfaces:**
- Produces: `TokenCredential` (frozen: `access_token: str`, `token_type: str = "Bearer"`,
  `expires_at: int | None`, `refresh_token: str | None`) with
  `TokenCredential.from_record(record: dict) -> TokenCredential`.
  `OAuth2TokenManager.acquire() -> TokenCredential` (non-interactive resolve + record read);
  `OAuth2TokenManager.refresh() -> TokenCredential` (force refresh + record read).

- [ ] **Step 1: Write the `TokenCredential` test (failing)**

Create `tests/oauth/lifecycle/test_token_credential.py`:

```python
from __future__ import annotations

from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential


def test_from_record_maps_store_keys():
    cred = TokenCredential.from_record(
        {"access_token": "at", "token_expires_at": 1900000000, "refresh_token": "rt"}
    )
    assert cred.access_token == "at"
    assert cred.expires_at == 1900000000
    assert cred.refresh_token == "rt"
    assert cred.token_type == "Bearer"   # synthesized, not stored


def test_from_record_tolerates_missing_optionals():
    cred = TokenCredential.from_record({"access_token": "at"})
    assert cred.expires_at is None and cred.refresh_token is None


def test_is_frozen():
    import dataclasses
    import pytest
    cred = TokenCredential.from_record({"access_token": "at"})
    with pytest.raises(dataclasses.FrozenInstanceError):
        cred.access_token = "x"
```

- [ ] **Step 2: Run — verify FAIL**

Run: `hatch run test:test-quick -q tests/oauth/lifecycle/test_token_credential.py`
Expected: FAIL — module `credential` does not exist.

- [ ] **Step 3: Implement `TokenCredential`**

Create `src/mountainash_auth_client/oauth/lifecycle/credential.py`:

```python
"""TokenCredential — the frozen token *output* of the OAuth2 acquisition seam.

A typed view of the token-store record (keys access_token / token_expires_at /
refresh_token). NOT a persisted credential schema — live token state is ops-managed
(Phase 2 evicted TOKEN_EXPIRES_AT from the schema). token_type is synthesized Bearer
(the record carries no token_type; these flows are Bearer-only).
"""
from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class TokenCredential:
    access_token: str
    token_type: str = "Bearer"
    expires_at: int | None = None
    refresh_token: str | None = None

    @classmethod
    def from_record(cls, record: dict) -> "TokenCredential":
        return cls(
            access_token=record["access_token"],
            expires_at=record.get("token_expires_at"),
            refresh_token=record.get("refresh_token"),
        )
```

- [ ] **Step 4: Run — verify PASS**

Run: `hatch run test:test-quick -q tests/oauth/lifecycle/test_token_credential.py`
Expected: PASS.

- [ ] **Step 5: Write the `acquire()`/`refresh()` manager tests (failing)**

Append to `tests/oauth/lifecycle/test_oauth2_manager.py` (reuses `_env`, `_provider`,
`_Auth`):

```python
from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential


def test_acquire_returns_token_credential():
    mgr, tokens = _env()
    tokens.set("testprovider.default",
               {"access_token": "tok", "refresh_token": "rt",
                "token_expires_at": int(time.time()) + 4000})
    cred = mgr.acquire()
    assert isinstance(cred, TokenCredential)
    assert cred.access_token == "tok"
    assert cred.refresh_token == "rt"


def test_acquire_raises_when_no_token_non_interactive():
    from mountainash_auth_client.errors import AuthorizationRequired
    mgr, _ = _env()                      # empty store, no refresh token
    with pytest.raises(AuthorizationRequired):
        mgr.acquire()                    # must NOT launch interactive authorize
```

- [ ] **Step 6: Run — verify FAIL**

Run: `hatch run test:test-quick -q tests/oauth/lifecycle/test_oauth2_manager.py -k acquire`
Expected: FAIL — `OAuth2TokenManager` has no `acquire`.

- [ ] **Step 7: Implement `acquire()`/`refresh()`**

In `src/mountainash_auth_client/oauth/lifecycle/oauth2.py`, add the import and methods
(keep `access_token()`, `status()`, `revoke()`, `authorize()` as-is):

```python
from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential
```
```python
    def acquire(self) -> TokenCredential:
        """Resolve a valid access token (refresh-if-stale) and return it as a
        TokenCredential. Non-interactive: raises AuthorizationRequired when no usable
        token exists — it never launches the interactive authorize dance.
        """
        flow = self._flow_cls()(self._provider, resolver=self._resolver)
        flow.resolve_access_token(self._auth, auto_authorize=False)   # refresh-or-raise, single-flight
        return self._credential()

    def refresh(self) -> TokenCredential:
        """Force a refresh under the per-key transaction, then return the credential."""
        flow = self._flow_cls()(self._provider, resolver=self._resolver)
        flow.resolve_access_token(self._auth, auto_authorize=False)
        return self._credential()

    def _credential(self) -> TokenCredential:
        backend = self._store()
        key = self._auth.persist_key()
        with backend.transaction(key):
            record = backend.get(key)
        if not record or not record.get("access_token"):
            from mountainash_auth_client.errors import AuthorizationRequired
            raise AuthorizationRequired(self._auth.persist_key())
        return TokenCredential.from_record(record)
```

> Note: `refresh()` changes return type from `TokenStatus` to `TokenCredential` (Phase 3 §3).
> If any in-repo caller relied on the old `TokenStatus` return, it is updated here — verify in
> Step 9. `resolve_access_token(..., auto_authorize=False)` is the non-interactive,
> single-flight path; this preserves the Phase 2 `SCOPE`/`CLIENT_SECRET`-guard invariants
> (they live in the flow it calls).

- [ ] **Step 8: Run the `acquire`/`refresh` tests — verify PASS**

Run: `hatch run test:test-quick -q tests/oauth/lifecycle/test_oauth2_manager.py`
Expected: PASS.

- [ ] **Step 9: Full suite (catch `refresh()` return-type callers) + lint**

Run: `hatch run test:test-quick -q && hatch run ruff:check`
Expected: green. If a test asserted the old `refresh() -> TokenStatus`, update it to the
`TokenCredential` contract (present the change; do not weaken the test).

- [ ] **Step 10: Commit**

```bash
git add src/mountainash_auth_client/oauth/lifecycle/credential.py \
        src/mountainash_auth_client/oauth/lifecycle/oauth2.py \
        tests/oauth/lifecycle/test_token_credential.py \
        tests/oauth/lifecycle/test_oauth2_manager.py
git commit -m "feat(lifecycle): add TokenCredential + non-interactive acquire()/refresh() seam (OAuth2)"
```

---

## Task 2: OAuth1 acquire-signer seam

OAuth1 application is per-request *signing*, not a Bearer header (Phase 3 §4). Expose the
`httpx.Auth` signer via the manager, reusing the schema's relocated `_oauth1_signer`
(`emit(HTTP)` on `OAuth1AuthProfile`).

**Files:**
- Modify: `src/mountainash_auth_client/oauth/lifecycle/oauth1.py` (`acquire_auth()`)
- Test: `tests/oauth/lifecycle/test_oauth1_manager.py` (append)

**Interfaces:**
- Produces: `OAuth1TokenManager.acquire_auth() -> httpx.Auth` — resolves the token pair
  (single-flight) and returns the authlib signer, for the consumer's `RequestCreds.auth`.

- [ ] **Step 1: Write the failing test**

Append to `tests/oauth/lifecycle/test_oauth1_manager.py` (mirror its existing seam-patching
style; `pytest.importorskip("authlib.integrations.httpx_client")` since the signer needs the
`[oauth1]` extra):

```python
def test_acquire_auth_returns_httpx_auth(monkeypatch):
    import pytest
    OAuth1Auth = pytest.importorskip("authlib.integrations.httpx_client").OAuth1Auth
    mgr, _ = _env()   # the file's env helper
    monkeypatch.setattr(type(mgr), "token_pair", lambda self: ("tok", "tok_secret"))
    auth = mgr.acquire_auth()
    assert isinstance(auth, OAuth1Auth)
```
(If `test_oauth1_manager.py` has no `_env`, construct the manager as its other tests do.)

- [ ] **Step 2: Run — verify FAIL**

Run: `hatch run test:test-quick -q tests/oauth/lifecycle/test_oauth1_manager.py -k acquire_auth`
Expected: FAIL — no `acquire_auth`.

- [ ] **Step 3: Implement `acquire_auth()`**

In `src/mountainash_auth_client/oauth/lifecycle/oauth1.py`, add:

```python
    def acquire_auth(self):
        """Resolve the OAuth1 token pair and return the httpx.Auth signer.

        OAuth1 is per-request signing, not a Bearer header — the consumer applies this
        via RequestCreds(auth=...). Reuses the schema's _oauth1_signer through emit(HTTP).
        """
        from mountainash_auth_client.targets import TargetFamily
        token, secret = self.token_pair()
        signer_profile = type(self._auth)(
            CONSUMER_KEY=self._auth.CONSUMER_KEY,
            CONSUMER_SECRET=self._auth.CONSUMER_SECRET.get_secret_value(),
            ACCESS_TOKEN=token,
            ACCESS_TOKEN_SECRET=secret,
            SETTINGS_SOURCE_SECRETS_PROVIDER=self._auth.SETTINGS_SOURCE_SECRETS_PROVIDER,
        )
        return signer_profile.emit(TargetFamily.HTTP)["auth"]
```

> This reuses the 1:M `_oauth1_signer` renderer rather than re-hand-rolling signing. If the
> concrete `OAuth1AuthProfile` subclass constructor differs, build the smallest profile that
> `emit(HTTP)` accepts (the test pins the contract).

- [ ] **Step 4: Run — verify PASS, then suite + lint + commit**

```bash
hatch run test:test-quick -q tests/oauth/lifecycle/test_oauth1_manager.py
hatch run test:test-quick -q && hatch run ruff:check
git add src/mountainash_auth_client/oauth/lifecycle/oauth1.py tests/oauth/lifecycle/test_oauth1_manager.py
git commit -m "feat(lifecycle): OAuth1 acquire_auth() returns the httpx.Auth signer"
```

---

## Task 3: Retire `OAuth2Connection` / `OAuth1Connection`

Delete the `httpx.Client`-building connection classes and their exports/tests. **This breaks
downstream `OAuth2Connection` importers (wearables) until their rewire lands** — it is part
of the coordinated set (see Task 5).

**Files:**
- Delete: `src/mountainash_auth_client/oauth/oauth2/connection.py`, `src/mountainash_auth_client/oauth/oauth1/connection.py`
- Modify: `src/mountainash_auth_client/oauth/oauth2/__init__.py`, `src/mountainash_auth_client/oauth/oauth1/__init__.py` (drop the connection re-exports)
- Modify: `src/mountainash_auth_client/__init__.py` (drop `OAuth2Connection`/`OAuth1Connection` from `_LAZY` + `__all__`; add `TokenCredential`)
- Delete: `tests/oauth/test_oauth2_connection.py`, `tests/oauth/test_oauth1_connection.py` (the moved connection tests)

**Interfaces:**
- Produces: no `OAuth2Connection`/`OAuth1Connection` anywhere; `TokenCredential` exported from
  the package root (lazily — it lives under `oauth/`).

- [ ] **Step 1: Delete the connection modules + their package re-exports**

```bash
git rm src/mountainash_auth_client/oauth/oauth2/connection.py \
       src/mountainash_auth_client/oauth/oauth1/connection.py \
       tests/oauth/test_oauth2_connection.py \
       tests/oauth/test_oauth1_connection.py
```
In `oauth/oauth2/__init__.py` and `oauth/oauth1/__init__.py`, remove the
`from .connection import OAuth2Connection` / `OAuth1Connection` lines and their `__all__`
entries.

- [ ] **Step 2: Update the package-root lazy exports**

In `src/mountainash_auth_client/__init__.py`:
- In `_LAZY`, **remove** the `"OAuth2Connection"` and `"OAuth1Connection"` entries.
- **Add** `"TokenCredential": "mountainash_auth_client.oauth.lifecycle.credential"`.
- In `__all__`, remove `"OAuth2Connection"`, `"OAuth1Connection"`; add `"TokenCredential"`.

- [ ] **Step 3: Verify no references remain in auth-client**

Run: `grep -rn "OAuth2Connection\|OAuth1Connection" src tests`
Expected: no output (exit code 1).

- [ ] **Step 4: Suite + boundary test (the `TokenCredential` lazy export must not break the boundary) + lint**

Run: `hatch run test:test-quick -q && hatch run ruff:check`
Expected: green. `tests/test_public_api.py` (every `__all__` name importable) and
`tests/test_boundary.py` (schemas import stays clean) both pass — `TokenCredential` resolves
lazily; removing the connection names leaves `__all__`/`_LAZY` consistent.

- [ ] **Step 5: Commit**

```bash
git add -A src tests
git commit -m "refactor: retire OAuth2Connection/OAuth1Connection; export TokenCredential (L4 purity)"
```

---

## Task 4: Docs — `INTEGRATION.md` (resolver + acquire + emit is the path)

**Files:**
- Modify: `docs/INTEGRATION.md` (the "Connections (batteries-included)" section + Pattern 2)

- [ ] **Step 1: Replace the connection guidance with the acquire/emit path**

Remove the `OAuth2Connection(...).connect()` / `.client` example(s) (the retired API). Make
the documented integration: resolve via the lifecycle seam and render via `emit`:
```python
from mountainash_auth_client import OAuth2TokenManager, TokenAuthProfile, TargetFamily

cred = OAuth2TokenManager(provider, auth_profile, resolver=resolver).acquire()  # TokenCredential
kw = TokenAuthProfile(TOKEN=cred.access_token).emit(TargetFamily.HTTP)           # {"headers": {...}}
# hand kw to the consumer's transport (http-client HttpConfig); wire creds_provider for refresh.
```
Document the **error contract**: a use-time auth failure raises `AuthorizationRequired` /
`TokenRefreshError`; when surfaced through http-client it arrives as
`SourceAuthenticationError` and the consumer maps `__cause__` (Phase 3 §6 / Phase 4).

- [ ] **Step 2: Grep + commit**

```bash
grep -rn "OAuth2Connection\|OAuth1Connection\|\.connect()\|\.client" docs/INTEGRATION.md   # expect: none of the retired API
git add docs/INTEGRATION.md
git commit -m "docs: INTEGRATION uses the acquire()+emit seam; drop retired connection classes"
```

> `errors.py` needs **no change** — auth-client already raises the domain errors
> (`AuthorizationRequired`/`TokenRefreshError`/`TokenExchangeError`). The `__cause__` mapping
> is consumer-side (wearables) and documented where the seam is wired.

---

## Task 5: Coordinated landing — dependencies and PR

Phase 3 auth-client cannot merge alone: retiring the connections breaks wearables. Sequence
and land the set together.

- [ ] **Step 1: Confirm the dependencies are ready**

- **Phase 4** (http-client `creds_provider` + `RefreshMode`) — merged or in the same landing
  train (the wearables rewire wires `creds_provider`).
- **Wearables rewire** — its **own spec/plan** (Phase 3 design §10): move `pipelines/shared/
  fetch.py` off `.client`/header-scraping onto `creds_provider=acquire→emit→RequestCreds` with
  `refresh_mode=PROACTIVE`; replace the 5 providers' `verify()` `self.client.get(...)` with a
  one-shot http-client request; map `SourceAuthenticationError.__cause__` for reauth. Garmin
  (`garmin_connect`/`garmin_health`) is **out of scope** (own SDK/OAuth1 clients, never used
  `OAuth2Connection`). **This spec must be written and planned before the set can land.**
- **mountainash-transport** — update the user-facing guidance in `connections/errors.py`
  (`~:64`) that points callers at the retired `OAuth2Connection`/`OAuth1Connection`; redirect
  to the `acquire()` seam. (Separate transport branch/PR; Phase 1 already repointed its deep
  imports.)

- [ ] **Step 2: Push + open the auth-client PR (mark the coordination)**

```bash
git push -u origin feature/oauth-phase3-l4-purity
gh pr create --base develop \
  --title "OAuth split Phase 3: L4 purity — acquire() seam + retire connection classes" \
  --body "auth-client half of Phase 3. Adds TokenCredential + non-interactive acquire()/refresh() (single-flight, SCOPE + optional-secret invariants preserved) and OAuth1 acquire_auth() signer; retires OAuth2Connection/OAuth1Connection (httpx.Client building moves to the consumer + http-client).

COORDINATED LANDING — do not merge alone: breaks wearables until its rewire lands. Depends on Phase 4 (http-client creds seam) and the wearables rewire spec; transport errors.py guidance updates separately.

See docs/superpowers/specs/2026-06-29-oauth-phase3-l4-purity-design.md.

🤖 Generated with [Claude Code](https://claude.com/claude-code)" )
```

- [ ] **Step 3: Link the coordinated PRs**

Comment on each PR (auth-client / http-client Phase 4 / wearables rewire / transport) linking
the others and stating they merge together.

---

## Self-Review

**1. Spec coverage** (against `2026-06-29-oauth-phase3-l4-purity-design.md`):
- §3 public seam `acquire()`/`refresh()` (no httpx.Client) → Task 1 (OAuth2), Task 2 (OAuth1).
- §4 `TokenCredential` (synthesized Bearer; maps from record) → Task 1 Steps 1-4; OAuth1
  signer return → Task 2.
- §5 capability/non-interactive/single-flight/SCOPE+secret invariants → Task 1 Step 7 + the
  Global Constraints.
- §6 error contract (`__cause__`, errors.py unchanged) → Task 4 Step 1 note.
- §7 `.client` retirement (live contract; Garmin carve-out) → Task 3 + Task 5 Step 1.
- §8 file list (delete connections, add TokenCredential + seam, __init__, INTEGRATION) →
  Tasks 1-4.
- §10 consumer impact (wearables rewire as its own spec; transport guidance) → Task 5.
- §11/§12 coordinated 3-repo landing, Phase 4 dependency → Task 5.

**2. Placeholder scan:** none — exact paths/code/commands. The OAuth1 `acquire_auth()`
profile construction is pinned by its test (Task 2 Step 1); the wearables rewire is correctly
scoped to its **own** spec (not stubbed here) per design §10.

**3. Type/name consistency:** `TokenCredential` fields/`from_record`, `acquire()`/`refresh()`
→ `TokenCredential`, `acquire_auth()` → `httpx.Auth`, `_LAZY`/`__all__` edits, and the record
keys (`access_token`/`token_expires_at`/`refresh_token`) are consistent across tasks and match
the Phase 1 lazy-`__init__` and the Phase 2 `ACCESS_TOKEN`/guard work.

## Dependency note (must precede the landing)

The **wearables rewire spec** (design §10) is a prerequisite artifact this plan does not
contain — it is its own brainstorm → spec → plan. Write it before executing Task 5 so the
coordinated set can land without leaving wearables on the retired `.client`.

# Connections Dedup — auth-client as the single source of truth for OAuth flow + callback servers

**Status:** Draft for review (fresh spec; not yet planned). Spans **two repos**: `mountainash-auth-client` (prerequisite) and `mountainash-utils-files` (transport).

**Date:** 2026-06-13

**Related:** memory `project_auth_client_source_of_truth`; follows Phase 3 (`2026-06-13-unified-emission-phase3-transport` / transport PR #70). Independent of Phase 4 (storage emission).

---

## Problem

Transport carries its own copies of the OAuth-flow / callback-server / protocol layer that `mountainash-auth-client` now owns and has improved. The copies have **diverged and gone stale** — auth-client's `LocalCallbackServer` gained `webbrowser.open` with a print fallback, guaranteed socket cleanup via `obtain_callback`, and typed `CallbackTimeoutError`/`AuthorizationDeniedError`; transport's copy still raises bare `TimeoutError` and has no browser fallback. Transport imports **nothing** from `auth_client.connections` today — it runs entirely on the stale fork.

Worse, the **OAuth token lifecycle is duplicated**, not just forked. Transport's `OAuth2Connection._resolve_token()` is the same ~50-line cache→refresh→authorize→persist logic as auth-client's `OAuth2Connection.connect()` (lines 38–77) — structurally the same, modulo two small divergences the extraction must reconcile (transport's fail-closed `if not access_token` vs auth-client's `is None`; transport not threading `callback_server`) — see the "lifecycle is NOT line-for-line identical" reconciliation in the architecture below. The only genuine transport-specific part is the final ~3 lines that bind the resolved token to the **storage endpoint's** httpx config (via `emit(HTTP, base=to_handler_kwargs())` → transport's `HTTPConnection`), rather than auth-client's hardcoded `base_url`/`timeout=30` client.

Transport could not simply import auth-client's `OAuth2Connection`: that class hardcodes its client (`base_url` ClassVar, `timeout=30.0`) and is shaped as subclass-per-provider, so adopting it wholesale would **drop** transport's per-endpoint storage settings (granular `httpx.Timeout`, `verify`/TLS, redirects, custom headers). The seam is the **lifecycle**, not the connection class.

## Goal

Auth-client becomes the single source of truth for the OAuth flow lifecycle and callback servers. Transport deletes its stale duplicates and keeps only the genuinely storage-specific connection binding. No behavioral regression to transport's storage endpoints; transport gains auth-client's callback-server improvements for free.

## Non-goals

- Changing OAuth flow semantics (token exchange, refresh, callback handling) — auth-client's behavior is canonical and adopted as-is.
- Phase 4 (storage `to_handler_kwargs()` → `__adapters__`). Separate spec.
- Touching transport's storage leaf connections (`http/s3/ssh/sftp/null/tunnel`) — those are not duplicated.

---

## Architecture

### Part A — auth-client: extract a client-agnostic token resolver (prerequisite PR)

The lifecycle currently embedded in `OAuth2Connection.connect()` (auth-client `connections/oauth2/connection.py:35-77`) is lifted into a reusable method on `OAuthFlow`:

```python
# mountainash_auth_client/connections/oauth2/flow.py
class OAuthFlow:
    def resolve_access_token(
        self,
        auth_profile: OAuth2AuthProfile | OAuth2AuthCodeAuthProfile,
        *,
        auto_authorize: bool = False,
        callback_server: CallbackServerFactory | None = None,
    ) -> str:
        """Resolve a valid access token: cached → refresh → authorize → persist.
        Client construction is the caller's responsibility."""
        # (the existing cache/is_expired/refresh-in-transaction/authorize/persist body,
        #  returning the access_token string; raises AuthorizationRequired as today)
```

**The OAuth2 lifecycle is NOT line-for-line identical across the two repos — the extraction must reconcile two real divergences (resolves Codex F2/F3):**

1. **Empty-token semantics.** Auth-client's `OAuth2Connection.connect()` guards `access_token is None` (`connections/oauth2/connection.py:66`); transport's Phase-3 connection guards `if not access_token` (fail-closed on empty string, `oauth2/connection.py:99`). The extracted `resolve_access_token` **adopts the fail-closed `if not access_token`** form — strictly safer, and it tightens auth-client's own connection (no behavioral loss; an empty cached token was never valid).
2. **Callback injection location.** Auth-client today threads `callback_server` into `flow.authorize(...)` at the call site (`connection.py:72`), and `OAuthFlow` itself does not hold a callback factory. The resolver therefore takes `callback_server` as a keyword and **forwards it to `authorize()`** (it does not move callback ownership onto the flow object). This keeps the flow stateless and matches the existing `authorize()` signature (`oauth2/flow.py:210`).

`OAuth2Connection.connect()` is refactored to call it, then build its own client — proving the primitive de-dupes auth-client internally:

```python
    def connect(self, auth_profile, *, auto_authorize=False, callback_server=None) -> Self:
        token = OAuthFlow(self._spec).resolve_access_token(
            auth_profile, auto_authorize=auto_authorize, callback_server=callback_server)
        self._client = httpx.Client(base_url=self._base_url,
                                    headers={"Authorization": f"Bearer {token}"}, timeout=30.0)
        return self
```

**OAuth1 equivalent — extracted from auth-client's EXISTING `OAuth1Connection`, not invented (resolves Codex F4).** Auth-client already has a full `OAuth1Connection` class with its own cache→authorize→persist lifecycle (`connections/oauth1/connection.py:18`, using `get_secrets_backend`/`persist_key`/`flow.authorize`). The resolver is lifted from *that class's* body — symmetric with the OAuth2 extraction — into `OAuth1Flow.resolve_token_pair(auth_profile, *, auto_authorize=False, callback_server=None) -> tuple[str, str]` returning `(oauth_token, oauth_token_secret)`, and auth-client's `OAuth1Connection` is refactored to call it. (So both repos' OAuth1 paths converge on one lifecycle, mirroring OAuth2.)

### Part B — transport: delete the dupes, collapse onto the resolver (consumer PR)

**Delete** (stale forks, replaced by auth-client imports):
- `connections/oauth2/flow.py`, `connections/oauth1/flow.py`
- `connections/server/callback.py`, `connections/server/manual.py`
- `connections/protocols/prtcl_callback.py`, `prtcl_oauth1_flow.py`, `prtcl_oauth2_flow.py`
- mirrored tests: `tests/connections/oauth{1,2}/test_flow.py`, `tests/connections/server/test_server.py`

**Collapse** transport's OAuth connections to pure storage binding (the lifecycle is gone):

```python
# connections/oauth2/connection.py
def connect(self) -> Self:
    token = OAuthFlow(self._spec).resolve_access_token(
        self._auth, auto_authorize=self._auto_authorize)
    merged = TokenAuthProfile(TOKEN=token).emit(
        TargetFamily.HTTP, base=self._profile.to_handler_kwargs())
    self._inner = HTTPConnection(merged)
    self._inner.connect()
    return self
```

```python
# connections/oauth1/connection.py
def connect(self) -> Self:
    oauth_token, oauth_token_secret = OAuth1Flow(self._spec).resolve_token_pair(
        self._auth, auto_authorize=self._auto_authorize)
    emitter = OAuth1AuthProfile(
        CONSUMER_KEY=self._auth.CONSUMER_KEY,
        CONSUMER_SECRET=self._auth.CONSUMER_SECRET,   # pass the SecretStr through; do NOT unwrap
        ACCESS_TOKEN=oauth_token, ACCESS_TOKEN_SECRET=oauth_token_secret)
    self._inner = HTTPConnection(emitter.emit(TargetFamily.HTTP, base=self._profile.to_handler_kwargs()))
    self._inner.connect()
    return self
```

> Note (Codex F5): the secret fields are `secret=True` ParameterSpecs that accept and re-hold a `SecretStr`, so the consumer/access secrets are passed through as `SecretStr` rather than round-tripped through `.get_secret_value()` — the plaintext is only ever unwrapped inside the adapter (`schemas/oauth1.py`), preserving the profile's secret contract.

`OAuthFlow`/`OAuth1Flow` are now imported from `mountainash_auth_client.connections...`. The `get_secrets_backend`/`backend.get`/`persist_key` lifecycle logic disappears from transport entirely (it lives inside the auth-client resolver).

**Repoint the legacy public re-exports.** `connections/__init__.py` re-exports `OAuthFlow`, `OAuth1Flow`, `LocalCallbackServer`, `OAuth2FlowProtocol`, `OAuth1FlowProtocol`, `extract_code_from_input`, `prompt_for_code`. These become straight re-exports from auth-client so transport's public surface is unchanged for downstream consumers. **No shim needed (corrects Codex F1):** auth-client already defines and exports both `extract_code_from_input` and `prompt_for_code` as free functions (`connections/server/manual.py:6,26`) *and* the `ManualCallbackServer` class — so every name transport re-exports today has a direct auth-client source. The repoint is a one-line import swap per name.

### Data flow (after)

```
create_connection(storage_profile, oauth_auth)
  → OAuth2Connection.connect()
      → auth-client OAuthFlow.resolve_access_token(...)   # the ONE lifecycle
          → secrets backend (cache) / flow.refresh / flow.authorize → token
      → TokenAuthProfile(token).emit(HTTP, base=storage_profile.to_handler_kwargs())
      → transport HTTPConnection(merged)                  # storage-config-preserving client
```

## Error handling

- `resolve_access_token` raises `AuthorizationRequired` exactly where transport does today (no cached/refreshable token and `auto_authorize=False`). Behavior preserved.
- Transport gains auth-client's improved callback errors (`CallbackTimeoutError`, `AuthorizationDeniedError`, `MalformedCallbackError`) and the browser-open fallback — a strict improvement over the bare `TimeoutError` fork.
- The Phase-3 empty-token fail-closed behavior is preserved: the `_bearer_header` adapter still drops empty tokens, and `resolve_access_token` returns a non-empty token or raises.

## Testing

- **auth-client:** unit tests for `resolve_access_token` / `resolve_token_pair` (cached / refresh / authorize / raises) — largely portable from transport's deleted `test_flow.py`. Confirm the refactored `OAuth2Connection` still passes its existing tests.
- **transport:** keep `tests/connections/oauth{1,2}/test_connection.py` (retargeted to mock `OAuthFlow.resolve_access_token` rather than the secrets backend); add a parity test that the collapsed connection still binds the token onto the storage profile's `to_handler_kwargs()` config (e.g. `verify=False` and granular timeouts survive). Delete the mirrored flow/server tests (auth-client owns them now).
- **Golden parity:** capture transport's current OAuth2/OAuth1 `_inner._connect_kwargs` for a representative storage profile + cached token before the change; assert identical after.

## Sequencing

1. **auth-client PR** — add `resolve_access_token` / `resolve_token_pair`; refactor auth-client's own `OAuth2Connection`; version bump (so transport's env picks it up, per the staleness gotcha in memory `transport_env_staleness_and_profile_rename`).
2. **transport PR** — delete dupes, collapse connections, repoint re-exports, update tests.

## Settled decisions (were open; resolved in this revision)

- **D1 — Callback-server threading.** Transport's collapsed connections pass `callback_server=None` (matching today's transport behavior); the resolver accepts the param and forwards it to `authorize()`, so threading a real factory through transport is a small follow-up, not part of this dedup.
- **D2 — OAuth1 resolver return shape.** `resolve_token_pair -> tuple[str, str]` `(oauth_token, oauth_token_secret)`. Transport constructs the `OAuth1AuthProfile` from the pair for emit.
- **D3 — Manual-entry re-exports.** No shim — `extract_code_from_input`/`prompt_for_code` exist as auth-client free functions (`server/manual.py:6,26`); transport re-exports them directly (one-line import swap).
- **D4 — Protocols.** Re-export auth-client's `OAuth2FlowProtocol`/`OAuth1FlowProtocol`/`CallbackServerProtocol`; delete transport's `connections/protocols/prtcl_*` copies.
- **D5 — Empty-token / lifecycle reconciliation.** The extracted resolver uses the fail-closed `if not access_token` form (tightening auth-client's `is None`); see Part A.

## Remaining open question

- **None blocking.** The only judgment call left is cosmetic: whether to keep transport's `connections/protocols/` package directory (now empty after deleting the prtcl files) or remove it — settled at plan time.

## Risks

- **Flow signature drift** (the 68-line divergence): auth-client's `OAuthFlow.refresh/.authorize` and `OAuth1Flow.authorize/.request_token/.exchange_verifier` signatures must match what transport's collapsed connections expect — the plan must diff call sites against auth-client's actual signatures and adapt.
- **Public-API surface**: downstream importers of transport's re-exported names must keep working; the re-export shims (D3/D4) cover this — verify against `tests/test_public_api.py`.
- **Env staleness**: requires the auth-client version bump + a transport-env wheel refresh before the transport PR is testable (see memory `transport_env_staleness_and_profile_rename`).

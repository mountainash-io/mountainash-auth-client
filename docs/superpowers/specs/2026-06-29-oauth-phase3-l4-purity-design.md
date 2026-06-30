# Design — OAuth Split Phase 3: L4 Purity (ops return a token, not a client)

**Date:** 2026-06-29
**Repo:** mountainash-auth-client
**Status:** Design — behavioural change; contracts locked (return type → `TokenCredential`;
refresh → capability/policy/selection split with an http-client seam; error → `__cause__`).
Depends on **Phase 4** (the mountainash-http-client creds-seam spec, §5) — which by number
is a label, not landing order: Phase 4 lands **first or alongside** Phase 3. Ready for planning.
**Phase:** 3 of 3 (depends on Phases 1–2; largest blast radius)
**Companion phases:** `2026-06-29-oauth-phase1-module-move-design.md`,
`2026-06-29-oauth-phase2-credential-deweave-design.md`

---

## 1. Goal

Make auth-client supply **L2 data + token acquisition only** — it stops building the
consumer's transport client. `OAuth2Connection`/`OAuth1Connection` (which build an
`httpx.Client`) are retired; the `oauth/lifecycle/` token manager becomes the public
seam, returning a token credential the consumer applies via its own L3 (reusing the
shipped `emit(target)` renderer).

This is the recursive application of the layering rule: ops *produce* a credential; the
consumer *renders* it for its target. It is the behavioural change deliberately
quarantined out of Phases 1–2 because it carries the real risk.

## 2. Why this is its own phase

Every High/Critical finding from the Codex review lands here, not in the move:
`.client` is a live contract; refresh semantics change; error wrapping changes;
cross-repo rewire. Phase 3 exists to design those contracts explicitly rather than let
them fall out of a move.

## 3. The public seam

`oauth/lifecycle/` token manager is the entry point:

```
acquire() -> <token credential>     # cache → refresh-if-needed → authorize → persist
refresh() -> <token credential>     # force refresh under the per-key transaction
```

No `httpx.Client` is constructed anywhere in auth-client. `OAuth2Connection` /
`OAuth1Connection` are removed; their `connect()` decomposes:
- token resolution → stays (the manager),
- `base_url` → the consumer's transport config,
- bearer header → the consumer's L3 (reuse `emit(HTTP)`),
- `httpx.Client(**merged)` → **http-client** (`transport/request.py:126` — already owns
  this; nothing to relocate).

## 4. Contract 1 — the return type (DECIDED → `TokenCredential`)

Ops return a credential carrying the live token state the consumer's refresh seam needs:

```
TokenCredential (frozen): access_token: str; token_type="Bearer"
                          expires_at: int | None; refresh_token: str | None
```

Distinct from the existing `oauth/lifecycle/status.py::TokenState` enum (a status
read-model — `valid/expired/missing`).

**DECISION — `TokenCredential` (closed by Phase 2, not a preference).** The alternative
("enrich `TokenAuthProfile` with token + expiry") requires **adding an expiry field to a
credential schema** — `TokenAuthProfile` carries only `TOKEN`, no expiry. That re-weaves
exactly the live token state Phase 2 evicted (`TOKEN_EXPIRES_AT` is ops-managed, not a
persisted schema field — §2b of the Phase 2 spec). So consistency with Phase 2 **forces**
a frozen ops-*output* value object, separate from any persisted credential. Its
`access_token` / `expires_at` / `refresh_token` are a typed view of the token-store record
keys (`access_token` / `token_expires_at` / `refresh_token`). **`token_type` is synthesized,
not stored** — the record has no `token_type`; these OAuth2 flows are Bearer-only, so
`token_type="Bearer"` is a constant. If a non-Bearer grant is ever supported, the
token-store record (not the credential schema) gains a `token_type` field; `TokenCredential`
reads it then. HTTP application reuses the shipped
renderer via `TokenAuthProfile(TOKEN=cred.access_token).emit(HTTP)` (Phase 2 keeps
`TokenAuthProfile.TOKEN`), preserving 1:M reuse without duplicating the Bearer logic.

**OAuth1:** application is per-request *signing*, not a Bearer header. Ops return an
`httpx.Auth` signer (from the relocated `_oauth1_signer`), consumed by http-client's
`RequestCreds.auth` — an existing contract (`mountainash-http-client/tests/.../
test_oauth1_httpx_contract.py`). Scoped exception: OAuth1's output is HTTP-runtime
shaped; documented as such.

## 5. Contract 2 — refresh lifecycle (DECIDED → capability / policy / selection)

Today the flow refreshes **proactively** (before expiry) and persists under a per-key
transaction with a re-check of the locked record to avoid concurrent-refresh races
(`oauth/oauth2/flow.py`, ~`272-309`). **http-client's `on_auth_refresh` fires only after a
401** (`mountainash-http-client/.../transport/request.py:155`; `Callable[[], RequestCreds |
None]`) — it is reactive, and it is **not** consulted to seed the *initial* request creds.
So proactive refresh **cannot** be delivered through `on_auth_refresh` alone: a client
built once with a then-valid token (wearables bakes headers once at
`pipelines/shared/fetch.py:81`) will later send an **expired** token and only refresh after
eating a 401.

The earlier "(i)/(ii)/(iii) mechanism fork" was a **false fork** — the three "options"
share one capability and differ only in *when/whether* refresh runs, i.e. they are policy
*values*, not rival architectures. **DECISION (2026-06-29): decompose into capability /
policy / selection.**

- **Capability → auth-client.** The `oauth/lifecycle/` manager owns refresh: `acquire()`
  (cache → refresh-if-stale → authorize → persist) and `refresh()` (force), single-flight.
  It is **policy-neutral** — it knows *how* to produce a valid token, not *when* anyone
  wants one. Single source of refresh.
- **Policy → http-client.** http-client gains (a) a **per-request creds provider** seam — a
  callable consulted *before each request* to obtain current creds, not only on a 401 — and
  (b) a **refresh-mode flag** on `HttpConfig` whose values subsume the old "options":
  `reactive` (consult only on 401 — today's `on_auth_refresh`, the **default**, so nothing
  regresses), `proactive` (consult before each request; refresh if inside the expiry
  buffer), `static`/off (bake once). This is a transport-lifecycle concern (when to fetch
  creds), **not** http-client owning refresh — the capability stays in auth-client. It is
  specified separately as **Phase 4** (the mountainash-http-client creds-seam spec) — a
  dependency that lands first or alongside this phase.
- **Selection → the consumer.** The consumer sets the flag and wires the provider to
  auth-client's `acquire()`. It chooses the policy; it never re-implements refresh.

**Invariants (regardless of policy):**
- `acquire()` returns a **valid** (non-expired, outside the refresh buffer) credential, or
  **raises `AuthorizationRequired`** — it is **non-interactive in the request path**: it
  refreshes (if it has a refresh token) or raises; it never launches the interactive
  authorize dance per request. Interactive `authorize()` stays an **explicit, out-of-band**
  call (user-initiated reauth), so a fleet of concurrent `acquire()` calls with no stored
  token raises `AuthorizationRequired` rather than fanning out into many authorizations.
- **Single-flight (concurrency contract):** `refresh()` and the refresh inside `acquire()`
  hold the **per-key transaction + locked-record re-check** (`flow.py` ~`272-309`), so N
  concurrent requests collapse to **one** network refresh; the rest read the freshly-written
  record. Initial *authorize* is **not** in this path (it is out-of-band, above), so there is
  no first-token thundering-herd under `PROACTIVE`.
- consumers **call the manager**; they never reimplement refresh.
- **Inherited from Phase 2** (the manager file is the same one Phase 2 touched): the public
  seam preserves the per-user `SCOPE` reads (override + provider `DEFAULT_SCOPE` fallback)
  and **must use the optional-`CLIENT_SECRET`-guarded** call (Phase 2 Task 1B fixed
  `OAuth2TokenManager.authorize()`'s previously-unconditional
  `CLIENT_SECRET.get_secret_value()`). Promoting the manager to a public seam **must not
  revert** to the unguarded dereference — the `TOKEN_ENDPOINT_AUTH_METHOD="none"` /
  optional-secret flow must keep working.

## 6. Contract 3 — error propagation

http-client wraps any `on_auth_refresh` exception into `SourceAuthenticationError` from
it (`transport/request.py:161-165`). auth-client raises domain errors —
`AuthorizationRequired` (no usable token; user must re-auth), `TokenRefreshError`,
`TokenExchangeError`. A revoked refresh token would surface as a generic
`SourceAuthenticationError`, and the wearables CLI branches on auth-exception identity
(`cli.py:235`) — so reauthorization flows could stop triggering.

**Decision — consumer unwraps `__cause__`.** Two options exist: (a) http-client preserves
auth-client exception types, or (b) the consumer maps `SourceAuthenticationError.__cause__`.
Choose **(b)**: option (a) would couple http-client to auth-client's exception taxonomy,
violating its credential-free design. So the wearables boundary maps
`SourceAuthenticationError.__cause__` (an `AuthorizationRequired` → its reauth flow);
http-client keeps wrapping rather than re-exporting auth-client's taxonomy. Document the
`__cause__` contract where the creds seam is wired.

**Interaction with §5's per-request seam (for the http-client seam spec):** under
`proactive`, the pre-request provider can raise `AuthorizationRequired` **before** any 401,
outside the `on_auth_refresh` path. The seam spec must define this — recommended: the
provider returning `None` means "no usable creds, proceed and let the 401 path handle it,"
while a *raised* domain error propagates wrapped in `SourceAuthenticationError` (same
`__cause__` contract), so the consumer's single `__cause__` mapping covers both the
reactive and proactive entry points. This keeps http-client free of auth-client's taxonomy
in both paths.

## 7. `.client` retirement (the live contract)

`OAuth2Connection.client` is **used as transport today** by the **5 OAuth2 providers**
(google, google_health, strava, oura, whoop): each calls `self.client.get(...)` in
`verify()`, and the shared pipeline scrapes its headers/base-url (§10). Retiring it requires
the wearables rewire to provide a replacement path (a one-shot http-client fetch + the
proactive creds seam). This is **not** a redundant client — Phase 3 must not claim it is.

**Out of scope — Garmin uses its own clients, not `OAuth2Connection`:** `garmin_connect`
wraps the `Garmin` **SDK** (`self._client: Garmin`; `.client` is the SDK's attribute), and
`garmin_health` hand-builds OAuth1 headers and sends its **own** `httpx.Client`. Neither
imports auth-client's `OAuth2Connection`, so retiring it does **not** touch them. They
migrate (if ever) under their own provider specs, independent of Phase 3.

## 8. File-level change list (auth-client)

| Action | Path |
|---|---|
| delete | `oauth/oauth2/connection.py` (`OAuth2Connection`), `oauth/oauth1/connection.py` (`OAuth1Connection`) |
| add | `TokenCredential` (in `oauth/lifecycle/`) + manager `acquire()`/`refresh()` returning it |
| edit | `oauth/lifecycle/oauth2.py`, `oauth1.py` — public `acquire()`/`refresh()` seam, lifecycle contract (§5) |
| edit | `__init__.py` — drop `OAuth2Connection`/`OAuth1Connection` exports + `__all__`; export `TokenCredential` |
| edit | `errors.py` / boundary doc — error-propagation contract (§6) |
| edit | `docs/INTEGRATION.md` — remove "Connections (batteries-included)"; make resolver+`emit` the documented path |

## 9. Doc / principle amendment (carried here)

Amend `connections-single-source-of-truth.md` (2026-06-11): narrow "auth-client owns
connection classes" → owns the OAuth **acquisition** (flow + callback) machinery;
**transport-client construction is consumer-owned** per the layering guide. (See
`[[connections-ssot-principle-narrow-intent]]`.)

## 10. Consumer impact (downstream — the big one)

- **mountainash-wearables** — its own detailed rewire spec; largest blast radius. Two
  `.client` consumption sites, **both** must move off the retired connection:
  - **shared pipeline fetch** (`pipelines/shared/fetch.py`) — the central one. It scrapes
    creds from the connection (`_resolve_auth_headers(connection)`, `_resolve_base_url`) and
    **bakes them once** into `HttpConfig(headers=…)` (the static-creds gap §5 describes).
    Rewire: wire `HttpConfig.creds_provider` to a use-time `acquire()` → `emit(HTTP)` →
    `RequestCreds` and set `refresh_mode=PROACTIVE` (Phase 4); drop the header scraping.
  - **per-provider `verify()`** (the 5 OAuth2 providers) — replace `self.client.get(...)`
    with a one-shot http-client request carrying the same proactive creds.
  - map `SourceAuthenticationError.__cause__` → reauth (§6). `garmin_connect`/`garmin_health`
    are **not** in scope (§7 — they never used `OAuth2Connection`).
- **mountainash-transport** — update the user-facing guidance in `connections/errors.py`
  (`~:64`) that points callers at the now-retired `OAuth2Connection`/`OAuth1Connection`;
  redirect to the `oauth/lifecycle` acquire seam. (Phase 1 already repointed its deep
  imports.)
- **mountainash-http-client** — gains the §5 **policy** layer: a per-request creds-provider
  seam + a `refresh-mode` flag on `HttpConfig` (`reactive` default → no behavioural change
  for current consumers; `proactive` opt-in). This is an explicit, separately-specced
  http-client enhancement (a named **dependency** of Phase 3), not a silent change. It owns
  *when* creds are fetched; it never owns refresh (that stays in auth-client).
- **mountainash-data** — unaffected by Phase 3 (it builds its own DB connection from the
  token; never used `OAuth2Connection`).

## 11. Risks

- Highest-risk phase. The three contracts (§4–§6) are now locked; the residual risk is
  execution — regressing refresh behaviour or reauth UX if the seam/policy wiring is wrong.
- Cross-repo coordination across **three** repos. Sequence: land **Phase 4** (the
  http-client creds-seam: per-request creds provider + `refresh-mode` flag) first or
  alongside, then Phase 3 auth-client (capability + `TokenCredential` + `.client` retirement)
  + the wearables rewire together. `reactive` default means existing http-client consumers
  see no change until they opt into `proactive`.

## 12. Decisions (all resolved) + dependency

1. **Refresh (§5) — RESOLVED.** Not a mechanism fork; decomposed into capability
   (auth-client `acquire()`/`refresh()`, policy-neutral) / policy (http-client `refresh-mode`
   flag + per-request creds seam) / selection (consumer sets the flag). `reactive` default
   preserves today's behaviour.
2. **Return type (§4) — RESOLVED → `TokenCredential`.** Forced by Phase 2's `TOKEN_EXPIRES_AT`
   eviction; enriching `TokenAuthProfile` would re-weave live token state onto a credential.
3. **`verify()` (§7) — RESOLVED (scope narrowed).** No special auth-client support needed:
   by the layering rule, wearables' `verify()` becomes `acquire()` → token → a one-shot
   request via http-client. The shape lands in the **wearables rewire spec**; auth-client's
   seam only returns the token.
4. **Error propagation (§6) — RESOLVED.** Consumer unwraps `SourceAuthenticationError.__cause__`
   for both the reactive (401) and proactive (pre-request) entry points; http-client keeps
   its taxonomy.

**Dependency — Phase 4 (must be specced + landed first or alongside):** the
**mountainash-http-client creds-seam spec** — per-request creds provider + `refresh-mode`
flag (§5 policy layer, §6 interaction). Phase 3's auth-client work (capability +
`TokenCredential` + `.client` retirement) and the wearables rewire both build on it.
(Phase 4 by number is a label; it sequences before Phase 3's proactive wiring.)

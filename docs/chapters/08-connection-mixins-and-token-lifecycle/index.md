---
title: Connection Mixins and Token Lifecycle
description: OAuth2ConnectionMixin for automatic token management, the five-state token lifecycle, file-locked refresh, end-to-end authorization orchestration, and the AuthorizationRequired exception.
generated_by: claude skill chapter-content-generator
date: 2026-06-03
version: 0.08
---

# Connection Mixins and Token Lifecycle

## Summary

This chapter covers the OAuth2ConnectionMixin that provides automatic token lifecycle management. It explains the connect method, auto-authorize flag, client property, context manager support, and profile parameter. It then covers the complete five-state token lifecycle (no-token, valid, expired-with-refresh, expired-no-refresh, cleared), file-locked refresh for concurrent-safe token renewal, and the end-to-end authorize orchestration. The chapter concludes with the AuthorizationRequired exception and provider/user context for targeted re-authorization prompts.

## Concepts Covered

- End To End Authorize
- OAuth2ConnectionMixin
- Connect Method
- Auto Authorize Flag
- Client Property
- Context Manager Support
- Profile Parameter
- Token Lifecycle Overview
- No Token State
- Valid Token State
- Expired With Refresh State
- Expired No Refresh State
- Cleared State
- File Locked Refresh
- AuthorizationRequired
- Provider User Context

## Prerequisites

- Chapter 1: Foundations (Context Managers)
- Chapter 5: OAuth 2.0 Flow (OAuthFlow Class, Build Authorize URL, Exchange Code, Refresh Token, Token Expiry Check)
- Chapter 6: Secret Storage (SecretStore Protocol, Clear Method, Lock Method)
- Chapter 7: Callback Server and Token Errors (LocalCallbackServer)

## Learning Objectives

After completing this chapter, you will be able to:

- Configure and use OAuth2ConnectionMixin for automatic token management
- Trace the token lifecycle through all five states and their transitions
- Implement auto-authorize logic for seamless re-authentication
- Use context managers for connection lifecycle management
- Apply file-locked refresh for concurrent-safe token renewal
- Orchestrate end-to-end authorization combining all flow components
- Raise and catch AuthorizationRequired to trigger re-authorization flows

---

## Bringing It All Together

The previous chapters covered the individual components of the mountainash-auth-client library: auth type schemas (Chapters 2-3), dispatch (Chapter 4), OAuth flows (Chapters 4-5), secret storage (Chapter 6), and callback/error handling (Chapter 7). This final chapter shows how the `OAuth2ConnectionMixin` orchestrates all of these components into a seamless connection experience.

The mixin's `connect` method is the library's central integration point. It loads stored tokens from the secret store, checks their validity, refreshes expired tokens, triggers interactive authorization when needed, and constructs an authenticated HTTP client -- all in a single method call. Understanding how it makes decisions requires understanding the token lifecycle model it implements.

<!-- concept:51 -->
## OAuth2ConnectionMixin

The `OAuth2ConnectionMixin` is a class designed to be mixed into connection classes that need OAuth 2.0 token management. It declares three class-level variables that the consuming class must provide.

```python
class OAuth2ConnectionMixin:
    _spec: ClassVar       # ProfileSpec with name and metadata
    _base_url: ClassVar[str]  # Base URL for API requests
    _client: httpx.Client | None  # HTTP client (set by connect)
```

The `_spec` class variable provides the provider name and OAuth metadata (authorize URL, token URL, PKCE configuration). The `_base_url` is the root URL for API requests (e.g., `https://api.provider.com/v1`). The `_client` instance variable holds the authenticated `httpx.Client` after connection, starting as `None`.

A typical usage pattern involves a provider-specific connection class that inherits from the mixin:

```python
class SnowflakeConnection(OAuth2ConnectionMixin):
    _spec = snowflake_profile_spec
    _base_url = "https://account.snowflakecomputing.com"
```

<!-- concept:54 -->
### Client Property

The `client` property provides read-only access to the underlying `httpx.Client` instance. After a successful `connect` call, this property returns the configured client with the `Authorization: Bearer <token>` header set. Before connection, it returns `None`.

```python
@property
def client(self) -> httpx.Client | None:
    return self._client
```

Consumers use this property to make authenticated API calls:

```python
conn = SnowflakeConnection()
conn.connect(profile, store=store, domain="prod")
response = conn.client.get("/api/data")
```

<!-- concept:56 -->
### Profile Parameter

The `connect` method accepts a `profile` parameter that provides the OAuth client credentials (client_id, client_secret, scope) needed for token operations. The profile is typically a configuration object with an `.auth` attribute containing an `OAuth2AuthCodeAuth` instance.

The mixin accesses `profile.auth` to extract:

- `client_id` and `client_secret` for token exchange and refresh
- `access_token` and `refresh_token` for legacy migration (when stored tokens do not yet exist)
- `scope` for authorization requests
- `token_expires_at` for legacy migration

This loose coupling (via attribute access rather than typed parameters) allows the mixin to work with different profile object structures across the mountainash ecosystem.

<!-- concept:55 -->
### Context Manager Support

The mixin implements `__enter__` and `__exit__` to support the `with` statement pattern for connection lifecycle management.

```python
def __enter__(self) -> Self:
    return self

def __exit__(self, *args) -> None:
    self.disconnect()
```

The `__enter__` method returns `self`, allowing the mixin to be used as a context manager after calling `connect`. The `__exit__` method calls `disconnect()`, which closes the underlying `httpx.Client` and releases its TCP connections and file descriptors.

```python
with SnowflakeConnection() as conn:
    conn.connect(profile, store=store, domain="prod")
    data = conn.client.get("/api/data")
# disconnect() called automatically here, even if an exception occurred
```

This guarantees cleanup even when exceptions occur during API calls, preventing resource leaks in long-running applications and scripts.

<!-- concept:52 -->
## The Connect Method

The `connect` method is the heart of the mixin. It accepts a profile object and several keyword arguments that control its behavior.

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
```

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `profile` | object | (required) | Configuration object with `.auth` attribute containing OAuth credentials |
| `user` | str | `"default"` | User identity for multi-user credential storage |
| `store` | SecretStore | (required) | Credential storage backend |
| `domain` | str | (required) | Environment namespace (e.g., `"production"`, `"staging"`) |
| `auto_authorize` | bool | `False` | Whether to trigger interactive authorization when no valid token exists |

<!-- concept:53 -->
### Auto Authorize Flag

The `auto_authorize` flag controls the mixin's behavior when no valid token is available and refresh has failed (or is not possible). When `True`, the mixin launches the interactive OAuth authorization flow (opening a browser for user consent). When `False`, it raises an `AuthorizationRequired` exception instead.

Setting `auto_authorize=False` (the default) is appropriate for:

- **Server-side applications** where no browser is available
- **CI/CD pipelines** where interactive authorization is not possible
- **Batch jobs** that should fail loudly rather than hang waiting for user input

Setting `auto_authorize=True` is appropriate for:

- **CLI tools** where the user is present to complete authorization
- **Interactive scripts** where first-time setup should be seamless
- **Development environments** where convenience outweighs automation concerns

<!-- concept:57 -->
## Token Lifecycle Overview

The connection mixin manages tokens through a five-state lifecycle. Each state represents a different combination of stored token presence, validity, and refresh token availability. The `connect` method evaluates the current state and takes the appropriate action.

#### Diagram: Token Lifecycle State Machine
<iframe src="../../sims/token-lifecycle-state-machine/main.html" width="100%" height="600px" scrolling="no"></iframe>
<details markdown="1">
<summary>Token Lifecycle State Machine</summary>
Type: diagram
**sim-id:** token-lifecycle-state-machine<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Display the five token lifecycle states and all possible transitions between them, showing the trigger conditions (token expiry, refresh success/failure, clear, authorize) and the connect method's decision at each state.

**Components:** Five state nodes arranged in a circle: No Token, Valid Token, Expired With Refresh, Expired No Refresh, Cleared. Directed edges show transitions: No Token -> Valid Token (authorize), Valid Token -> Expired With Refresh (time passes + refresh_token present), Valid Token -> Expired No Refresh (time passes + no refresh_token), Expired With Refresh -> Valid Token (refresh success), Expired With Refresh -> Cleared (refresh failure), Expired No Refresh -> Valid Token (re-authorize), Cleared -> Valid Token (re-authorize), No Token -> Valid Token (legacy migration).

**Interactions:** Click each state node to see the connect method's decision logic for that state. Click transition edges to see the code path. A "Simulate" button walks through a realistic lifecycle scenario. Toggle "auto_authorize=True" vs "auto_authorize=False" to see how the flag changes outcomes at No Token and Expired states.

**Colors:** No Token=SteelBlue, Valid Token=DarkGreen, Expired With Refresh=Gold, Expired No Refresh=Orange, Cleared=Crimson. Transition edges=DarkSlateBlue.

**Learning Objective:** Analyze (Bloom Level 4) the complete token lifecycle state machine and predict the connect method's behavior for any given token state and configuration.
</details>

<!-- concept:58 -->
### No Token State

The No Token state occurs when `store.load()` returns `None` and `store.is_cleared()` returns `False`. This is the initial state before any authorization has occurred.

Before triggering authorization, the mixin checks for a legacy migration opportunity: if the profile's `.auth` attribute contains an `access_token` field (from a pre-migration configuration), the mixin imports those tokens into the store. This one-time migration allows the system to transition from inline tokens to store-managed tokens without requiring re-authorization.

```python
if tokens is None and not store.is_cleared(domain, provider, user):
    auth = profile.auth
    if getattr(auth, "access_token", None) is not None:
        tokens = {
            "access_token": auth.access_token.get_secret_value(),
            "refresh_token": auth.refresh_token.get_secret_value() if auth.refresh_token else None,
            "token_expires_at": auth.token_expires_at,
        }
        store.save(domain, provider, user, tokens)
```

If no legacy tokens exist and `auto_authorize` is `True`, the mixin launches the full OAuth authorization flow. If `auto_authorize` is `False`, it raises `AuthorizationRequired`.

<!-- concept:59 -->
### Valid Token State

A token is in the Valid state when `store.load()` returns a token dictionary and `OAuthFlow.is_expired()` returns `False` for the stored `token_expires_at`. This is the happy path -- the mixin extracts the access token and constructs the HTTP client immediately.

```python
if tokens and not flow.is_expired(tokens.get("token_expires_at")):
    access_token = tokens["access_token"]
```

No network calls are needed. The token is used directly.

<!-- concept:60 -->
### Expired With Refresh State

When the token has expired but a refresh token is available, the mixin attempts to obtain a new access token using `OAuthFlow.refresh()`. This state triggers the file-locked refresh mechanism (discussed in the next section).

If the refresh succeeds, the new tokens are saved to the store and the connection proceeds with the fresh access token. If the refresh fails (raising `TokenRefreshError`), the mixin clears the stored credentials and either re-authorizes (if `auto_authorize=True`) or raises `AuthorizationRequired`.

<!-- concept:61 -->
### Expired No Refresh State

When the token has expired and no refresh token is available, the mixin cannot silently renew the credentials. Some providers do not issue refresh tokens (especially for client-credentials grants), and some tokens may have had their refresh token revoked.

In this state, the only option is a full re-authorization. If `auto_authorize=True`, the mixin launches the interactive flow. If `False`, it raises `AuthorizationRequired`.

<!-- concept:62 -->
### Cleared State

The Cleared state occurs when `store.load()` returns `None` AND `store.is_cleared()` returns `True`. This indicates that credentials were intentionally revoked (Chapter 6's tombstone semantics).

The critical behavior in this state is that the mixin does NOT attempt legacy migration. Even if the profile contains inline tokens, the tombstone signals that those tokens should not be re-imported. The user explicitly cleared them, and the mixin respects that intent.

From the Cleared state, the only path forward is a fresh authorization (if `auto_authorize=True`) or `AuthorizationRequired`.

<!-- concept:63 -->
## File Locked Refresh

When multiple processes share the same credential store (common in data pipelines with parallel workers), a race condition can occur during token refresh. If two processes both detect an expired token simultaneously, they might both attempt to refresh using the same refresh token. With providers that rotate refresh tokens, the second refresh attempt would use an already-invalidated refresh token and fail.

The mixin prevents this with a double-check locking pattern using the `store.lock()` method:

```python
elif tokens and tokens.get("refresh_token"):
    with store.lock(domain, provider, user):
        # Re-load inside lock -- another process may have refreshed
        tokens = store.load(domain, provider, user)
        if tokens and not flow.is_expired(tokens.get("token_expires_at")):
            # Another process already refreshed; use the fresh token
            access_token = tokens["access_token"]
        else:
            # We hold the lock; safe to refresh
            new_tokens = flow.refresh(
                refresh_token=tokens["refresh_token"],
                client_id=auth.client_id,
                client_secret=auth.client_secret.get_secret_value(),
            )
            store.save(domain, provider, user, new_tokens)
            access_token = new_tokens["access_token"]
```

The pattern works as follows:

1. **First check (without lock):** detect that the token is expired and a refresh token exists
2. **Acquire the lock:** only one process can hold the lock at a time
3. **Second check (with lock):** re-load the token from the store. If another process refreshed while we were waiting for the lock, the re-loaded token will be fresh
4. **Refresh or skip:** if the re-loaded token is still expired, perform the refresh. If it is now valid, use it directly

This double-check pattern minimizes lock contention. Most of the time (when tokens are valid), no lock is acquired at all. The lock is only acquired when a refresh is needed, and the second check inside the lock avoids redundant refreshes.

#### Diagram: Double-Check Lock Refresh Pattern
<iframe src="../../sims/double-check-lock-refresh/main.html" width="100%" height="550px" scrolling="no"></iframe>
<details markdown="1">
<summary>Double-Check Lock Refresh Pattern</summary>
Type: microsim
**sim-id:** double-check-lock-refresh<br/>
**Library:** p5.js<br/>
**Status:** Specified

**Purpose:** Animate the double-check locking pattern for concurrent token refresh, showing two processes racing to refresh and how the lock + re-check prevents double-refresh.

**Components:** Two process timelines running in parallel against a shared timeline. Process A: check expired -> acquire lock -> re-check (still expired) -> refresh -> save -> release lock. Process B: check expired -> acquire lock (blocked, waiting) -> re-check (now valid!) -> use fresh token -> release lock. A shared credential file indicator shows the token state changes.

**Interactions:** Click "Race Condition" to show what happens without locking (both refresh, second fails). Click "With Locking" to show the safe pattern. Adjust the timing slider to vary when Process B attempts to acquire the lock. A step-through mode lets you advance one operation at a time.

**Colors:** Process A=SteelBlue, Process B=Gold, Lock held=DarkGreen border, Lock waiting=Orange border, Credential state=MediumPurple.

**Learning Objective:** Evaluate (Bloom Level 5) why double-check locking is necessary for concurrent token refresh and trace the execution through both the normal and contention scenarios.
</details>

<!-- concept:44 -->
## End To End Authorize

When the mixin determines that a full authorization is needed (no valid token and `auto_authorize=True`), it delegates to `OAuthFlow.authorize()`, which orchestrates the complete flow described in Chapter 5.

```python
if auto_authorize:
    auth = profile.auth
    new_tokens = flow.authorize(
        client_id=auth.client_id,
        client_secret=auth.client_secret.get_secret_value(),
        scope=auth.scope,
    )
    store.save(domain, provider, user, new_tokens)
    access_token = new_tokens["access_token"]
```

The end-to-end flow involves all the components covered in previous chapters:

1. `OAuthFlow.build_authorize_url()` constructs the URL with PKCE and state (Chapter 5)
2. `LocalCallbackServer` captures the redirect (Chapter 7) or `prompt_for_code` handles manual entry
3. `OAuthFlow.exchange_code()` obtains tokens from the provider (Chapter 5)
4. `store.save()` persists the tokens for future use (Chapter 6)
5. The `_client` is constructed with the fresh access token

After the flow completes, the mixin constructs the authenticated HTTP client:

```python
self._client = httpx.Client(
    base_url=self._base_url,
    headers={"Authorization": f"Bearer {access_token}"},
    timeout=30.0,
)
return self
```

The client is configured with the provider's base URL, a Bearer token authorization header, and a 30-second timeout. The method returns `self` to support method chaining.

<!-- concept:84 -->
## AuthorizationRequired Exception

When the mixin cannot obtain a valid token and `auto_authorize` is `False`, it raises `AuthorizationRequired`. This exception carries the provider name and user identity so that upstream code can present a targeted re-authorization prompt.

```python
class AuthorizationRequired(Exception):
    def __init__(self, *, provider: str, user: str) -> None:
        self.provider = provider
        self.user = user
        super().__init__(f"Authorization required for {provider}/{user}")
```

<!-- concept:85 -->
### Provider User Context

The `provider` and `user` attributes on `AuthorizationRequired` enable precise error handling. A data pipeline that connects to multiple providers can catch this exception and determine exactly which provider needs re-authorization, without affecting connections to other providers.

```python
try:
    snowflake_conn.connect(profile, store=store, domain="prod")
except AuthorizationRequired as exc:
    print(f"Please re-authorize {exc.provider} for user {exc.user}")
    print(f"Run: mountainash auth login --provider={exc.provider} --user={exc.user}")
```

The keyword-only constructor (`*, provider, user`) prevents positional argument mistakes and makes the call site self-documenting.

`AuthorizationRequired` is raised in two specific contexts within the `connect` method:

- **After a failed refresh** when `auto_authorize=False` -- the refresh token was invalid, credentials have been cleared, and the user must re-authorize
- **When no token exists** and `auto_authorize=False` -- either the first-time setup case or the cleared-credentials case

| Trigger | Preceding Action | Credentials After |
|---|---|---|
| No token, no legacy, `auto_authorize=False` | None | Still absent |
| Refresh failed, `auto_authorize=False` | `store.clear()` called | Cleared (tombstone) |
| Expired, no refresh token, `auto_authorize=False` | None | Expired tokens remain |

!!! note "Why Not Auto-Authorize by Default?"
    Setting `auto_authorize=False` as the default is a deliberate safety choice. Interactive authorization opens a browser and blocks the process waiting for user input. In production pipelines, this would cause silent hangs instead of clear failures. The explicit opt-in via `auto_authorize=True` ensures that only code paths where interactive authorization is expected will trigger it.

## Complete Connect Method Flow

The following pseudocode summarizes the `connect` method's decision logic:

```
1. Load tokens from store
2. If tokens is None and not cleared:
   a. Check for legacy tokens in profile.auth
   b. If found, migrate to store
3. If tokens are valid (not expired):
   -> Use access_token directly
4. Else if tokens exist with refresh_token:
   a. Acquire file lock
   b. Re-load tokens (double-check)
   c. If now valid: use access_token
   d. Else: refresh, save new tokens
   e. If refresh fails: clear, then auto_authorize or raise
5. If no valid access_token:
   a. If auto_authorize: run full OAuth flow, save tokens
   b. Else: raise AuthorizationRequired
6. Build httpx.Client with Bearer token
7. Return self
```

#### Diagram: Connect Method Decision Flow
<iframe src="../../sims/connect-method-decision-flow/main.html" width="100%" height="600px" scrolling="no"></iframe>
<details markdown="1">
<summary>Connect Method Decision Flow</summary>
Type: workflow
**sim-id:** connect-method-decision-flow<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Show the complete decision flow of the connect method as a flowchart, with all branching paths from token loading through to either a configured client or an exception.

**Components:** A flowchart starting from "store.load()" with decision diamonds for: tokens exist?, is_cleared?, legacy tokens available?, token expired?, refresh_token available?, refresh succeeded?, auto_authorize?. Terminal nodes: "Use Token" (green), "Refresh Token" (blue), "Full Authorization" (gold), "AuthorizationRequired" (red), "Build Client" (green).

**Interactions:** Click any decision node to highlight all paths that pass through it. Click terminal nodes to see the corresponding code. Toggle "auto_authorize" on/off to see how the flag changes reachable outcomes. Hover decision edges to see the boolean condition.

**Colors:** Decision diamonds=Gold, Success terminals=DarkGreen, Auth flow terminals=SteelBlue, Error terminals=Crimson, Process nodes=DarkSlateBlue.

**Learning Objective:** Analyze (Bloom Level 4) the complete connect method decision tree and predict outcomes for any combination of token state and configuration parameters.
</details>

## Key Takeaways

- **OAuth2ConnectionMixin** is a mixin class that provides automatic token lifecycle management for connection classes, requiring only `_spec`, `_base_url`, and `_client` class variables from the consuming class.
- **The `connect` method** orchestrates token loading, validation, refresh, and authorization into a single call, accepting `profile`, `user`, `store`, `domain`, and `auto_authorize` parameters.
- **The `auto_authorize` flag** controls whether the mixin launches interactive browser-based authorization (`True`) or raises `AuthorizationRequired` (`False`, the default). Default-off prevents silent hangs in production.
- **The `client` property** provides read-only access to the authenticated `httpx.Client` after connection. **Context manager support** (`__enter__`/`__exit__`) guarantees client cleanup.
- **The profile parameter** is loosely coupled via attribute access, allowing the mixin to work with different profile structures across the ecosystem.
- **The five token lifecycle states** (No Token, Valid Token, Expired With Refresh, Expired No Refresh, Cleared) each trigger different behavior in the connect method, from direct token use to full re-authorization.
- **Legacy migration** imports inline tokens from profile configurations into the store on first access, but only if the credentials have not been explicitly cleared (tombstone check).
- **File-locked refresh** uses a double-check locking pattern: check expired, acquire lock, re-check (another process may have refreshed), then refresh or use the fresh token. This prevents double-refresh race conditions with rotating refresh tokens.
- **End-to-end authorization** delegates to `OAuthFlow.authorize()`, combining URL building, browser interaction, callback capture, and token exchange into a single operation, then persisting the result.
- **`AuthorizationRequired`** carries `provider` and `user` context, enabling targeted re-authorization prompts. It is raised when no valid token exists and `auto_authorize=False`.

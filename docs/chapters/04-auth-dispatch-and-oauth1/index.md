---
title: Auth Dispatch and OAuth 1.0a
description: The auth dispatch registry that maps auth types to driver kwargs, type-based dispatch, backend-specific handling, and the complete OAuth 1.0a three-legged flow with optional authlib dependency.
generated_by: claude skill chapter-content-generator
date: 2026-06-03
version: 0.08
---

# Auth Dispatch and OAuth 1.0a

## Summary

This chapter covers two related subsystems. First, the auth dispatch mechanism that maps auth types to driver-specific keyword arguments through a registry, type-based dispatch, and backend-specific handling of unmapped types. Second, the OAuth 1.0a flow implementation including the OAuth1Flow class, request token acquisition, the three-legged authorization flow, verifier exchange, and the optional authlib dependency with its import guard pattern.

## Concepts Covered

- Auth Dispatch Registry
- Auth To Driver Kwargs
- Auth Kwargs Function
- Type Based Dispatch
- Unmapped Auth Types
- Backend Specific Handling
- OAuth1Flow Class
- Request Token
- Three Legged Flow
- Verifier Exchange
- Authlib Dependency
- Optional Import Guard

## Prerequisites

- Chapter 1: Foundations (OAuth 1.0a Basics)
- Chapter 2: Auth Type System and Basic Types (Discriminated Union)
- Chapter 3: Advanced Auth Type Variants (AzureADAuth Type, WindowsAuth Type, KerberosAuth Type, CertificateAuth Type, ServiceAccountAuth Type)

## Learning Objectives

After completing this chapter, you will be able to:

- Describe how the dispatch registry maps auth types to driver kwargs
- Trace a dispatch call from auth type through to driver-specific output
- Handle unmapped auth types gracefully in custom backends
- Implement the three-legged OAuth 1.0a authorization flow
- Apply the optional import guard pattern for graceful dependency degradation

---

## Part 1: Auth Dispatch

### The Bridge Between Auth Types and Drivers

The auth type system (Chapters 2-3) defines how credentials are structured and validated. But database drivers and API clients expect their authentication parameters in specific formats -- a PostgreSQL driver wants `user` and `password` kwargs, while a Trino driver wants a `token` kwarg. The dispatch system bridges this gap by translating from the library's type-safe auth models to the flat dictionaries that drivers expect.

This translation layer is intentionally thin. Its job is to extract values from `AuthSpec` instances (calling `.get_secret_value()` on `SecretStr` fields as needed) and arrange them into the kwargs format that a particular backend's driver expects.

### Auth Dispatch Registry

The dispatch registry is a dictionary that maps auth type classes to converter functions. Each converter function accepts an instance of a specific `AuthSpec` subclass and returns a `dict[str, Any]` suitable for passing to a driver.

```python
AUTH_TO_DRIVER_KWARGS: dict[type[AuthSpec], Callable[[Any], dict[str, Any]]] = {
    NoAuth: _noauth,
    PasswordAuth: _password,
    TokenAuth: _token,
    JWTAuth: _jwt,
    OAuth2Auth: _oauth2,
    IAMAuth: _iam,
}
```

The registry is a module-level constant, not a class instance. This makes it easy for backend adapters to inspect, extend, or override individual entries. The keys are the auth type classes themselves (not strings), which ensures that the mapping is refactoring-safe -- renaming a class or moving it to a different module does not break the registry.

Six of the thirteen auth types have default converters. The remaining seven (`WindowsAuth`, `AzureADAuth`, `KerberosAuth`, `CertificateAuth`, `ServiceAccountAuth`, `OAuth1Auth`, `OAuth2AuthCodeAuth`) are intentionally absent because they require platform-specific handling that cannot be captured in a single function.

### Auth To Driver Kwargs

The `auth_to_driver_kwargs` function is the primary dispatch entry point. It looks up the converter for the given auth instance's type and invokes it. If no converter is registered for the type, it raises a `KeyError`.

```python
def auth_to_driver_kwargs(auth: AuthSpec) -> dict[str, Any]:
    """Look up the default mapper for auth and produce driver kwargs."""
    return AUTH_TO_DRIVER_KWARGS[type(auth)](auth)
```

The implementation is a single line: index the registry with `type(auth)` to get the converter function, then call that function with the auth instance. This is a classic example of type-based dispatch -- the runtime type of the object determines which code path executes, but without a chain of `if isinstance(...)` checks.

The converters for each registered type perform straightforward field extraction. The following list summarizes what each converter produces.

- **`_noauth`** returns `{}` -- an empty dict signals no credentials
- **`_password`** returns `{"user": auth.username, "password": auth.password.get_secret_value()}`
- **`_token`** returns `{"token": auth.token.get_secret_value()}`
- **`_jwt`** returns `{"token": auth.token.get_secret_value()}`
- **`_oauth2`** branches on available fields: token, client credentials, or empty
- **`_iam`** conditionally includes `iam_role_arn`, `aws_access_key_id`, `aws_secret_access_key`, and `aws_session_token`

#### Diagram: Dispatch Registry Flow
<iframe src="../../sims/dispatch-registry-flow/main.html" width="100%" height="500px" scrolling="no"></iframe>
<details markdown="1">
<summary>Dispatch Registry Flow</summary>
Type: workflow
**sim-id:** dispatch-registry-flow<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Trace the complete dispatch path from an AuthSpec instance through registry lookup to driver kwargs output, including the KeyError path for unmapped types.

**Components:** Input node (AuthSpec instance) connects to a "type(auth)" resolution node, which connects to the registry lookup node. From there, six converter function nodes fan out (one per registered type). Each converter connects to a "Driver Kwargs" output node showing the specific dict produced. A separate "KeyError" node branches from the registry lookup for unmapped types.

**Interactions:** Click the input node to cycle through different auth type examples. The active path highlights through registry lookup to the correct converter. The output node updates to show the actual kwargs dict produced. Click "Unmapped" to show the KeyError path.

**Colors:** Input=DarkSlateBlue, Registry=Gold, Converters=SteelBlue, Output=DarkGreen, Error=Crimson.

**Learning Objective:** Apply (Bloom Level 3) the dispatch mechanism to trace how a specific auth type instance produces driver kwargs.
</details>

### Auth Kwargs Function

The `auth_kwargs` function is a convenience wrapper that extracts auth from any object with an optional `.auth` attribute. This is designed for profile objects that may or may not include authentication configuration.

```python
def auth_kwargs(profile: object) -> dict[str, Any]:
    """Extract auth kwargs from any object with an optional .auth attribute."""
    auth = getattr(profile, "auth", None)
    if auth is None:
        return {}
    return auth_to_driver_kwargs(auth)
```

This function demonstrates a common pattern in the library: graceful handling of absent authentication. If the profile has no `.auth` attribute, or if `.auth` is `None`, the function returns an empty dict rather than raising an error. This allows backend connection code to unconditionally call `auth_kwargs(profile)` and merge the result into driver kwargs without conditional checks.

### Type Based Dispatch

The dispatch mechanism uses Python's `type()` function for routing rather than `isinstance()` checks or pattern matching. This is a deliberate design choice with specific tradeoffs.

Using `type(auth)` means exact type matching -- a subclass of `PasswordAuth` would NOT match the `PasswordAuth` entry in the registry. This is appropriate for the discriminated union because each variant is a leaf class with no further inheritance. The `Literal` kind discriminator already prevents meaningful subclassing.

The advantages of registry-based dispatch over `isinstance()` chains are:

- **Open for extension** -- adding a new auth type with a default converter requires only adding an entry to the dict
- **Inspectable** -- code can iterate the registry to discover supported types
- **Overridable** -- a backend adapter can replace a converter by reassigning `AUTH_TO_DRIVER_KWARGS[SomeType] = my_custom_converter`

The alternative approaches (a `match` statement, an abstract method on each auth type, or visitor pattern) would each tightly couple the dispatch logic to the type definitions. The registry keeps them independent.

### Unmapped Auth Types

Five auth types have no entry in the default dispatch registry: `WindowsAuth`, `AzureADAuth`, `KerberosAuth`, `CertificateAuth`, and `ServiceAccountAuth`. When `auth_to_driver_kwargs` encounters one of these, the registry lookup raises a `KeyError`.

This is not a bug -- it is intentional signaling. These types require platform-specific SDK calls (Azure SDK, AWS STS, `gssapi`, OpenSSL) that the auth-client library does not depend on. The `KeyError` tells the backend adapter: "the generic dispatch cannot handle this type; you must implement your own handling."

### Backend Specific Handling

A backend adapter handles unmapped types by catching the `KeyError` from dispatch and applying its own logic.

```python
def connect_to_backend(profile):
    try:
        kwargs = auth_to_driver_kwargs(profile.auth)
    except KeyError:
        # Backend-specific handling for unmapped types
        if isinstance(profile.auth, WindowsAuth):
            kwargs = {"trusted_connection": "yes"}
            if profile.auth.username:
                kwargs["UID"] = f"{profile.auth.domain}\\{profile.auth.username}"
        elif isinstance(profile.auth, CertificateAuth):
            kwargs = {"private_key": load_private_key(profile.auth)}
        else:
            raise TypeError(f"Unsupported auth type: {type(profile.auth)}")
    return driver.connect(**kwargs)
```

This pattern keeps the generic library thin while allowing each backend to bring its own dependencies and logic. The MSSQL adapter knows about Windows domains and trusted connections. The Snowflake adapter knows how to load private keys and sign JWTs. The BigQuery adapter knows how to exchange service account JSON for access tokens.

!!! tip "Extending the Registry"
    If your organization frequently uses a particular auth type across multiple backends and wants consistent dispatch, you can add entries to `AUTH_TO_DRIVER_KWARGS` at import time. This is safe because the registry is a mutable dictionary. However, be cautious about adding converters that depend on platform-specific libraries, as this would pull those dependencies into all consumers of the module.

## Part 2: OAuth 1.0a Flow

### OAuth1Flow Class

The `OAuth1Flow` class encapsulates the complete OAuth 1.0a three-legged authorization flow. It is constructed with a spec object (typically a `ProfileSpec`) that contains metadata about the provider's OAuth endpoints.

```python
class OAuth1Flow:
    def __init__(self, spec) -> None:
        self._metadata = spec.metadata

    @property
    def request_token_url(self) -> str:
        return self._metadata["request_token_url"]

    @property
    def authorize_url(self) -> str:
        return self._metadata["authorize_url"]

    @property
    def access_token_url(self) -> str:
        return self._metadata["access_token_url"]
```

The class reads three URLs from the provider metadata: the request token endpoint, the authorization URL (where the user grants consent), and the access token endpoint. These URLs are specific to each OAuth 1.0a provider -- for example, Garmin's connect API uses `https://connectapi.garmin.com/oauth-service/oauth/request_token`.

### Request Token

The first step in the OAuth 1.0a flow is obtaining a temporary request token. The client sends its consumer credentials to the provider's request token endpoint and receives back an `oauth_token` and `oauth_token_secret` pair.

The `request_token` method uses `authlib`'s `OAuth1Client` to handle the cryptographic signing required by OAuth 1.0a. Each request must include an HMAC-SHA1 signature computed over the HTTP method, URL, and parameters using the consumer secret as the key.

```python
def request_token(
    self,
    consumer_key: str,
    consumer_secret: str,
    callback_url: str = "oob",
) -> dict[str, str]:
    from authlib.integrations.httpx_client import OAuth1Client
    client = OAuth1Client(client_id=consumer_key, client_secret=consumer_secret)
    token = client.fetch_request_token(
        self.request_token_url, params={"oauth_callback": callback_url}
    )
    return token
```

The `callback_url` parameter tells the provider where to redirect the user after they grant authorization. Setting it to `"oob"` (out-of-band) indicates that the application will use manual code entry rather than an HTTP redirect. When using the local callback server, this is set to `http://localhost:<port>/callback`.

### Three Legged Flow

The "three legs" of OAuth 1.0a refer to the three parties involved in the authorization dance: the consumer (your application), the provider (the API), and the user. The flow proceeds through three HTTP interactions.

| Leg | From | To | Purpose |
|---|---|---|---|
| 1 | Consumer | Provider | Obtain request token |
| 2 | User | Provider | Authorize the request token (via browser) |
| 3 | Consumer | Provider | Exchange authorized token + verifier for access token |

After obtaining the request token, the flow constructs an authorization URL that includes the `oauth_token` as a query parameter. The user visits this URL in their browser, signs in to the provider, reviews the permissions being requested, and clicks "Allow."

```python
def build_authorize_url(self, oauth_token: str) -> str:
    return f"{self.authorize_url}?{urlencode({'oauth_token': oauth_token})}"
```

Once the user authorizes, the provider redirects them back to the callback URL with an `oauth_verifier` parameter. This verifier is a one-time code that proves the user actually granted consent.

#### Diagram: OAuth 1.0a Three-Legged Flow
<iframe src="../../sims/oauth1-three-legged-flow/main.html" width="100%" height="550px" scrolling="no"></iframe>
<details markdown="1">
<summary>OAuth 1.0a Three-Legged Flow</summary>
Type: workflow
**sim-id:** oauth1-three-legged-flow<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Animate the complete OAuth 1.0a three-legged flow showing the consumer, user, and provider interactions with request token, authorization, and verifier exchange steps.

**Components:** Three lane nodes (Consumer App, User Browser, Provider API) with message arrows between them: (1) Consumer requests temp token from Provider, (2) Provider returns oauth_token + oauth_token_secret, (3) Consumer redirects User to Provider authorize URL, (4) User grants consent, (5) Provider redirects User back with oauth_verifier, (6) Consumer exchanges verifier for access token, (7) Provider returns permanent oauth_token + oauth_token_secret.

**Interactions:** Click "Play" to animate steps sequentially. Click any step number to jump to that stage. Hover on arrows to see the HTTP request/response details. Toggle "Signing Detail" to show HMAC-SHA1 signature computation.

**Colors:** Consumer=SteelBlue, User=Gold, Provider=DarkGoldenrod. Request arrows=DarkSlateBlue, Response arrows=DarkGreen.

**Learning Objective:** Understand (Bloom Level 2) the complete sequence of the OAuth 1.0a three-legged authorization flow and the role of each party.
</details>

### Verifier Exchange

The final step exchanges the authorized request token and verifier code for permanent access credentials. The `exchange_verifier` method calls the provider's access token endpoint with all the cryptographic material needed to prove the exchange is legitimate.

```python
def exchange_verifier(
    self,
    consumer_key: str,
    consumer_secret: str,
    oauth_token: str,
    oauth_token_secret: str,
    verifier: str,
) -> dict[str, str]:
    from authlib.integrations.httpx_client import OAuth1Client
    client = OAuth1Client(
        client_id=consumer_key,
        client_secret=consumer_secret,
        token=oauth_token,
        token_secret=oauth_token_secret,
    )
    token = client.fetch_access_token(self.access_token_url, verifier=verifier)
    return {
        "oauth_token": token["oauth_token"],
        "oauth_token_secret": token["oauth_token_secret"],
    }
```

The returned dictionary contains the permanent `oauth_token` and `oauth_token_secret`. These are stored by the `SecretStore` (Chapter 6) and used for all subsequent API requests. Unlike OAuth 2.0 tokens, OAuth 1.0a access tokens typically do not expire -- they remain valid until the user explicitly revokes them.

If the exchange fails (invalid verifier, expired request token, or provider error), the method raises a `TokenExchangeError` with the URL, HTTP status code, and response body for diagnostics.

### Authlib Dependency

The OAuth 1.0a implementation depends on the `authlib` library for HMAC-SHA1 request signing. However, `authlib` is declared as an optional dependency in the package metadata under the `oauth1` extra. This means users who never connect to OAuth 1.0a providers do not need to install it.

The package declares this optional dependency in `pyproject.toml`:

```toml
[project.optional-dependencies]
oauth1 = ["authlib>=1.0"]
```

Users install it explicitly when needed:

```bash
pip install mountainash-auth-client[oauth1]
```

### Optional Import Guard

Since `authlib` is optional, the code must handle its absence gracefully. The library uses a deferred import pattern: rather than importing `authlib` at the top of the module (which would fail at import time if uninstalled), it imports inside each method that needs it.

```python
def request_token(self, consumer_key, consumer_secret, callback_url="oob"):
    try:
        from authlib.integrations.httpx_client import OAuth1Client
    except ImportError as exc:
        raise ImportError(
            "OAuth1 requires authlib: pip install mountainash-auth-client[oauth1]"
        ) from exc
    # ... use OAuth1Client
```

This pattern provides three important properties. First, the module itself imports successfully even without `authlib`, so importing the package does not fail. Second, the error message clearly tells the user what to install. Third, by chaining `from exc`, the original traceback is preserved for debugging.

The import guard appears in every method that uses `authlib` (both `request_token` and `exchange_verifier`). Placing it in `__init__` would not work because the class might be instantiated speculatively before the flow is actually run.

#### Diagram: Optional Dependency Import Guard Pattern
<iframe src="../../sims/optional-import-guard/main.html" width="100%" height="400px" scrolling="no"></iframe>
<details markdown="1">
<summary>Optional Dependency Import Guard Pattern</summary>
Type: workflow
**sim-id:** optional-import-guard<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Illustrate the deferred import guard pattern showing module load time vs runtime behavior, with and without the optional dependency installed.

**Components:** Two parallel paths. "Installed" path: Module loads -> Method called -> `from authlib import...` succeeds -> OAuth1Client used -> Success. "Not installed" path: Module loads (same, succeeds) -> Method called -> `from authlib import...` raises ImportError -> Caught -> Clear error message raised with install instructions.

**Interactions:** Toggle between "authlib installed" and "authlib missing" to animate the respective paths. Click on the error node to see the full exception chain.

**Colors:** Success path=DarkGreen, Error path=Crimson, Module load=SteelBlue, Method call=Gold.

**Learning Objective:** Apply (Bloom Level 3) the optional import guard pattern to handle optional dependencies gracefully in Python libraries.
</details>

## OAuth 1.0a vs OAuth 2.0: Key Implementation Differences

Having now seen both OAuth 1.0a (this chapter) and OAuth 2.0 (Chapter 5) implementations, it is worth summarizing the key differences that drive the architectural split into separate flow classes.

| Aspect | OAuth 1.0a | OAuth 2.0 |
|---|---|---|
| Request signing | Every API request signed with HMAC-SHA1 | No request signing; bearer token in header |
| Token structure | Token + token secret (two values) | Access token only (one value) |
| Token expiry | Typically never expires | Short-lived (usually 1 hour) |
| Refresh mechanism | None needed (tokens persist) | Refresh token exchange |
| Transport security | Signature provides integrity without TLS | Relies entirely on TLS |
| Library dependency | Requires `authlib` for signing | Uses `httpx` directly |
| PKCE equivalent | Not applicable (signatures prevent interception) | PKCE extension |

These differences explain why the library uses separate `OAuth1Flow` and `OAuthFlow` classes rather than a single polymorphic flow class. The token lifecycle model (Chapter 8) also differs: OAuth 1.0a tokens do not expire, so the connection mixin for OAuth 1.0a does not implement refresh logic.

## The Complete OAuth 1.0a `authorize` Method

The `OAuth1Flow.authorize` method orchestrates the entire flow end-to-end. It supports two redirect modes: `local_server` (starts an ephemeral HTTP server to capture the callback) and `manual` (uses out-of-band code entry). The method coordinates request token acquisition, user authorization, and verifier exchange into a single call.

```python
def authorize(
    self,
    consumer_key: str,
    consumer_secret: str,
    redirect_mode: Literal["local_server", "manual"] = "local_server",
) -> dict[str, str]:
    if redirect_mode == "local_server":
        server = LocalCallbackServer(port=0)
        callback_url = server.redirect_uri
    else:
        callback_url = "oob"

    request_token = self.request_token(consumer_key, consumer_secret, callback_url)
    url = self.build_authorize_url(request_token["oauth_token"])

    if redirect_mode == "local_server":
        webbrowser.open(url)
        params = server.wait_for_callback()
        verifier = params.get("oauth_verifier", "")
    else:
        params = prompt_for_code(url)
        verifier = params.get("oauth_verifier", params.get("code", ""))

    return self.exchange_verifier(
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        oauth_token=request_token["oauth_token"],
        oauth_token_secret=request_token["oauth_token_secret"],
        verifier=verifier,
    )
```

The method returns a dictionary with `oauth_token` and `oauth_token_secret` keys -- the permanent credentials for accessing the API. These are then persisted by the connection mixin through the `SecretStore`.

## Key Takeaways

- **The dispatch registry** (`AUTH_TO_DRIVER_KWARGS`) maps auth type classes to converter functions that produce driver-compatible kwargs dictionaries. It covers six of thirteen types.
- **`auth_to_driver_kwargs`** uses `type(auth)` for exact-type dispatch, delegating to the registered converter and raising `KeyError` for unmapped types.
- **`auth_kwargs`** is a convenience wrapper that safely extracts auth from any profile object, returning an empty dict if no auth is present.
- **Type-based dispatch** via a dictionary registry is open for extension, inspectable, and overridable, making it preferable to `isinstance()` chains for this use case.
- **Unmapped auth types** (WindowsAuth, AzureADAuth, KerberosAuth, CertificateAuth, ServiceAccountAuth) intentionally lack default dispatch. Backend adapters catch the `KeyError` and apply platform-specific logic.
- **OAuth1Flow** implements the three-legged OAuth 1.0a flow: request token, user authorization, and verifier exchange, producing permanent access credentials.
- **The authlib dependency** is optional (installed via `[oauth1]` extra). The **import guard pattern** uses `try: from authlib... except ImportError` inside methods, allowing the module to load without the dependency while providing clear install instructions at call time.
- Both dispatch and OAuth1 flows use **error chaining** (`from exc`) to preserve diagnostic context when re-raising exceptions.

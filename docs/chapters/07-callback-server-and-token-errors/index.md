---
title: Callback Server and Token Errors
description: The LocalCallbackServer for capturing OAuth redirects, fallback code entry modes, and the typed exception hierarchy for token exchange and refresh failures.
generated_by: claude skill chapter-content-generator
date: 2026-06-03
version: 0.08
---

# Callback Server and Token Errors

## Summary

This chapter covers two components that support OAuth authorization flows. First, the LocalCallbackServer used for capturing OAuth redirect callbacks, including the ephemeral HTTP server, callback capture with state validation, the prompt-for-code fallback, and manual redirect mode for headless environments. Second, the typed exceptions for token operation failures: TokenExchangeError with its diagnostic URL, and TokenRefreshError with HTTP status code context.

## Concepts Covered

- LocalCallbackServer
- Ephemeral HTTP Server
- Callback Capture
- Prompt For Code
- Manual Redirect Mode
- TokenExchangeError
- Token Exchange URL
- TokenRefreshError
- Refresh Status Code

## Prerequisites

- Chapter 1: Foundations (Context Managers)
- Chapter 5: OAuth 2.0 Flow (State Parameter, Token Exchange, Refresh Token)

## Learning Objectives

After completing this chapter, you will be able to:

- Start and stop a LocalCallbackServer for OAuth redirects
- Capture authorization callbacks with state parameter validation
- Fall back to manual code entry when local binding is unavailable
- Configure manual redirect mode for headless environments
- Handle TokenExchangeError with diagnostic URL information
- Handle TokenRefreshError with HTTP status code context

---

## The Callback Problem

OAuth authorization flows require capturing a redirect from the authorization server back to the client. The authorization server appends an authorization code and state parameter to a redirect URI, and the client must receive these values to continue the flow. In web applications, the redirect URI points to an application endpoint. In CLI tools and desktop applications, there is no pre-existing HTTP endpoint to receive the redirect.

The mountainash-auth-client library solves this with a short-lived local HTTP server that starts, waits for a single redirect, extracts the parameters, and shuts down. For environments where binding a local port is not possible (containers, remote SSH sessions, CI/CD), the library provides a fallback mode where the user manually copies the redirect URL or authorization code.

<!-- concept:75 -->
## LocalCallbackServer

The `LocalCallbackServer` class manages the lifecycle of an ephemeral HTTP server that captures a single OAuth callback. It binds to localhost, generates a redirect URI based on the assigned port, and blocks until a callback request arrives or a timeout expires.

The constructor accepts two parameters: the port number (defaulting to 0 for automatic assignment) and a timeout in seconds (defaulting to 120).

```python
class LocalCallbackServer:
    def __init__(self, port: int = 0, timeout: int = 120) -> None:
        self._server = HTTPServer(("localhost", port), _CallbackHandler)
        self._server._callback_params = None
        self._timeout = timeout
```

Specifying port 0 tells the operating system to assign an available ephemeral port. This avoids conflicts with other services and removes the need for users to configure a specific port. The actual assigned port is available through the `port` property after construction.

Two properties provide the server's addressing information:

- **`port`** -- the actual port number assigned by the OS (useful for constructing the redirect URI)
- **`redirect_uri`** -- the full callback URL in the format `http://localhost:{port}/callback`

<!-- concept:76 -->
### Ephemeral HTTP Server

The underlying HTTP server uses Python's standard library `HTTPServer` from `http.server`. It is configured with a custom request handler class (`_CallbackHandler`) that processes a single GET request and extracts query parameters from the URL.

```python
class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        self.server._callback_params = {k: v[0] for k, v in params.items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Authorization complete.</h1>"
                         b"<p>You can close this window.</p></body></html>")

    def log_message(self, format, *args) -> None:
        pass
```

The handler does four things on receiving a request. First, it parses the query string into a dictionary (flattening multi-value params by taking the first value). Second, it stores the parameters on the server instance for later retrieval. Third, it responds with a simple HTML page telling the user they can close the browser tab. Fourth, it suppresses the default request logging by overriding `log_message` with a no-op.

The term "ephemeral" is significant: the server handles exactly one request and then shuts down. It is not a long-running service. This minimizes the window during which the port is open, reducing the attack surface.

<!-- concept:77 -->
### Callback Capture

The `wait_for_callback` method blocks the calling thread until the HTTP server receives a callback request or the timeout expires. It delegates to `HTTPServer.handle_request()`, which processes a single incoming request.

```python
def wait_for_callback(self) -> dict[str, str]:
    self._server.timeout = self._timeout
    self._server.handle_request()
    if self._server._callback_params is None:
        raise TimeoutError("No callback received within timeout")
    try:
        return self._server._callback_params
    finally:
        self._server.server_close()
```

After the callback is captured, the method closes the server socket (via `server_close()`) in a `finally` block to ensure cleanup even if subsequent code raises an exception. The returned dictionary typically contains `code` (the authorization code) and `state` (the CSRF protection token).

If the timeout expires before any request arrives, the method raises a `TimeoutError`. This can happen when the user closes the browser without completing authorization, when a firewall blocks the redirect, or when the provider's redirect URI does not match the registered callback URL.

#### Diagram: Callback Server Lifecycle
<iframe src="../../sims/callback-server-lifecycle/main.html" width="100%" height="500px" scrolling="no"></iframe>
<details markdown="1">
<summary>Callback Server Lifecycle</summary>
Type: workflow
**sim-id:** callback-server-lifecycle<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Show the complete lifecycle of the LocalCallbackServer from instantiation through port binding, waiting, callback receipt, parameter extraction, response to browser, and server close.

**Components:** Sequential nodes: Construct (port=0) -> OS assigns port -> redirect_uri available -> wait_for_callback() blocking -> Browser redirects to localhost:port/callback?code=X&state=Y -> Handler extracts params -> 200 response sent -> server_close() -> return params dict. A timeout branch shows the TimeoutError path.

**Interactions:** Click "Play" to animate the normal flow. Click "Simulate Timeout" to see the timeout path. Hover on the "blocking" node to see what the thread is doing while waiting. Click the browser redirect to see the full URL with query parameters.

**Colors:** Server lifecycle=SteelBlue, Browser interaction=Gold, Success path=DarkGreen, Timeout path=Crimson.

**Learning Objective:** Understand (Bloom Level 2) the complete lifecycle of the LocalCallbackServer and how it bridges the gap between browser-based OAuth redirects and CLI applications.
</details>

## Fallback Modes

Not every environment can bind a local port. Remote SSH sessions, Docker containers without exposed ports, headless CI runners, and sandboxed environments all present situations where `LocalCallbackServer` cannot function. The library provides two fallback approaches.

<!-- concept:78 -->
### Prompt For Code

The `prompt_for_code` function implements the simplest fallback: print the authorization URL, ask the user to visit it in a browser, complete the consent flow, and then paste either the redirect URL or the bare authorization code back into the terminal.

```python
def prompt_for_code(authorize_url: str) -> dict[str, str]:
    print(f"\nOpen this URL in your browser to authorize:\n\n  {authorize_url}\n")
    user_input = input("Paste the redirect URL or authorization code: ")
    return extract_code_from_input(user_input)
```

The companion `extract_code_from_input` function handles two input formats. If the user pastes a full URL (starting with `http`), it parses the query parameters and extracts `code` and `state`. If the user pastes a bare string (the authorization code itself), it wraps it in a `{"code": user_input}` dictionary.

```python
def extract_code_from_input(user_input: str) -> dict[str, str]:
    user_input = user_input.strip()
    if user_input.startswith("http"):
        parsed = urlparse(user_input)
        params = parse_qs(parsed.query)
        result: dict[str, str] = {}
        if "code" in params:
            result["code"] = params["code"][0]
        if "state" in params:
            result["state"] = params["state"][0]
        return result
    return {"code": user_input}
```

This dual-format handling accommodates different provider behaviors. Some providers redirect to the callback URL (which the user can copy from the browser address bar). Others display the code directly on a page (particularly when using the `urn:ietf:wg:oauth:2.0:oob` redirect URI).

<!-- concept:79 -->
### Manual Redirect Mode

Manual redirect mode is engaged at the `OAuthFlow.authorize()` level by passing `redirect_mode="manual"`. When this mode is active, the flow uses `urn:ietf:wg:oauth:2.0:oob` as the redirect URI instead of a localhost URL. This special URI tells the authorization server to display the authorization code on-screen rather than performing an HTTP redirect.

The `urn:ietf:wg:oauth:2.0:oob` URI is a well-known special value defined by Google's OAuth implementation and adopted by other providers. When the authorization server receives this as the redirect URI, it knows to display the authorization code on a page rather than issuing an HTTP redirect. Not all providers support this URI -- some require a registered `http://localhost` redirect URI even for manual mode. The library's use of this URI works with the major providers in the mountainash ecosystem.

The two redirect modes and their use cases are:

| Mode | Redirect URI | User Interaction | Best For |
|---|---|---|---|
| `local_server` | `http://localhost:{port}/callback` | Browser opens automatically; callback captured silently | Desktop environments with browser access |
| `manual` | `urn:ietf:wg:oauth:2.0:oob` | User copies URL to browser, pastes code back | SSH sessions, containers, headless environments |

The flow logic for choosing between modes is straightforward: the `OAuthFlow.authorize` method checks the `redirect_mode` parameter and either starts a `LocalCallbackServer` or calls `prompt_for_code`.

## Token Error Types

When token operations fail, the library raises typed exceptions that carry diagnostic information. Rather than catching generic HTTP errors and re-raising them with string messages, the library defines two specific exception classes that preserve the URL, status code, and response body.

<!-- concept:80 -->
### TokenExchangeError

`TokenExchangeError` is raised when the authorization code exchange fails -- typically because the code has expired, the redirect URI does not match, or the client credentials are invalid.

```python
class TokenExchangeError(Exception):
    def __init__(self, *, url: str, status_code: int, body: str) -> None:
        self.url = url
        self.status_code = status_code
        self.body = body
        super().__init__(f"Token exchange failed: HTTP {status_code} POST {url} -- {body[:200]}")
```

The exception carries three structured attributes:

- **`url`** -- the token endpoint URL that was called (the Token Exchange URL)
- **`status_code`** -- the HTTP response status code (e.g., 400 for invalid grant, 401 for bad credentials)
- **`body`** -- the first 2000 characters of the response body, which typically contains a JSON error description from the provider

<!-- concept:81 -->
### Token Exchange URL

The `url` attribute on `TokenExchangeError` serves a specific diagnostic purpose. When a token exchange fails, knowing which URL was called helps determine whether the issue is a misconfigured endpoint (wrong URL), a network problem (connection refused), or a provider-side error. The same URL is used for both initial exchange and refresh, so the error message includes the HTTP method (`POST`) for clarity.

The error message is constructed to be immediately useful in logs: `"Token exchange failed: HTTP 400 POST https://oauth.provider.com/token -- {"error":"invalid_grant","error_description":"Code expired"}"`. This includes the status code, the URL, and enough of the body to identify the provider's error message without overwhelming log aggregators with multi-kilobyte responses.

<!-- concept:82 -->
### TokenRefreshError

`TokenRefreshError` has an identical structure to `TokenExchangeError` but represents a different failure context: the refresh token exchange failed, meaning the refresh token may be expired or revoked.

```python
class TokenRefreshError(Exception):
    def __init__(self, *, url: str, status_code: int, body: str) -> None:
        self.url = url
        self.status_code = status_code
        self.body = body
        super().__init__(f"Token refresh failed: HTTP {status_code} POST {url} -- {body[:200]}")
```

<!-- concept:83 -->
### Refresh Status Code

The `status_code` attribute on `TokenRefreshError` is particularly important for determining the correct recovery action. Different status codes indicate different failure modes.

| Status Code | Meaning | Recommended Action |
|---|---|---|
| 400 | Invalid grant (expired or revoked refresh token) | Clear credentials, require re-authorization |
| 401 | Invalid client credentials | Check client_id/client_secret configuration |
| 403 | Scope or permission denied | Review requested scopes |
| 429 | Rate limited | Retry after delay |
| 500+ | Provider server error | Retry with exponential backoff |

The connection mixin (Chapter 8) uses the presence of a `TokenRefreshError` to trigger credential clearing and, if `auto_authorize` is enabled, a full re-authorization flow. The status code can be inspected by upstream code for more nuanced error handling.

#### Diagram: Token Error Hierarchy and Recovery
<iframe src="../../sims/token-error-recovery/main.html" width="100%" height="450px" scrolling="no"></iframe>
<details markdown="1">
<summary>Token Error Hierarchy and Recovery</summary>
Type: workflow
**sim-id:** token-error-recovery<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Show how TokenExchangeError and TokenRefreshError are raised, caught, and used to determine recovery actions in the connection mixin.

**Components:** Two source nodes (exchange_code method, refresh method) each connect to their respective error types when HTTP errors occur. Each error type connects to decision nodes based on status_code, leading to different recovery actions (re-authorize, clear credentials, retry, check config). A "Connection Mixin" node shows how it catches these errors and decides between clear+re-auth and propagation.

**Interactions:** Click on a status code to see the recovery path highlight. Toggle between "Exchange Error" and "Refresh Error" contexts to see how the same status codes lead to different actions. Click "Show Code" on any node to see the relevant exception handling code.

**Colors:** Error types=Crimson, Recovery actions=DarkGreen, Decision nodes=Gold, Source methods=SteelBlue.

**Learning Objective:** Evaluate (Bloom Level 5) which recovery strategy is appropriate for different token error status codes and how the connection mixin uses these errors to manage token lifecycle.
</details>

## Error Design Philosophy

The token error types in mountainash-auth-client follow several design principles that are worth examining.

**Structured attributes over message parsing.** Each error carries typed attributes (`url`, `status_code`, `body`) rather than embedding all information in the exception message string. This allows programmatic error handling without regex parsing. Code can inspect `exc.status_code` directly rather than extracting it from a message like `"Token exchange failed: HTTP 400..."`.

**Keyword-only constructors.** Both error classes use `*` in their `__init__` signatures, forcing callers to use named arguments: `TokenExchangeError(url=..., status_code=..., body=...)`. This prevents a common bug where positional arguments are accidentally swapped (passing the body as the URL, for example).

**Truncated body for safety.** The response body is truncated to 2000 characters at the point of capture (`exc.response.text[:2000]`). This prevents memory issues when providers return large HTML error pages, and keeps log output manageable. The truncation happens at the raise site, not in the exception constructor, so the stored `body` attribute is already safe to log or display.

**Separation of exchange and refresh errors.** Despite having identical structures, `TokenExchangeError` and `TokenRefreshError` are separate classes. This allows `except` clauses to catch them independently, enabling different recovery strategies. An exchange failure during initial authorization has different implications than a refresh failure during background token renewal.

**Exception chaining.** Both errors are raised with `from exc` to preserve the original `httpx.HTTPStatusError`. This means that `exc.__cause__` contains the full HTTP response object, headers, and request details for deep debugging without polluting the primary exception's interface.

## How the Components Work Together

The callback server and token errors are support components that plug into the OAuth 2.0 flow (Chapter 5) and connection mixin (Chapter 8). Their interactions form a coherent error-handling and user-interaction layer.

During authorization, the flow is:

1. `OAuthFlow.authorize()` decides the redirect mode
2. If `local_server`: `LocalCallbackServer` starts, browser opens, callback is captured
3. If `manual`: `prompt_for_code` prints URL and reads user input
4. `OAuthFlow.exchange_code()` sends the code to the token endpoint
5. If the endpoint returns an error: `TokenExchangeError` is raised with full context

During token refresh (triggered by the connection mixin):

1. `OAuthFlow.refresh()` sends the refresh token to the token endpoint
2. If the endpoint returns an error: `TokenRefreshError` is raised
3. The connection mixin catches `TokenRefreshError`, clears stored credentials, and either re-authorizes or raises `AuthorizationRequired`

!!! tip "Debugging Token Errors"
    When encountering a `TokenExchangeError` or `TokenRefreshError`, the `body` attribute is your primary diagnostic tool. Most OAuth providers include an `error` field (`"invalid_grant"`, `"invalid_client"`, `"unauthorized_client"`) and an `error_description` field with human-readable details. Check the `body` first before investigating network-level issues.

## Security Considerations for the Callback Server

The `LocalCallbackServer` listens on `localhost` only, which means it is not accessible from other machines on the network. However, other processes on the same machine can make requests to it. This creates a theoretical attack vector where a malicious local process sends a forged callback with a fake authorization code.

The state parameter mitigates this attack. Because the state is a cryptographic random value generated fresh for each flow and validated on receipt, a local attacker would need to guess the state value (256 bits of entropy) to forge a valid callback. Without the correct state, the `OAuthFlow.authorize` method rejects the callback with a state mismatch error.

Additionally, the server handles exactly one request and then shuts down. The window of vulnerability is narrow -- typically a few seconds to two minutes. Combined with the state validation, this makes callback forgery attacks impractical in real-world scenarios.

For high-security environments where even local-host callbacks are unacceptable, the `manual` redirect mode avoids binding a port entirely. The tradeoff is user convenience: manual mode requires the user to copy and paste a URL rather than having the browser handle the redirect automatically.

## Key Takeaways

- **LocalCallbackServer** is an ephemeral HTTP server that binds to `localhost` on an OS-assigned port, captures a single OAuth redirect callback, responds with a user-friendly HTML page, and shuts down.
- **The ephemeral server** uses Python's `HTTPServer` with a custom handler that extracts query parameters from the redirect URL and stores them for retrieval.
- **Callback capture** blocks until a request arrives or the timeout (default 120 seconds) expires. The server is closed in a `finally` block to guarantee cleanup.
- **`prompt_for_code`** is the fallback for environments without local port access. It accepts both full redirect URLs and bare authorization codes as user input.
- **Manual redirect mode** uses the `urn:ietf:wg:oauth:2.0:oob` URI to signal that the provider should display the code on-screen rather than performing an HTTP redirect.
- **`TokenExchangeError`** carries the token endpoint URL, HTTP status code, and response body (truncated to 2000 chars) for diagnostics when authorization code exchange fails.
- **`TokenRefreshError`** has the same structure and is raised when refresh token exchange fails, typically indicating an expired or revoked refresh token.
- **The status code** on both error types enables structured recovery logic: 400 means clear and re-authorize, 401 means check configuration, 429/5xx means retry.
- Both errors use **keyword-only constructors** (`*, url, status_code, body`) for clarity at the call site, preventing argument ordering mistakes.

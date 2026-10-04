# mountainash-auth-client — Integration Guide

**Audience:** developers integrating `mountainash-auth-client` into a transport,
client, or service layer (the canonical consumer today is `mountainash-transport`).

Start with the [runnable recipes](../examples/) for complete offline examples,
or the [README quick start](../README.md#quick-start). See [typing](typing.md)
for the public profile and credential contracts.

`mountainash-auth-client` is the **single source of truth** for authentication in the
mountainash stack. It owns:

1. **Auth profiles** — declarative credential carriers (`TokenAuthProfile`, `IAMAuthProfile`, …).
2. **`emit()`** — the one primitive that injects a profile's credentials into an SDK client's kwargs.
3. **OAuth flow lifecycle + callback servers** — `OAuthFlow`/`OAuth1Flow` resolvers and `LocalCallbackServer`/`ManualCallbackServer`.

It depends on `mountainash-settings` (the `Profile`/`Registry`/`emit` machinery and the
secrets backend) and is consumed *above* by transport/client layers.

---

## Install

Requires **Python 3.12+**. Runtime metadata selects
`mountainash-settings>=0.1.0,<0.2`.

```toml
# pyproject.toml
dependencies = ["mountainash-auth-client"]

# optional extras (only pull what you use):
# [oauth1] → authlib  (OAuth 1.0a 3-legged flow)
# [sftp]   → paramiko (SSH/SFTP auth strategies)
```

`mountainash-auth-client[oauth1]` and `mountainash-auth-client[sftp]` guard their SDKs
behind `require_authlib(...)` / `require_paramiko(...)`, so importing the package without
the extra is safe — the optional dependency is only needed when you actually use that path.

---

## Core concepts

### Auth profiles

Every credential type is a `Profile` subclass with `UPPER_CASE` fields and a stable name.
Profiles carry **only credentials/config** — no I/O, no SDK clients. Construct them directly:

```python
from mountainash_auth_client import TokenAuthProfile, IAMAuthProfile, PasswordAuthProfile

TokenAuthProfile(TOKEN="abc123")
IAMAuthProfile(ACCESS_KEY_ID="AKIA…", SECRET_ACCESS_KEY="…", SESSION_TOKEN="…")
PasswordAuthProfile(USERNAME="u", PASSWORD="p")
```

### `TargetFamily`

The SDK family a profile emits *for*. Only three families are modelled today — the SDKs
auth-client knows how to inject credentials into:

```python
from mountainash_auth_client import TargetFamily
TargetFamily.HTTP      # httpx clients   → Authorization headers, auth= param
TargetFamily.BOTO      # boto3 clients   → aws_access_key_id / _secret / _session_token
TargetFamily.PARAMIKO  # paramiko SSH    → password / key_filename / gss_* kwargs
```

A given auth profile resolves to a **different strategy per family** — e.g. `PasswordAuthProfile`
emits an HTTP `Authorization: Basic …` header for `HTTP`, but `password=`/`username=` kwargs
for `PARAMIKO`.

### `emit()` — the integration primitive

```python
def emit(self, target: TargetFamily, *, base: dict | None = None) -> dict
```

`emit(target, base=...)` returns **`base` with the profile's credentials layered in** for that
SDK family. This is the *entire* integration surface for credential injection:

```python
import httpx

from mountainash_auth_client import TokenAuthProfile, TargetFamily

base = {"timeout": 30}                                  # your SDK config
kwargs = TokenAuthProfile(TOKEN="abc").emit(TargetFamily.HTTP, base=base)
# → {"timeout": 30, "headers": {"Authorization": "Bearer abc"}}
with httpx.Client(**kwargs) as client:
    request = client.build_request("GET", "https://files.example.com/sales.csv")
```

Contract:
- **`base` is caller-owned** — `emit` takes a shallow copy; it never mutates your dict.
- **`NoAuthProfile` / no credentials → passthrough** — `emit` returns `base` unchanged.
- **Targeted & fail-closed** — auth profiles are target-scoped, so `emit()` with no/unknown
  target raises rather than silently dropping credentials. Always pass the `TargetFamily`.
- **Nested bases** (e.g. an S3 assume-role envelope `{base_kwargs, role_arn, …}`) — emit
  credentials onto the inner `base_kwargs`, not the envelope; the consumer decides this.

---

## Pattern 1 — Credential injection via `emit()` (the primary integration)

This is how a transport/client layer should assemble an authenticated SDK client. The
canonical consumer (`mountainash-transport`) does a **two-stage emit on one family**: the
storage/endpoint profile emits its config, then the auth profile layers credentials onto it.

```python
from mountainash_auth_client import NoAuthProfile, TargetFamily

def build_kwargs(endpoint_profile, auth_profile, family: TargetFamily) -> dict:
    base = endpoint_profile.emit(family)               # SDK config (your layer)
    if auth_profile is None or isinstance(auth_profile, NoAuthProfile):
        return base                                    # no credentials
    if "base_kwargs" in base:                          # nested envelope (e.g. S3 assume-role)
        return {**base, "base_kwargs": auth_profile.emit(family, base=base["base_kwargs"])}
    return auth_profile.emit(family, base=base)        # credentials layered on the same family
```

Then hand `build_kwargs(...)` to your SDK constructor (`httpx.Client(**kwargs)`,
`boto3.client("s3", **kwargs)`, `paramiko.SSHClient().connect(**kwargs)`).

> Reference implementation: `mountainash-transport` `connections/__init__.py::_emit_kwargs`.

### Auth-profile catalogue

| Profile | Key fields | Emits for | Injects |
|---|---|---|---|
| `NoAuthProfile` | — | any | passthrough |
| `TokenAuthProfile` | `TOKEN` | HTTP | `Authorization: Bearer …` |
| `JWTAuthProfile` | `TOKEN` | HTTP | `Authorization: Bearer …` |
| `PasswordAuthProfile` | `USERNAME`, `PASSWORD` | HTTP / PARAMIKO | Basic header / `username`+`password` |
| `IAMAuthProfile` | `ACCESS_KEY_ID`, `SECRET_ACCESS_KEY`, `SESSION_TOKEN`, `ROLE_ARN`, `PROFILE_NAME` | BOTO | `aws_access_key_id`/`_secret_access_key`/`_session_token` |
| `KerberosAuthProfile` | `SERVICE_NAME`, `PRINCIPAL`, `KEYTAB` | PARAMIKO | `gss_auth`/`gss_host`/`gss_kex` |
| `CertificateAuthProfile` | `PRIVATE_KEY`/`PRIVATE_KEY_PATH`, `PASSPHRASE` | PARAMIKO | `key_filename`/`pkey` + `passphrase` |
| `OAuth1AuthProfile` | `CONSUMER_KEY`, `CONSUMER_SECRET`, `ACCESS_TOKEN`, `ACCESS_TOKEN_SECRET` | HTTP | authlib `auth=` (OAuth1 signing) |
| `OAuth2AuthProfile` | `CLIENT_ID`, `CLIENT_SECRET`, `ACCESS_TOKEN`, `REFRESH_TOKEN`, `SCOPE` | HTTP | `Authorization: Bearer …` (from `ACCESS_TOKEN`) |

`WindowsAuthProfile`, `AzureADAuthProfile` and `ServiceAccountAuthProfile` also
describe credentials, but currently provide no built-in target renderers.
Consumer-specific shapes should be rendered by consumer-owned adapters.

Secret fields (`*_SECRET`, `PASSWORD`, …) are `SecretStr`. Built-in renderers
unwrap them when needed; consumers using `emit()` need not unwrap fields first.
Custom consumer-owned adapters may unwrap at their own SDK boundary. Emitted
kwargs and acquired `TokenCredential` values contain usable plaintext secrets.

`CONST_AUTH_PROFILES` enumerates the modes for registry/config use:
`NONE, PASSWORD, TOKEN, JWT, OAUTH1, OAUTH2, IAM, AZURE_AD, WINDOWS, KERBEROS, CERTIFICATE, SERVICE_ACCOUNT`.

---

## Pattern 2 — OAuth flow lifecycle (resolvers + acquire seam)

For OAuth providers the token must be *resolved* (cached → refreshed → authorized → persisted)
before it can be emitted. auth-client owns this lifecycle; integrate at the **resolver** seam.

### Resolvers (client-agnostic — recommended for custom binding)

```python
from mountainash_auth_client import OAuthFlow              # OAuth2
from mountainash_auth_client.oauth.oauth1.flow import OAuth1Flow

# OAuth2: cache → refresh → authorize → persist → access token
token = OAuthFlow(provider, token_store=store).resolve_access_token(
    auth_profile, auto_authorize=False, callback_server=None,
)  # -> str ; raises AuthorizationRequired when no usable token and auto_authorize=False

# OAuth1: cache → authorize → persist → token pair
oauth_token, oauth_token_secret = OAuth1Flow(provider, token_store=store).resolve_token_pair(
    auth_profile, auto_authorize=False, callback_server=None,
)  # -> tuple[str, str]
```

Bind the resolved token onto **your** endpoint config via `emit()`:

```python
from mountainash_auth_client import TokenAuthProfile, TargetFamily

token = OAuthFlow(provider, token_store=store).resolve_access_token(auth_profile)
kwargs = TokenAuthProfile(TOKEN=token).emit(TargetFamily.HTTP, base=my_endpoint_config)
client = httpx.Client(**kwargs)
```

This lets transport keep its per-endpoint httpx config (timeouts, TLS, redirects)
while reusing auth-client's lifecycle. Here `store` is the raw, open store selected
by the application, as shown below. Downstream callers must migrate to this interface.

### Token acquisition seam (`acquire()` / `acquire_auth()`)

`OAuth2TokenManager` and `OAuth1TokenManager` are the lifecycle entry points. They resolve a
token (cache → refresh → authorize → persist) and return a credential you can emit directly:

```python
from mountainash_auth_client import OAuth2TokenManager, TokenAuthProfile, TargetFamily
from mountainash_settings.secrets import FilesystemBackend

# root, provider and auth_profile are supplied by the application.
with FilesystemBackend(root) as store:
    manager = OAuth2TokenManager(provider, auth_profile, token_store=store)
    cred = manager.acquire()  # TokenCredential; non-interactive
    kw = TokenAuthProfile(TOKEN=cred.access_token).emit(TargetFamily.HTTP)
    # Use kw with the consumer's transport inside this application-owned lifetime.
    # Any creds_provider callback using manager must finish before store closes.
```

For OAuth 1.0a, `OAuth1TokenManager(provider, auth_profile, token_store=store).acquire_auth()` returns an `httpx.Auth` signer for
`RequestCreds(auth=…)` — OAuth1 is per-request signing, not a Bearer header, so the signer is
passed directly rather than emitted as headers.

**Error contract:** a use-time auth failure raises `AuthorizationRequired` (no usable token and
interactive authorize is disabled) or `TokenRefreshError` (refresh call failed). When surfaced
through http-client's request path these arrive as `SourceAuthenticationError`; the consumer
maps `__cause__` to detect which domain error triggered reauth (Phase 3 §6 / Phase 4).

### Selected token store and ownership

Both lifecycle managers require an explicit `token_store=` implementing settings'
`ClearableSecretStore`: `get`, `set`, `delete`, `is_cleared`, and per-key `transaction`.
There is no token-store registry, implicit backend, or provider-name lookup.
Flows may omit the store for wire-only authorization/exchange operations; persistence
operations require it and report missing capabilities as errors.

Managers also require credential profiles with an application-defined
`persist_key()`. For example:

```python
from mountainash_auth_client import OAuth2AuthProfile

class ReportCredentials(OAuth2AuthProfile):
    def persist_key(self) -> str:
        return "reports_app.report_user"

auth_profile = ReportCredentials(CLIENT_ID="reports-client", SCOPE="reports.read")
```

Choose keys that distinguish accounts sharing the store. Built-in auth profiles
do not supply `persist_key()`. Interactive OAuth2 authorization requires a
non-empty client ID even when `TOKEN_ENDPOINT_AUTH_METHOD="none"`. Cached flow
resolvers can accept key-only objects; see the [typing contracts](typing.md).

Pass the **raw store** to managers and flows, never a pre-namespaced wrapper.
auth-client applies `oauth` exactly once, retaining `persist_key()`, token field names,
clear markers, and on-disk addressing. A clear marker takes precedence over stale data.
Store errors propagate rather than becoming a missing token or successful authentication.

The application constructs and closes the store (for example, with
`with FilesystemBackend(root) as store:` above). Provision the root directory before
opening it. Managers and flows borrow it and never close it.
Refresh read/decision/exchange/write is serialized per key; interactive
authorization happens outside the transaction, followed by a short serialized write.

Configured credential profiles remain data consumed by existing, consumer-selected
renderers. Acquired OAuth tokens live in the selected store; selecting that store
does not mutate renderers or turn configured profiles into acquired-token records.
Non-OAuth credential emission needs no token store.

### Callback servers (interactive authorize)

When `auto_authorize=True` and no token is cached, the flow runs the authorization-code
exchange via a **callback server**. auth-client provides:

- `LocalCallbackServer` — binds a localhost port, opens the browser (with a print fallback), waits for the redirect, guarantees socket cleanup.
- `ManualCallbackServer` — out-of-band: prints the URL, reads the pasted redirect/code. (`extract_code_from_input`, `prompt_for_code` are the free functions behind it.)

Pass a `CallbackServerFactory` (a `Callable[[], CallbackServerProtocol]`) as `callback_server=`
to a manager or flow constructor, or as a per-call override on a flow's resolver
or `authorize()`. Flows select built-ins through `redirect_mode` (`"local_server"`
or `"manual"`); managers use `authorize(mode=...)`.

For example, with a configured provider, credential profile and open token store:

```python
manager = OAuth2TokenManager(provider, auth_profile, token_store=store)
manager.authorize(mode="manual", manual_redirect_uri="https://reports.example.com/callback")
credential = manager.acquire()
```

This is a live operation: register the redirect with the provider and paste the
complete callback URL, including its state. OAuth2 rejects a bare code without
matching state. `acquire()` remains non-interactive; `revoke()` removes local
tokens and does not call a provider revocation endpoint.

---

## Errors

```python
from mountainash_auth_client import (
    AuthorizationRequired,     # no usable token & auto_authorize=False
    TokenExchangeError,        # token endpoint failed during code exchange
    TokenRefreshError,         # refresh failed
    CallbackError,             # base for callback failures
    AuthorizationDeniedError,  # provider returned ?error= on the callback
    MalformedCallbackError,    # callback missing code/verifier
    CallbackTimeoutError,      # callback wait timed out (also a TimeoutError)
)
```

If your layer exposes its own exception hierarchy, **translate at the boundary** (catch
auth-client's, re-raise yours) rather than leaking auth-client's types — this is what transport
does to preserve its public `AuthorizationRequired` contract.

---

## Integration checklist

1. **Depend on** `mountainash-auth-client` (+ `[oauth1]`/`[sftp]` extras only if used). The settings dependency supplies `mountainash_settings.secrets`; there is no separate secrets dependency.
2. **Credential injection:** call `auth_profile.emit(family, base=sdk_config)` and feed the result to your SDK constructor. Treat `NoAuthProfile`/`None` as passthrough; layer onto nested `base_kwargs` when present.
3. **Pick the family explicitly** — `emit()` is fail-closed; never call it untargeted.
4. **OAuth:** select and own a raw `ClearableSecretStore`, pass `token_store=store` to `OAuth2TokenManager(provider, auth_profile, token_store=store).acquire()` (OAuth2) or `OAuth1TokenManager(provider, auth_profile, token_store=store).acquire_auth()` (OAuth1), then render the acquired credential for your endpoint config. Provide a `callback_server` factory if you support interactive authorize.
5. **Render at the consumer boundary** — use `emit()` for built-in targets or a consumer-owned adapter for another shape; keep plaintext credentials out of logs.
6. **Errors:** catch auth-client's error types; translate to your own at the boundary if you have a public contract.
7. **Don't fork** the flow/callback/connection code into your layer — import it. auth-client is the single source of truth (transport's former fork was deleted; see its connections-dedup spec).

---

## Reference

- Canonical `emit()` consumer: `mountainash-transport` `connections/` (factory `_emit_kwargs`). `mountainash-wearables` consumes the `acquire()` + `creds_provider`/`emit(HTTP)` seam — http-client builds the authenticated client from the emitted kwargs.
- Emission design: `docs/superpowers/specs/2026-06-12-unified-profile-kwargs-emission-design.md`.
- Connections-dedup (why transport imports auth-client instead of forking): `docs/superpowers/specs/2026-06-13-connections-dedup-design.md`.

# mountainash-auth-client — Integration Guide

**Audience:** developers integrating `mountainash-auth-client` into a transport,
client, or service layer (the canonical consumer today is `mountainash-transport`).

`mountainash-auth-client` is the **single source of truth** for authentication in the
mountainash stack. It owns:

1. **Auth profiles** — declarative credential carriers (`TokenAuthProfile`, `IAMAuthProfile`, …).
2. **`emit()`** — the one primitive that injects a profile's credentials into an SDK client's kwargs.
3. **OAuth flow lifecycle + callback servers** — `OAuthFlow`/`OAuth1Flow` resolvers and `LocalCallbackServer`/`ManualCallbackServer`.

It depends on `mountainash-settings` (the `Profile`/`Registry`/`emit` machinery and the
secrets backend) and is consumed *above* by transport/client layers.

---

## Install

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
from mountainash_auth_client import TokenAuthProfile, TargetFamily

base = {"timeout": 30}                                  # your SDK config
kwargs = TokenAuthProfile(TOKEN="abc").emit(TargetFamily.HTTP, base=base)
# → {"timeout": 30, "headers": {"Authorization": "Bearer abc"}}
httpx.Client(**kwargs)
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

> Secret fields (`*_SECRET`, `PASSWORD`, …) are `SecretStr` — **pass them through as `SecretStr`**;
> the plaintext is unwrapped only inside the adapter. Don't call `.get_secret_value()` at the call site.

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
token = OAuthFlow(provider, resolver=resolver).resolve_access_token(
    auth_profile, auto_authorize=False, callback_server=None,
)  # -> str ; raises AuthorizationRequired when no usable token and auto_authorize=False

# OAuth1: cache → authorize → persist → token pair
oauth_token, oauth_token_secret = OAuth1Flow(provider, resolver=resolver).resolve_token_pair(
    auth_profile, auto_authorize=False, callback_server=None,
)  # -> tuple[str, str]
```

Bind the resolved token onto **your** endpoint config via `emit()`:

```python
from mountainash_auth_client import TokenAuthProfile, TargetFamily

token = OAuthFlow(provider, resolver=resolver).resolve_access_token(auth_profile)
kwargs = TokenAuthProfile(TOKEN=token).emit(TargetFamily.HTTP, base=my_endpoint_config)
client = httpx.Client(**kwargs)
```

This is exactly how transport keeps its per-endpoint httpx config (timeouts, TLS, redirects)
while reusing auth-client's one lifecycle.

### Token acquisition seam (`acquire()` / `acquire_auth()`)

`OAuth2TokenManager` and `OAuth1TokenManager` are the lifecycle entry points. They resolve a
token (cache → refresh → authorize → persist) and return a credential you can emit directly:

```python
from mountainash_auth_client import OAuth2TokenManager, TokenAuthProfile, TargetFamily

cred = OAuth2TokenManager(provider, auth_profile, resolver=resolver).acquire()  # TokenCredential
kw = TokenAuthProfile(TOKEN=cred.access_token).emit(TargetFamily.HTTP)           # {"headers": {...}}
# hand kw to the consumer's transport (http-client HttpConfig); wire creds_provider for refresh.
```

For OAuth 1.0a, `OAuth1TokenManager(...).acquire_auth()` returns an `httpx.Auth` signer for
`RequestCreds(auth=…)` — OAuth1 is per-request signing, not a Bearer header, so the signer is
passed directly rather than emitted as headers.

**Error contract:** a use-time auth failure raises `AuthorizationRequired` (no usable token and
interactive authorize is disabled) or `TokenRefreshError` (refresh call failed). When surfaced
through http-client's request path these arrive as `SourceAuthenticationError`; the consumer
maps `__cause__` to detect which domain error triggered reauth (Phase 3 §6 / Phase 4).

### Secrets backend (required for OAuth)

The resolvers persist/read tokens through a **secrets backend** keyed by the auth profile's
`SETTINGS_SOURCE_SECRETS_PROVIDER` + `persist_key()`. You must register one before resolving:

```python
from mountainash_settings.secrets.registry import register_secrets_backend

register_secrets_backend("my_provider", my_backend)  # get/set/delete/transaction
# auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER == "my_provider"
```

A backend implements `get(key)`, `set(key, data)`, `delete(key)`, and a `transaction(key)`
context manager. (Non-OAuth profiles need no backend.)

### Callback servers (interactive authorize)

When `auto_authorize=True` and no token is cached, the flow runs the authorization-code
exchange via a **callback server**. auth-client provides:

- `LocalCallbackServer` — binds a localhost port, opens the browser (with a print fallback), waits for the redirect, guarantees socket cleanup.
- `ManualCallbackServer` — out-of-band: prints the URL, reads the pasted redirect/code. (`extract_code_from_input`, `prompt_for_code` are the free functions behind it.)

Pass a `CallbackServerFactory` (a `Callable[[], CallbackServerProtocol]`) as `callback_server=`
to `resolve_access_token` / `resolve_token_pair` / `connect`, or rely on the default chosen by
`redirect_mode` (`"local_server"` | `"manual"`).

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

1. **Depend on** `mountainash-auth-client` (+ `[oauth1]`/`[sftp]` extras only if used). It pulls `mountainash_settings` and `mountainash_secrets`.
2. **Credential injection:** call `auth_profile.emit(family, base=sdk_config)` and feed the result to your SDK constructor. Treat `NoAuthProfile`/`None` as passthrough; layer onto nested `base_kwargs` when present.
3. **Pick the family explicitly** — `emit()` is fail-closed; never call it untargeted.
4. **OAuth:** register a secrets backend, acquire a token via `OAuth2TokenManager(...).acquire()` (OAuth2) or `OAuth1TokenManager(...).acquire_auth()` (OAuth1), then `emit` the resolved token onto your endpoint config. Provide a `callback_server` factory if you support interactive authorize.
5. **Secrets stay `SecretStr`** — pass profile secret fields through; never unwrap at the call site.
6. **Errors:** catch auth-client's error types; translate to your own at the boundary if you have a public contract.
7. **Don't fork** the flow/callback/connection code into your layer — import it. auth-client is the single source of truth (transport's former fork was deleted; see its connections-dedup spec).

---

## Reference

- Canonical `emit()` consumer: `mountainash-transport` `connections/` (factory `_emit_kwargs`). `mountainash-wearables` consumes the `acquire()` + `creds_provider`/`emit(HTTP)` seam — http-client builds the authenticated client from the emitted kwargs.
- Emission design: `docs/superpowers/specs/2026-06-12-unified-profile-kwargs-emission-design.md`.
- Connections-dedup (why transport imports auth-client instead of forking): `docs/superpowers/specs/2026-06-13-connections-dedup-design.md`.

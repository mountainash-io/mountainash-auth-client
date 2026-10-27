# mountainash-auth-client

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Authentication profiles and OAuth token lifecycles for Python applications.
Describe credentials once, render them for HTTP, Boto or Paramiko, and acquire
OAuth tokens through an application-selected store. Your application constructs
the client and chooses how to use the credentials.

[Examples](examples/) · [Integration guide](docs/INTEGRATION.md) ·
[Typing](docs/typing.md) · [Release process](RELEASE.md)

## What it provides

| Area | Capabilities | Explore |
|---|---|---|
| Credential profiles | Password, bearer/JWT, IAM, certificate, Kerberos and other credential schemas; explicit target rendering | [Credential rendering](examples/credential_rendering/) |
| Configuration sources | File-backed profiles, deployment overrides and selected secret readers | [Configuration-to-client recipes](examples/#from-configuration-to-client-options) |
| Consumer adapters | Nested client options and custom credential objects, composed at the consumer boundary | [Nested adapters](examples/nested_client_adapter/) · [SDK credentials](examples/consumer_credentials/) |
| Provider profiles | OAuth endpoint configuration kept separate from user credentials | [Provider profiles](examples/provider_profiles/) |
| OAuth2 lifecycle | Cached acquisition, refresh, explicit authorization, consumer flow injection, local revoke and registration-preserving sign-out | [Cached acquisition](examples/oauth2_cached_acquisition/) |
| Token persistence | Application-selected stores, `oauth` namespacing and profile-defined record keys | [Store ownership](examples/token_store_ownership/) |
| Authorization | OAuth2 authorization URLs, state and optional PKCE; local, manual or injected callbacks | [Authorization URLs](examples/authorization_urls/) |
| OAuth1 | Authorization flow, cached token pairs and request signing through optional Authlib | [OAuth1 signing](examples/oauth1_signing/) |

Available credential schemas do not imply every target has a built-in renderer.
See the [profile catalogue](docs/INTEGRATION.md#auth-profile-catalogue) for supported
targets. Consumer-specific credential shapes belong in the consumer's adapter.

## Installation

Requires **Python 3.12+** and `mountainash-settings>=0.1.0,<0.2`.
This README describes the **0.1.0 development baseline**. To use development
checkouts before compatible public packages are available, install settings and
auth-client side by side in your virtual environment:

```bash
git clone --branch develop https://github.com/mountainash-io/mountainash-settings.git
git clone --branch develop https://github.com/mountainash-io/mountainash-auth-client.git
python -m pip install -e ./mountainash-settings
python -m pip install -e ./mountainash-auth-client
cd mountainash-auth-client
```

| Extra | Adds | Install from this checkout |
|---|---|---|
| `oauth1` | Authlib for OAuth1 flows and signing | `python -m pip install -e ".[oauth1]"` |
| `sftp` | Paramiko for private-key parsing | `python -m pip install -e ".[sftp]"` |

OAuth2 needs no extra. Package imports leave optional integrations unloaded until
used. Inline typing and the `py.typed` marker are qualified with installed consumers
on Python 3.12/3.13; see [typing contracts and limits](docs/typing.md).

## Quick start

Render a bearer credential for a consumer-owned HTTP client. Save this as
`quickstart.py` and run `python quickstart.py`:

```python
import httpx

from mountainash_auth_client import TargetFamily, TokenAuthProfile

auth = TokenAuthProfile(TOKEN="example-report-token")
base = {"headers": {"Accept": "text/csv"}, "timeout": 10}
kwargs = auth.emit(TargetFamily.HTTP, base=base)

with httpx.Client(**kwargs) as client:
    request = client.build_request("GET", "https://files.example.com/sales.csv")

assert request.headers["Authorization"] == "Bearer example-report-token"
assert request.headers["Accept"] == "text/csv"
assert base == {"headers": {"Accept": "text/csv"}, "timeout": 10}
print(f"{request.method} {request.url.path}: bearer credential attached")
```

Expected output:

```text
GET /sales.csv: bearer credential attached
```

This builds a request without sending it. The profile keeps its token in a
`SecretStr`; `emit()` unwraps it for the selected client. Emitted kwargs contain
usable credentials, so the example prints only a summary.

## From configuration to client options

Auth profiles inherit settings' file loading and secret-reference support. The
[file-backed recipe](examples/file_backed_profiles/) loads TOML defaults and YAML
deployment values directly into a built-in auth profile. YAML has priority over
TOML regardless of file-list order. The [configured-secrets recipe](examples/configured_secrets/)
loads a `secret:` reference through a selected reader and uses a separate store
for acquired OAuth tokens.

Consumers can compose output beyond a flat kwargs dictionary:

- The [nested-adapter recipe](examples/nested_client_adapter/) declares an
  endpoint profile with `__adapters__`, builds nested session/retry options, then
  renders authentication into the inner HTTP session.
- The [SDK-credential recipe](examples/consumer_credentials/) adapts the same
  token into a consumer-owned credential object as well as HTTP headers.

Both check the real output and show a redacted structure. Consumer-specific
names and shapes stay in those adapters; shared auth profiles retain their
canonical credential fields.

## OAuth token storage

OAuth provider profiles describe endpoints; auth profiles describe client/user
credentials. For persisted tokens, subclass `OAuth2AuthProfile` or
`OAuth1AuthProfile` and supply a stable `persist_key()` identifying the account.
The [cached-acquisition recipe](examples/oauth2_cached_acquisition/) shows all
three pieces together.

Managers require a raw `ClearableSecretStore` through `token_store=`. Auth-client
applies the `oauth` namespace once. The application keeps the store open for all
manager operations and owns its closure. Configuration secret readers and token
stores are selected separately. See [store ownership](examples/token_store_ownership/).

`OAuth2TokenManager.acquire()` is non-interactive: it uses a cached token,
refreshes when necessary, or raises `AuthorizationRequired`. Call `authorize()`
explicitly when interaction is appropriate. Authorization needs a non-empty
client ID, including when token-endpoint authentication is `none`. Local and
manual callbacks and custom factories are covered in the
[integration guide](docs/INTEGRATION.md).

Use `flow_factory=` to select consumer-owned OAuth2 request, identity-validation
and permission policy without copying the lifecycle. Acquired credentials expose
effective scope, issued client identity and approved metadata.
`sign_out()` retains registration and cancels older pending authorization;
`revoke()` remains local-only and deletes registration too.

## Learn more

The [authentication recipes](examples/) run independently and offline, with
synthetic credentials and documented output.

| Guide | Contents |
|---|---|
| [Integration](docs/INTEGRATION.md) | Credential rendering, profile catalogue, OAuth lifecycle and callback injection |
| [Typing](docs/typing.md) | Static profile fields, credential protocols, installed qualification and dynamic boundaries |
| [Contributing](CONTRIBUTING.md) | Local setup, verification and PRs |
| [Release process](RELEASE.md) | Candidate verification, dependency provenance and publication |

Design principles, backlog, specs and plans live in
[mountainash-central](https://github.com/mountainash-io/mountainash-central)
under `mountainash-auth-client`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Branch from `develop`; PRs target `develop`.

Part of the [Mountain Ash ecosystem](https://github.com/mountainash-io), alongside
`mountainash-settings`, `mountainash-transport`, `mountainash-files`,
`mountainash-data` and `mountainash`. Settings supplies configuration and storage
primitives; auth-client owns authentication profiles and OAuth; transport owns
file operations and storage connections.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).

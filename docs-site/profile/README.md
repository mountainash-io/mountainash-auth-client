# mountainash-auth-client

**Authentication that handles itself.**

## Vision

Authentication in data applications is plumbing that everyone rebuilds. OAuth flows,
token refresh, credential storage, multi-tenant token isolation -- the same patterns,
reimplemented for every integration. mountainash-auth-client makes authentication
declarative: pick an auth type as typed data, and the library handles the flow, the
lifecycle, and the storage.

Every authentication method is represented as a validated Pydantic model with
SecretStr-protected credentials. OAuth 2.0 with PKCE runs end-to-end -- opening the
browser, capturing the callback, exchanging the code, and storing the tokens -- while
OAuth 1.0a handles the three-legged flow for legacy APIs. Once authorized, tokens refresh
automatically. Credentials are stored securely by default, with domain-namespaced paths
that isolate tokens per provider and user.

Connection mixins bring this together for provider integrations. Define the provider's
metadata -- URLs, scopes, flags -- and the mixin gives you connect/disconnect lifecycle
management, automatic token refresh, and secure storage out of the box. The result is a
library where authentication decisions are made once, expressed as data, and then managed
for the lifetime of the application.

## Installation

```bash
pip install mountainash-auth-client
```

For OAuth 1.0a support (requires authlib):

```bash
pip install mountainash-auth-client[oauth1]
```

## Use Cases

### The Multi-Provider Data Pipeline

A pipeline ingests from Garmin (OAuth1), Google Health (OAuth2 with PKCE), and Strava
(OAuth2). Each provider has different auth requirements -- different protocols, different
token formats, different refresh mechanisms. One auth library handles all three: flows,
token refresh, secure storage. The pipeline code deals with data, not authentication
plumbing. When a token expires mid-run, the library refreshes it transparently. When a
refresh token is revoked, it raises a typed exception that the pipeline can handle
precisely.

### Multi-Tenant Credential Isolation

A SaaS platform manages data connections for multiple users, each with their own OAuth
tokens for different providers. Domain-namespaced storage isolates credentials per user
per provider, ensuring that one tenant's tokens are never accidentally loaded for another.
Token refresh happens per-user with file locking to prevent concurrent refresh races --
when two pipeline workers try to refresh the same user's token simultaneously, one acquires
the lock and refreshes while the other waits and uses the fresh token.

### The Migration from Inline Credentials

Legacy config files have OAuth tokens stored inline -- access tokens and refresh tokens
sitting in YAML alongside connection parameters. mountainash-auth-client detects these
inline tokens on first connection, migrates them to the secure store with proper file
permissions, and replaces the inline values with store references. The migration is
transparent and happens exactly once. Tombstone semantics ensure that if a credential is
later intentionally cleared, it will not be re-migrated from a stale config file.

## Key Capabilities

### Auth Types as a Discriminated Union

The type system is built around a discriminated union where setting a single `kind` field
selects the authentication strategy. Thirteen auth types are available -- from `NoAuth` for
local databases to `OAuth2Auth` for web APIs to `IAMAuth` for cloud services to
`KerberosAuth` for enterprise environments -- each defining its own required and optional
fields as a Pydantic model.

The `auth_kwargs()` convenience function takes a profile object and maps its auth
configuration to the keyword arguments your database driver expects. A built-in registry
handles common auth types, and you can register custom mappers for backend-specific
handling. Some auth types intentionally have no default mapper, signalling that the
backend integration must provide its own translation logic.

### OAuth 2.0 Authorization Code Flow with PKCE

The full OAuth2 Authorization Code flow is implemented with S256 PKCE code challenge
generation, synchronous token exchange via httpx, and automatic refresh with a
configurable expiry buffer window. Two levels of control are available.

`OAuthFlow` gives you fine-grained control over each step of the flow -- generating the
authorization URL, handling the callback, exchanging the code, and refreshing tokens. This
is the right choice when you need to integrate the flow into an existing web application
or handle non-standard provider behaviour.

`OAuth2ConnectionMixin` provides a batteries-included experience. Call `connect()`, and the
mixin handles the full decision tree: load stored tokens, check expiry, acquire a file
lock for concurrent-safe refresh, attempt refresh, and fall back to re-authorization when
needed. Browser-based and manual redirect modes are both supported.

### OAuth 1.0a Flow

Three-legged OAuth1 authorization for providers that require it, available as an optional
install via `pip install mountainash-auth-client[oauth1]`. The same flow/mixin pattern as
OAuth2 keeps the programming model consistent across both protocols. `OAuth1ConnectionMixin`
provides the same connect/disconnect lifecycle, and the same spec/metadata convention
drives provider configuration. Switching between OAuth1 and OAuth2 providers does not
require learning a new API.

The OAuth1 modules use deferred imports with descriptive `ImportError` messages, so the
core install remains lightweight. They are intentionally not re-exported from the package
root -- import them directly from `flows.oauth1` and `mixins.oauth1` when you need them.

### Credential Storage

A pluggable credential storage system ships with a secure filesystem backend out of the
box. Credentials are organized by a three-level key space -- domain, provider, and user --
and stored as YAML files with restrictive permissions: 0o600 for files and 0o700 for
directories.

The filesystem backend enforces several security invariants: symlink rejection on load
prevents path traversal attacks, atomic writes via temp-file-and-os.replace prevent
partial writes from corrupting credential files, and fcntl exclusive file locking ensures
that concurrent token refresh operations in multi-process pipelines do not race.

The `SecretStore` protocol is runtime-checkable and defines six methods for credential
persistence. Organisations that need Vault, KMS, or keychain integration can implement
the protocol and plug in their own backend.

### Typed Error Handling

A focused set of auth-specific exceptions -- `TokenExchangeError`, `TokenRefreshError`,
and `AuthorizationRequired` -- each carry structured context including URL, status code,
provider, and user. This structured context means error handling logic can make informed
decisions about recovery: retry the refresh, trigger re-authorization, or escalate to the
user -- rather than parsing status codes and guessing at the cause.

## Architecture

mountainash-auth-client is built around a discriminated-union type system with pluggable
dispatch, protocol-based extensibility, and a clear separation between auth schemas,
protocol flows, connection lifecycle, and credential persistence. The `AuthSpec` subclass
hierarchy defines the type system, the `AUTH_TO_DRIVER_KWARGS` registry handles dispatch
to driver-specific code, the `SecretStore` protocol provides pluggable credential
persistence, and the spec/metadata convention decouples OAuth flows from provider-specific
configuration.

The connection mixins implement a token lifecycle state machine with five states:
no-token, valid-token, expired-with-refresh, expired-no-refresh, and cleared. Provider
configuration is carried by spec objects that expose a `.name` identifier and a `.metadata`
dictionary containing flow-specific URLs, flags, and settings. Mixins reference specs via
a `_spec` ClassVar set at class definition time, keeping provider config static and
declarative while the flow logic remains generic and reusable.

## Extending

Adding a new auth type follows a consistent pattern: create an `AuthSpec` subclass in
`schemas/` with a unique `Literal` kind value, re-export from `schemas/__init__.py` and the
package root, and optionally register a default mapper in the dispatch registry. Adding a
new OAuth provider means defining a spec object with the provider's authorization URL,
token URL, PKCE preferences, default scopes, and callback port, then subclassing the
appropriate connection mixin with `_spec` and `_base_url` class variables. The mixin handles
the token lifecycle automatically -- the provider-specific code focuses on what makes that
provider unique.

## Contributing

The project uses Hatch as its build system with hatchling backend, Ruff for linting
(E, F, FA, TCH rules with 120-character line length), and pytest for testing with
coverage configured for both source and test directories. Tests follow established patterns
using `FakeSpec`, `FakeAuth`, and `FakeProfile` fixtures for isolation, `tmp_path` for
store tests, and httpx mocking via `unittest.mock.patch` for token exchanges. Each layer
of the package -- schemas, flows, mixins, store -- has its own focused test files that
mirror the module structure.

## Maintaining

The discriminated union architecture intentionally omits `kind` at the `AuthSpec` base
level to avoid `reportIncompatibleVariableOverride` issues in type checkers, with each
subclass declaring its own `Literal` discriminator. Some auth types are deliberately left
unmapped in the dispatch registry to signal that backend-specific handling is required --
this is a design choice, not an oversight.

The security invariants in the filesystem store -- restrictive permissions, symlink
rejection, atomic writes, and localhost-only callback binding -- are load-bearing safety
guarantees that should be preserved across all changes to the storage and server layers.
Any modification to file handling should maintain these properties.

OAuth1 support sits behind an optional dependency boundary managed via
`[project.optional-dependencies]` in pyproject.toml. The OAuth1 modules use deferred
imports with descriptive `ImportError` messages and are intentionally excluded from
package-root re-exports, keeping the default install lightweight. When updating authlib or
considering new optional integrations, this boundary pattern should be followed. OAuth1
connection mixin test coverage is an area where additional investment would strengthen
confidence in the integration path.

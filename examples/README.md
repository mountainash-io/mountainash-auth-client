# Authentication recipes

Focused, independently runnable examples of credential rendering, file-backed
configuration, secret references, consumer adapters and OAuth lifecycles. Start
with the small API examples, then follow the configuration-to-client recipes.
Each recipe declares what it uses; none imports another recipe.

## Setup

Use Python 3.12+ and install the sibling settings checkout as described in the
[root README](../README.md#installation). From the auth-client repository root:

```bash
python -m pip install -e ".[oauth1]"
```

Only the signing recipe needs the `oauth1` extra. All commands below run from
the repository root; an absolute script path also works from another directory.
Run without Python's `-O` flag so the examples' assertions are evaluated.
Unset `REPORT_*` environment variables to reproduce file-backed fixture values.
Each file-backed recipe keeps its YAML/TOML inputs beside its script and resolves
them relative to that script.

No recipe contacts a network service or opens a browser. The signing recipe
uses `httpx.MockTransport`; the filesystem recipe uses a temporary directory
and closes its stores before cleanup.

## Shared example data

The application is `reports_app`, its user is `report_user`, its client ID is
`reports-client`, and its resource host is `files.example.com`. OAuth endpoints
use `identity.example.com`. Credentials are synthetic and never printed;
random state, PKCE challenges and signatures are checked without printing them.

## Start with credentials

| Recipe | Question |
|---|---|
| [Credential rendering](credential_rendering/) | How does one credential render for different client families? |
| [Provider profiles](provider_profiles/) | How do endpoint configuration and user credentials combine? |

## From configuration to client options

| Recipe | Input → output | Question |
|---|---|---|
| [File-backed profiles](file_backed_profiles/) | TOML defaults + YAML deployment → SSH kwargs | How do settings sources configure built-in auth profiles? |
| [Configured secrets](configured_secrets/) | Provider TOML + auth YAML + selected stores → acquired HTTP credential | How do config readers and OAuth token stores stay separate? |
| [Nested client adapter](nested_client_adapter/) | Endpoint YAML + token TOML + caller options → nested session/retry options | How do consumer adapters compose endpoint and auth rendering? |
| [Consumer-specific credentials](consumer_credentials/) | YAML secret reference → HTTP headers and a typed SDK object | How can one credential serve different client shapes? |

These recipes print the actual resulting structure with credential values
replaced for display, and assert the full unredacted results internally. Inline
adapters live on application-owned endpoint profiles; credential reshaping lives
in consumer-owned functions. Neither requires modifying shared auth classes.

## OAuth2 and persistence

| Recipe | Question |
|---|---|
| [Cached acquisition](oauth2_cached_acquisition/) | How do I acquire a cached token and handle missing authorization? |
| [Store ownership](token_store_ownership/) | Who selects, namespaces and closes persisted token storage? |
| [Authorization URLs](authorization_urls/) | How do client identity, scope, state and PKCE appear in an authorization URL? |

## OAuth1

| Recipe | Question |
|---|---|
| [OAuth1 signing](oauth1_signing/) | How do I attach a request signer instead of a bearer header? |

## Live authorization

Interactive authorization and token exchange/refresh need a registered client,
provider endpoints and a callback accepted by that provider. These recipes seed
synthetic cached records or inspect generated requests; they do not demonstrate
a successful live grant. See the [integration guide](../docs/INTEGRATION.md) for
local, manual and injected callbacks and explicit manager authorization.

## Verification

Each recipe is copied and executed independently in a temporary directory.
Its output must match the **Expected output** block in its README. The root
README quick start is executed separately:

```bash
hatch run test:test-quick tests/examples -q
```

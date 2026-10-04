# Authentication recipes

Focused, independently runnable examples of credential rendering, provider
configuration, token acquisition, store ownership, authorization URLs and signing.
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

No recipe contacts a network service or opens a browser. The signing recipe
uses `httpx.MockTransport`; the filesystem recipe uses a temporary directory
and closes its stores before cleanup.

## Shared example data

The application is `reports_app`, its user is `report_user`, its client ID is
`reports-client`, and its resource host is `files.example.com`. OAuth endpoints
use `identity.example.com`. Credentials are synthetic and never printed;
random state, PKCE challenges and signatures are checked without printing them.

## Credentials

| Recipe | Question |
|---|---|
| [Credential rendering](credential_rendering/) | How does one credential render for different client families? |
| [Provider profiles](provider_profiles/) | How do endpoint configuration and user credentials combine? |

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

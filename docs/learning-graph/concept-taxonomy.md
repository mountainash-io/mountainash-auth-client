# Concept Taxonomy

This taxonomy organizes the 85 mountainash-auth-client concepts into 9 categories.

## Categories

### FOUND — Foundation Concepts
Prerequisites: OAuth protocols, tokens, Pydantic, protocols, file security.

### ATYPE — Auth Type System
The 13-variant discriminated union of auth types with Literal kind discriminator.

### DISP — Auth Dispatch
Registry mapping auth types to driver-specific kwargs via type-based dispatch.

### OA2 — OAuth 2.0 Flow
OAuthFlow class with Authorization Code + PKCE, token exchange, refresh, expiry.

### OA1 — OAuth 1.0a Flow
OAuth1Flow with three-legged flow, optional authlib dependency.

### CONN — Connection Mixins
OAuth2ConnectionMixin with five-state token lifecycle and file-locked refresh.

### STORE — Secret Storage
SecretStore protocol and FilesystemStore with YAML, locking, tombstone semantics.

### CALLB — Callback Server
LocalCallbackServer for OAuth redirect capture and manual redirect mode.

### ERROR — Error Handling
Three typed exceptions: TokenExchangeError, TokenRefreshError, AuthorizationRequired.

## Taxonomy Summary Table

| TaxonomyID | Category Name | Concept Range | Count |
|------------|---------------|---------------|-------|
| FOUND | Foundation Concepts | 1-10 | 10 |
| ATYPE | Auth Type System | 11-26 | 16 |
| DISP | Auth Dispatch | 27-32 | 6 |
| OA2 | OAuth 2.0 Flow | 33-44 | 12 |
| OA1 | OAuth 1.0a Flow | 45-50 | 6 |
| CONN | Connection Mixins | 51-63 | 13 |
| STORE | Secret Storage | 64-74 | 11 |
| CALLB | Callback Server | 75-79 | 5 |
| ERROR | Error Handling | 80-85 | 6 |

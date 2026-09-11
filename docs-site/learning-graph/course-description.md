---
title: Mountainash Auth Client Package Description
description: A detailed description of the mountainash-auth-client type-safe authentication library
quality_score: 87
---

# Mountainash Auth Client Package Description

## Title

Mountainash Auth Client: Type-Safe Multi-Provider Authentication Library

## Target Audience

Python developers integrating with OAuth 2.0 and OAuth 1.0a APIs who need declarative, type-safe authentication with automatic token lifecycle management and pluggable credential storage.

## Prerequisites

- Intermediate Python (Pydantic models, protocols, context managers)
- Basic understanding of OAuth 2.0 and OAuth 1.0a flows
- Familiarity with HTTP authentication (Bearer tokens, API keys)
- Understanding of credential security (file permissions, atomic writes)

## Topics Covered

1. **Auth Type System** — Discriminated union of 13 auth types with Literal kind discriminator
2. **OAuth 2.0 Flows** — Authorization Code with PKCE, token exchange, refresh, expiry
3. **OAuth 1.0a Flows** — Three-legged OAuth 1.0a (optional, requires authlib)
4. **Connection Mixins** — OAuth2ConnectionMixin and OAuth1ConnectionMixin with token lifecycle
5. **Token Lifecycle** — Five-state machine (no-token, valid, expired-with-refresh, expired-no-refresh, cleared)
6. **Secret Storage** — SecretStore protocol with FilesystemStore (YAML, file locking, atomic writes)
7. **Auth Dispatch** — Registry mapping auth types to driver-specific kwargs
8. **Callback Server** — LocalCallbackServer for OAuth redirect capture
9. **Error Handling** — TokenExchangeError, TokenRefreshError, AuthorizationRequired

## Topics Excluded

- Identity provider administration
- SAML/OIDC federation
- Certificate authority management
- Network security protocols

## Learning Outcomes

After studying this package, developers will be able to:

### Remember

- List the 13 auth type variants in the discriminated union
- Name the five states in the token lifecycle state machine
- Identify the three error types (TokenExchangeError, TokenRefreshError, AuthorizationRequired)

### Understand

- Explain the discriminated union + dispatch pattern for auth types
- Describe how PKCE prevents authorization code interception
- Explain file-locked concurrent-safe token refresh

### Apply

- Configure OAuth2Auth and OAuth2AuthCodeAuth for API providers
- Implement custom SecretStore backends
- Use OAuth2ConnectionMixin for automatic token management

### Analyze

- Analyze token lifecycle state transitions and edge cases
- Compare auth type dispatch strategies across different backends

### Evaluate

- Assess security properties of the FilesystemStore implementation
- Judge when to use OAuth2Auth vs OAuth2AuthCodeAuth

### Create

- Implement new auth type variants for custom authentication schemes
- Build OAuth provider connection mixins with custom metadata
- Design SecretStore backends for vault or keyring systems

## Context

Mountainash-auth-client makes authentication declarative by representing each auth method as a typed, frozen Pydantic model in a discriminated union. A central dispatch registry maps auth types to driver kwargs, while connection mixins manage the full OAuth token lifecycle with concurrent-safe refresh and pluggable credential storage.

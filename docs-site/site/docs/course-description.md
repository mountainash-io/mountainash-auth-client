---
title: Course Description
description: 'What mountainash-auth-client does, who it is for, and what this manual covers'
---

# Course Description

mountainash-auth-client is a type-safe, multi-provider authentication library for Python. It replaces scattered, provider-specific auth code with a single discriminated union of auth types, a central dispatch registry, and connection mixins that manage the entire OAuth token lifecycle — acquisition, refresh, expiry, and clearing — behind a small, consistent surface. See [Home](index.md) for the full package overview and [List of Chapters](chapters/index.md) for the chapter-by-chapter table of contents; this page frames the same material as a course: who it's for, what you need going in, and what you'll be able to do by the end.

## Target Audience

Python developers integrating with OAuth 2.0 and OAuth 1.0a APIs who need declarative, type-safe authentication with automatic token lifecycle management and pluggable credential storage.

## Prerequisites

- Intermediate Python (Pydantic models, protocols, context managers)
- Basic understanding of OAuth 2.0 and OAuth 1.0a flows
- Familiarity with HTTP authentication (Bearer tokens, API keys)
- Understanding of credential security (file permissions, atomic writes)

## What This Manual Covers

1. **Foundations** — Why authentication is modeled as data, the discriminated-union pattern, and how the pieces of the library fit together
2. **Auth Type System and Basic Types** — The discriminated union of 13 auth types with a `Literal` kind discriminator
3. **Advanced Auth Type Variants** — The less common auth type variants and how they extend the base system
4. **Auth Dispatch and OAuth 1.0a** — The registry that maps auth types to driver-specific kwargs, and three-legged OAuth 1.0a support (optional, requires `authlib`)
5. **OAuth 2.0 Flow** — Authorization Code with PKCE, token exchange, refresh, and expiry handling
6. **Secret Storage** — The `SecretStore` protocol and the `FilesystemStore` implementation (YAML, file locking, atomic writes)
7. **Callback Server and Token Errors** — `LocalCallbackServer` for capturing OAuth redirects, plus `TokenExchangeError`, `TokenRefreshError`, and `AuthorizationRequired`
8. **Connection Mixins and Token Lifecycle** — `OAuth2ConnectionMixin` and `OAuth1ConnectionMixin`, and the five-state token lifecycle machine (no-token, valid, expired-with-refresh, expired-no-refresh, cleared)

## What This Manual Does Not Cover

- Identity provider administration
- SAML/OIDC federation
- Certificate authority management
- Network security protocols

## Learning Outcomes

By the end of this manual, you will be able to:

- **Remember** the 13 auth type variants in the discriminated union, the five states in the token lifecycle, and the three dedicated error types
- **Understand** the discriminated-union-plus-dispatch pattern, how PKCE prevents authorization code interception, and how file-locked refresh stays concurrent-safe
- **Apply** `OAuth2Auth` and `OAuth2AuthCodeAuth` to real providers, implement custom `SecretStore` backends, and wire up `OAuth2ConnectionMixin` for automatic token management
- **Analyze** token lifecycle state transitions and their edge cases, and compare auth dispatch strategies across backends
- **Evaluate** the security properties of `FilesystemStore` and judge when `OAuth2Auth` is preferable to `OAuth2AuthCodeAuth`
- **Create** new auth type variants, custom OAuth provider connection mixins, and `SecretStore` backends for vaults or keyrings

## Key Capabilities

**Authentication as data** — Each auth method is a typed, frozen Pydantic model in a discriminated union with a `Literal` kind field. Configuration is validated at construction time, not discovered as a runtime failure deep in an HTTP call.

**One dispatch point for every auth type** — A central registry maps each auth type to the driver-specific keyword arguments it needs, so adding a new auth type doesn't mean touching every call site that constructs a client.

**A full, concurrent-safe token lifecycle** — `OAuth2ConnectionMixin` and `OAuth1ConnectionMixin` track a five-state token lifecycle and refresh tokens safely even when multiple processes share the same credential store.

**Pluggable, secure-by-default storage** — The `SecretStore` protocol decouples token persistence from token logic. `FilesystemStore` ships with YAML serialization, file locking, and atomic writes; other backends (vaults, keyrings) implement the same protocol.

**Errors that say what actually failed** — `TokenExchangeError`, `TokenRefreshError`, and `AuthorizationRequired` distinguish "the exchange failed," "the refresh failed," and "the user needs to re-authorize" instead of surfacing a generic HTTP error.

## Context

mountainash-auth-client makes authentication declarative by representing each auth method as a typed, frozen Pydantic model in a discriminated union. A central dispatch registry maps auth types to driver kwargs, while connection mixins manage the full OAuth token lifecycle with concurrent-safe refresh and pluggable credential storage. For the narrative introduction and getting-started guidance, start at [Home](index.md); for the full syllabus, go to [List of Chapters](chapters/index.md).
</content>

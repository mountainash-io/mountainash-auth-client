---
title: About
description: 'Who this manual is for, what you need to know beforehand, and how to get the most out of it'
---

# About

## Who This Is For

This manual is for Python developers integrating with OAuth 2.0 and OAuth 1.0a APIs who need declarative, type-safe authentication with automatic token lifecycle management and pluggable credential storage. You might be wiring up a new API client that needs an authorization-code-with-PKCE flow, replacing ad-hoc token-refresh code with something concurrent-safe, or designing a credential store that isn't tied to the filesystem. If any of that sounds familiar, this is for you.

## What You Should Already Know

You should be comfortable with:

- Intermediate Python — Pydantic models, protocols, and context managers
- The basics of OAuth 2.0 and OAuth 1.0a flows (authorization codes, access tokens, refresh tokens)
- HTTP authentication mechanics (Bearer tokens, API keys, signed requests)
- Credential security fundamentals (file permissions, atomic writes, avoiding plaintext leaks)

## What You'll Get Out of This

After working through this manual, you'll know how to:

- Represent any of the 13 supported auth types as a typed, frozen Pydantic model in a discriminated union
- Configure `OAuth2Auth` and `OAuth2AuthCodeAuth` for real API providers, including the PKCE exchange
- Use `OAuth2ConnectionMixin` and `OAuth1ConnectionMixin` to get automatic, concurrent-safe token refresh for free
- Reason about the five-state token lifecycle (no-token, valid, expired-with-refresh, expired-no-refresh, cleared) and its edge cases
- Implement a custom `SecretStore` backend when the built-in `FilesystemStore` isn't enough
- Diagnose failures using the library's dedicated error types — `TokenExchangeError`, `TokenRefreshError`, and `AuthorizationRequired`

## How to Navigate

- **Read in order** — chapters are arranged in dependency order, so each builds on what came before
- **Use search** — the search bar (top right) indexes every page; use it to jump to a specific class or concept
- **Try the MicroSims** — interactive simulations are the fastest way to build intuition for how the pieces fit together
- **Check the Learning Graph** — the [Learning Graph](learning-graph/index.md) shows how concepts relate and where each fits in the bigger picture

## About mountainash-auth-client

mountainash-auth-client is a type-safe, multi-provider authentication library for Python. It makes authentication declarative by representing each auth method as a typed, frozen Pydantic model in a discriminated union, dispatched through a central registry that maps auth types to driver-specific keyword arguments. Connection mixins layer on top to manage the full OAuth 2.0 and OAuth 1.0a token lifecycle, including concurrent-safe refresh and pluggable credential storage — so callers get working, refreshed credentials without reimplementing token bookkeeping for every API they talk to. It is deliberately scoped to client-side authentication: identity provider administration, SAML/OIDC federation, certificate authority management, and general network security are out of scope.

Source code and issues: [github.com/mountainash-io/mountainash-auth-client](https://github.com/mountainash-io/mountainash-auth-client)

## License

This manual is licensed under [CC BY-NC-SA 4.0](license.md) for non-commercial use. Commercial licensing is available on request — see [Contact](contact.md).

## Author

Nathaniel Ramm
</content>

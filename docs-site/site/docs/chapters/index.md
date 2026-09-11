# Chapters

This textbook is organized into 8 chapters covering 85 concepts across the mountainash-auth-client type-safe multi-provider authentication library.

## Chapter Overview

1. [Foundations](./01-foundations/index.md) — Core prerequisites: OAuth protocols, tokens, API keys, Pydantic models, and file security primitives.
2. [Auth Type System and Basic Types](./02-auth-type-system-and-basic-types/index.md) — The AuthSpec base model, discriminated union pattern, and the first five auth type variants.
3. [Advanced Auth Type Variants](./03-advanced-auth-type-variants/index.md) — OAuth, cloud provider, and platform-specific auth type variants.
4. [Auth Dispatch and OAuth 1.0a](./04-auth-dispatch-and-oauth1/index.md) — Registry-based type dispatch and the three-legged OAuth 1.0a flow.
5. [OAuth 2.0 Flow](./05-oauth2-flow/index.md) — OAuthFlow class with Authorization Code grant, PKCE extension, and token operations.
6. [Secret Storage](./06-secret-storage/index.md) — SecretStore protocol and FilesystemStore with YAML serialization, locking, and tombstone semantics.
7. [Callback Server and Token Errors](./07-callback-server-and-token-errors/index.md) — LocalCallbackServer for OAuth redirects and typed exceptions for token failures.
8. [Connection Mixins and Token Lifecycle](./08-connection-mixins-and-token-lifecycle/index.md) — OAuth2ConnectionMixin with five-state token lifecycle, end-to-end authorization, and authorization errors.

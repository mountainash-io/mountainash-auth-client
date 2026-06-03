---
title: Foundations
description: Core prerequisite concepts for understanding the mountainash-auth-client library, covering OAuth protocols, Pydantic models, Python protocols, context managers, and file security primitives.
generated_by: claude skill chapter-content-generator
date: 2026-06-03
version: 0.08
---

# Foundations

## Summary

This chapter introduces the core prerequisite concepts needed to understand the mountainash-auth-client library. It covers the basics of OAuth 2.0 and OAuth 1.0a protocols, Bearer tokens, API keys, Pydantic model fundamentals including frozen models, Python protocols for structural subtyping, context managers for resource lifecycle, and file security primitives including permissions and atomic writes.

## Concepts Covered

- OAuth 2.0 Basics
- OAuth 1.0a Basics
- Bearer Tokens
- API Keys
- Pydantic Models
- Frozen Models
- Python Protocols
- Context Managers
- File Permissions
- Atomic File Writes

## Prerequisites

None. This is the introductory chapter.

## Learning Objectives

After completing this chapter, you will be able to:

- Explain the purpose and high-level flow of OAuth 2.0 and OAuth 1.0a
- Distinguish between Bearer tokens and API keys as authentication mechanisms
- Create and validate Pydantic models with frozen configuration
- Define Python protocols for structural subtyping
- Use context managers for resource lifecycle management
- Apply file permissions and atomic write patterns for secure credential storage

---

## Why Authentication Matters in Data Libraries

Every data platform requires some form of identity verification before granting access. Whether you are querying a Snowflake warehouse, pulling metrics from a SaaS API, or connecting to a PostgreSQL database, the client must prove who it is. The mountainash-auth-client library provides a unified, type-safe interface for handling these diverse authentication mechanisms in Python.

Before diving into the library itself, you need a solid understanding of the protocols and patterns it builds upon. This chapter establishes that foundation by walking through the authentication standards, data modeling tools, and Python language features that appear throughout the codebase.

## Authentication Protocols

### OAuth 2.0 Basics

OAuth 2.0 is an authorization framework that enables a third-party application to obtain limited access to an HTTP service. Rather than sharing a username and password directly, the resource owner (the user) grants the application a time-limited access token through a delegation flow. The framework defines four roles that interact during an authorization exchange.

- **Resource Owner** -- the user who owns the data and grants access
- **Client** -- the application requesting access on behalf of the user
- **Authorization Server** -- the server that authenticates the resource owner and issues tokens (for example, Google's `accounts.google.com`)
- **Resource Server** -- the API that accepts tokens and serves protected resources

The most common OAuth 2.0 grant type is the Authorization Code grant, which proceeds in three stages. First, the client redirects the user to the authorization server with a request for specific permissions (scopes). Second, after the user consents, the authorization server redirects back with a short-lived authorization code. Third, the client exchanges that code for an access token and, optionally, a refresh token. The access token is then sent with each API request.

#### Diagram: OAuth 2.0 Authorization Code Flow
<iframe src="../../sims/oauth2-auth-code-flow/main.html" width="100%" height="500px" scrolling="no"></iframe>
<details markdown="1">
<summary>OAuth 2.0 Authorization Code Flow</summary>
Type: workflow
**sim-id:** oauth2-auth-code-flow<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Visualize the three-stage OAuth 2.0 Authorization Code grant flow showing the interactions between the four roles (Resource Owner, Client, Authorization Server, Resource Server).

**Components:** Four nodes representing the four OAuth roles, with directed edges showing: (1) Client redirects Resource Owner to Authorization Server, (2) Resource Owner authenticates and grants consent, (3) Authorization Server redirects back with authorization code, (4) Client exchanges code for tokens at Authorization Server, (5) Client uses access token against Resource Server.

**Interactions:** Hover over each node to highlight its role description. Click edges to see detailed step descriptions. Steps animate sequentially on play button click.

**Colors:** Client=SteelBlue, Resource Owner=DarkSlateBlue, Authorization Server=Gold, Resource Server=Teal.

**Learning Objective:** Understand (Bloom Level 2) the sequence and purpose of each interaction in an OAuth 2.0 Authorization Code grant.
</details>

OAuth 2.0 also supports other grant types -- client credentials for server-to-server communication, device code for input-constrained devices, and the now-deprecated implicit grant. The mountainash-auth-client library primarily implements the Authorization Code grant with PKCE (Proof Key for Code Exchange), which is covered in detail in Chapter 5.

### OAuth 1.0a Basics

OAuth 1.0a is the predecessor to OAuth 2.0, and it takes a fundamentally different approach to security. While OAuth 2.0 relies on TLS for transport security and uses simple bearer tokens, OAuth 1.0a requires each request to be cryptographically signed using HMAC-SHA1 or RSA-SHA1. This signature covers the HTTP method, URL, and parameters, providing request integrity even without TLS.

The OAuth 1.0a flow involves three sets of credentials that participate in a "three-legged" authorization dance.

| Credential Type | Purpose | Who Holds It |
|---|---|---|
| Consumer Key/Secret | Identifies the application | The client application |
| Request Token/Secret | Temporary credential during authorization | Exchanged at authorization time |
| Access Token/Secret | Long-lived credential for API access | Stored after authorization |

The flow proceeds as follows: the client obtains a temporary request token from the provider, redirects the user to authorize that token, and then exchanges the authorized request token (along with a verifier code) for a permanent access token. Some providers, such as the Garmin Health API, still require OAuth 1.0a, which is why the mountainash-auth-client library supports it through an optional `authlib` dependency.

### Bearer Tokens

A bearer token is the simplest form of OAuth token usage. Any party that possesses the token can use it to access the protected resource -- there is no additional proof of identity required beyond the token itself. In HTTP, bearer tokens are transmitted in the `Authorization` header.

The format follows the pattern defined in RFC 6750:

```
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

The critical security implication is that bearer tokens must be protected in transit (via TLS) and at rest (via secure storage). If a bearer token is leaked, anyone who obtains it gains the same access as the legitimate holder. The mountainash-auth-client library addresses storage security through its `SecretStore` abstraction, covered in Chapter 6.

### API Keys

API keys are static strings that identify and authenticate a client to an API. Unlike OAuth tokens, API keys are typically long-lived and do not expire. They are commonly passed as query parameters or custom headers.

- **Query parameter:** `GET /api/data?api_key=abc123`
- **Custom header:** `X-API-Key: abc123`
- **Basic auth (user field):** `Authorization: Basic base64(api_key:)`

API keys are simpler than OAuth but provide weaker security properties. They cannot be scoped to specific permissions, they do not support delegation (a user granting limited access to an app), and revoking them typically requires generating a new key and updating all clients. Many internal APIs and developer tools still use API keys for their simplicity.

!!! note "Bearer Tokens vs API Keys"
    The key distinction is delegation. OAuth bearer tokens represent a user's delegated permission to an application, while API keys represent the application itself. In mountainash-auth-client, the `TokenAuth` type handles bearer tokens and the dispatch system maps them to the appropriate driver kwargs.

## Data Modeling with Pydantic

### Pydantic Models

Pydantic is a data validation library for Python that uses type annotations to define data schemas. A Pydantic model is a Python class that inherits from `BaseModel` and declares its fields with type hints. When you instantiate a model, Pydantic validates the input data, coerces compatible types, and raises clear errors for invalid input.

The mountainash-auth-client library uses Pydantic models as the foundation of its type system. Every authentication configuration -- from a simple API key to a complex OAuth2 credential set -- is represented as a Pydantic model. This gives the library automatic serialization, validation, and schema generation.

The following example demonstrates a basic Pydantic model with validation. The `BaseModel` parent class provides the `model_config` class variable for configuring model behavior, and each field declared with a type annotation becomes a validated attribute.

```python
from pydantic import BaseModel, SecretStr

class DatabaseCredential(BaseModel):
    host: str
    port: int = 5432
    username: str
    password: SecretStr
```

Pydantic's `SecretStr` type is particularly important for authentication libraries. It wraps string values so they are masked in string representations and logs. The actual value is only accessible through the `.get_secret_value()` method, reducing the risk of accidental credential exposure.

### Frozen Models

A frozen model is a Pydantic model configured with `frozen=True` in its `model_config`. Once instantiated, a frozen model's fields cannot be modified. Any attempt to set an attribute raises a `ValidationError`.

```python
from pydantic import BaseModel, ConfigDict

class AuthSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
```

Freezing models provides two benefits for an authentication library. First, it prevents accidental mutation of credential objects after they are constructed, which could lead to subtle bugs where one part of the code modifies a shared credential reference. Second, frozen models are hashable, which means they can be used as dictionary keys or stored in sets.

The `extra="forbid"` setting in the configuration shown above is equally important. It tells Pydantic to raise an error if the constructor receives any fields not declared in the model. This catches typos and misconfiguration early -- for example, passing `username` to a `TokenAuth` model that only accepts `token`.

#### Diagram: Pydantic Model Validation Pipeline
<iframe src="../../sims/pydantic-validation-pipeline/main.html" width="100%" height="400px" scrolling="no"></iframe>
<details markdown="1">
<summary>Pydantic Model Validation Pipeline</summary>
Type: workflow
**sim-id:** pydantic-validation-pipeline<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Show the flow of data through Pydantic's validation pipeline: raw input dict enters, passes through type coercion, field validation, extra-field rejection (for `extra="forbid"`), and frozen enforcement, producing either a valid model instance or a ValidationError.

**Components:** Five sequential process nodes (Input Dict, Type Coercion, Field Validation, Extra Check, Freeze) connected by directed edges. A branch from Field Validation and Extra Check leading to a red ValidationError node.

**Interactions:** Click on each stage to see a tooltip explaining what happens. Hover to highlight the path for valid vs invalid input.

**Colors:** Valid path=SteelBlue, Error path=Crimson, Process nodes=white with colored borders.

**Learning Objective:** Understand (Bloom Level 2) how Pydantic validates and constrains model input, and why `frozen=True` and `extra="forbid"` matter for authentication schemas.
</details>

## Structural Typing and Resource Management

### Python Protocols

Python protocols, introduced in PEP 544 and available through the `typing` module, enable structural subtyping -- a form of duck typing with static type checker support. A protocol defines a set of methods and attributes that a class must have, without requiring explicit inheritance. Any class that implements the required methods is considered compatible with the protocol, whether or not it inherits from it.

The mountainash-auth-client library uses a protocol called `SecretStore` to define the interface for credential storage backends. This means that any class implementing the six required methods (`load`, `save`, `clear`, `is_cleared`, `list_users`, `lock`) is a valid store -- no base class inheritance needed.

```python
import typing as t

@t.runtime_checkable
class SecretStore(t.Protocol):
    def load(self, domain: str, provider: str, user: str) -> dict[str, t.Any] | None: ...
    def save(self, domain: str, provider: str, user: str, data: dict[str, t.Any]) -> None: ...
    def clear(self, domain: str, provider: str, user: str) -> None: ...
    def is_cleared(self, domain: str, provider: str, user: str) -> bool: ...
    def list_users(self, domain: str, provider: str) -> list[str]: ...
    def lock(self, domain: str, provider: str, user: str) -> AbstractContextManager[None]: ...
```

The `@runtime_checkable` decorator allows `isinstance()` checks at runtime, so you can verify that an object satisfies the protocol before passing it to a function. Without this decorator, the protocol would only be enforced by static type checkers like mypy or pyright.

The practical advantage of protocols over abstract base classes is that third-party code can implement the interface without importing or depending on the library. A team could write a Vault-backed secret store or a Keyring-backed store without any mountainash-auth-client imports, and it would be fully type-safe.

### Context Managers

A context manager is a Python object that defines `__enter__` and `__exit__` methods, enabling it to be used with the `with` statement. The `__enter__` method sets up a resource, and `__exit__` tears it down, guaranteeing cleanup even if an exception occurs.

In mountainash-auth-client, context managers appear in two places.

- **Connection mixins** use `__enter__` / `__exit__` to manage the lifecycle of an HTTP client. When the `with` block exits, the underlying `httpx.Client` is closed, releasing TCP connections and file descriptors.
- **The `lock` method** on `SecretStore` returns a context manager that acquires and releases a file lock. This ensures that concurrent processes do not corrupt credential files during token refresh.

The following example shows the standard pattern for using a context manager to manage a connection, where the `with` block guarantees cleanup:

```python
with connection.connect(profile, store=store, domain="prod") as conn:
    data = conn.client.get("/api/data")
# conn.disconnect() is called automatically here
```

Python also provides the `@contextmanager` decorator from the `contextlib` module, which allows you to write context managers as generator functions rather than classes. The code before `yield` acts as `__enter__`, and the code after `yield` acts as `__exit__`. The `FilesystemStore.lock()` method uses this pattern.

## File Security Primitives

### File Permissions

Unix file permissions control which users and groups can read, write, or execute a file. Permissions are expressed as a three-digit octal number, where each digit represents the owner, group, and others respectively. Each digit encodes read (4), write (2), and execute (1) permissions.

For credential files, the mountainash-auth-client library enforces strict permission checks.

| Permission | Octal | Meaning |
|---|---|---|
| `0o700` | rwx------ | Owner can read/write/execute; no access for group or others. Used for credential directories. |
| `0o600` | rw------- | Owner can read/write; no access for group or others. Used for credential files. |
| `0o077` | ---rwxrwx | Bitmask for group+other permissions. If `stat.st_mode & 0o077` is nonzero, the file is group- or world-readable. |

The `FilesystemStore` rejects any credential file where `mode & 0o077` is nonzero, meaning group or world-readable files are treated as a security violation. It also rejects symlinks, which could be used to redirect credential reads to attacker-controlled paths.

These checks prevent a common class of credential leaks where files are created with default permissions (often `0o644`, world-readable) and then left exposed on shared systems or in container images.

### Atomic File Writes

An atomic file write is a technique that ensures a file is either fully written or not modified at all. The standard approach is a two-step process: write the data to a temporary file, then rename (move) the temporary file to the target path. On POSIX systems, `os.replace()` is an atomic operation -- the target file is either the old version or the new version, never a partially written intermediate state.

The mountainash-auth-client library uses this pattern when saving credentials to disk. The sequence is as follows:

1. Open a temporary file (`.provider-user.tmp`) with `os.open()` using `0o600` permissions
2. Write the serialized credential data to the temporary file
3. Call `os.replace()` to atomically swap the temp file into the target path
4. If any step fails, delete the temporary file in the cleanup handler

This approach protects against two failure scenarios. Power loss or process crashes during the write leave the original file intact, because the rename has not yet occurred. Concurrent reads during the write always see a complete file, because `os.replace()` is atomic from the perspective of other processes reading the target path.

#### Diagram: Atomic Write Sequence
<iframe src="../../sims/atomic-write-sequence/main.html" width="100%" height="450px" scrolling="no"></iframe>
<details markdown="1">
<summary>Atomic Write Sequence</summary>
Type: workflow
**sim-id:** atomic-write-sequence<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Illustrate the four-step atomic write sequence used by FilesystemStore.save(), showing the temporary file, the atomic replace, and the cleanup path on failure.

**Components:** Four sequential step nodes (Create Temp File, Write Data, Atomic Replace, Cleanup on Error). The happy path flows linearly from step 1 to step 3. A branch from step 2 leads to step 4 (error cleanup). A "Reader" node observes the target file and always sees a consistent state.

**Interactions:** Click "Simulate Write" to animate the happy path. Click "Simulate Failure" to animate the error cleanup path. The Reader node shows what it would see at each step.

**Colors:** Happy path=DarkGreen, Error path=Crimson, Reader=SteelBlue.

**Learning Objective:** Apply (Bloom Level 3) the atomic write pattern to understand how FilesystemStore ensures credential file integrity.
</details>

Together, file permissions and atomic writes form the security foundation for the `FilesystemStore` implementation. Permissions ensure only the owning user can access credentials, while atomic writes ensure those credentials are never in a corrupt intermediate state.

## How These Foundations Connect

The concepts in this chapter are not isolated -- they form an interconnected foundation that the rest of the library builds upon. Understanding how they relate helps you anticipate the architecture covered in subsequent chapters.

OAuth 2.0 and OAuth 1.0a define the protocols that the flow classes (Chapters 4-5) implement. Bearer tokens are what those flows produce and what the connection mixins (Chapter 8) manage. API keys motivate the simpler auth types (Chapter 2) that do not require interactive flows.

Pydantic models and frozen configuration define how auth types are structured (Chapter 2-3). The `extra="forbid"` and `frozen=True` settings catch configuration errors and prevent accidental mutation -- properties that become critical when credentials are shared across threads or stored in caches.

Python protocols define the `SecretStore` interface (Chapter 6) that any storage backend can satisfy without inheritance. This enables the filesystem store, vault stores, and keyring stores to be completely independent implementations.

Context managers appear in the connection mixin's `__enter__`/`__exit__` (Chapter 8) for HTTP client lifecycle, and in the secret store's `lock` method (Chapter 6) for exclusive file access during refresh operations.

File permissions and atomic writes are implemented directly in the `FilesystemStore` (Chapter 6), where credentials must be protected from both unauthorized access and corruption.

## Key Takeaways

- **OAuth 2.0** is a delegation framework where users grant applications time-limited access tokens, avoiding direct credential sharing. The Authorization Code grant with PKCE is the primary flow used by mountainash-auth-client.
- **OAuth 1.0a** requires cryptographic request signing and uses a three-legged flow involving consumer credentials, request tokens, and access tokens. It is supported through an optional `authlib` dependency.
- **Bearer tokens** grant access to anyone who possesses them, making secure storage and transport (TLS) essential. API keys are a simpler, static alternative without delegation support.
- **Pydantic models** provide validated, type-safe data structures. The mountainash-auth-client library uses them with `frozen=True` and `extra="forbid"` to prevent mutation and catch misconfiguration.
- **Python protocols** enable structural subtyping, allowing custom credential storage backends without inheriting from library classes. The `SecretStore` protocol defines six methods that any storage backend must implement.
- **Context managers** guarantee resource cleanup via `__enter__`/`__exit__`, used for both HTTP connection lifecycle and file locking in the library.
- **File permissions** (`0o600` for files, `0o700` for directories) and **atomic file writes** (write to temp, then `os.replace()`) together ensure credentials are stored securely and never left in a corrupt state.

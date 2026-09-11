---
title: Auth Type System and Basic Types
description: The discriminated union architecture of mountainash-auth-client's auth type system, covering the AuthSpec base model, literal kind discriminators, and the five basic auth type variants.
generated_by: claude skill chapter-content-generator
date: 2026-06-03
version: 0.08
---

# Auth Type System and Basic Types

## Summary

This chapter covers the foundational type system architecture of mountainash-auth-client. It explains how the AuthSpec base model provides a common interface, how the discriminated union pattern enables type-safe polymorphism with a Literal kind discriminator, and introduces the first five auth type variants: NoAuth, PasswordAuth, TokenAuth, JWTAuth, and OAuth2Auth.

---

## The Problem of Diverse Authentication

Data platforms use wildly different authentication mechanisms. A DuckDB file needs no authentication at all. A PostgreSQL database requires a username and password. A Snowflake warehouse might use an OAuth 2.0 token. A Trino cluster could accept a JWT. A single data platform team may need to connect to all of these within a single pipeline.

The mountainash-auth-client library solves this by representing every authentication mechanism as a single type hierarchy. Configuration files, validation logic, and dispatch code all work with one polymorphic type rather than a sprawling set of unrelated dictionaries. This chapter explains how that type hierarchy is constructed using Pydantic's discriminated union pattern.

<!-- concept:11 -->
## The AuthSpec Base Model

The `AuthSpec` class is the root of the authentication type hierarchy. It is a Pydantic `BaseModel` configured as frozen (immutable) and strict about extra fields. Every authentication variant in the library inherits from this class.

The actual implementation is remarkably concise. The base class declares no fields of its own -- it exists purely to establish shared configuration and serve as the common type for the discriminated union.

```python
from pydantic import BaseModel, ConfigDict

class AuthSpec(BaseModel):
    """Base for typed auth modes used as a pydantic discriminated union."""
    model_config = ConfigDict(extra="forbid", frozen=True)
```

The `ConfigDict` applies two constraints that propagate to all subclasses. The `frozen=True` setting prevents any field on any auth type from being modified after construction, which is essential for credential safety. The `extra="forbid"` setting causes Pydantic to reject any unrecognized fields, catching configuration errors at parse time rather than at runtime.

A deliberate design choice in AuthSpec is the absence of a `kind` field on the base class itself. If the base declared `kind: str`, every subclass that narrows `kind` to a `Literal` would trigger a type checker warning (`reportIncompatibleVariableOverride`). By omitting `kind` from the base, each subclass is free to declare its own `Literal` discriminator without conflict.

<!-- concept:13 -->
<!-- concept:12 -->
## Discriminated Unions and the Literal Kind Discriminator

### Understanding Discriminated Unions

A discriminated union is a type that can be one of several variants, where a single field (the discriminator) determines which variant is active. In Pydantic, discriminated unions are declared using Python's `Annotated` type with a `Discriminator` annotation, or more commonly, by defining a `Union` of models that share a discriminator field.

The discriminator field must be a `Literal` type -- a type that accepts only a single, fixed string value. When Pydantic encounters a dictionary with `{"kind": "password", "username": "admin", "password": "secret"}`, it reads the `kind` field first, determines that the variant is `PasswordAuth`, and then validates the remaining fields against that specific model.

Without discriminated unions, Pydantic would have to try each variant in order until one validates successfully. This is fragile (the wrong variant might accidentally match) and produces confusing error messages when validation fails.

### The Literal Kind Discriminator

Each auth type subclass declares a `kind` field with a `Literal` type that serves as its unique identifier within the union. The field has a default value matching the literal, so users can omit it when constructing the model programmatically.

The pattern looks like this for every variant:

```python
import typing as t
from .base import AuthSpec

class SomeAuth(AuthSpec):
    kind: t.Literal["some"] = "some"
    # ... additional fields
```

The default value is important for ergonomic construction. When creating a `PasswordAuth` programmatically, you do not need to specify `kind="password"` -- the default fills it in automatically. But when deserializing from JSON or YAML, the `kind` field must be present because it is how Pydantic selects the correct variant from the union.

The `kind` field serves three purposes simultaneously.

- **Discriminator** -- Pydantic uses it to select the correct variant during deserialization
- **Serialization tag** -- when the model is serialized to JSON or YAML, the `kind` field identifies which variant was used
- **Runtime type indicator** -- code that receives an `AuthSpec` instance can inspect `auth.kind` to determine the variant without using `isinstance()`

#### Diagram: Discriminated Union Type Resolution
<iframe src="../../sims/discriminated-union-resolution/main.html" width="100%" height="500px" scrolling="no"></iframe>
<details markdown="1">
<summary>Discriminated Union Type Resolution</summary>
Type: workflow
**sim-id:** discriminated-union-resolution<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Visualize how Pydantic resolves a discriminated union: an input dictionary enters, the `kind` field is inspected, and the correct variant model is selected for full validation.

**Components:** One entry node (Input Dict), a decision node (Read `kind` field), five variant nodes (NoAuth, PasswordAuth, TokenAuth, JWTAuth, OAuth2Auth) arranged in a fan, and two outcome nodes (Valid Model, ValidationError). Edges from decision to each variant are labeled with the matching `kind` value.

**Interactions:** Click on the Input Dict node to cycle through sample inputs. The active path highlights showing which variant is selected. Click a variant node to see its field requirements. Invalid input highlights the error path.

**Colors:** Entry=SteelBlue, Decision=Gold, Variants=DarkSlateBlue, Valid=DarkGreen, Error=Crimson.

**Learning Objective:** Analyze (Bloom Level 4) how the discriminated union pattern routes input to the correct auth type variant based on the `kind` field.
</details>

The complete union type, as it would appear in a profile schema, combines all variants using Python's `Union`:

```python
from typing import Annotated, Union
from pydantic import Discriminator

AuthType = Annotated[
    Union[NoAuth, PasswordAuth, TokenAuth, JWTAuth, OAuth2Auth, ...],
    Discriminator("kind"),
]
```

This single type annotation gives consuming code full type safety: a function accepting `AuthType` can pattern-match on the `kind` field and have each branch narrowed to the specific variant type.

## The Basic Auth Type Variants

The library defines thirteen auth type variants in total. This chapter covers the five basic variants that handle the most common authentication scenarios. The remaining eight advanced variants are covered in Chapter 3.

<!-- concept:14 -->
### NoAuth Type

The simplest variant represents the absence of authentication. Some data sources -- local file databases like SQLite and DuckDB, or in-memory engines like PySpark -- require no credentials at all. Rather than using `None` or an empty dictionary to represent this case, the library uses an explicit type.

```python
class NoAuth(AuthSpec):
    kind: t.Literal["none"] = "none"
```

`NoAuth` has no fields beyond `kind`. Its purpose is to make the "no authentication needed" case explicit and type-safe. When the dispatch system encounters a `NoAuth` instance, it produces an empty kwargs dictionary, signaling to the backend driver that no credentials should be applied.

Using an explicit type rather than `None` avoids a common source of bugs: code that checks `if auth is None` versus `if auth.kind == "none"` behaves differently when authentication is optional versus explicitly disabled. The discriminated union guarantees that every auth configuration has a `kind`, making the intent unambiguous.

In configuration files, `NoAuth` appears as simply `kind: none`, making it clear to anyone reading the configuration that the absence of credentials is intentional, not an oversight.

<!-- concept:15 -->
### PasswordAuth Type

Username-and-password authentication remains the most prevalent mechanism for traditional databases. The `PasswordAuth` type captures a username as a plain string and a password as a `SecretStr`.

```python
class PasswordAuth(AuthSpec):
    kind: t.Literal["password"] = "password"
    username: str
    password: SecretStr
```

The `SecretStr` type for the password field ensures the value is masked in logs and string representations. Printing a `PasswordAuth` instance shows `password=SecretStr('**********')` rather than the actual credential. The real value is only accessible through `password.get_secret_value()`, which the dispatch system calls when constructing driver kwargs.

Both `username` and `password` are required fields with no defaults, meaning Pydantic raises a `ValidationError` if either is missing during construction. Combined with `extra="forbid"` from the base class, this means the only valid `PasswordAuth` configuration is one that provides exactly `kind`, `username`, and `password` -- nothing more, nothing less.

<!-- concept:16 -->
### TokenAuth Type

The `TokenAuth` type represents opaque bearer token authentication, where the client presents a single secret string to identify itself. This pattern is common in SaaS APIs and managed database services like MotherDuck.

```python
class TokenAuth(AuthSpec):
    kind: t.Literal["token"] = "token"
    token: SecretStr
```

An opaque token is called "opaque" because the client treats it as an arbitrary string without interpreting its contents. The client does not decode, parse, or validate the token -- it simply passes it through to the server in the `Authorization: Bearer <token>` header. This contrasts with JWTs (next section), which have a defined internal structure.

Opaque tokens are often preferred by API providers because revocation is straightforward -- the provider simply marks the token as invalid in its database. The client cannot cache or extend the token's validity because it has no access to the token's metadata.

<!-- concept:17 -->
### JWTAuth Type

JSON Web Tokens (JWTs) are a specific token format defined by RFC 7519. Unlike opaque tokens, JWTs are structured: they consist of three base64-encoded parts separated by dots (header, payload, signature). The payload contains claims about the authenticated entity, such as expiration time, issuer, and subject.

Despite this structural difference, the `JWTAuth` model stores the token the same way as `TokenAuth` -- as a `SecretStr`. The distinction between the two types exists for dispatch purposes.

```python
class JWTAuth(AuthSpec):
    kind: t.Literal["jwt"] = "jwt"
    token: SecretStr
```

Some backend drivers (such as Trino) require knowing that the token is a JWT rather than an opaque bearer token, because they may need to extract claims or validate the signature locally. By separating `JWTAuth` from `TokenAuth`, the dispatch system can route these two token types to different handling code.

| Auth Type | Kind Value | Fields | Typical Use Case |
|---|---|---|---|
| NoAuth | `"none"` | (none) | SQLite, DuckDB, PySpark |
| PasswordAuth | `"password"` | `username`, `password` | PostgreSQL, MySQL, MSSQL |
| TokenAuth | `"token"` | `token` | MotherDuck, REST APIs |
| JWTAuth | `"jwt"` | `token` | Trino, JWT-authenticated APIs |
| OAuth2Auth | `"oauth2"` | `client_id`, `client_secret`, `token`, `refresh_token`, `server_uri`, `scope` | Snowflake, PyIceberg REST |

<!-- concept:18 -->
### OAuth2Auth Type

The `OAuth2Auth` type captures the full set of OAuth 2.0 credentials that a client might need. Unlike the previous types where all fields are required, OAuth2Auth makes every field beyond `kind` optional. This flexibility reflects the reality that OAuth 2.0 configurations vary significantly across providers.

```python
class OAuth2Auth(AuthSpec):
    kind: t.Literal["oauth2"] = "oauth2"
    client_id: str | None = None
    client_secret: SecretStr | None = None
    token: SecretStr | None = None
    refresh_token: SecretStr | None = None
    server_uri: str | None = None
    scope: str | None = None
```

This design supports several different OAuth 2.0 usage patterns. When only `token` is provided, the type acts as a simple bearer token with OAuth 2.0 context. When `client_id` and `client_secret` are provided without a `token`, the dispatch system can produce a credential string for client-credentials grant. When all fields are populated, the connection mixin can manage the full token lifecycle including refresh.

The dispatch function for `OAuth2Auth` demonstrates this branching logic. It first checks for a direct token, then for client credentials, and falls back to an empty dict if neither is available.

#### Diagram: OAuth2Auth Field Combinations
<iframe src="../../sims/oauth2auth-field-combos/main.html" width="100%" height="450px" scrolling="no"></iframe>
<details markdown="1">
<summary>OAuth2Auth Field Combinations</summary>
Type: chart
**sim-id:** oauth2auth-field-combos<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Show how different field combinations in OAuth2Auth lead to different dispatch behaviors: token-only, client-credentials, full lifecycle, or empty.

**Components:** A central OAuth2Auth node with four branch paths. Each path is labeled with the field combination present (e.g., "token only", "client_id + client_secret", "all fields", "no fields") and the resulting dispatch output (e.g., `{"token": "..."}`, `{"credential": "id:secret"}`, empty dict). A legend explains each use case.

**Interactions:** Click each branch to highlight the active field combination. Hover to see a tooltip with the actual dispatch code path. Toggle between "Configuration View" and "Dispatch Output View".

**Colors:** Token path=Gold, Credential path=DarkSlateBlue, Full path=DarkGreen, Empty path=SteelBlue.

**Learning Objective:** Evaluate (Bloom Level 5) which OAuth2Auth field combination is appropriate for a given authentication scenario.
</details>

## Design Decisions: Why a Discriminated Union?

Several alternative patterns could model a polymorphic auth system, but each has drawbacks that the discriminated union avoids.

**Abstract base class with subclass registration** requires every new auth type to inherit from a specific class and register itself. This creates tight coupling and makes it harder for third-party code to define new types without importing the library's base classes.

**Dictionary with a "type" key** is the untyped equivalent of a discriminated union. It works at runtime but provides no static type checking, no IDE autocompletion, and no automatic validation. A typo in a key name (`"usernmae"` instead of `"username"`) becomes a runtime KeyError rather than a validation error.

**Separate configuration classes with no common type** forces consuming code to handle each type independently with `isinstance` checks, leading to fragile code that breaks when new types are added.

**Enum-based dispatch** uses an enum to select behavior but separates the type tag from the data, requiring two fields (the enum and a generic dict) instead of one validated model.

The discriminated union pattern combines the strengths of all these approaches: it provides a common base type (`AuthSpec`) for polymorphic handling, validates field names and types at parse time, supports static type narrowing in editors, and is open for extension without modifying existing code. The Pydantic implementation adds JSON Schema generation, which means the complete auth type system can be exported as a machine-readable schema for use in configuration editors and documentation.

## Putting It Together: From Configuration to Validation

To see how these pieces work together, consider a YAML configuration file that defines authentication for three different backends. The discriminated union enables Pydantic to parse all three from a single `auth` field.

```yaml
# DuckDB -- no auth needed
duckdb_backend:
  auth:
    kind: none

# PostgreSQL -- username and password
postgres_backend:
  auth:
    kind: password
    username: etl_user
    password: "s3cret!"

# Snowflake -- OAuth 2.0 with token
snowflake_backend:
  auth:
    kind: oauth2
    client_id: "abc123"
    client_secret: "def456"
    token: "eyJhbGciOi..."
```

When Pydantic deserializes each `auth` block, it reads the `kind` field, selects the matching variant, and validates the remaining fields against that variant's schema. A missing required field (like `username` on a `password` type) or an unrecognized field (like `username` on an `oauth2` type) raises an immediate, clear `ValidationError`.

This early validation is one of the primary benefits of the discriminated union approach. Configuration errors surface at load time with precise messages ("Field required: username for PasswordAuth"), rather than at connection time with cryptic driver errors ("authentication failed").

Consider what happens when a user accidentally provides an OAuth2 configuration with `kind: password`. Pydantic reads `kind`, selects `PasswordAuth`, and immediately reports that `username` and `password` are required while `client_id`, `client_secret`, `token`, and other OAuth fields are forbidden. This specificity makes misconfiguration obvious and easy to fix.

The same YAML configuration format works across all environments -- development, staging, and production -- with only the credential values changing. The structural validation ensures that the configuration shape is correct regardless of where it is deployed.

#### Diagram: Auth Type Hierarchy
<iframe src="../../sims/auth-type-hierarchy/main.html" width="100%" height="500px" scrolling="no"></iframe>
<details markdown="1">
<summary>Auth Type Hierarchy</summary>
Type: graph-model
**sim-id:** auth-type-hierarchy<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Display the inheritance hierarchy from AuthSpec to all thirteen auth type variants, with the five basic types covered in this chapter highlighted and the eight advanced types grayed out as a preview of Chapter 3.

**Components:** A root node (AuthSpec) with thirteen child nodes, one per variant. The five basic types (NoAuth, PasswordAuth, TokenAuth, JWTAuth, OAuth2Auth) are highlighted with full color and labels. The eight advanced types are present but dimmed. Each node displays the `kind` value and key fields.

**Interactions:** Click any highlighted node to see its full field list and a sample JSON configuration. Hover over dimmed nodes to see a "Covered in Chapter 3" tooltip. Drag nodes to rearrange the layout.

**Colors:** AuthSpec=SteelBlue, Basic types=DarkSlateBlue, Advanced types=LightGray with DarkSlateBlue border.

**Learning Objective:** Understand (Bloom Level 2) the complete auth type hierarchy and how the five basic types fit within it.
</details>

## Key Takeaways

- **AuthSpec** is a frozen, strict Pydantic base model that serves as the root of the auth type hierarchy. It declares `frozen=True` and `extra="forbid"` but intentionally omits the `kind` field to avoid type checker conflicts with subclass overrides.
- **Discriminated unions** enable Pydantic to parse polymorphic auth configurations efficiently and safely. The `kind` field acts as the discriminator, routing input to the correct variant for validation.
- **Literal kind discriminators** use `t.Literal["value"]` to give each variant a unique, fixed tag. This tag serves as the serialization marker, the Pydantic discriminator, and a runtime type indicator.
- **NoAuth** explicitly represents "no authentication needed," avoiding the ambiguity of `None` in configuration and dispatch logic.
- **PasswordAuth** captures `username` and `password` (as `SecretStr`) for traditional database authentication, with both fields required.
- **TokenAuth and JWTAuth** both store a single `SecretStr` token but use different `kind` values to enable backend-specific dispatch.
- **OAuth2Auth** makes all fields optional to support multiple OAuth 2.0 usage patterns, from simple bearer token to full client-credentials with refresh.
- The discriminated union validates configuration at parse time, surfacing errors like missing fields or extra fields immediately rather than at connection time.

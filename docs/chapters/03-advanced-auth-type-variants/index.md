---
title: Advanced Auth Type Variants
description: The remaining eight auth type variants covering interactive OAuth flows, cloud provider identity, enterprise single sign-on, and machine-to-machine authentication.
generated_by: claude skill chapter-content-generator
date: 2026-06-03
version: 0.08
---

# Advanced Auth Type Variants

## Summary

This chapter covers the remaining eight auth type variants in the discriminated union. It introduces OAuth2AuthCodeAuth for interactive authorization code flows, OAuth1Auth for legacy APIs, IAMAuth for AWS-style identity, AzureADAuth for Microsoft identity platform, WindowsAuth and KerberosAuth for enterprise single sign-on, CertificateAuth for mutual TLS, and ServiceAccountAuth for machine-to-machine authentication.

## Concepts Covered

- OAuth2AuthCodeAuth Type
- OAuth1Auth Type
- IAMAuth Type
- AzureADAuth Type
- WindowsAuth Type
- KerberosAuth Type
- CertificateAuth Type
- ServiceAccountAuth Type

## Prerequisites

- Chapter 1: Foundations (OAuth 2.0 Basics, OAuth 1.0a Basics)
- Chapter 2: Auth Type System and Basic Types (Discriminated Union)

## Learning Objectives

After completing this chapter, you will be able to:

- Distinguish OAuth2AuthCodeAuth from OAuth2Auth and choose the right one
- Configure OAuth1Auth for legacy OAuth 1.0a APIs
- Set up cloud provider auth types (IAMAuth, AzureADAuth, ServiceAccountAuth)
- Apply platform-specific auth types (WindowsAuth, KerberosAuth, CertificateAuth)
- Map real-world authentication requirements to the correct auth type variant

---

## Beyond the Basics: Specialized Authentication

Chapter 2 covered the five auth types that handle the most common scenarios: no auth, passwords, tokens, JWTs, and OAuth 2.0 client credentials. However, enterprise and cloud environments introduce authentication mechanisms that require richer configuration -- interactive browser flows, cryptographic key pairs, platform-native identity systems, and legacy protocols.

This chapter introduces the eight advanced variants that complete the discriminated union. These types share the same `AuthSpec` base class and frozen/strict configuration, but they model more complex credential structures. Some of them (like `WindowsAuth` and `KerberosAuth`) have no default dispatch mapping because they require backend-specific handling that cannot be generalized.

## Interactive OAuth Types

### OAuth2AuthCodeAuth Type

The `OAuth2AuthCodeAuth` type represents the credentials needed for an interactive OAuth 2.0 Authorization Code grant -- the flow where a user opens a browser, signs in, and grants consent. This is distinct from the `OAuth2Auth` type covered in Chapter 2, which stores static credentials and pre-obtained tokens.

The key difference is that `OAuth2AuthCodeAuth` always carries a `client_id` and `client_secret` (both required), because it expects to execute the authorization flow at connection time rather than reuse a pre-obtained token. It also stores the tokens obtained from that flow so they can be persisted and refreshed.

```python
class OAuth2AuthCodeAuth(AuthSpec):
    kind: t.Literal["oauth2_authcode"] = "oauth2_authcode"
    client_id: str
    client_secret: SecretStr
    access_token: SecretStr | None = None
    refresh_token: SecretStr | None = None
    token_expires_at: int | None = None
    scope: str | None = None
```

The `access_token` and `refresh_token` fields are optional because they may not exist when the configuration is first created. The connection mixin (Chapter 8) detects their absence and triggers the interactive authorization flow to populate them. The `token_expires_at` field stores a Unix timestamp indicating when the access token expires, enabling the mixin to refresh proactively.

When should you choose `OAuth2AuthCodeAuth` over `OAuth2Auth`? The decision table below provides guidance.

| Scenario | Use This Type | Reason |
|---|---|---|
| Pre-obtained token from another system | `OAuth2Auth` | Token already exists; no flow needed |
| Client-credentials grant (server-to-server) | `OAuth2Auth` | No user interaction required |
| Interactive browser-based user consent | `OAuth2AuthCodeAuth` | Requires authorization code flow |
| Token refresh with automatic re-authorization | `OAuth2AuthCodeAuth` | Needs client_id/secret for refresh |
| Embedding tokens in CI/CD pipelines | `OAuth2Auth` | Tokens injected from vault; no browser available |

### OAuth1Auth Type

OAuth 1.0a remains in use at several major providers, including the Garmin Health API, certain enterprise Twitter integrations, and some financial data providers. The `OAuth1Auth` type captures the consumer credentials and, optionally, previously-obtained access tokens.

```python
class OAuth1Auth(AuthSpec):
    kind: t.Literal["oauth1"] = "oauth1"
    consumer_key: str
    consumer_secret: SecretStr
    access_token: SecretStr | None = None
    access_token_secret: SecretStr | None = None
```

The `consumer_key` and `consumer_secret` are always required because they identify the application to the OAuth 1.0a provider. These are analogous to `client_id` and `client_secret` in OAuth 2.0. The `access_token` and `access_token_secret` are optional because, like `OAuth2AuthCodeAuth`, they may need to be obtained through an interactive flow.

A fundamental difference from OAuth 2.0 is that OAuth 1.0a requires both a token and a token secret for signing requests. The token alone is not sufficient -- every API request must be signed using HMAC-SHA1 with the consumer secret and token secret as key material. This is why `access_token_secret` exists as a separate field rather than being embedded in a single credential string.

#### Diagram: OAuth1 vs OAuth2 Credential Structure
<iframe src="../../sims/oauth1-vs-oauth2-credentials/main.html" width="100%" height="450px" scrolling="no"></iframe>
<details markdown="1">
<summary>OAuth1 vs OAuth2 Credential Structure</summary>
Type: diagram
**sim-id:** oauth1-vs-oauth2-credentials<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Compare the credential structures of OAuth1Auth and OAuth2AuthCodeAuth side by side, showing which fields participate in request signing (OAuth1) versus bearer token transmission (OAuth2).

**Components:** Two column groups. Left column: OAuth1Auth with nodes for consumer_key, consumer_secret, access_token, access_token_secret, connected to an "HMAC-SHA1 Signature" process node, then to a "Signed Request" output. Right column: OAuth2AuthCodeAuth with nodes for client_id, client_secret, access_token, connected to a "Bearer Header" process node, then to an "Authenticated Request" output.

**Interactions:** Click on each field node to highlight which parts of the request it affects. Toggle between "Storage View" (what is saved) and "Request View" (how credentials are used at request time).

**Colors:** OAuth1 column=DarkGoldenrod, OAuth2 column=Gold, Process nodes=SteelBlue, Output nodes=DarkGreen.

**Learning Objective:** Analyze (Bloom Level 4) the structural differences between OAuth 1.0a and OAuth 2.0 credential management and their security implications.
</details>

## Cloud Provider Auth Types

Cloud platforms implement their own identity systems that do not fit neatly into the standard OAuth model. The following three types capture the credentials for AWS, Microsoft Azure, and Google Cloud platforms respectively.

### IAMAuth Type

AWS Identity and Access Management (IAM) uses a credential model based on access key pairs, role assumption, and session tokens. The `IAMAuth` type supports all of these patterns through optional fields.

```python
class IAMAuth(AuthSpec):
    kind: t.Literal["iam"] = "iam"
    role_arn: str | None = None
    access_key_id: str | None = None
    secret_access_key: SecretStr | None = None
    session_token: SecretStr | None = None
    profile_name: str | None = None
```

Every field is optional because AWS supports ambient credential resolution -- the SDK automatically checks environment variables, instance profiles, and SSO configuration. When the `IAMAuth` type is dispatched with all fields empty, it signals the backend to use ambient credentials. When specific fields are provided, they override the default resolution chain.

The supported credential patterns are:

- **Ambient resolution** -- all fields `None`; uses `AWS_ACCESS_KEY_ID` env var, `~/.aws/credentials`, or instance metadata
- **Explicit key pair** -- `access_key_id` + `secret_access_key`; useful for service accounts outside AWS
- **Role assumption** -- `role_arn` provided; assumes the role using ambient credentials or an explicit key pair
- **Session credentials** -- `access_key_id` + `secret_access_key` + `session_token`; short-lived credentials from STS
- **Named profile** -- `profile_name` references a configuration in `~/.aws/config`

### AzureADAuth Type

Microsoft's identity platform (Azure Active Directory, now Microsoft Entra ID) supports both interactive user authentication and managed identity for services running inside Azure. The `AzureADAuth` type captures the parameters for both patterns.

```python
class AzureADAuth(AuthSpec):
    kind: t.Literal["azure_ad"] = "azure_ad"
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None
    managed_identity: bool = False
    msi_endpoint: str | None = None
```

When `managed_identity` is `True`, the backend uses Azure's Managed Service Identity (MSI) endpoint to obtain tokens without storing any secrets. This is the recommended approach for applications running on Azure VMs, App Service, or Functions. The `msi_endpoint` field allows overriding the default MSI endpoint for custom environments.

When `managed_identity` is `False`, the type behaves as a standard OAuth 2.0 client-credentials configuration using `tenant_id`, `client_id`, and `client_secret`. This is appropriate for applications running outside Azure that need to authenticate against Azure resources.

### ServiceAccountAuth Type

Google Cloud Platform uses service account JSON key files for machine-to-machine authentication. The `ServiceAccountAuth` type accepts either the raw JSON key data as a dictionary or a path to the key file.

```python
class ServiceAccountAuth(AuthSpec):
    kind: t.Literal["service_account"] = "service_account"
    info: dict[str, t.Any] | None = None
    file: Path | None = None
```

Providing the key data inline (via `info`) is useful when credentials are injected from a vault or secrets manager at runtime. Providing a file path (via `file`) is common in development environments where the JSON key file is downloaded from the Google Cloud Console. In production, Google recommends Workload Identity Federation over exported key files, but the key-file approach remains widespread.

!!! warning "Security of Cloud Credentials"
    Cloud provider auth types (`IAMAuth`, `AzureADAuth`, `ServiceAccountAuth`) often carry highly privileged credentials. AWS access keys can grant full account access. Azure client secrets allow impersonating a service principal. Google service account keys have no expiry by default. Always store these credentials using the `SecretStore` mechanism (Chapter 6) and rotate them on a regular schedule.

## Enterprise Auth Types

Enterprise environments often use platform-native authentication mechanisms that leverage existing identity infrastructure (Active Directory, Kerberos realms, PKI certificates). These types typically require no stored secrets because they rely on the operating system or network environment for credential material.

### WindowsAuth Type

Windows Integrated Authentication (also known as NTLM or SSPI) allows applications to authenticate using the logged-in Windows user's credentials. This is the default authentication mechanism for Microsoft SQL Server in Windows domain environments.

```python
class WindowsAuth(AuthSpec):
    kind: t.Literal["windows"] = "windows"
    username: str | None = None
    domain: str | None = None
```

Both fields are optional. When both are `None`, the backend uses the current process's Windows credentials (the logged-in user). When `username` and `domain` are specified, the backend attempts to authenticate as that specific domain user, which may require the process to have delegation privileges.

### KerberosAuth Type

Kerberos is a network authentication protocol that uses tickets issued by a Key Distribution Center (KDC) to authenticate clients to services. It is commonly used in Hadoop ecosystems, PostgreSQL with GSS-API, and Trino/Presto clusters.

```python
class KerberosAuth(AuthSpec):
    kind: t.Literal["kerberos"] = "kerberos"
    service_name: str = "postgres"
    principal: str | None = None
    keytab: Path | None = None
```

The `service_name` defaults to `"postgres"` because that is the most common Kerberos-authenticated service in the data platform context. For Trino, you would set it to `"trino"` or `"HTTP"`. The `principal` overrides the default client principal (usually derived from the logged-in user), and `keytab` points to a file containing pre-exported keys for non-interactive authentication.

### CertificateAuth Type

Certificate-based authentication uses public-key cryptography. The client holds a private key and presents a certificate (containing the corresponding public key) to the server. The server validates the certificate against a trusted Certificate Authority and challenges the client to prove possession of the private key.

In the mountainash-auth-client context, `CertificateAuth` is primarily used for Snowflake's key-pair authentication, where the private key signs a JWT that serves as the access token.

```python
class CertificateAuth(AuthSpec):
    kind: t.Literal["certificate"] = "certificate"
    private_key: SecretStr | None = None
    private_key_path: Path | None = None
    passphrase: SecretStr | None = None
```

The private key can be provided inline (via `private_key` as a PEM-encoded string) or by file path (via `private_key_path`). The `passphrase` field is needed if the private key file is encrypted. Providing both `private_key` and `private_key_path` is not an error, but the inline value takes precedence.

#### Diagram: Enterprise Auth Decision Tree
<iframe src="../../sims/enterprise-auth-decision-tree/main.html" width="100%" height="550px" scrolling="no"></iframe>
<details markdown="1">
<summary>Enterprise Auth Decision Tree</summary>
Type: diagram
**sim-id:** enterprise-auth-decision-tree<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Guide users through selecting the correct enterprise auth type based on their environment, platform, and available credential material.

**Components:** A decision tree with branching questions: "Is this a cloud platform?" (yes -> IAMAuth/AzureADAuth/ServiceAccountAuth branch), "Does your environment have Windows domain?" (yes -> WindowsAuth), "Is Kerberos configured?" (yes -> KerberosAuth), "Do you have a private key or certificate?" (yes -> CertificateAuth). Each leaf node shows the recommended type and its key fields.

**Interactions:** Click decision nodes to expand branches. Each path highlights in a distinct color. Leaf nodes show a sample YAML configuration on click. A "Reset" button returns to the root.

**Colors:** Cloud branch=MediumPurple, Windows branch=SteelBlue, Kerberos branch=Teal, Certificate branch=DarkGoldenrod, decision nodes=Gold.

**Learning Objective:** Evaluate (Bloom Level 5) which auth type variant is appropriate for a given enterprise authentication requirement.
</details>

## Unmapped Types and Backend Responsibility

A critical design decision in the mountainash-auth-client library is that not all auth types have a default dispatch mapping. The `AUTH_TO_DRIVER_KWARGS` registry (covered in detail in Chapter 4) only includes types where a sensible default exists:

- `NoAuth` maps to an empty dict
- `PasswordAuth` maps to `{"user": ..., "password": ...}`
- `TokenAuth` and `JWTAuth` map to `{"token": ...}`
- `OAuth2Auth` maps based on available fields
- `IAMAuth` maps to AWS credential fields

The five types without default dispatch are:

- `WindowsAuth` -- Windows authentication is highly platform-specific
- `AzureADAuth` -- requires Azure SDK calls to obtain tokens
- `KerberosAuth` -- requires GSSAPI/kinit interaction
- `CertificateAuth` -- requires private key loading and JWT signing
- `ServiceAccountAuth` -- requires Google Cloud SDK interaction

These types are intentionally left unmapped. Their respective backend adapters (MSSQL, BigQuery, Snowflake) are responsible for interpreting the fields and calling the appropriate platform SDKs. This separation keeps the auth-client library focused on type definitions and common patterns, without pulling in heavy platform-specific dependencies.

When dispatch encounters one of these unmapped types, it raises a `KeyError`. The backend adapter catches this and applies its own handling logic. This design is explored further in Chapter 4's coverage of backend-specific handling.

## Choosing Between Similar Types

Several auth type pairs appear similar at first glance but serve different purposes. Understanding these distinctions prevents misconfiguration.

**OAuth2Auth vs OAuth2AuthCodeAuth:** `OAuth2Auth` is for static credentials -- tokens pre-obtained through external tooling or client-credentials grants that do not involve user interaction. `OAuth2AuthCodeAuth` is for interactive flows where the library manages the full authorization lifecycle. If your tokens come from a vault or CI/CD secret, use `OAuth2Auth`. If users need to click "Allow" in a browser, use `OAuth2AuthCodeAuth`.

**TokenAuth vs JWTAuth:** Both store a single `SecretStr` token. The distinction exists for dispatch: some drivers need to know the token is a JWT (to validate claims, extract expiry, or send it in a specific header format). If the driver treats the token as opaque, use `TokenAuth`. If it needs to decode or validate the JWT structure, use `JWTAuth`.

**IAMAuth vs ServiceAccountAuth:** Both handle cloud machine-to-machine authentication, but for different providers. `IAMAuth` is AWS-specific (access keys, role ARN, session tokens). `ServiceAccountAuth` is Google-specific (JSON key files or inline key dicts). Despite the conceptual similarity, their credential structures are completely different.

**WindowsAuth vs KerberosAuth:** Both are ticket-based enterprise SSO mechanisms, but at different layers. `WindowsAuth` uses NTLM/SSPI (Windows-specific, domain-integrated). `KerberosAuth` uses the cross-platform Kerberos protocol (works on Linux, macOS, and Windows). A domain-joined Windows SQL Server uses `WindowsAuth`. A Kerberized Hadoop cluster uses `KerberosAuth`.

## Complete Auth Type Reference

The following table provides a complete reference for all thirteen auth type variants, showing their `kind` value, required vs optional fields, and typical use cases.

| Kind | Type Class | Required Fields | Optional Fields | Common Backends |
|---|---|---|---|---|
| `none` | NoAuth | -- | -- | SQLite, DuckDB, PySpark |
| `password` | PasswordAuth | username, password | -- | PostgreSQL, MySQL, MSSQL |
| `token` | TokenAuth | token | -- | MotherDuck, REST APIs |
| `jwt` | JWTAuth | token | -- | Trino |
| `oauth2` | OAuth2Auth | -- | client_id, client_secret, token, refresh_token, server_uri, scope | Snowflake, PyIceberg |
| `oauth2_authcode` | OAuth2AuthCodeAuth | client_id, client_secret | access_token, refresh_token, token_expires_at, scope | Interactive OAuth2 providers |
| `oauth1` | OAuth1Auth | consumer_key, consumer_secret | access_token, access_token_secret | Garmin, legacy APIs |
| `iam` | IAMAuth | -- | role_arn, access_key_id, secret_access_key, session_token, profile_name | Redshift, Athena, S3 |
| `azure_ad` | AzureADAuth | -- | tenant_id, client_id, client_secret, managed_identity, msi_endpoint | Azure SQL, Synapse |
| `windows` | WindowsAuth | -- | username, domain | MSSQL (domain-joined) |
| `kerberos` | KerberosAuth | -- | service_name, principal, keytab | PostgreSQL GSS, Trino |
| `certificate` | CertificateAuth | -- | private_key, private_key_path, passphrase | Snowflake key-pair |
| `service_account` | ServiceAccountAuth | -- | info, file | BigQuery, GCS |

#### Diagram: Auth Types by Authentication Model
<iframe src="../../sims/auth-types-by-model/main.html" width="100%" height="500px" scrolling="no"></iframe>
<details markdown="1">
<summary>Auth Types by Authentication Model</summary>
Type: infographic
**sim-id:** auth-types-by-model<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Categorize all thirteen auth types by their underlying authentication model: credentials (something you know), tokens (something you have), certificates (something you possess cryptographically), and platform identity (something the environment asserts).

**Components:** Four cluster groups arranged in quadrants. "Credentials" cluster contains NoAuth, PasswordAuth. "Tokens" cluster contains TokenAuth, JWTAuth, OAuth2Auth, OAuth2AuthCodeAuth, OAuth1Auth. "Certificates" cluster contains CertificateAuth. "Platform Identity" cluster contains IAMAuth, AzureADAuth, WindowsAuth, KerberosAuth, ServiceAccountAuth. Edges connect types that can be used together (e.g., ServiceAccountAuth produces tokens).

**Interactions:** Click a cluster to expand and see the types within. Click an individual type to see its fields. Drag to rearrange clusters. Toggle "Dispatch Status" overlay to see which types have default dispatch (green) vs unmapped (red).

**Colors:** Credentials=SteelBlue, Tokens=Gold, Certificates=DarkGoldenrod, Platform Identity=MediumPurple.

**Learning Objective:** Analyze (Bloom Level 4) the relationship between authentication models and the library's type system, and understand why some types lack default dispatch mappings.
</details>

## Key Takeaways

- **OAuth2AuthCodeAuth** is for interactive browser-based authorization flows, with required `client_id` and `client_secret`. Use it when users must grant consent through a browser. Use `OAuth2Auth` when tokens are pre-obtained or injected.
- **OAuth1Auth** carries both consumer credentials and access tokens for legacy APIs that require HMAC-SHA1 request signing. The token secret is a separate field because it participates in signature generation.
- **IAMAuth** supports AWS credential resolution from explicit keys, role ARN, session tokens, or ambient (all-None) mode where the SDK resolves credentials from the environment.
- **AzureADAuth** toggles between managed identity (`managed_identity=True`, no secrets needed) and explicit client-credentials via `tenant_id`/`client_id`/`client_secret`.
- **WindowsAuth and KerberosAuth** use platform-native identity with minimal configuration, typically just a service name or principal identifier.
- **CertificateAuth** stores private key material (inline or by path) for public-key authentication schemes like Snowflake's key-pair JWT signing.
- **ServiceAccountAuth** accepts Google Cloud credentials either as a raw JSON dict or a file path, supporting both vault injection and local development workflows.
- Five of the eight advanced types have **no default dispatch mapping** because their authentication logic is platform-specific. Backend adapters handle these types directly.

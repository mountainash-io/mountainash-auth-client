# `ProviderProfileProtocol` — Generalising the Provider Profile Pattern (Layer A)

**Date:** 2026-06-15
**Status:** Design (pre-plan)
**Repo:** mountainash-auth-client (`feature/provider-profile-protocol`, off `develop`)

## 1. Context & Goal

auth-client's provider-profile pattern lets a consumer carry a provider's
coordinates as a typed, validated `Profile` and hand it to a parameterised
connection, instead of fusing provider metadata into bespoke per-provider classes.
But the pattern is **realised only as OAuth concretes** — `OAuth2ProviderProfile`
and `OAuth1ProviderProfile` — and there is **no protocol**. The only
runtime-checkable protocol in auth-client is `CallbackServerProtocol` (OAuth
callbacks). Consequences:

- Connections and flows type their `provider` parameter against the **concrete
  OAuth class** (`provider: OAuth2ProviderProfile`), so a consumer cannot type
  against the contract, hold providers polymorphically, or supply its own provider
  profile without importing the concrete.
- A **non-OAuth** provider (a plain HTTP API authenticated by a bearer token, basic
  auth, or IAM) has no provider-profile surface at all — the pattern is shaped to
  OAuth even though the underlying `Profile` + `emit(TargetFamily)` machinery is
  auth-method-agnostic.

**Goal (Layer A):** formalise the provider-profile contract as a runtime-checkable
**`ProviderProfileProtocol`**, with OAuth2/OAuth1 refinements, and retype the
connections/flows against the protocol. This completes the pattern (consumers type
against the contract, not a concrete) and makes it extensible to non-OAuth auth
methods — without changing any runtime behaviour.

**Out of scope — Layer B** (its own backlog doc,
`docs/superpowers/backlog/2026-06-15-generic-nonoauth-http-connection.md`): a
generic non-OAuth HTTP connection that composes a provider profile + a non-lifecycle
auth profile (Token/Basic/IAM/None) into an authed client. Layer A is the protocol
Layer B will build on; **transport is Layer B's forcing consumer**, not this work.

## 2. What exists today (verified)

```python
# providers/oauth2.py
class OAuth2ProviderProfile(Profile):
    __spec__ = OAUTH2_PROVIDER_SPEC      # NAME, AUTHORIZE_URL, TOKEN_URL, BASE_URL,
                                         # DEFAULT_SCOPE, USE_PKCE, CALLBACK_PORT
    __adapters__ = {TargetFamily.HTTP: _provider_http_kwargs}   # emits {"base_url": …}

# Profile.emit(target: Hashable = …, *, base: dict | None = None) -> dict   (mountainash_settings)
```

- `OAuth1ProviderProfile`: `NAME`, `REQUEST_TOKEN_URL`, `AUTHORIZE_URL`,
  `ACCESS_TOKEN_URL`, `BASE_URL`, `CALLBACK_PORT`; same `__adapters__`.
- `OAuth2Connection.__init__(provider: OAuth2ProviderProfile, …)`,
  `OAuth1Connection.__init__(provider: OAuth1ProviderProfile, …)`, and the flows
  (`OAuthFlow`/`OAuth1Flow`) read provider fields directly.

What a **connection** actually needs from *any* provider, regardless of auth
method, is exactly two things: `NAME` (for error labels/logging) and
`emit(TargetFamily.HTTP)` (→ the resource-client kwargs, i.e. `base_url`). The
auth-server fields (`AUTHORIZE_URL`/`TOKEN_URL`/…) are an **OAuth-specific
extension**, consumed only by the OAuth flows.

## 3. Design

### 3.1 The protocol hierarchy (`providers/protocols.py`, NEW)

```python
import typing as t

__all__ = [
    "ProviderProfileProtocol",
    "OAuth2ProviderProfileProtocol",
    "OAuth1ProviderProfileProtocol",
]


@t.runtime_checkable
class ProviderProfileProtocol(t.Protocol):
    """The resource-coordinate contract every provider profile satisfies,
    independent of auth method.

    A connection needs only a name (labels/logging) and the ability to emit its
    resource-client kwargs (``base_url`` + future transport knobs) for a target
    SDK family. Auth-server coordinates are an auth-method-specific refinement.
    """

    NAME: str

    # `target` is required at the protocol level; the concrete `Profile.emit`
    # supplies a default for internal convenience. Callers always pass a target.
    def emit(
        self, target: t.Hashable, *, base: dict[str, t.Any] | None = None
    ) -> dict[str, t.Any]: ...


@t.runtime_checkable
class OAuth2ProviderProfileProtocol(ProviderProfileProtocol, t.Protocol):
    """An OAuth2 authorization-code provider: base contract + auth-server URLs."""

    AUTHORIZE_URL: str
    TOKEN_URL: str
    BASE_URL: str
    DEFAULT_SCOPE: str | None
    USE_PKCE: bool
    CALLBACK_PORT: int | None


@t.runtime_checkable
class OAuth1ProviderProfileProtocol(ProviderProfileProtocol, t.Protocol):
    """An OAuth1 provider: base contract + the three-legged handshake URLs."""

    REQUEST_TOKEN_URL: str
    AUTHORIZE_URL: str
    ACCESS_TOKEN_URL: str
    BASE_URL: str
    CALLBACK_PORT: int | None
```

This mirrors the storage family's established precedent (`ProfileProtocol` →
`StorageProfileProtocol`) in mountainash-transport: a universal base protocol with
a per-family refinement. The base contract here is `NAME` + `emit`; transport's is
`to_handler_kwargs()`. (Unifying the two universal verbs — `emit` vs
`to_handler_kwargs` — is explicitly **not** in scope; each family keeps its actual
mechanism.)

**The base is structural, not target-semantic.** `ProviderProfileProtocol`
guarantees only `NAME` and a *target-parametric* `emit` — it does **not** promise
that `emit(TargetFamily.HTTP)` returns HTTP-ready kwargs, because a provider may
target a different family (`BOTO`, `PARAMIKO`) with no `base_url` at all. The
"`emit(HTTP)` yields `{base_url: …}`" semantic is a **per-target precondition a
connection states of the providers it accepts** — e.g. an HTTP connection (Layer B)
documents "requires a provider whose `emit(TargetFamily.HTTP)` includes `base_url`".
That is why `BASE_URL` lives on the OAuth refinements (which are HTTP providers) and
not on the base: the base is auth-method- *and* target-agnostic by design. The
refinements add both the OAuth auth-server fields and, implicitly, the HTTP-target
guarantee.

`runtime_checkable` checks **member presence only** (names, not types/signatures),
matching the honest-scope convention already used across the ecosystem
(mountainash-secrets' capability protocols, the storage protocols): structural
conformance is asserted by tests, not promised by `isinstance`.

### 3.2 Retype the consumers (behaviour-identical)

Replace concrete provider types with the protocol at every boundary that only
needs the contract:

| Site | Was | Becomes |
|---|---|---|
| `OAuth2Connection.__init__` | `provider: OAuth2ProviderProfile` | `provider: OAuth2ProviderProfileProtocol` |
| `OAuth1Connection.__init__` | `provider: OAuth1ProviderProfile` | `provider: OAuth1ProviderProfileProtocol` |
| `OAuthFlow.__init__` | `provider: OAuth2ProviderProfile` | `provider: OAuth2ProviderProfileProtocol` |
| `OAuth1Flow.__init__` | `provider: OAuth1ProviderProfile` | `provider: OAuth1ProviderProfileProtocol` |
| `OAuth2TokenManager` / `OAuth1TokenManager` `provider` param | concrete | matching protocol |

These are type-annotation changes only (the annotations are already under
`TYPE_CHECKING`/`from __future__ import annotations` in these modules). No runtime
code changes; the concrete profiles satisfy the protocols structurally, so every
existing test passes unchanged.

### 3.3 Concrete profiles unchanged

`OAuth2ProviderProfile` / `OAuth1ProviderProfile` are **not modified** — they
already expose `NAME`, the auth-server fields, and `emit` via `__adapters__`. They
satisfy the protocols by structure. (No explicit `class X(…, Protocol)` inheritance
is added to the concretes; structural typing is the point.)

## 4. Exports

`providers/protocols.py` is re-exported through `providers/__init__.py` and the
package root `__init__.py` (`__all__`, alphabetised): `ProviderProfileProtocol`,
`OAuth2ProviderProfileProtocol`, `OAuth1ProviderProfileProtocol`. Consumers
(wearables now; transport via Layer B later) import the protocol, not the concrete.

## 5. Testing

`tests/providers/test_provider_protocols.py` (NEW):

- **Conformance:** `isinstance(OAuth2ProviderProfile(NAME=…, AUTHORIZE_URL=…,
  TOKEN_URL=…, BASE_URL=…), OAuth2ProviderProfileProtocol)` is `True`; likewise
  OAuth1. Both also satisfy `ProviderProfileProtocol`.
- **Base-protocol minimality:** a hand-written dummy with only `NAME` + `emit`
  satisfies `ProviderProfileProtocol` but **not** the OAuth refinements — proving
  the base is genuinely auth-method-agnostic and the refinements add the OAuth
  surface.
- **Structural emit:** `emit(TargetFamily.HTTP)` on a concrete returns
  `{"base_url": …}` (locks the resource-emit contract the connection relies on).
- **Load-bearing export test:** the three names import from the package root and
  are in `__all__`.

The conformance test proves member **presence only** — `isinstance` does not check
field types, URL validity, or the shape `emit()` returns (a degenerate provider
could pass the check yet emit `{}`). Semantic correctness remains the concrete
profile's `ParameterSpec`/adapter job; the protocol is a structural contract.

No behavioural tests change — §3.2 is annotation-only, so the full existing suite
(317 passed, 2 skipped) stays green.

## 6. Consumption (why this matters)

- **wearables** (the in-flight consumer collapse) types its provider profiles
  against `OAuth2ProviderProfileProtocol` and can hold all providers as
  `ProviderProfileProtocol` for uniform registry/dispatch — instead of importing
  concrete OAuth classes. Item #2 of that migration's canonical-pattern audit
  becomes truly method-agnostic.
- **Layer B / transport** builds the generic non-OAuth HTTP connection on
  `ProviderProfileProtocol`: any provider (token/basic/IAM) implements the base
  protocol; the connection composes `provider.emit(HTTP)` + the auth strategy.

## 7. Out of Scope

- Layer B (the generic non-OAuth connection + token/basic/IAM provider concretes) —
  separate backlog doc; transport-driven.
- Adding/renaming any field on the concrete profiles.
- Unifying the cross-family universal verb (`emit` vs `to_handler_kwargs`).
- Moving the protocol into mountainash-settings as a shared base (auth-client owns
  its provider protocol, as transport owns `StorageProfileProtocol`).

## 8. Risks

- **Structural-typing false confidence:** `runtime_checkable` only checks member
  names, so a profile missing a *type* (e.g. `USE_PKCE` as the wrong type) still
  passes `isinstance`. Mitigation: the convention is documented (members-only), and
  the conformance test pins the real concretes; semantic correctness is the
  concrete's `ParameterSpec` job, not the protocol's.
- **Annotation drift:** if a flow later reads a provider field not declared on the
  refinement protocol, mypy won't catch it until the annotation is added.
  Mitigation: the refinement protocols list exactly the fields the flows read today
  (audited against `OAuthFlow`/`OAuth1Flow`).

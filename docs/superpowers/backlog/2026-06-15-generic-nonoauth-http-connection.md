# Backlog — Generic Non-OAuth HTTP Connection (Layer B)

**Date:** 2026-06-15
**Status:** Backlog (problem statement + sketch — not yet a design spec)
**Repo:** mountainash-auth-client
**Depends on:** Layer A (`ProviderProfileProtocol`,
`docs/superpowers/specs/2026-06-15-provider-profile-protocol-design.md`)
**Forcing consumer:** mountainash-transport

## Problem

auth-client's parameterised connections are OAuth-shaped. `OAuth2Connection` /
`OAuth1Connection` drive a **token lifecycle** (authorize / refresh / persist) via
the flows and managers. But many providers authenticate to an HTTP API with **no
token dance at all** — a static bearer token, HTTP Basic, an IAM signature, or
nothing. For those there is no "given a provider profile + an auth profile, hand me
an authenticated client" path. A consumer either reaches for an OAuth connection it
doesn't need, or hand-rolls client construction.

The building blocks already exist; only the composition is missing:

- **Provider coordinates:** Layer A's `ProviderProfileProtocol` (`NAME` +
  `emit(TargetFamily.HTTP)` → `base_url` + transport knobs).
- **Credential injection:** the auth-strategy resolver
  (`resolve_auth_strategy(auth_profile, provider_type)`) already maps a non-OAuth
  auth profile (`TokenAuthProfile`, `PasswordAuthProfile` → Basic, `IAMAuthProfile`,
  `NoAuthProfile`) to a strategy that injects credentials into SDK-client kwargs.

What's missing is a connection that **composes** them for the non-lifecycle case.

## Sketch (to be designed)

A lifecycle-free HTTP connection:

```python
class HTTPConnection:                      # working name
    def __init__(self, provider: ProviderProfileProtocol,
                 auth_profile, *, resolver=None): ...

    def connect(self) -> Self:
        base = self._provider.emit(TargetFamily.HTTP)          # base_url + knobs
        auth_kw = resolve_auth_strategy(self._auth).emit(...)  # bearer/basic/iam/none
        self._client = httpx.Client(**{**base, **auth_kw})
        return self
```

Plus the **non-OAuth provider concretes** that satisfy `ProviderProfileProtocol`
without auth-server URLs — a minimal `HTTPProviderProfile` (just `NAME` +
`BASE_URL`/emit), and whatever IAM/regional coordinates the boto family needs (a
`BOTO`-family emit, paralleling the existing `HTTP` adapter).

Open questions for the design phase:

- Does this stay one `HTTPConnection`, or a small family per `TargetFamily`
  (HTTP/BOTO/PARAMIKO) mirroring the emit targets? (transport already has leaf
  connections per SDK — `HTTPConnection`, `S3Connection`, `SSHConnection`.)
- How much of transport's existing `connections/` leaf layer is this, vs. a thinner
  auth-client primitive transport composes? (Avoid duplicating transport's leaf
  connections; auth-client may own only the provider-profile + auth-strategy
  composition, with transport keeping its SDK-specific leaves.)
- Does the token-*lifecycle* (OAuth) connection get refactored to sit on top of the
  same base composition, or stay separate?

## Why transport is the forcing consumer

mountainash-transport already spans exactly these non-OAuth HTTP/SDK auth methods —
S3/IAM (boto), HTTP token/basic (httpx), SFTP/SSH (paramiko) — and already has a
parallel `ProfileProtocol`/`StorageProfileProtocol` + `resolve_auth_strategy` +
leaf-connection layer of its own. Layer B is where the auth-client provider-profile
pattern and transport's storage-profile pattern can converge on a shared
provider-profile protocol + auth-strategy composition, instead of two parallel
copies. transport is the consumer whose real providers exercise the non-OAuth path —
so it should drive the Layer B design, the way wearables drove the OAuth managers.

## Why deferred (not in Layer A, not in the wearables collapse)

- wearables' non-OAuth providers do **not** fit this model: garmin_connect's auth
  is owned by the `garminconnect` SSO library, and apple is offline file import with
  no auth. So wearables is not a forcing consumer for Layer B.
- Layer A (the protocol) is the prerequisite and ships first.
- Building a generic non-OAuth connection without its forcing consumer (transport)
  risks designing to a guess. Pick this up as a transport-driven design spec once
  Layer A has landed.

## Next step when picked up

Brainstorm → design spec with transport as the lens: inventory transport's leaf
connections + auth strategies, decide the auth-client/transport boundary (what auth-
client owns vs. what transport keeps), then a plan. Cross-repo, auth-client-first
sequencing as usual.

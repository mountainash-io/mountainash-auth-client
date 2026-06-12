# Unified Profile → Kwargs Emission

> **Status:** PROPOSED (design, not yet implemented) — 2026-06-12

## Problem

There are two parallel engines that turn a profile into SDK kwargs, and they do
the same job with different mechanisms:

1. **Declarative** — `ParameterSpec.driver_key` + `Profile._default_kwargs()`
   (mountainash-settings). Renames fields, unwraps `SecretStr`, applies per-field
   `transform`. Driven entirely by spec metadata.
2. **Imperative** — `AuthStrategy` subclasses + `resolve_auth_strategy()`
   (mountainash-transport `_core/auth`). Eight hand-rolled classes behind an
   `isinstance` ladder keyed on `provider_type`.

The imperative engine won by default even though the declarative one is more
capable. This is the **second occurrence** of the same anti-pattern. The
`2026-06-07-auth-settings-alignment` spec already deleted auth-client's
`dispatch.py` for "reinventing `_default_kwargs()` — manually mapping auth fields
to driver kwargs with per-type handler functions." Transport's `_core/auth` is
that exact reinvention, resurfaced one layer downstream.

### Why the declarative engine wasn't enough

`_default_kwargs()` can only express a **flat 1:1 rename** of one field to one
output key. The auth path needs three things it can't do:

- **Cross-field construction.** HTTP Basic is `base64(user:pass)` folded into one
  `Authorization` header — two fields → one transformed value. Per-field
  `transform` can't combine fields.
- **Object construction.** OAuth1 becomes an authlib `OAuth1Auth(...)` object
  under `kwargs["auth"]`, built from four fields.
- **Target-dependent shape.** The *same* `PasswordAuth` must become an HTTP
  `Authorization: Basic` header or an SSH `password=`/`username=` kwarg — one
  profile, two different outputs. (There is no password→boto path in the current
  strategies; `BasicAuthStrategy` is HTTP-only and `SSHPasswordStrategy` is
  paramiko-only.) `driver_key` encodes exactly one name.

So transport hand-rolled strategies. The cost is the duplication the alignment
spec already rejected once: the auth specs' `driver_key`s are now **dead and
inconsistent** because nothing on the auth path reads them —
`TOKEN_SPEC.driver_key="token"` is ignored (the strategy emits a Bearer header);
`PASSWORD_SPEC.driver_key="user"` doesn't match paramiko's `username`;
`OAUTH1_SPEC` gives `CONSUMER_KEY` a driver_key but its access-token fields none.
If those values were live they'd be bugs. They rot instead.

### Evidence: IAM is pure duplication

```python
# transport IAMCredentialStrategy.apply() — hand-rolled
result["aws_access_key_id"]     = self._access_key_id
result["aws_secret_access_key"] = self._secret_access_key
result["aws_session_token"]     = self._session_token

# auth-client IAM_SPEC — declarative, already says the same thing
ACCESS_KEY_ID     driver_key="aws_access_key_id"
SECRET_ACCESS_KEY driver_key="aws_secret_access_key"  secret=True
SESSION_TOKEN     driver_key="aws_session_token"      secret=True
```

For IAM the entire strategy is `_default_kwargs()` re-implemented, secret-unwrap
included.

## Goals

- One emission primitive for every profile: `profile.emit(target) -> dict`.
- Make the genuinely-transforming auth cases (Basic, Bearer, OAuth1 object, SSH
  key parse) expressible **without** a parallel class hierarchy or a resolver.
- Delete transport's `_core/auth` (strategies + resolver), finishing for
  transport what the alignment spec did for auth-client's `dispatch.py`. This is
  also already mandated by the `connections-single-source-of-truth` principle,
  which lists `_core/auth` as auth-client-owned.
- Make `driver_key` live and correct again, or absent — never dead.
- Keep mountainash-settings **domain-agnostic**. The alignment spec removed
  `auth_modes` from `ProfileSpec` precisely to stop domain coupling leaking into
  the generic base; this design must not re-introduce any.

## Non-Goals

- Token refresh / OAuth lifecycle. That is not emission (see "Refresh is not
  emission" below) and stays in `connections/oauth*/flow.py`.
- Migrating storage profiles' hand-rolled `to_handler_kwargs()` to the new
  primitive. Desirable for full unification but a separate, broader phase
  (Phase 4) — out of this spec's committed scope.
- Changing the profile + auth separation pattern, the registry, or config/secret
  loading.

## Design

### The emission primitive and the three-tier rule

Every profile produces kwargs the same way. How a field reaches the output is
decided by its complexity, lowest tier first:

| Tier | Field shape | Mechanism | Code? |
|------|-------------|-----------|-------|
| 1 | rename (`SECRET_ACCESS_KEY → aws_secret_access_key`) | `ParameterSpec.driver_key` | none |
| 2 | per-field value transform (unwrap, encode) | `ParameterSpec.transform` + `secret` | none |
| 3 | cross-field / object / target-specific (Basic header, authlib object, key parse) | `__adapters__[target]` | a small function |

Tiers 1 and 2 already exist and work. Tier 3 already exists as the **single**
`__adapter__` hook on `Profile` (`profile.py:79`, currently unused) — this design
generalizes it from one adapter to a per-target mapping.

### Target family is an explicit axis owned by the connection

The axis that selects an auth shape is the **SDK family**, not the storage
provider. Today it is smuggled in as `provider_type` (a storage enum) doing
double duty in `resolve_auth_strategy(profile, provider_type=...)`. It becomes a
first-class token:

```python
# auth-client (domain owns the enum; settings only sees a Hashable)
class TargetFamily(str, Enum):
    HTTP = "http"        # httpx
    BOTO = "boto"        # boto3
    PARAMIKO = "paramiko"  # ssh/sftp
```

The **connection** owns its family (`HTTPConnection.family = TargetFamily.HTTP`),
so nothing threads `provider_type` through the call graph. settings never imports
this enum — it stores adapters under an opaque `Hashable` key.

### The one settings change: keyed adapters + target-aware emission

`Profile` gains a target-keyed adapter map (generalizing the existing single
`__adapter__`) and `emit()` / `_default_kwargs()` learn an optional `target`:

```python
# mountainash-settings — generic, no domain knowledge.
# Two DISTINCT adapter signatures — do not collapse them:
Adapter       = t.Callable[["Profile", dict[str, t.Any]], dict[str, t.Any]]  # new: 2-arg compose
LegacyAdapter = t.Callable[["Profile"], dict[str, t.Any]]                    # existing: 1-arg, owns pipeline
_UNSET = object()  # distinguishes "no target passed" from an explicit None target

class Profile(MountainAshBaseSettings):
    __adapters__: t.ClassVar[dict[t.Hashable, Adapter]] = {}
    # Retained AS-IS. The pre-existing single hook is 1-arg and owns the whole
    # output pipeline (it calls _default_kwargs() itself and ignores `base`).
    # It is the all-targets fallback in emit(), but its signature is NOT the
    # same as __adapters__ — they are dispatched separately below.
    __adapter__:  t.ClassVar[LegacyAdapter | None] = None

    def _is_targeted(self) -> bool:
        """True if this profile's emission depends on a target (any dict-scoped
        driver_key or any registered per-target adapter)."""
        if self.__adapters__:
            return True
        return any(isinstance(p.driver_key, dict) for p in self.__spec__.parameters)

    def emit(self, target: t.Hashable = _UNSET, *, base: dict | None = None) -> dict:
        # Fail closed: a targeted profile emitted without an explicit target would
        # silently drop credentials. Require the caller to name the family.
        if target is _UNSET:
            if self._is_targeted():
                raise ValueError(
                    f"{type(self).__name__} is target-scoped; call emit(<TargetFamily>)."
                )
            target = None
        elif target is not None and self._is_targeted() and not self._knows_target(target):
            # Unknown explicit target on a profile that declares target-scoped
            # emission is a programming error, not a silent no-op.
            raise ValueError(
                f"{type(self).__name__} has no emission for target {target!r}; "
                f"known: {sorted(self._known_targets(), key=repr)}."
            )
        base_kwargs = {**(base or {})}
        rename_kwargs = self._default_kwargs(target)
        # Disjointness guard: tier-1 driver_keys and the adapter must own distinct
        # output keys (see Emission safety contract). Overlap is a spec error.
        merged = {**base_kwargs, **rename_kwargs}
        # Dispatch by signature: per-target adapter (2-arg compose) →
        # legacy __adapter__ (1-arg, owns pipeline, ignores merged) → merged.
        adapter = self.__adapters__.get(target)
        if adapter is not None:
            return adapter(self, merged)
        if self.__adapter__ is not None:
            return self.__adapter__(self)
        return merged
```

`_knows_target`/`_known_targets` enumerate `__adapters__` keys ∪ every
`driver_key` dict key — generic diagnostics with no domain knowledge.

`ParameterSpec.driver_key` becomes **target-aware**: a bare `str` means "all
targets" (back-compatible — every current storage profile keeps working); a
`dict[Hashable, str]` scopes the rename per target.

```python
driver_key: str | dict[t.Hashable, str] | None = None
```

`_default_kwargs(target)` resolves each param's key as:
`driver_key` if `str`; `driver_key.get(target)` if `dict` (skip when absent);
skip when `None`.

### The field-leak wrinkle (and why target-scoped driver_key is required, not optional)

If `PasswordAuth` had a bare `driver_key="password"`, the HTTP `base` dict would
carry `password=` *and* the Basic-header adapter would add the header — httpx
would receive a stray `password=` kwarg it rejects. Resolution: scope the
driver_key so the HTTP target emits **nothing** at tier 1 and the adapter is the
sole producer.

```python
PASSWORD_SPEC = ProfileSpec(name="password", provider_type="password", parameters=[
    ParameterSpec("USERNAME", str, tier="core",
                  driver_key={TargetFamily.PARAMIKO: "username"}),
    ParameterSpec("PASSWORD", str, tier="core", secret=True,
                  driver_key={TargetFamily.PARAMIKO: "password"}),
])

def _basic_header(p, kw):
    raw = f"{p.USERNAME}:{p.PASSWORD.get_secret_value()}".encode()
    # Copy-on-write: never mutate a nested container owned by the caller's `base`.
    kw["headers"] = {**kw.get("headers", {}), "Authorization": "Basic " + b64encode(raw).decode()}
    return kw

class PasswordAuthProfile(Profile):
    __spec__ = PASSWORD_SPEC
    __adapters__ = {TargetFamily.HTTP: _basic_header}
```

This is also the bug-fix: today `SSHPasswordStrategy` sets only `password=` and
silently drops the username; the scoped driver_key restores `username`.

### Emission safety contract

`emit()` and adapters obey four rules, each test-enforced:

1. **Copy-on-write, all the way down.** `emit()` shallow-copies the top-level
   dict. Adapters MUST NOT mutate any nested container reached through `base`;
   they rebuild it (`kw["headers"] = {**kw.get("headers", {}), ...}`). This makes
   double-emit safe: `auth.emit(family, base=config_profile.emit(family))` cannot
   corrupt the config dict's nested `headers`/`config` objects. A test emits
   twice from a shared `base` and asserts the first result is unchanged.

2. **Tier-1 / adapter key disjointness.** For a given `(profile, target)`, the
   set of keys produced by `driver_key` renames and the set written by the
   adapter MUST be disjoint. This is **test-enforced, not structurally
   guaranteed** — `emit()` does not police it at runtime; overlap is caught by the
   per-target golden test asserting exact output. An adapter that *intends* to
   replace a tier-1 key must instead use a target-scoped `driver_key` that doesn't
   emit for that target (the Password/HTTP pattern), so the adapter is the sole
   producer. (A future hardening could make `emit()` assert disjointness in debug
   builds; deferred as out of scope.)

3. **Fail-closed targeting.** A target-scoped profile emitted with no explicit
   target raises (the `_UNSET` guard above) rather than silently dropping
   credentials. An unknown explicit target on a target-scoped profile also raises.

4. **No bare driver_key behind an adapter.** A profile that registers any
   `__adapters__` MUST NOT declare a bare (all-target) `driver_key` on any field
   the adapter also handles — otherwise that field leaks into every target's
   `base`. Enforced by a registry-time invariant in
   `spec_invariants_for(AUTH_REGISTRY)`: for each profile with adapters, every
   field's `driver_key` is either `None` or a `dict` (target-scoped), never a
   bare `str`. (Profiles with no adapters may keep bare driver_keys.)

### Connection composition model

Emission is **per leaf connection**, not once against the outermost wrapper. Each
connection that actually constructs an SDK client (`HTTPConnection`,
`S3Connection`, `SSHConnection`) declares its `family` and consumes exactly one
`(config_profile, auth_profile)` pair. Decorators and tunnels compose leaves;
they do not emit on a leaf's behalf.

| Connection | Role | family | Emits? |
|-----------|------|--------|--------|
| `HTTPConnection` | leaf | HTTP | yes — config + static auth |
| `S3Connection` | leaf | BOTO | yes — config + IAM creds |
| `SSHConnection` | leaf | PARAMIKO | yes — config + SSH auth |
| `SFTPConnection` | decorator over SSH | — | no — auth already emitted by the SSH leaf |
| `TunnelledConnection` | decorator | — | no — bastion SSH leaf and inner target leaf each emit independently |
| `OAuth1Connection` / `OAuth2Connection` | decorator over HTTP | — | leaf emits the *current* token; decorator owns refresh (see below) |

- **SFTP-over-SSH:** auth belongs to the SSH transport leaf (PARAMIKO family).
  The SFTP decorator adds no credentials. `create_connection` already builds
  `SSHConnection → SFTPConnection`; only the SSH leaf calls `emit(PARAMIKO)`.
- **Tunnelled:** the bastion is an SSH leaf emitting `bastion_auth.emit(PARAMIKO)`;
  the inner target is a separate leaf built by `inner_factory` emitting its own
  `target_auth.emit(target.family)`. Two independent emissions, never merged —
  exactly the existing two-call structure in `create_tunnelled_connection`.
- **OAuth1/OAuth2 decorators — two modes, cleanly split:**
  - *Rendering the current token* is emission. Given a token already in hand,
    `OAuth2AuthCodeAuthProfile.emit(HTTP)` → a Bearer header and
    `OAuth1AuthProfile.emit(HTTP)` → an authlib `auth=` signer object. These are
    ordinary tier-3 adapters (see the profile table), identical in spirit to
    today's `OAuth1SignedStrategy`.
  - *Acquiring or refreshing the token* is the flow's job, not emission. When the
    decorator runs a flow (`auto_authorize`) or a token refresh, it produces an
    updated token and either (a) for a fixed token, lets the leaf's static
    `emit()` render it, or (b) for a **refreshable** token, installs a live
    `auth=` callable on the leaf that re-reads the current token per request.
    Case (b) is exactly what the dropped `RefreshableAuthStrategy` was groping at;
    it belongs to the flow/decorator, which owns the clock, not to `emit()`.
  - **No double-auth, ever.** Static header and live `auth=` object must never
    coexist on one client. The decorator, when it installs a live `auth=` object,
    first strips any statically-emitted `Authorization` header **and** any `auth=`
    from the leaf kwargs, so the live object is the *sole* credential on a
    refreshable client. The ordering rule is: static `emit()` runs first
    (unconditionally, at leaf build); the decorator then either leaves it (fixed
    token) or replaces it wholesale (refreshable token). There is no merge.

  So the OAuth profiles **do** carry static adapters (for the have-a-token case),
  and the decorator supersedes them with a live `auth=` object only when refresh
  is active. The boundary is "render current value" (emit) vs "obtain/refresh
  value" (flow).

The factory thus calls `emit()` once **per leaf**, with that leaf's family — there
is no single `conn.family` for a composed chain.

### What each auth profile becomes

| Profile | Tier-1 (driver_key) | Tier-3 (adapter) |
|---------|---------------------|------------------|
| `IAMAuthProfile` | `{BOTO: aws_*}` — entire mapping | none (strategy deleted) |
| `TokenAuthProfile` / `JWTAuthProfile` | none | `{HTTP: bearer_header}` |
| `OAuth2AuthCodeAuthProfile` | none | `{HTTP: bearer_from_access_token}` |
| `PasswordAuthProfile` | `{PARAMIKO: username/password}` | `{HTTP: basic_header}` |
| `CertificateAuthProfile` | none | `{PARAMIKO: ssh_key}` (key-path or parse PEM) |
| `KerberosAuthProfile` | none | `{PARAMIKO: gss_flags}` |
| `OAuth1AuthProfile` | none | `{HTTP: oauth1_authlib_object}` |
| `NoAuthProfile` | none | none (empty emit) |

IAM, NoAuth, and any future token-as-kwarg case become **pure data, zero code**.
The transforming cases collapse to one small function each, co-located with the
profile in auth-client.

### Connection factory after: no resolver, no isinstance ladder

```python
# before: two pipelines + resolver + provider_type dispatch
kwargs = profile.to_handler_kwargs()
strategy = resolve_auth_strategy(auth_profile, provider_type=...)
client = leaf_cls(kwargs, strategy)           # leaf calls strategy.apply() in connect()

# after: one polymorphic call, credentials layered onto config
kwargs = config_profile.emit(conn.family)
kwargs = auth_profile.emit(conn.family, base=kwargs) if auth_profile else kwargs
client = conn.build(kwargs)
```

`resolve_auth_strategy` (105 lines), the eight strategy classes (~230 lines), and
all dead `driver_key`s are deleted. `_core/auth/` is removed from transport.

### BOTO credential layering (the assume-role nested shape)

`S3StorageProfile.to_handler_kwargs()` returns one of two shapes: a flat
`boto3.client("s3", **kwargs)` dict, or — when `ROLE_ARN` is set — a nested
`{"base_kwargs": {...}, "role_arn": ..., "session_name": ...}` describing an
assume-role step. Credential layering must target the right level:

- **Flat shape (no ROLE_ARN):** `IAMAuthProfile.emit(BOTO, base=config_kwargs)`
  layers `aws_access_key_id` / `aws_secret_access_key` / `aws_session_token`
  directly into the flat dict. If none are set, the keys are absent and boto's
  default resolver applies (today's behavior).
- **Nested shape (ROLE_ARN set):** IAM credentials are the *source* credentials
  used to call `sts:AssumeRole`, so they layer into `base_kwargs` (the client
  that performs the assume-role), **never** the outer dict. The factory, on
  seeing the nested shape, copies the outer dict before reassigning so it never
  mutates a config dict the profile might cache or reuse:
  `nested = {**nested}; nested["base_kwargs"] = iam.emit(BOTO, base=nested["base_kwargs"])`.
  (`iam.emit` already copy-on-writes its `base` per safety rule 1; the extra outer
  copy extends that guarantee to the **factory-owned** mutation, which the
  emission contract does not otherwise cover.) `role_arn` / `session_name` are
  config, not credentials, and are untouched.
- **Precedence (all three credential keys).** Explicit IAM credentials —
  `aws_access_key_id`, `aws_secret_access_key`, and `aws_session_token` alike —
  override boto's default resolver (matching the old strategy). They do **not**
  override a value of the same key already present in the config `base` unless the
  profile actually supplies that field; `emit()` skips `None`/absent fields, so a
  partially-populated `IAMAuthProfile` overlays only the keys it sets and leaves
  any config-supplied credential keys intact.

This nested case is the one place config and credential shapes interact
non-trivially; the connection factory owns the branch (flat vs nested) **and the
copy-on-write of its own nested reassignment**, not the auth profile, which only
ever produces flat credential keys.

### Refresh is not emission

`RefreshableAuthStrategy` (`refresh()` + `get_headers()`) is a runtime
*lifecycle*, not a static kwarg map — a leak of the OAuth flow into the emission
layer. Emission is a pure function of the profile; anything with a clock or a
network call stays in `connections/oauth2/flow.py`. This protocol is dropped from
the emission layer entirely (it has no consumers there today).

## Ownership and placement

- **mountainash-settings** — generalize `__adapter__` → `__adapters__`; make
  `driver_key` target-aware; add `emit(target)`. Stays domain-agnostic (the
  target key is an opaque `Hashable`). This is the only change to the substrate.
- **mountainash-auth-client** — owns `TargetFamily`; auth profiles gain corrected
  target-scoped `driver_key`s and ~6 small adapters; consumes settings.
- **mountainash-transport** — connections declare `family`; factory calls
  `emit()`; `_core/auth/` deleted; storage backends unchanged.

This matches the `connections-single-source-of-truth` principle: `_core/auth`
moves to auth-client (as adapters next to the profiles), not copied.

## Phasing (independently shippable sub-projects)

1. **Settings substrate** — `__adapters__`, target-aware `driver_key`,
   `emit(target)`. Profile *output* is unchanged for every existing bare-string
   spec, but the substrate's **API surface changes**: `ParameterSpec.driver_key`
   widens `str | None → str | dict[Hashable, str] | None` and `_default_kwargs`
   gains a `target` parameter. Any consumer that introspects or serializes
   `driver_key` as `str | None` must be checked (Phase 1 adds compat tests for
   spec serialization, `spec_invariants_for`, and registry introspection). Ships
   alone, green, behind output-equivalence tests.
2. **Auth-client adapters** — `TargetFamily`; per-profile adapters + corrected
   driver_keys; `_default_kwargs`/`emit` covered by tests asserting exact output
   per target. auth-client still exports the same profile classes.
3. **Transport wiring + deletion** — connections gain `family`; factory uses
   `emit()`; delete `_core/auth`, `resolve_auth_strategy`, strategy classes;
   update connection tests. This is the phase that removes the duplication.
4. **(Later, optional)** — migrate storage profiles' hand-rolled
   `to_handler_kwargs()` into `__adapters__[BOTO/HTTP/...]` so config and
   credential emission share one primitive end-to-end.

## Backward compatibility

- **Output, not surface.** Bare-string `driver_key` keeps meaning "all targets" →
  every existing profile's `_default_kwargs()` *output* is byte-for-byte
  unchanged. The *type signature* of `driver_key` and `_default_kwargs` does
  change (see Phase 1) — this is an additive API-surface change, not an
  output-behavior change, and the distinction is tested explicitly.
- `__adapter__` (singular) is retained as the all-targets fallback in `emit()`,
  so any profile already using it keeps working.
- For an untargeted profile (no adapters, no dict driver_keys), `emit()` with no
  target argument reproduces today's `_default_kwargs()`. Targeted profiles fail
  closed (they require an explicit family) rather than silently degrade.
- Phases 2–3 are internal to the auth/connection layer; the public profile
  classes and the `create_connection(profile, auth_profile)` signature are
  unchanged.

## Testing strategy

- **Settings (Phase 1):** unit tests for `emit()` precedence (per-target adapter
  > `__adapter__` > none), target-scoped vs bare `driver_key`, and that
  `target=None` reproduces current `_default_kwargs()` output byte-for-byte.
- **Auth-client (Phase 2):** per-profile, per-target golden tests asserting exact
  emitted kwargs — e.g. `PasswordAuthProfile.emit(HTTP)` yields only the Basic
  header (no stray `password=`); `.emit(PARAMIKO)` yields `username`+`password`;
  `IAMAuthProfile.emit(BOTO)` matches the old strategy output. Secret values must
  appear unwrapped only inside the emitted dict, never logged.
- **Transport (Phase 3):** connection tests assert the merged config+credential
  kwargs reaching each SDK client are identical to pre-refactor output (golden
  comparison captured before deletion). Parametrize across HTTP/BOTO/PARAMIKO.
  Include the S3 `ROLE_ARN` nested-shape case (credentials land in `base_kwargs`,
  outer `role_arn`/`session_name` untouched) and a per-leaf emission test for the
  SFTP-over-SSH and tunnelled chains (each leaf emits with its own family).
- **Safety contract (Phase 1–2):** (a) double-emit from a shared `base` leaves the
  first result's nested `headers`/`config` unmutated; (b) a profile declaring both
  a bare `driver_key` and an adapter fails `spec_invariants_for`; (c) a
  target-scoped profile `.emit()` with no target raises, and with an unknown
  target raises; (d) a constructed overlap of tier-1 key and adapter key is caught
  by the per-target golden test.
- No count-based assertions (per repo test-design rule); assert membership and
  exact key/value shape.

## Resolved by this revision (was: open questions)

These were raised in adversarial review and are now specified in the body:

- **Adapter mutation / double-emit safety** → Emission safety contract rule 1
  (copy-on-write all the way down; tested by a double-emit-from-shared-base test).
- **Tier-1 / adapter key collision** → rule 2 (disjointness, golden-test enforced).
- **`target=None` silently dropping credentials** → rule 3 + the `_UNSET`
  fail-closed guard in `emit()`.
- **Bare `driver_key` leaking behind an adapter** → rule 4 (registry-time
  invariant: adapter-bearing profiles may not declare bare driver_keys).
- **S3 `ROLE_ARN` nested-shape layering** → "BOTO credential layering" section
  (credentials target `base_kwargs`, factory owns the flat/nested branch).
- **Decorator/tunnelled family ambiguity** → "Connection composition model"
  (emission is per leaf; SFTP/tunnel/OAuth decorators do not emit on a leaf's
  behalf; OAuth refresh is flow-owned, not emission).
- **authlib/paramiko import placement** → adapters import optional deps **inside
  the adapter function** via `connections/_optional.py` (`require_authlib`, new
  `require_paramiko`), so importing a profile module never imports an optional
  dep and the extras-missing error fires only when that adapter runs.
- **Phase 1 "no observable change" overclaim** → narrowed to *output*-equivalence;
  the `driver_key` type/`_default_kwargs` signature change is an acknowledged
  additive API-surface change with its own compat tests.

## Remaining open questions

- **Refreshable-token rendering mechanism (Phase 3 detail).** For a refreshable
  OAuth2 token the decorator installs a live `auth=` callable rather than a static
  header. The exact object (httpx `auth=` hook vs. per-request header recompute)
  is a Phase-3 implementation choice, not settled here. The static-token path is
  fully specified; the refresh path defers to the existing flow layer.
- **Is `provider_type` still needed on auth ProfileSpecs?** After the resolver is
  gone it is only an identity label. Keep it (the registry keys on it); just stop
  dispatching on it. Low risk; noted for the plan.
- **`require_paramiko` placement.** `connections/_optional.py` currently exposes
  `require_authlib`; a sibling `require_paramiko` is needed. Trivial, but it adds
  a paramiko awareness to auth-client's optional layer — confirm the `[sftp]`
  extra name matches transport's so the error message is consistent cross-repo.

## Out of scope

- Storage-profile `to_handler_kwargs()` unification (Phase 4).
- OAuth token refresh / flow lifecycle.
- Any change to `mountainash-data` / `mountainash-wearables` emission (separate
  downstream follow-up, mirroring the alignment spec's downstream note).

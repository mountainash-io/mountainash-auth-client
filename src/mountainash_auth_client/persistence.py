"""OAuth token persistence contract + addressing helper.

Single home for the §7.4 storage contract used by both the flows and the
lifecycle managers: WHERE tokens live (the named store, the "oauth" namespace)
and the typed identity an auth profile must carry.
"""
from __future__ import annotations

import typing as t

from mountainash_secrets import ClearableStore, NamespacedStore

if t.TYPE_CHECKING:
    from mountainash_secrets import SecretStoreResolver

__all__ = ["PersistableAuthProfile", "token_store"]


@t.runtime_checkable
class PersistableAuthProfile(t.Protocol):
    """An auth profile that knows WHERE its tokens persist and under WHAT key.

    `SETTINGS_SOURCE_SECRETS_PROVIDER` names the store registered in the
    consumer's SecretStoreResolver. `persist_key()` returns a per-(provider,
    account) key, unique within that store, composed of `[a-z0-9_]+` segments
    joined by "." (no "/", "\\", "..", empty segments, or a leading "oauth"/
    "cred" segment). auth-client defines the contract; consumers supply values.
    """

    SETTINGS_SOURCE_SECRETS_PROVIDER: str

    def persist_key(self) -> str: ...


def token_store(
    resolver: SecretStoreResolver,
    auth_profile: PersistableAuthProfile,
) -> NamespacedStore:
    """Resolve the OAuth token store for an auth profile.

    Resolves the named store as a ClearableStore (raising CapabilityError if it
    cannot clear), then namespaces it under "oauth". Every OAuth-token read or
    write — flow OR manager — goes through this, so the namespace/capability
    decision lives in one place. Mutation *ordering* is the caller's job, via
    `transaction(key)` (see the design spec §5.1).
    """
    store = resolver.resolve_as(auth_profile.SETTINGS_SOURCE_SECRETS_PROVIDER, ClearableStore)
    return NamespacedStore(store, "oauth")

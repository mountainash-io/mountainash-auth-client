"""OAuth token persistence contract + addressing helper.

Single home for the §7.4 storage contract used by both the flows and the
lifecycle managers: WHERE tokens live (the selected store, the "oauth" namespace)
and the typed identity an auth profile must carry.
"""
from __future__ import annotations

import typing as t

from mountainash_settings.secrets import ClearableSecretStore, NamespacedSecretStore, SecretCapabilityError

if t.TYPE_CHECKING:
    from pydantic import SecretStr

__all__ = ["PersistableAuthProfile", "OAuth1CredentialProfile", "OAuth2CredentialProfile", "token_store"]


@t.runtime_checkable
class PersistableAuthProfile(t.Protocol):
    """An auth profile that knows under WHAT key its tokens persist.

    `persist_key()` returns a per-(provider, account) key, unique within the
    consumer-selected store, composed of `[a-z0-9_]+` segments
    joined by "." (no "/", "\\", "..", empty segments, or a leading "oauth"/
    "cred" segment). auth-client defines the contract; consumers supply values.
    """

    def persist_key(self) -> str: ...


class OAuth2CredentialProfile(PersistableAuthProfile, t.Protocol):
    """Credentials needed for OAuth2 authorization and authenticated refresh."""

    @property
    def CLIENT_ID(self) -> str | None: ...

    @property
    def CLIENT_SECRET(self) -> SecretStr | None: ...

    @property
    def SCOPE(self) -> str | None: ...


class OAuth1CredentialProfile(PersistableAuthProfile, t.Protocol):
    """Credentials needed for OAuth1 authorization and signing."""

    @property
    def CONSUMER_KEY(self) -> str: ...

    @property
    def CONSUMER_SECRET(self) -> SecretStr: ...


def token_store(store: ClearableSecretStore) -> NamespacedSecretStore:
    """Namespace the consumer-selected OAuth token store.

    Requires a ClearableSecretStore (raising SecretCapabilityError if it
    cannot clear), then namespaces it under "oauth". Every OAuth-token read or
    write — flow OR manager — goes through this, so the namespace/capability
    decision lives in one place. Mutation *ordering* is the caller's job, via
    `transaction(key)` (see the design spec §5.1).
    """
    if not isinstance(store, ClearableSecretStore):
        raise SecretCapabilityError("OAuth persistence requires a clearable token store")
    return NamespacedSecretStore(store, "oauth")

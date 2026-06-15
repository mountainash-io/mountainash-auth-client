from __future__ import annotations

import pytest

from mountainash_auth_client.persistence import PersistableAuthProfile, token_store
from mountainash_secrets import (
    CapabilityError,
    InMemoryStore,
    NamespacedStore,
    RegistryResolver,
)


class _Auth:
    SETTINGS_SOURCE_SECRETS_PROVIDER = "mem"

    def persist_key(self) -> str:
        return "garmin.default"


class _ReadOnly:
    """Satisfies SecretReader (get only) — NOT ClearableStore."""

    def get(self, key):
        return None


def test_satisfies_persistable_protocol():
    assert isinstance(_Auth(), PersistableAuthProfile)


def test_token_store_namespaces_under_oauth():
    store = InMemoryStore()
    resolver = RegistryResolver({"mem": store})
    ts = token_store(resolver, _Auth())
    assert isinstance(ts, NamespacedStore)
    ts.set("k", {"v": 1})
    # The raw underlying key carries the dot-prefixed "oauth" namespace.
    assert store.get("oauth.k") == {"v": 1}


def test_token_store_capability_error_for_read_only_store():
    resolver = RegistryResolver({"mem": _ReadOnly()})
    with pytest.raises(CapabilityError):
        token_store(resolver, _Auth())

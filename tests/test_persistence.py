from __future__ import annotations

import pytest

from mountainash_auth_client.oauth.persistence import PersistableAuthProfile, token_store
from mountainash_settings.secrets import (
    SecretCapabilityError,
    MemorySecretStore,
)


class _Auth:
    def persist_key(self) -> str:
        return "garmin.default"


class _ReadOnly:
    """Satisfies SecretReader (get only) — NOT ClearableSecretStore."""

    def get(self, key):
        return None

    def __repr__(self):
        raise AssertionError("must not render store")


def test_satisfies_persistable_protocol():
    assert isinstance(_Auth(), PersistableAuthProfile)


def test_token_store_uses_selected_instance_and_one_namespace():
    first, second = MemorySecretStore(), MemorySecretStore()
    token_store(first).set("garmin.default", {"oauth_token": "first"})
    assert first.get("oauth.garmin.default") == {"oauth_token": "first"}
    assert first.get("oauth.oauth.garmin.default") is None
    assert second.get("oauth.garmin.default") is None


def test_read_only_store_is_rejected_without_repr():
    with pytest.raises(SecretCapabilityError):
        token_store(_ReadOnly())

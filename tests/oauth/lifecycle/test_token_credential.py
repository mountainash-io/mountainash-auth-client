from __future__ import annotations

from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential


def test_from_record_maps_store_keys():
    cred = TokenCredential.from_record(
        {"access_token": "at", "token_expires_at": 1900000000, "refresh_token": "rt"}
    )
    assert cred.access_token == "at"
    assert cred.expires_at == 1900000000
    assert cred.refresh_token == "rt"
    assert cred.token_type == "Bearer"   # synthesized, not stored


def test_from_record_tolerates_missing_optionals():
    cred = TokenCredential.from_record({"access_token": "at"})
    assert cred.expires_at is None and cred.refresh_token is None


def test_is_frozen():
    import dataclasses
    import pytest
    cred = TokenCredential.from_record({"access_token": "at"})
    with pytest.raises(dataclasses.FrozenInstanceError):
        cred.access_token = "x"

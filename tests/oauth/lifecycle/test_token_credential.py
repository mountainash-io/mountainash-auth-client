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


def test_credential_preserves_grant_and_owns_nested_metadata():
    from mountainash_auth_client.oauth.records import read_oauth2_record, token_record

    record = {
        "access_token": "accepted", "client_id": "issued", "scope": "",
        "registration": {"subject": "account"},
        "session_metadata": {"claims": {"nonce": "private-nonce"}},
    }
    tokens = read_oauth2_record(record)
    stored = token_record(tokens)
    cred = TokenCredential.from_record(stored)
    assert cred.client_id == "issued"
    assert cred.scope == ""
    assert cred.registration == {"subject": "account"}
    assert cred.session_metadata == {"claims": {"nonce": "private-nonce"}}
    cred.session_metadata["claims"] = {"nonce": "changed"}
    assert stored["session_metadata"] == {"claims": {"nonce": "private-nonce"}}
    assert record["session_metadata"] == {"claims": {"nonce": "private-nonce"}}
    assert "private-nonce" not in repr(cred)

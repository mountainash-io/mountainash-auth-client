"""Harmless installed smoke; never execute the static fixtures' invalid calls."""
from __future__ import annotations

from typing import assert_type

import mountainash_auth_client as auth
from pydantic import SecretStr


def main() -> None:
    # Resolve every root export, including the lazy operations, without extras.
    for name in auth.__all__:
        getattr(auth, name)
    profile = auth.PasswordAuthProfile(USERNAME="alice", PASSWORD="example")
    assert isinstance(profile.PASSWORD, SecretStr)
    assert profile.emit(auth.TargetFamily.HTTP) == {"headers": {"Authorization": "Basic YWxpY2U6ZXhhbXBsZQ=="}}
    token = auth.TokenAuthProfile(TOKEN="example")
    assert token.emit(auth.TargetFamily.HTTP) == {"headers": {"Authorization": "Bearer example"}}
    provider = auth.OAuth2ProviderProfile(
        NAME="example", AUTHORIZE_URL="https://example.invalid/authorize",
        TOKEN_URL="https://example.invalid/token", BASE_URL="https://example.invalid/api",
    )
    assert provider.emit(auth.TargetFamily.HTTP) == {"base_url": "https://example.invalid/api"}
    assert_type(provider.USE_PKCE, bool)
    assert provider.USE_PKCE is False
    credential = auth.TokenCredential.from_record({
        "access_token": "example", "token_expires_at": 123, "client_id": "issued", "scope": "openid",
        "registration": {"subject": "account"}, "session_metadata": {"claims": {"nonce": "accepted"}},
    })
    assert credential.access_token == "example"
    assert credential.expires_at == 123
    assert credential.refresh_token is None
    assert credential.client_id == "issued"
    assert credential.scope == "openid"
    assert credential.registration == {"subject": "account"}
    assert credential.session_metadata == {"claims": {"nonce": "accepted"}}
    print("Installed exports, profile construction/emission and token record smoke passed")


if __name__ == "__main__":
    main()

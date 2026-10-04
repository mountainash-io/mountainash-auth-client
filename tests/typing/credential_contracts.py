"""Static credential refinements and key-specific token result contracts."""
from __future__ import annotations

from typing import TYPE_CHECKING, assert_type

from pydantic import SecretStr

from mountainash_auth_client import OAuth1AuthProfile, OAuth2AuthProfile, OAuth1TokenManager, OAuth2TokenManager
from mountainash_auth_client.oauth.records import OAuth1Tokens, OAuth2Tokens

if TYPE_CHECKING:
    from mountainash_settings.secrets import ClearableSecretStore

    from mountainash_auth_client import OAuth1Flow, OAuthFlow, OAuth1ProviderProfile, OAuth2ProviderProfile
    from mountainash_auth_client.oauth.persistence import (
        OAuth1CredentialProfile,
        OAuth2CredentialProfile,
        PersistableAuthProfile,
    )


class KeyOnly:
    def persist_key(self) -> str:
        return "example.account"


class Credentials1(OAuth1AuthProfile):
    def persist_key(self) -> str:
        return "example.account"


class Credentials2(OAuth2AuthProfile):
    def persist_key(self) -> str:
        return "example.account"


class PlainSecret(KeyOnly):
    CLIENT_ID: str = "client"
    CLIENT_SECRET: str = "wrong-secret-type"
    SCOPE: str | None = None


def structural_credentials(
    one: OAuth1ProviderProfile, two: OAuth2ProviderProfile, store: ClearableSecretStore,
) -> None:
    key: PersistableAuthProfile = KeyOnly()
    first: OAuth1CredentialProfile = Credentials1(CONSUMER_KEY="client", CONSUMER_SECRET=SecretStr("secret"))
    second: OAuth2CredentialProfile = Credentials2(CLIENT_ID="client")
    assert_type(OAuth1TokenManager(one, first, token_store=store), OAuth1TokenManager)
    assert_type(OAuth2TokenManager(two, second, token_store=store), OAuth2TokenManager)
    OAuth1TokenManager(one, key, token_store=store)  # type: ignore[arg-type]
    OAuth2TokenManager(two, PlainSecret(), token_store=store)  # type: ignore[arg-type]


def resolvers(
    oauth1: OAuth1Flow, oauth2: OAuthFlow, key: PersistableAuthProfile,
    credentials1: OAuth1CredentialProfile, credentials2: OAuth2CredentialProfile,
    interactive: bool,
) -> None:
    assert_type(oauth1.resolve_token_pair(key), tuple[str, str])
    assert_type(oauth2.resolve_access_token(key, auto_authorize=False), str)
    assert_type(oauth1.resolve_token_pair(credentials1, auto_authorize=True), tuple[str, str])
    assert_type(oauth2.resolve_access_token(credentials2, auto_authorize=True), str)
    assert_type(oauth1.resolve_token_pair(credentials1, auto_authorize=interactive), tuple[str, str])
    assert_type(oauth2.resolve_access_token(credentials2, auto_authorize=interactive), str)
    oauth1.resolve_token_pair(key, auto_authorize=True)  # type: ignore[call-overload]
    oauth2.resolve_access_token(key, auto_authorize=interactive)  # type: ignore[call-overload]


def results(oauth1: OAuth1Flow, oauth2: OAuthFlow) -> None:
    pair = oauth1.exchange_verifier("key", "secret", "token", "token-secret", "verifier")
    assert_type(pair, OAuth1Tokens)
    assert_type(pair["oauth_token_secret"], str)
    token = oauth2.exchange_code("code", "https://app.example/callback")
    assert_type(token, OAuth2Tokens)
    assert_type(token["access_token"], str)
    assert_type(token.get("token_expires_at"), int | None)
    assert_type(token.get("refresh_token"), str | None)
    assert_type(oauth2.authorize("client-id", None), OAuth2Tokens)
    assert_type(oauth2.refresh("refresh"), OAuth2Tokens)
    token["access_token"] = False  # type: ignore[typeddict-item]

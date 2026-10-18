"""Regressions for authorization identity and untrusted persisted JSON."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from mountainash_settings.secrets import MemorySecretStore

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential
from mountainash_auth_client.oauth.lifecycle.oauth2 import OAuth2TokenManager
from mountainash_auth_client.oauth.oauth1.flow import OAuth1Flow
from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.oauth.providers.oauth1 import OAuth1ProviderProfile
from mountainash_auth_client.oauth.providers.oauth2 import OAuth2ProviderProfile


class KeyOnly:
    def persist_key(self) -> str:
        return "provider.account"


class Credentials(KeyOnly):
    CLIENT_ID: str | None = "actual-client-id"
    CLIENT_SECRET = None
    SCOPE = None


def provider(method="none"):
    return OAuth2ProviderProfile(
        NAME="provider", AUTHORIZE_URL="https://provider.example/authorize",
        TOKEN_URL="https://provider.example/token", BASE_URL="https://provider.example",
        TOKEN_ENDPOINT_AUTH_METHOD=method,
        TOKEN_REQUEST_HEADERS={"X-Provider": "required"},
    )


class Captured(Exception):
    pass


class CaptureCallback:
    redirect_uri = "https://app.example/callback"
    url = ""

    def obtain_callback(self, url: str) -> dict[str, str]:
        self.url = url
        raise Captured


@pytest.mark.parametrize("owner", ["manager", "flow"])
def test_none_auth_preserves_authorization_identity(owner):
    callback = CaptureCallback()
    store = MemorySecretStore()
    with pytest.raises(Captured):
        if owner == "manager":
            OAuth2TokenManager(provider(), Credentials(), token_store=store,
                               callback_server=lambda: callback).authorize()
        else:
            OAuthFlow(provider(), token_store=store, callback_server=lambda: callback).resolve_access_token(
                Credentials(), auto_authorize=True,
            )
    assert parse_qs(urlsplit(callback.url).query)["client_id"] == ["actual-client-id"]


@pytest.mark.parametrize("owner", ["manager", "flow", "url", "authorize"])
@pytest.mark.parametrize("client_id", [None, ""])
def test_missing_identity_rejected_before_callback_construction(owner, client_id):
    auth = Credentials()
    auth.CLIENT_ID = client_id

    def forbidden():
        pytest.fail("callback constructed without a client ID")

    flow = OAuthFlow(provider(), token_store=MemorySecretStore(), callback_server=forbidden)
    with pytest.raises(ValueError, match="non-empty client_id"):
        if owner == "manager":
            OAuth2TokenManager(provider(), auth, token_store=MemorySecretStore(),
                               callback_server=forbidden).authorize()
        elif owner == "flow":
            flow.resolve_access_token(auth, auto_authorize=True)
        elif owner == "url":
            flow.build_authorize_url(client_id, "https://app.example/callback")
        else:
            flow.authorize(client_id, None)


@pytest.mark.parametrize("method", ["none", "client_secret_post", "client_secret_basic"])
def test_authorization_token_endpoint_auth_contract(monkeypatch, method):
    requests = []

    def endpoint(request):
        requests.append(request)
        return httpx.Response(200, json={"access_token": "issued"})

    class Callback:
        redirect_uri = "https://app.example/callback"

        def obtain_callback(self, url):
            query = parse_qs(urlsplit(url).query)
            assert query["client_id"] == ["actual-client-id"]
            return {"code": "code", "state": query["state"][0]}

    client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda: client(transport=httpx.MockTransport(endpoint)))
    result = OAuthFlow(provider(method), callback_server=Callback).authorize(
        "actual-client-id", None if method == "none" else "secret",
    )
    assert result["access_token"] == "issued"
    assert result["client_id"] == "actual-client-id"
    assert len(requests) == 1
    request = requests[0]
    body = parse_qs(request.content.decode(), keep_blank_values=True)
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert request.headers["x-provider"] == "required"
    assert body == {
        "grant_type": ["authorization_code"], "code": ["code"],
        "redirect_uri": ["https://app.example/callback"],
        **({"client_id": ["actual-client-id"]} if method != "client_secret_basic" else {}),
        **({"client_secret": ["secret"]} if method == "client_secret_post" else {}),
    }
    if method == "client_secret_basic":
        assert request.headers["authorization"] == "Basic YWN0dWFsLWNsaWVudC1pZDpzZWNyZXQ="
    else:
        assert "authorization" not in request.headers


@pytest.mark.parametrize("field,bad", [
    (field, bad) for field in ("access_token", "refresh_token")
    for bad in (False, 0, ["secret-marker"])
] + [("token_expires_at", True), ("token_expires_at", "secret-marker")])
@pytest.mark.parametrize("owner", ["flow", "credential", "refresh"])
def test_malformed_oauth2_record_rejected_without_mutation(owner, field, bad, monkeypatch):
    record = {"access_token": "secret-access", "refresh_token": "secret-refresh", "token_expires_at": 1}
    record[field] = bad
    store = MemorySecretStore()
    store.set("oauth.provider.account", record)

    def forbidden(*args, **kwargs):
        pytest.fail("malformed record reached the token endpoint")

    monkeypatch.setattr(httpx, "Client", forbidden)
    with pytest.raises(ValueError) as caught:
        if owner == "credential":
            TokenCredential.from_record(record)
        elif owner == "refresh":
            OAuthFlow(provider(), token_store=store).force_refresh(KeyOnly())
        else:
            OAuthFlow(provider(), token_store=store).resolve_access_token(KeyOnly())
    assert str(caught.value) == f"Invalid OAuth token record field: {field}"
    assert store.get("oauth.provider.account") == record
    assert not store.is_cleared("oauth.provider.account")


@pytest.mark.parametrize("oauth", [1, 2])
def test_key_only_cached_resolution_and_missing_record(oauth):
    store = MemorySecretStore()
    if oauth == 2:
        resolve = OAuthFlow(provider(), token_store=store).resolve_access_token
        record = {"access_token": "cached"}
        expected = "cached"
        assert TokenCredential.from_record(record) == TokenCredential("cached")
    else:
        resolve = oauth1_flow(store).resolve_token_pair
        record = {"oauth_token": "cached", "oauth_token_secret": "secret"}
        expected = ("cached", "secret")
    with pytest.raises(AuthorizationRequired):
        resolve(KeyOnly())
    store.set("oauth.provider.account", record)
    assert resolve(KeyOnly()) == expected
    assert store.get("oauth.provider.account") == record


def oauth1_flow(store):
    return OAuth1Flow(OAuth1ProviderProfile(
        NAME="provider", REQUEST_TOKEN_URL="https://provider.example/request",
        AUTHORIZE_URL="https://provider.example/authorize",
        ACCESS_TOKEN_URL="https://provider.example/token", BASE_URL="https://provider.example",
    ), token_store=store)


@pytest.mark.parametrize("field", ["oauth_token", "oauth_token_secret"])
@pytest.mark.parametrize("bad", [False, 0, ["secret-marker"]])
def test_malformed_oauth1_pair_rejected_without_mutation(field, bad):
    record = {"oauth_token": "secret-access", "oauth_token_secret": "secret-signing"}
    record[field] = bad
    store = MemorySecretStore()
    store.set("oauth.provider.account", record)
    with pytest.raises(ValueError) as caught:
        oauth1_flow(store).resolve_token_pair(KeyOnly())
    assert str(caught.value) == f"Invalid OAuth token record field: {field}"
    assert store.get("oauth.provider.account") == record
    assert not store.is_cleared("oauth.provider.account")

"""Secrets must not leak through repr(), exception text/attrs, or settings reprs."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from mountainash_auth_client.errors import TokenExchangeError, TokenRefreshError
from mountainash_auth_client.oauth.lifecycle.credential import TokenCredential
from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.oauth.providers.oauth2 import OAuth2ProviderProfile
from mountainash_auth_client.schemas.service_account import SERVICE_ACCOUNT_SPEC, ServiceAccountAuthProfile

SENTINEL = "SENTINEL-SECRET-9f3a"


def _flow():
    return OAuthFlow(OAuth2ProviderProfile(
        NAME="p", AUTHORIZE_URL="https://a.example/authorize",
        TOKEN_URL="https://a.example/token", BASE_URL="https://api.example",
    ))


def _assert_clean(exc):
    blob = repr(exc) + str(exc) + repr(exc.__dict__)
    assert SENTINEL not in blob


def test_token_credential_repr_hides_tokens():
    cred = TokenCredential(access_token=SENTINEL, refresh_token=SENTINEL + "r")
    assert SENTINEL not in repr(cred) and SENTINEL not in str(cred)


def test_service_account_info_is_secret():
    spec = next(p for p in SERVICE_ACCOUNT_SPEC.parameters if p.name == "INFO")
    assert spec.secret is True
    profile = ServiceAccountAuthProfile(INFO='{"private_key": "%s"}' % SENTINEL)
    assert SENTINEL not in repr(profile) and SENTINEL not in str(profile)


def _http_error(text):
    resp = MagicMock(status_code=400, text=text)
    return httpx.HTTPStatusError("e", request=MagicMock(), response=resp)


@pytest.mark.parametrize("op", ["exchange", "refresh"])
def test_http_error_body_keeps_only_error_fields(op):
    body = '{"error":"invalid_grant","error_description":"expired","refresh_token":"%s","echo":"%s"}' % (SENTINEL, SENTINEL)
    with patch("httpx.Client") as Client:
        Client.return_value.__enter__.return_value.post.side_effect = _http_error(body)
        with pytest.raises((TokenExchangeError, TokenRefreshError)) as caught:
            if op == "exchange":
                _flow().exchange_code(code=SENTINEL, redirect_uri="http://l/cb", client_id="c", client_secret=SENTINEL)
            else:
                _flow().refresh(refresh_token=SENTINEL, client_id="c", client_secret=SENTINEL)
    _assert_clean(caught.value)
    assert caught.value.error_code == "invalid_grant"
    assert "expired" in caught.value.body


@pytest.mark.parametrize("op", ["exchange", "refresh"])
@pytest.mark.parametrize("kind", ["invalid_json", "missing_access_token"])
def test_malformed_success_bodies_do_not_echo_payload(op, kind):
    resp = MagicMock(status_code=200, text="not json " + SENTINEL)
    if kind == "invalid_json":
        resp.json.side_effect = ValueError("bad")
    else:
        resp.json.return_value = {"refresh_token": SENTINEL, "id_token": SENTINEL}
    with patch("httpx.Client") as Client:
        Client.return_value.__enter__.return_value.post.return_value = resp
        with pytest.raises((TokenExchangeError, TokenRefreshError)) as caught:
            if op == "exchange":
                _flow().exchange_code(code="c", redirect_uri="http://l/cb", client_id="c", client_secret="s")
            else:
                _flow().refresh(refresh_token="r", client_id="c", client_secret="s")
    _assert_clean(caught.value)


def test_oauth1_endpoint_error_body_keeps_only_error_fields():
    from mountainash_auth_client.oauth.oauth1.flow import _raise_token_endpoint_error

    resp = httpx.Response(401, json={"error": "denied", "oauth_token_secret": SENTINEL})
    with pytest.raises(TokenExchangeError) as caught:
        _raise_token_endpoint_error(resp, url="https://a.example/t")
    _assert_clean(caught.value)
    assert caught.value.error_code == "denied"

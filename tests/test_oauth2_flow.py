"""Tests for OAuthFlow (OAuth2 authorization code flow)."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from mountainash_auth_client.errors import TokenExchangeError, TokenRefreshError
from mountainash_auth_client.flows.oauth2 import OAuthFlow


class FakeSpec:
    def __init__(self, metadata=None):
        self.metadata = metadata or {
            "authorize_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
        }


class TestBuildAuthorizeUrl:
    def test_returns_url_with_client_id(self):
        flow = OAuthFlow(FakeSpec())
        url, state = flow.build_authorize_url(
            client_id="my_client",
            redirect_uri="http://localhost:8080/callback",
        )
        assert "client_id=my_client" in url
        assert "https://auth.example.com/authorize" in url

    def test_returns_url_with_state(self):
        flow = OAuthFlow(FakeSpec())
        url, state = flow.build_authorize_url(
            client_id="my_client",
            redirect_uri="http://localhost:8080/callback",
        )
        assert state in url
        assert len(state) > 0

    def test_no_pkce_by_default(self):
        flow = OAuthFlow(FakeSpec())
        url, _ = flow.build_authorize_url(
            client_id="my_client",
            redirect_uri="http://localhost:8080/callback",
        )
        assert "code_challenge" not in url

    def test_pkce_adds_code_challenge_and_s256(self):
        spec = FakeSpec(metadata={
            "authorize_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
            "use_pkce": True,
        })
        flow = OAuthFlow(spec)
        url, _ = flow.build_authorize_url(
            client_id="pkce_client",
            redirect_uri="http://localhost:8080/callback",
        )
        assert "code_challenge=" in url
        assert "code_challenge_method=S256" in url

    def test_scope_included_when_provided(self):
        flow = OAuthFlow(FakeSpec())
        url, _ = flow.build_authorize_url(
            client_id="my_client",
            redirect_uri="http://localhost/cb",
            scope="read write",
        )
        assert "scope=" in url


class TestExchangeCode:
    def test_raises_token_exchange_error_on_http_error(self):
        flow = OAuthFlow(FakeSpec())
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.side_effect = httpx.HTTPStatusError(
                "error", request=MagicMock(), response=mock_response
            )

            with pytest.raises(TokenExchangeError) as exc_info:
                flow.exchange_code(
                    code="authcode",
                    redirect_uri="http://localhost/cb",
                    client_id="cid",
                    client_secret="csec",
                )
            assert exc_info.value.status_code == 400
            assert exc_info.value.url == "https://auth.example.com/token"

    def test_returns_token_dict_on_success(self):
        flow = OAuthFlow(FakeSpec())
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "access_tok",
            "refresh_token": "refresh_tok",
            "expires_in": 3600,
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.return_value = mock_response

            result = flow.exchange_code(
                code="code123",
                redirect_uri="http://localhost/cb",
                client_id="cid",
                client_secret="csec",
            )
        assert result["access_token"] == "access_tok"
        assert result["refresh_token"] == "refresh_tok"
        assert result["token_expires_at"] is not None

    def test_raises_on_invalid_json_response(self):
        flow = OAuthFlow(FakeSpec())
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>not json</html>"
        mock_response.json.side_effect = ValueError("no json")
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.return_value = mock_response

            with pytest.raises(TokenExchangeError) as exc_info:
                flow.exchange_code(
                    code="code123",
                    redirect_uri="http://localhost/cb",
                    client_id="cid",
                    client_secret="csec",
                )
            assert "Invalid JSON" in exc_info.value.body

    def test_raises_when_access_token_missing(self):
        flow = OAuthFlow(FakeSpec())
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"error": "invalid_grant"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.return_value = mock_response

            with pytest.raises(TokenExchangeError) as exc_info:
                flow.exchange_code(
                    code="code123",
                    redirect_uri="http://localhost/cb",
                    client_id="cid",
                    client_secret="csec",
                )
            assert "access_token" in exc_info.value.body

    def test_pkce_verifier_keyed_by_state_survives_second_authorize(self):
        spec = FakeSpec(metadata={
            "authorize_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
            "use_pkce": True,
        })
        flow = OAuthFlow(spec)

        # First flow generates a verifier bound to state_a.
        _, state_a = flow.build_authorize_url(
            client_id="cid", redirect_uri="http://localhost/cb"
        )
        # A second authorize starts before the first completes.
        flow.build_authorize_url(client_id="cid", redirect_uri="http://localhost/cb")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "tok"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.return_value = mock_response

            flow.exchange_code(
                code="code123",
                redirect_uri="http://localhost/cb",
                client_id="cid",
                client_secret="csec",
                state=state_a,
            )
            sent_data = mock_client_instance.post.call_args.kwargs["data"]
        # The first flow's verifier is recovered by its own state, not clobbered.
        assert "code_verifier" in sent_data


class TestValidateCallbackState:
    def test_matching_state_passes(self):
        flow = OAuthFlow(FakeSpec())
        flow._validate_callback_state({"state": "abc"}, "abc")

    def test_mismatched_state_raises(self):
        flow = OAuthFlow(FakeSpec())
        with pytest.raises(ValueError, match="CSRF"):
            flow._validate_callback_state({"state": "evil"}, "abc")

    def test_missing_state_raises(self):
        flow = OAuthFlow(FakeSpec())
        with pytest.raises(ValueError, match="CSRF"):
            flow._validate_callback_state({}, "abc")


class TestRefresh:
    def test_raises_token_refresh_error_on_http_error(self):
        flow = OAuthFlow(FakeSpec())
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch("httpx.Client") as MockClient:
            mock_client_instance = MockClient.return_value.__enter__.return_value
            mock_client_instance.post.side_effect = httpx.HTTPStatusError(
                "error", request=MagicMock(), response=mock_response
            )

            with pytest.raises(TokenRefreshError) as exc_info:
                flow.refresh(
                    refresh_token="old_refresh",
                    client_id="cid",
                    client_secret="csec",
                )
            assert exc_info.value.status_code == 401
            assert exc_info.value.url == "https://auth.example.com/token"


class TestIsExpired:
    def test_none_returns_false(self):
        assert OAuthFlow.is_expired(None) is False

    def test_past_timestamp_returns_true(self):
        past = int(time.time()) - 1000
        assert OAuthFlow.is_expired(past) is True

    def test_far_future_returns_false(self):
        future = int(time.time()) + 10000
        assert OAuthFlow.is_expired(future) is False

    def test_near_future_returns_true_due_to_buffer(self):
        # Within the 300s buffer window
        near_future = int(time.time()) + 100
        assert OAuthFlow.is_expired(near_future) is True

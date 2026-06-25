"""ProviderProfile: validation, emit golden, extension mechanism."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from mountainash_settings import ParameterSpec, ProfileSpec
from mountainash_auth_client.targets import TargetFamily
from mountainash_auth_client.providers.oauth2 import (
    OAuth2ProviderProfile,
)
from mountainash_auth_client.providers.oauth1 import (
    OAUTH1_PROVIDER_PARAMS,
    OAuth1ProviderProfile,
)


def _oauth2(**overrides):
    base = dict(
        NAME="strava",
        AUTHORIZE_URL="https://www.strava.com/oauth/authorize",
        TOKEN_URL="https://www.strava.com/oauth/token",
        BASE_URL="https://www.strava.com/api/v3",
    )
    base.update(overrides)
    return OAuth2ProviderProfile(**base)


def _oauth1(**overrides):
    base = dict(
        NAME="garmin",
        REQUEST_TOKEN_URL="https://connectapi.garmin.com/oauth-service/oauth/request_token",
        AUTHORIZE_URL="https://connect.garmin.com/oauthConfirm",
        ACCESS_TOKEN_URL="https://connectapi.garmin.com/oauth-service/oauth/access_token",
        BASE_URL="https://apis.garmin.com",
    )
    base.update(overrides)
    return OAuth1ProviderProfile(**base)


class TestOAuth2ProviderProfile:
    def test_fields_round_trip(self):
        p = _oauth2(DEFAULT_SCOPE="read", USE_PKCE=True, CALLBACK_PORT=8923)
        assert p.NAME == "strava"
        assert p.AUTHORIZE_URL == "https://www.strava.com/oauth/authorize"
        assert p.TOKEN_URL == "https://www.strava.com/oauth/token"
        assert p.DEFAULT_SCOPE == "read"
        assert p.USE_PKCE is True
        assert p.CALLBACK_PORT == 8923

    def test_advanced_defaults(self):
        p = _oauth2()
        assert p.DEFAULT_SCOPE is None
        assert p.USE_PKCE is False
        assert p.CALLBACK_PORT is None

    def test_emit_http_is_base_url_only(self):
        assert _oauth2().emit(TargetFamily.HTTP) == {"base_url": "https://www.strava.com/api/v3"}

    def test_emit_without_target_fails_closed(self):
        with pytest.raises(ValueError):
            _oauth2().emit()

    def test_missing_required_field_fails_at_construction(self):
        with pytest.raises(ValidationError):
            OAuth2ProviderProfile(NAME="x", TOKEN_URL="t", BASE_URL="b")

    def test_not_registered_in_auth_registry(self):
        from mountainash_auth_client.schemas.registry import AUTH_REGISTRY
        assert "oauth2_provider" not in AUTH_REGISTRY
        assert "oauth1_provider" not in AUTH_REGISTRY


class TestOAuth1ProviderProfile:
    def test_fields_round_trip(self):
        p = _oauth1(CALLBACK_PORT=7000)
        assert p.NAME == "garmin"
        assert p.REQUEST_TOKEN_URL.endswith("/request_token")
        assert p.AUTHORIZE_URL == "https://connect.garmin.com/oauthConfirm"
        assert p.ACCESS_TOKEN_URL.endswith("/access_token")
        assert p.CALLBACK_PORT == 7000

    def test_emit_http_is_base_url_only(self):
        assert _oauth1().emit(TargetFamily.HTTP) == {"base_url": "https://apis.garmin.com"}

    def test_missing_required_field_fails_at_construction(self):
        with pytest.raises(ValidationError):
            OAuth1ProviderProfile(NAME="x", AUTHORIZE_URL="a", BASE_URL="b")


def test_new_client_auth_params_default_to_standard():
    from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
    p = OAuth2ProviderProfile(NAME="x", AUTHORIZE_URL="a", TOKEN_URL="t", BASE_URL="b")
    assert p.TOKEN_ENDPOINT_AUTH_METHOD == "client_secret_post"
    assert p.TOKEN_REQUEST_HEADERS is None
    assert p.TOKEN_REQUEST_CONTENT_TYPE == "application/x-www-form-urlencoded"


def test_new_client_auth_params_overridable():
    from mountainash_auth_client.providers.oauth2 import OAuth2ProviderProfile
    p = OAuth2ProviderProfile(
        NAME="privy", AUTHORIZE_URL="", TOKEN_URL="t", BASE_URL="b",
        TOKEN_ENDPOINT_AUTH_METHOD="none",
        TOKEN_REQUEST_HEADERS={"privy-app-id": "abc", "Origin": "https://x"},
        TOKEN_REQUEST_CONTENT_TYPE="application/json",
    )
    assert p.TOKEN_ENDPOINT_AUTH_METHOD == "none"
    assert p.TOKEN_REQUEST_HEADERS["privy-app-id"] == "abc"


class TestExtension:
    """Esoteric providers extend the base param list + subclass the base."""

    def test_subclass_adds_field_and_keeps_base(self):

        EXT_SPEC = ProfileSpec(
            name="garmin_health_provider",
            provider_type="garmin_health_provider",
            parameters=[*OAUTH1_PROVIDER_PARAMS, ParameterSpec(name="USER_INFO_URL", type=str, tier="core")],
        )

        class GarminHealthProvider(OAuth1ProviderProfile):
            __spec__ = EXT_SPEC

        p = GarminHealthProvider(
            NAME="garmin",
            REQUEST_TOKEN_URL="https://g/request_token",
            AUTHORIZE_URL="https://g/authorize",
            ACCESS_TOKEN_URL="https://g/access_token",
            BASE_URL="https://apis.garmin.com",
            USER_INFO_URL="https://apis.garmin.com/wellness-api/rest/user/id",
        )
        assert p.USER_INFO_URL.endswith("/user/id")
        assert p.REQUEST_TOKEN_URL == "https://g/request_token"
        assert p.emit(TargetFamily.HTTP) == {"base_url": "https://apis.garmin.com"}

"""Tests for auth mode Profile subclasses."""
from __future__ import annotations

from mountainash_auth_client.schemas.registry import AUTH_REGISTRY


class TestAuthRegistry:
    def test_noauth_registered(self):
        assert "none" in AUTH_REGISTRY

    def test_noauth_lookup_by_name(self):
        cls = AUTH_REGISTRY.get_settings_class("none")
        instance = cls()
        assert instance.profile_name == "none"

    def test_noauth_default_kwargs_empty(self):
        cls = AUTH_REGISTRY.get_settings_class("none")
        instance = cls()
        assert instance._default_kwargs() == {}


class TestPasswordAuth:
    def test_registered(self):
        assert "password" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("password")
        instance = cls(USERNAME="alice", PASSWORD="hunter2")
        assert instance.USERNAME == "alice"
        assert instance.profile_name == "password"

    def test_default_kwargs(self):
        # USERNAME/PASSWORD are PARAMIKO-scoped now; untargeted emit is empty.
        cls = AUTH_REGISTRY.get_settings_class("password")
        instance = cls(USERNAME="alice", PASSWORD="hunter2")
        assert instance._default_kwargs() == {}
        assert instance._default_kwargs("paramiko") == {
            "username": "alice",
            "password": "hunter2",
        }


class TestTokenAuth:
    def test_registered(self):
        assert "token" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("token")
        instance = cls(TOKEN="my-bearer-token")
        assert instance.profile_name == "token"

    def test_default_kwargs(self):
        # token is now adapter-only (HTTP Bearer); no bare driver_key.
        cls = AUTH_REGISTRY.get_settings_class("token")
        instance = cls(TOKEN="my-bearer-token")
        assert instance._default_kwargs() == {}


class TestJWTAuth:
    def test_registered(self):
        assert "jwt" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("jwt")
        instance = cls(TOKEN="eyJhbGciOi...")
        assert instance.profile_name == "jwt"

    def test_default_kwargs(self):
        cls = AUTH_REGISTRY.get_settings_class("jwt")
        instance = cls(TOKEN="eyJhbGciOi...")
        assert instance._default_kwargs() == {}


class TestOAuth2Auth:
    def test_registered(self):
        assert "oauth2" in AUTH_REGISTRY

    def test_construction_with_token(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls(ACCESS_TOKEN="access-tok")
        assert instance.profile_name == "oauth2"

    def test_default_kwargs_token(self):
        # ACCESS_TOKEN now renders via the HTTP Bearer adapter, not a bare driver_key.
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls(ACCESS_TOKEN="access-tok")
        assert instance._default_kwargs() == {}

    def test_default_kwargs_client_credentials(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls(CLIENT_ID="cid", CLIENT_SECRET="csec")
        # client-credentials are flow inputs, not emitted kwargs.
        assert instance._default_kwargs() == {}

    def test_all_fields_optional(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls()
        assert instance._default_kwargs() == {}

    def test_construction_with_all_token_fields(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth2")
        instance = cls(
            CLIENT_ID="cid",
            CLIENT_SECRET="csec",
            ACCESS_TOKEN="at",
            REFRESH_TOKEN="rt",
            SCOPE="read write",
        )
        assert instance.profile_name == "oauth2"
        assert instance.ACCESS_TOKEN.get_secret_value() == "at"
        assert instance.SCOPE == "read write"


class TestOAuth1Auth:
    def test_registered(self):
        assert "oauth1" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth1")
        instance = cls(CONSUMER_KEY="key", CONSUMER_SECRET="secret")
        assert instance.profile_name == "oauth1"
        assert instance.ACCESS_TOKEN is None

    def test_with_tokens(self):
        cls = AUTH_REGISTRY.get_settings_class("oauth1")
        instance = cls(
            CONSUMER_KEY="key",
            CONSUMER_SECRET="secret",
            ACCESS_TOKEN="at",
            ACCESS_TOKEN_SECRET="ats",
        )
        assert instance.ACCESS_TOKEN is not None


class TestIAMAuth:
    def test_registered(self):
        assert "iam" in AUTH_REGISTRY

    def test_construction_ambient(self):
        cls = AUTH_REGISTRY.get_settings_class("iam")
        instance = cls()
        assert instance._default_kwargs("boto") == {}

    def test_construction_with_role(self):
        # ROLE_ARN is stored as a field but no longer emitted (config, not a
        # boto3.client kwarg).
        cls = AUTH_REGISTRY.get_settings_class("iam")
        instance = cls(ROLE_ARN="arn:aws:iam::123:role/myrole")
        assert instance.ROLE_ARN == "arn:aws:iam::123:role/myrole"
        assert instance._default_kwargs("boto") == {}

    def test_construction_with_keys(self):
        cls = AUTH_REGISTRY.get_settings_class("iam")
        instance = cls(
            ACCESS_KEY_ID="AKID",
            SECRET_ACCESS_KEY="secret",
            SESSION_TOKEN="tok",
        )
        result = instance._default_kwargs("boto")
        assert result["aws_access_key_id"] == "AKID"
        assert result["aws_secret_access_key"] == "secret"
        assert result["aws_session_token"] == "tok"


class TestWindowsAuth:
    def test_registered(self):
        assert "windows" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("windows")
        instance = cls(USERNAME="admin", DOMAIN="CORP")
        assert instance.USERNAME == "admin"
        assert instance.DOMAIN == "CORP"


class TestAzureADAuth:
    def test_registered(self):
        assert "azure_ad" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("azure_ad")
        instance = cls(TENANT_ID="tid", CLIENT_ID="cid")
        assert instance.TENANT_ID == "tid"

    def test_managed_identity(self):
        cls = AUTH_REGISTRY.get_settings_class("azure_ad")
        instance = cls(MANAGED_IDENTITY=True)
        assert instance.MANAGED_IDENTITY is True


class TestKerberosAuth:
    def test_registered(self):
        assert "kerberos" in AUTH_REGISTRY

    def test_construction_defaults(self):
        cls = AUTH_REGISTRY.get_settings_class("kerberos")
        instance = cls()
        assert instance.SERVICE_NAME == "postgres"

    def test_construction_custom(self):
        cls = AUTH_REGISTRY.get_settings_class("kerberos")
        instance = cls(SERVICE_NAME="trino", PRINCIPAL="user@REALM")
        assert instance.SERVICE_NAME == "trino"
        assert instance.PRINCIPAL == "user@REALM"


class TestCertificateAuth:
    def test_registered(self):
        assert "certificate" in AUTH_REGISTRY

    def test_construction(self):
        cls = AUTH_REGISTRY.get_settings_class("certificate")
        instance = cls(PRIVATE_KEY="key-data")
        assert instance.profile_name == "certificate"


class TestServiceAccountAuth:
    def test_registered(self):
        assert "service_account" in AUTH_REGISTRY

    def test_construction_with_file(self):
        cls = AUTH_REGISTRY.get_settings_class("service_account")
        instance = cls(FILE="/path/to/sa.json")
        assert instance.profile_name == "service_account"

    def test_construction_with_info(self):
        cls = AUTH_REGISTRY.get_settings_class("service_account")
        instance = cls(INFO={"type": "service_account", "project_id": "test"})
        assert instance.INFO["project_id"] == "test"

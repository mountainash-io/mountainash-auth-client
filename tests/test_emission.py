"""Per-profile, per-target golden emission tests (Phase 2)."""
from __future__ import annotations

import base64

import pytest

from mountainash_auth_client.targets import TargetFamily


@pytest.mark.unit
class TestTargetFamily:
    def test_members_and_values(self):
        assert TargetFamily.HTTP == "http"
        assert TargetFamily.BOTO == "boto"
        assert TargetFamily.PARAMIKO == "paramiko"

    def test_is_str_enum(self):
        # str-Enum so it doubles as an opaque Hashable settings key.
        assert isinstance(TargetFamily.HTTP, str)

    def test_exported_from_package_root(self):
        from mountainash_auth_client import TargetFamily as Exported
        assert Exported is TargetFamily


@pytest.mark.unit
class TestRequireParamiko:
    def test_returns_module(self):
        # paramiko is in the test env (added in this task); require returns it.
        from mountainash_auth_client._optional import require_paramiko
        paramiko = require_paramiko()
        assert hasattr(paramiko, "RSAKey")

    def test_returns_named_attr(self):
        from mountainash_auth_client._optional import require_paramiko
        RSAKey = require_paramiko("RSAKey")
        assert RSAKey.__name__ == "RSAKey"

    def test_missing_extra_message(self, monkeypatch):
        # Simulate paramiko not installed → consistent install hint.
        # Patch importlib.import_module directly (the seam `require` uses),
        # mirroring the existing tests/connections/test_optional.py pattern.
        import importlib

        from mountainash_auth_client._optional import require_paramiko

        def boom(name):
            raise ImportError("simulated missing paramiko")

        monkeypatch.setattr(importlib, "import_module", boom)
        with pytest.raises(ImportError) as exc_info:
            require_paramiko("RSAKey")
        msg = str(exc_info.value)
        assert "SSH key/Kerberos auth requires paramiko" in msg
        assert "pip install mountainash-auth-client[sftp]" in msg


@pytest.mark.unit
class TestBearer:
    def test_token_http(self):
        from mountainash_auth_client import TokenAuthProfile
        out = TokenAuthProfile(TOKEN="abc").emit(TargetFamily.HTTP)
        assert out == {"headers": {"Authorization": "Bearer abc"}}

    def test_jwt_http(self):
        from mountainash_auth_client import JWTAuthProfile
        out = JWTAuthProfile(TOKEN="eyJ").emit(TargetFamily.HTTP)
        assert out == {"headers": {"Authorization": "Bearer eyJ"}}

    def test_layers_onto_base_headers_copy_on_write(self):
        from mountainash_auth_client import TokenAuthProfile
        base = {"headers": {"X-Trace": "1"}, "timeout": 5}
        out = TokenAuthProfile(TOKEN="abc").emit(TargetFamily.HTTP, base=base)
        assert out["headers"] == {"X-Trace": "1", "Authorization": "Bearer abc"}
        assert out["timeout"] == 5
        # base untouched (copy-on-write).
        assert base["headers"] == {"X-Trace": "1"}

    def test_targeted_no_target_raises(self):
        from mountainash_auth_client import TokenAuthProfile
        with pytest.raises(ValueError, match="target-scoped"):
            TokenAuthProfile(TOKEN="abc").emit()

    def test_empty_token_emits_nothing(self):
        # Matches the old resolver truthiness: a falsy token yields no header.
        from mountainash_auth_client import TokenAuthProfile
        assert TokenAuthProfile(TOKEN="").emit(TargetFamily.HTTP) == {}


@pytest.mark.unit
class TestPassword:
    def test_http_basic_header(self):
        from mountainash_auth_client import PasswordAuthProfile
        out = PasswordAuthProfile(USERNAME="alice", PASSWORD="hunter2").emit(
            TargetFamily.HTTP
        )
        expected = base64.b64encode(b"alice:hunter2").decode()
        assert out == {"headers": {"Authorization": f"Basic {expected}"}}

    def test_paramiko_username_and_password(self):
        from mountainash_auth_client import PasswordAuthProfile
        out = PasswordAuthProfile(USERNAME="alice", PASSWORD="hunter2").emit(
            TargetFamily.PARAMIKO
        )
        # Restores username the old SSHPasswordStrategy dropped.
        assert out == {"username": "alice", "password": "hunter2"}

    def test_http_no_stray_username_password(self):
        from mountainash_auth_client import PasswordAuthProfile
        out = PasswordAuthProfile(USERNAME="alice", PASSWORD="hunter2").emit(
            TargetFamily.HTTP
        )
        assert "username" not in out and "password" not in out and "user" not in out

    def test_unknown_target_raises(self):
        from mountainash_auth_client import PasswordAuthProfile
        with pytest.raises(ValueError, match="no emission for target"):
            PasswordAuthProfile(USERNAME="a", PASSWORD="b").emit(TargetFamily.BOTO)


@pytest.mark.unit
class TestIAM:
    def test_boto_full_credentials(self):
        from mountainash_auth_client import IAMAuthProfile
        out = IAMAuthProfile(
            ACCESS_KEY_ID="AKID", SECRET_ACCESS_KEY="secret", SESSION_TOKEN="tok"
        ).emit(TargetFamily.BOTO)
        assert out == {
            "aws_access_key_id": "AKID",
            "aws_secret_access_key": "secret",
            "aws_session_token": "tok",
        }

    def test_boto_skips_unset(self):
        from mountainash_auth_client import IAMAuthProfile
        out = IAMAuthProfile(ACCESS_KEY_ID="AKID").emit(TargetFamily.BOTO)
        assert out == {"aws_access_key_id": "AKID"}

    def test_boto_ambient_is_empty(self):
        from mountainash_auth_client import IAMAuthProfile
        assert IAMAuthProfile().emit(TargetFamily.BOTO) == {}

    def test_role_arn_not_emitted(self):
        from mountainash_auth_client import IAMAuthProfile
        # role_arn is config (storage-profile owned), not a boto3.client kwarg.
        out = IAMAuthProfile(
            ROLE_ARN="arn:aws:iam::123:role/r", ACCESS_KEY_ID="AKID"
        ).emit(TargetFamily.BOTO)
        assert "iam_role_arn" not in out
        assert out == {"aws_access_key_id": "AKID"}

    def test_layers_onto_base(self):
        from mountainash_auth_client import IAMAuthProfile
        out = IAMAuthProfile(ACCESS_KEY_ID="AKID").emit(
            TargetFamily.BOTO, base={"region_name": "us-east-1"}
        )
        assert out == {"region_name": "us-east-1", "aws_access_key_id": "AKID"}


@pytest.mark.unit
class TestOAuth2AuthCode:
    def test_http_bearer_from_access_token(self):
        from mountainash_auth_client import OAuth2AuthCodeAuthProfile
        out = OAuth2AuthCodeAuthProfile(
            CLIENT_ID="cid", CLIENT_SECRET="csec", ACCESS_TOKEN="at"
        ).emit(TargetFamily.HTTP)
        assert out == {"headers": {"Authorization": "Bearer at"}}

    def test_http_no_token_is_empty(self):
        from mountainash_auth_client import OAuth2AuthCodeAuthProfile
        # No access token in hand → nothing static to render (flow acquires it).
        out = OAuth2AuthCodeAuthProfile(CLIENT_ID="cid", CLIENT_SECRET="csec").emit(
            TargetFamily.HTTP
        )
        assert out == {}

    def test_no_stray_client_fields(self):
        from mountainash_auth_client import OAuth2AuthCodeAuthProfile
        out = OAuth2AuthCodeAuthProfile(
            CLIENT_ID="cid", CLIENT_SECRET="csec", ACCESS_TOKEN="at"
        ).emit(TargetFamily.HTTP)
        assert "client_id" not in out and "access_token" not in out


@pytest.mark.unit
class TestOAuth1:
    def test_http_installs_authlib_signer(self):
        from mountainash_auth_client import OAuth1AuthProfile
        OAuth1Auth = pytest.importorskip(
            "authlib.integrations.httpx_client"
        ).OAuth1Auth
        out = OAuth1AuthProfile(
            CONSUMER_KEY="ck", CONSUMER_SECRET="cs",
            ACCESS_TOKEN="at", ACCESS_TOKEN_SECRET="ats",
        ).emit(TargetFamily.HTTP)
        assert set(out) == {"auth"}
        assert isinstance(out["auth"], OAuth1Auth)
        # authlib stores the consumer key as client_id.
        assert out["auth"].client_id == "ck"

    def test_no_stray_consumer_fields(self):
        from mountainash_auth_client import OAuth1AuthProfile
        pytest.importorskip("authlib.integrations.httpx_client")
        out = OAuth1AuthProfile(
            CONSUMER_KEY="ck", CONSUMER_SECRET="cs",
            ACCESS_TOKEN="at", ACCESS_TOKEN_SECRET="ats",
        ).emit(TargetFamily.HTTP)
        assert "consumer_key" not in out and "consumer_secret" not in out


@pytest.mark.unit
class TestCertificate:
    def test_paramiko_key_path(self):
        from mountainash_auth_client import CertificateAuthProfile
        out = CertificateAuthProfile(
            PRIVATE_KEY_PATH="/home/u/.ssh/id_rsa", PASSPHRASE="pp"
        ).emit(TargetFamily.PARAMIKO)
        assert out == {"key_filename": "/home/u/.ssh/id_rsa", "passphrase": "pp"}

    def test_paramiko_key_path_no_passphrase(self):
        from mountainash_auth_client import CertificateAuthProfile
        out = CertificateAuthProfile(
            PRIVATE_KEY_PATH="/home/u/.ssh/id_rsa"
        ).emit(TargetFamily.PARAMIKO)
        assert out == {"key_filename": "/home/u/.ssh/id_rsa"}

    def test_paramiko_raw_pem_parsed_to_pkey(self):
        paramiko = pytest.importorskip("paramiko")
        from mountainash_auth_client import CertificateAuthProfile
        key = paramiko.RSAKey.generate(2048)
        import io
        buf = io.StringIO()
        key.write_private_key(buf)
        pem = buf.getvalue()
        out = CertificateAuthProfile(PRIVATE_KEY=pem).emit(TargetFamily.PARAMIKO)
        assert set(out) == {"pkey"}
        assert isinstance(out["pkey"], paramiko.PKey)
        assert out["pkey"].get_fingerprint() == key.get_fingerprint()

    def test_no_key_material_raises(self):
        # Fail-fast (matches old SSHKeyStrategy): no key path or PEM → error,
        # not a silent keyless connect.
        from mountainash_auth_client import CertificateAuthProfile
        with pytest.raises(ValueError, match="PRIVATE_KEY_PATH or PRIVATE_KEY"):
            CertificateAuthProfile().emit(TargetFamily.PARAMIKO)


@pytest.mark.unit
class TestKerberos:
    def test_paramiko_gss_flags_default_service(self):
        from mountainash_auth_client import KerberosAuthProfile
        out = KerberosAuthProfile().emit(TargetFamily.PARAMIKO)
        # SERVICE_NAME defaults to "postgres"; mirrors SSHKerberosStrategy(gss_host=SERVICE_NAME).
        assert out == {"gss_auth": True, "gss_host": "postgres"}

    def test_paramiko_gss_flags_custom_service(self):
        from mountainash_auth_client import KerberosAuthProfile
        out = KerberosAuthProfile(SERVICE_NAME="trino").emit(TargetFamily.PARAMIKO)
        assert out == {"gss_auth": True, "gss_host": "trino"}

    def test_layers_onto_base(self):
        from mountainash_auth_client import KerberosAuthProfile
        out = KerberosAuthProfile(SERVICE_NAME="trino").emit(
            TargetFamily.PARAMIKO, base={"hostname": "h"}
        )
        assert out == {"hostname": "h", "gss_auth": True, "gss_host": "trino"}


@pytest.mark.unit
class TestPlainOAuth2:
    def test_http_bearer_from_token(self):
        from mountainash_auth_client import OAuth2AuthProfile
        out = OAuth2AuthProfile(ACCESS_TOKEN="access-tok").emit(TargetFamily.HTTP)
        assert out == {"headers": {"Authorization": "Bearer access-tok"}}

    def test_http_no_token_is_empty(self):
        from mountainash_auth_client import OAuth2AuthProfile
        # client-credentials-only (no token yet) → nothing to render statically.
        out = OAuth2AuthProfile(CLIENT_ID="cid", CLIENT_SECRET="csec").emit(
            TargetFamily.HTTP
        )
        assert out == {}

    def test_no_stray_client_fields(self):
        from mountainash_auth_client import OAuth2AuthProfile
        out = OAuth2AuthProfile(ACCESS_TOKEN="access-tok").emit(TargetFamily.HTTP)
        assert "client_id" not in out and "token" not in out

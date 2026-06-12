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
        from mountainash_auth_client.connections._optional import require_paramiko
        paramiko = require_paramiko()
        assert hasattr(paramiko, "RSAKey")

    def test_returns_named_attr(self):
        from mountainash_auth_client.connections._optional import require_paramiko
        RSAKey = require_paramiko("RSAKey")
        assert RSAKey.__name__ == "RSAKey"

    def test_missing_extra_message(self, monkeypatch):
        # Simulate paramiko not installed → consistent install hint.
        # Patch importlib.import_module directly (the seam `require` uses),
        # mirroring the existing tests/connections/test_optional.py pattern.
        import importlib

        from mountainash_auth_client.connections._optional import require_paramiko

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

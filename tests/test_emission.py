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

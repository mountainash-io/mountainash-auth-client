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

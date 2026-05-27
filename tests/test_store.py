"""Tests for SecretStore protocol and FilesystemStore implementation."""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest

from mountainash_auth_client.store import FilesystemStore, SecretStore


@pytest.fixture
def tmp_store(tmp_path):
    return FilesystemStore(base_dir=tmp_path)


class TestFilesystemStoreBasic:
    def test_save_and_load_round_trip(self, tmp_store):
        data = {"access_token": "abc123", "refresh_token": "def456"}
        tmp_store.save("wearables", "fitbit", "alice", data)
        result = tmp_store.load("wearables", "fitbit", "alice")
        assert result == data

    def test_load_missing_returns_none(self, tmp_store):
        result = tmp_store.load("wearables", "fitbit", "nobody")
        assert result is None

    def test_clear_removes_token(self, tmp_store):
        tmp_store.save("wearables", "fitbit", "alice", {"token": "x"})
        tmp_store.clear("wearables", "fitbit", "alice")
        assert tmp_store.load("wearables", "fitbit", "alice") is None

    def test_is_cleared_after_clear(self, tmp_store):
        tmp_store.save("wearables", "fitbit", "alice", {"token": "x"})
        tmp_store.clear("wearables", "fitbit", "alice")
        assert tmp_store.is_cleared("wearables", "fitbit", "alice") is True

    def test_is_not_cleared_before_clear(self, tmp_store):
        tmp_store.save("wearables", "fitbit", "alice", {"token": "x"})
        assert tmp_store.is_cleared("wearables", "fitbit", "alice") is False

    def test_save_after_clear_removes_tombstone(self, tmp_store):
        tmp_store.save("wearables", "fitbit", "alice", {"token": "x"})
        tmp_store.clear("wearables", "fitbit", "alice")
        assert tmp_store.is_cleared("wearables", "fitbit", "alice") is True
        tmp_store.save("wearables", "fitbit", "alice", {"token": "y"})
        assert tmp_store.is_cleared("wearables", "fitbit", "alice") is False
        assert tmp_store.load("wearables", "fitbit", "alice") == {"token": "y"}

    def test_list_users_empty(self, tmp_store):
        result = tmp_store.list_users("wearables", "fitbit")
        assert result == []

    def test_list_users_after_saves(self, tmp_store):
        tmp_store.save("wearables", "fitbit", "alice", {"token": "a"})
        tmp_store.save("wearables", "fitbit", "bob", {"token": "b"})
        tmp_store.save("wearables", "strava", "alice", {"token": "c"})  # different provider
        result = tmp_store.list_users("wearables", "fitbit")
        assert sorted(result) == ["alice", "bob"]

    def test_list_users_not_include_other_providers(self, tmp_store):
        tmp_store.save("wearables", "fitbit", "alice", {"token": "a"})
        tmp_store.save("wearables", "strava", "bob", {"token": "b"})
        assert "bob" not in tmp_store.list_users("wearables", "fitbit")

    def test_domain_isolation(self, tmp_store):
        tmp_store.save("wearables", "fitbit", "alice", {"token": "wearables"})
        tmp_store.save("other", "fitbit", "alice", {"token": "other"})
        assert tmp_store.load("wearables", "fitbit", "alice") == {"token": "wearables"}
        assert tmp_store.load("other", "fitbit", "alice") == {"token": "other"}


class TestFilesystemStorePermissions:
    def test_file_permissions_600(self, tmp_store):
        tmp_store.save("wearables", "fitbit", "alice", {"token": "x"})
        domain_dir = tmp_store.base_dir / "wearables"
        token_path = domain_dir / "fitbit-alice.yaml"
        mode = token_path.stat().st_mode
        assert not (mode & 0o077), f"Expected 0o600 but got {oct(mode)}"

    def test_directory_permissions_700(self, tmp_store):
        tmp_store.save("wearables", "fitbit", "alice", {"token": "x"})
        domain_dir = tmp_store.base_dir / "wearables"
        mode = domain_dir.stat().st_mode
        assert not (mode & 0o077), f"Expected 0o700 but got {oct(mode)}"


class TestFilesystemStoreLock:
    def test_lock_context_manager(self, tmp_store):
        with tmp_store.lock("wearables", "fitbit", "alice") as result:
            assert result is None  # context manager yields None

    def test_lock_allows_operations_inside(self, tmp_store):
        with tmp_store.lock("wearables", "fitbit", "alice"):
            tmp_store.save("wearables", "fitbit", "alice", {"token": "locked"})
        assert tmp_store.load("wearables", "fitbit", "alice") == {"token": "locked"}


class TestFilesystemStoreValidation:
    def test_invalid_domain_raises_value_error(self, tmp_store):
        with pytest.raises(ValueError, match="domain"):
            tmp_store.save("INVALID", "fitbit", "alice", {})

    def test_invalid_provider_raises_value_error(self, tmp_store):
        with pytest.raises(ValueError, match="provider"):
            tmp_store.save("wearables", "FitBit!", "alice", {})

    def test_invalid_user_raises_value_error(self, tmp_store):
        with pytest.raises(ValueError, match="user"):
            tmp_store.save("wearables", "fitbit", "Alice Smith", {})

    def test_hyphens_not_allowed_in_name(self, tmp_store):
        with pytest.raises(ValueError):
            tmp_store.save("wearables", "fitbit-api", "alice", {})


class TestSecretStoreProtocol:
    def test_filesystem_store_satisfies_protocol(self, tmp_store):
        assert isinstance(tmp_store, SecretStore)

    def test_plain_object_does_not_satisfy_protocol(self):
        class NotAStore:
            pass

        assert not isinstance(NotAStore(), SecretStore)

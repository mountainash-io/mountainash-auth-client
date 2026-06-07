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
        cls = AUTH_REGISTRY.get_settings_class("password")
        instance = cls(USERNAME="alice", PASSWORD="hunter2")
        result = instance._default_kwargs()
        assert result["user"] == "alice"
        assert result["password"] == "hunter2"

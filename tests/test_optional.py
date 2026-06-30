"""Tests for the centralised optional-dependency loader."""
from __future__ import annotations

import importlib
import json

import pytest

from mountainash_auth_client._optional import require, require_authlib


class TestRequireSuccess:
    def test_returns_module_when_no_attrs(self):
        assert require("json", extra="x", feature="F") is json

    def test_returns_single_attr_unwrapped(self):
        assert require("json", "dumps", extra="x", feature="F") is json.dumps

    def test_returns_tuple_for_multiple_attrs(self):
        loads, dumps = require("json", "loads", "dumps", extra="x", feature="F")
        assert loads is json.loads
        assert dumps is json.dumps


class TestRequireMissing:
    def test_raises_importerror_naming_package_and_extra(self):
        with pytest.raises(ImportError) as exc_info:
            require("nope_not_a_real_pkg.sub", extra="oauth1", feature="OAuth1")
        msg = str(exc_info.value)
        assert "OAuth1 requires nope_not_a_real_pkg" in msg
        assert "pip install mountainash-auth-client[oauth1]" in msg

    def test_require_authlib_message_when_absent(self, monkeypatch):
        def boom(name):
            raise ImportError("simulated missing authlib")

        monkeypatch.setattr(importlib, "import_module", boom)
        with pytest.raises(ImportError) as exc_info:
            require_authlib("OAuth1Client")
        assert str(exc_info.value) == (
            "OAuth1 requires authlib: pip install mountainash-auth-client[oauth1]"
        )

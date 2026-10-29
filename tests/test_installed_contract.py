"""Validate the dependency contract consumed by installers."""

from __future__ import annotations

from importlib.metadata import metadata

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name


def test_settings_requirement_selects_the_supported_api() -> None:
    requirements = [Requirement(value) for value in metadata("mountainash-auth-client").get_all("Requires-Dist", [])]
    settings = [requirement for requirement in requirements if canonicalize_name(requirement.name) == "mountainash-settings"]
    assert len(settings) == 1
    assert settings[0].marker is None
    assert settings[0].url is None
    assert "0.1.0" in settings[0].specifier
    assert "0.2.0" not in settings[0].specifier
    assert "26.5.0" not in settings[0].specifier


def test_python_requirement_selects_supported_interpreters() -> None:
    supported = SpecifierSet(metadata("mountainash-auth-client")["Requires-Python"])
    assert "3.11" not in supported
    assert "3.12" in supported
    assert "3.13" in supported


def test_retired_secrets_package_is_not_required() -> None:
    requirements = [Requirement(value) for value in metadata("mountainash-auth-client").get_all("Requires-Dist", [])]
    assert all(canonicalize_name(requirement.name) != "mountainash-secrets" for requirement in requirements)

"""Rule 4 (emission safety): no bare driver_key behind an adapter.

A profile that registers any __adapters__ must not declare a bare-string
driver_key on any field — bare keys emit for every target and would leak into
an adapter target's base. Target-scoped (dict) or absent (None) only.
"""
from __future__ import annotations

import pytest

from mountainash_auth_client.schemas.registry import AUTH_REGISTRY


def _adapter_bearing_profiles():
    out = []
    for name in AUTH_REGISTRY.specs:
        cls = AUTH_REGISTRY.get_settings_class(name)
        if getattr(cls, "__adapters__", {}):
            out.append((name, cls))
    return out


@pytest.mark.unit
class TestNoBareDriverKeyBehindAdapter:
    def test_registry_compliant(self):
        offenders = []
        for name, cls in _adapter_bearing_profiles():
            for param in cls.__spec__.parameters:
                if isinstance(param.driver_key, str):  # bare string
                    offenders.append(f"{name}.{param.name} -> {param.driver_key!r}")
        assert not offenders, (
            "adapter-bearing profiles must not declare bare driver_keys: "
            + ", ".join(offenders)
        )

    def test_at_least_one_adapter_profile_exists(self):
        # Guard against the invariant silently passing because nothing registers
        # an adapter (e.g. a future import regression).
        assert _adapter_bearing_profiles(), "expected adapter-bearing profiles"

    def test_detects_a_bad_profile(self):
        # A constructed profile that violates rule 4 is caught by the same check.
        from mountainash_settings import ParameterSpec, Profile, ProfileSpec

        from mountainash_auth_client.targets import TargetFamily

        bad_spec = ProfileSpec(
            name="bad_rule4", provider_type="bad_rule4",
            parameters=[
                ParameterSpec(name="TOKEN", type=str, tier="core", driver_key="token"),
            ],
        )

        def _adapter(profile, kw):
            return kw

        class BadProfile(Profile):
            __spec__ = bad_spec
            __adapters__ = {TargetFamily.HTTP: _adapter}

        offenders = [
            p.name for p in BadProfile.__spec__.parameters
            if isinstance(p.driver_key, str)
        ]
        assert offenders == ["TOKEN"]

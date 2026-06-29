"""Every public name stays importable through the lazy package root."""
from __future__ import annotations

import mountainash_auth_client as pkg


def test_every_public_name_resolves():
    missing = [name for name in pkg.__all__ if not hasattr(pkg, name)]
    assert not missing, missing


def test_lazy_map_and_all_agree():
    # Every lazily-mapped name must be advertised in __all__ (no orphan lazies).
    assert set(pkg._LAZY).issubset(set(pkg.__all__))

from __future__ import annotations

import mountainash_auth_client as ac


def test_lifecycle_symbols_exported_at_top_level():
    from mountainash_auth_client import (
        OAuth1TokenManager,
        OAuth2TokenManager,
        PersistableAuthProfile,
        TokenState,
        TokenStatus,
    )

    # Imports are load-bearing: each must be the SAME object on the package and
    # listed in __all__ (so ruff F401 is satisfied and the export is real).
    exported = {
        "OAuth1TokenManager": OAuth1TokenManager,
        "OAuth2TokenManager": OAuth2TokenManager,
        "PersistableAuthProfile": PersistableAuthProfile,
        "TokenState": TokenState,
        "TokenStatus": TokenStatus,
    }
    for name, obj in exported.items():
        assert name in ac.__all__
        assert getattr(ac, name) is obj

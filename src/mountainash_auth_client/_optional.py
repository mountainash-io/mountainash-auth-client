"""Centralised lazy loading of optional connection dependencies.

Some connections need third-party packages that ship only with a packaging
extra (e.g. authlib via the ``[oauth1]`` extra). Import them through
:func:`require` so the lazy-import and the "missing extra" error message live
in exactly one place instead of being copied into every call site.
"""
from __future__ import annotations

import importlib
from typing import Any

_DISTRIBUTION = "mountainash-auth-client"


def require(module: str, *attrs: str, extra: str, feature: str) -> Any:
    """Import an optional dependency, or raise a consistent install hint.

    Args:
        module: Dotted module path to import, e.g.
            ``"authlib.integrations.httpx_client"``.
        *attrs: Attribute names to pull from the module. With none, the module
            is returned; with one, that attribute; with several, a tuple in the
            order given.
        extra: The packaging extra that provides the dependency, e.g. ``"oauth1"``.
        feature: Human-readable capability name for the error, e.g. ``"OAuth1"``.

    Raises:
        ImportError: If the dependency (i.e. the extra) is not installed.
    """
    try:
        mod = importlib.import_module(module)
    except ImportError as exc:
        package = module.split(".", 1)[0]
        raise ImportError(
            f"{feature} requires {package}: pip install {_DISTRIBUTION}[{extra}]"
        ) from exc

    if not attrs:
        return mod
    resolved = tuple(getattr(mod, name) for name in attrs)
    return resolved[0] if len(resolved) == 1 else resolved


def require_authlib(*attrs: str) -> Any:
    """Load symbols from authlib's httpx client, behind the ``[oauth1]`` extra."""
    return require(
        "authlib.integrations.httpx_client",
        *attrs,
        extra="oauth1",
        feature="OAuth1",
    )


def require_paramiko(*attrs: str) -> Any:
    """Load paramiko (or named attributes), behind the ``[sftp]`` extra."""
    return require(
        "paramiko",
        *attrs,
        extra="sftp",
        feature="SSH key/Kerberos auth",
    )

"""Shared precedence logic for resolving a callback-server factory."""
from __future__ import annotations

import typing as t

from .callback import LocalCallbackServer
from .manual import ManualCallbackServer

if t.TYPE_CHECKING:
    from ..protocols import CallbackServerFactory


def resolve_callback_factory(
    *,
    redirect_mode: str,
    callback_server: CallbackServerFactory | None,
    instance_default: CallbackServerFactory | None,
    callback_port: int | None = None,
    manual_redirect_uri: str | None = None,
) -> CallbackServerFactory:
    """Resolve the callback-server factory to use for one authorize() call.

    Precedence: explicit per-call ``callback_server`` -> flow ``instance_default``
    -> built-in selected by ``redirect_mode``. A ``callback_server`` (per-call or
    construction default) shadows ``redirect_mode`` entirely.
    """
    if callback_server is not None:
        return callback_server
    if instance_default is not None:
        return instance_default
    if redirect_mode == "manual":
        if manual_redirect_uri is not None:
            return lambda: ManualCallbackServer(redirect_uri=manual_redirect_uri)
        return ManualCallbackServer
    port = callback_port or 0
    return lambda: LocalCallbackServer(port=port)

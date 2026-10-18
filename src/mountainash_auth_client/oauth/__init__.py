"""Connection infrastructure — OAuth flows, callback servers, token lifecycle."""
from __future__ import annotations

from .oauth1.flow import OAuth1Flow
from .oauth2.flow import OAuth2Context, OAuthFlow
from .protocols import CallbackServerFactory, CallbackServerProtocol
from .server.callback import LocalCallbackServer
from .server.manual import ManualCallbackServer, extract_code_from_input, prompt_for_code

__all__ = [
    "CallbackServerFactory",
    "CallbackServerProtocol",
    "LocalCallbackServer",
    "ManualCallbackServer",
    "OAuth1Flow",
    "OAuth2Context",
    "OAuthFlow",
    "extract_code_from_input",
    "prompt_for_code",
]

"""Connection infrastructure — OAuth flows, callback servers, token lifecycle."""
from __future__ import annotations

from .oauth1.flow import OAuth1Flow
from .oauth1.connection import OAuth1Connection
from .oauth2.flow import OAuthFlow
from .oauth2.connection import OAuth2Connection
from .protocols import CallbackServerFactory, CallbackServerProtocol
from .server.callback import LocalCallbackServer
from .server.manual import ManualCallbackServer, extract_code_from_input, prompt_for_code

__all__ = [
    "CallbackServerFactory",
    "CallbackServerProtocol",
    "LocalCallbackServer",
    "ManualCallbackServer",
    "OAuth1Connection",
    "OAuth1Flow",
    "OAuth2Connection",
    "OAuthFlow",
    "extract_code_from_input",
    "prompt_for_code",
]

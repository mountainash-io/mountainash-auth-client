"""Protocol for OAuth callback collectors."""
from __future__ import annotations

import typing as t


@t.runtime_checkable
class CallbackServerProtocol(t.Protocol):
    """Interface for OAuth callback collectors.

    An implementation knows the redirect URI to advertise in the authorize
    request, and how to present that request to the user and return the raw
    callback query parameters.
    """

    @property
    def port(self) -> int | None:
        """Bound TCP port, or None when there is no port (manual/remote)."""
        ...

    @property
    def redirect_uri(self) -> str:
        """Redirect URI to embed in the authorization request."""
        ...

    def obtain_callback(self, authorize_url: str) -> dict[str, str]:
        """Present ``authorize_url`` to the user, then block until the OAuth
        callback parameters are available and return them as a flat, raw
        ``{key: value}`` dict. Must release any acquired resources before
        returning OR raising. Validation is the flow's responsibility."""
        ...


CallbackServerFactory = t.Callable[[], CallbackServerProtocol]

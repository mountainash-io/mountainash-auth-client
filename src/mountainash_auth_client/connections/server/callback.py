from __future__ import annotations

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        self.server._callback_params = {k: v[0] for k, v in params.items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Authorization complete.</h1>"
                         b"<p>You can close this window.</p></body></html>")

    def log_message(self, format, *args) -> None:
        pass


class LocalCallbackServer:
    """Ephemeral HTTP server that captures a single OAuth callback."""

    def __init__(self, port: int = 0, timeout: int = 120) -> None:
        self._server = HTTPServer(("localhost", port), _CallbackHandler)
        self._server._callback_params = None
        self._timeout = timeout

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def redirect_uri(self) -> str:
        return f"http://localhost:{self.port}/callback"

    def wait_for_callback(self) -> dict[str, str]:
        """Block until a callback is received or timeout expires."""
        self._server.timeout = self._timeout
        self._server.handle_request()
        if self._server._callback_params is None:
            raise TimeoutError("No callback received within timeout")
        try:
            return self._server._callback_params
        finally:
            self._server.server_close()

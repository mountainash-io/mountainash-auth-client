from __future__ import annotations

import ipaddress
import socket
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from mountainash_auth_client.errors import CallbackTimeoutError


class _CallbackHTTPServer(HTTPServer):
    _callback_params: dict[str, str] | None = None
    callback_path: str = "/callback"

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.timeout)
        return connection, address


class _IPv6CallbackHTTPServer(_CallbackHTTPServer):
    address_family = socket.AF_INET6


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _CallbackHTTPServer

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != self.server.callback_path:
            self.send_error(404)
            return
        params = parse_qs(parsed.query, keep_blank_values=True)
        self.server._callback_params = {k: v[0] for k, v in params.items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><body><h1>Authorization complete.</h1>" b"<p>You can close this window.</p></body></html>"
        )

    def log_message(self, format, *args) -> None:
        pass


class LocalCallbackServer:
    """Ephemeral HTTP server that captures a single OAuth callback."""

    def __init__(
        self, port: int = 0, timeout: int = 120, *,
        host: str = "localhost", path: str = "/callback",
    ) -> None:
        if host != "localhost" and not ipaddress.ip_address(host).is_loopback:
            raise ValueError("Callback host must be a loopback address or localhost")
        if not path.startswith("/") or urlparse(path).path != path:
            raise ValueError("Callback path must be an absolute URL path without query or fragment")
        server_type = _IPv6CallbackHTTPServer if ":" in host else _CallbackHTTPServer
        self._server = server_type((host, port), _CallbackHandler)
        self._server._callback_params = None
        self._server.callback_path = path
        self._timeout = timeout
        self._host = host
        self._path = path

    @property
    def port(self) -> int | None:
        return self._server.server_address[1]

    @property
    def redirect_uri(self) -> str:
        host = f"[{self._host}]" if ":" in self._host else self._host
        return f"http://{host}:{self.port}{self._path}"

    def wait_for_callback(self) -> dict[str, str]:
        """Wait against one total deadline, including unrelated HTTP requests."""
        deadline = time.monotonic() + self._timeout
        try:
            while self._server._callback_params is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CallbackTimeoutError("No callback received within timeout")
                self._server.timeout = remaining
                self._server.handle_request()
            return self._server._callback_params
        finally:
            self._server.server_close()

    def obtain_callback(self, authorize_url: str) -> dict[str, str]:
        """Present the authorization URL and release the socket on every exit."""
        try:
            if not webbrowser.open(authorize_url):
                print(f"Open this URL to authorize:\n\n  {authorize_url}\n")
            return self.wait_for_callback()
        finally:
            self._server.server_close()

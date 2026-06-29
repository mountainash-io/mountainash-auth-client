"""Tests for OAuth callback server and manual auth utilities."""
from __future__ import annotations

import threading
import urllib.request


from mountainash_auth_client.oauth.server import LocalCallbackServer, prompt_for_code
from mountainash_auth_client.oauth.server.manual import extract_code_from_input


class TestLocalCallbackServer:
    def test_port_is_assigned(self):
        server = LocalCallbackServer(port=0)
        assert server.port > 0

    def test_redirect_uri_format(self):
        server = LocalCallbackServer(port=0)
        assert server.redirect_uri == f"http://localhost:{server.port}/callback"

    def test_receives_callback_with_code(self):
        server = LocalCallbackServer(port=0, timeout=5)
        port = server.port

        def send_request():
            url = f"http://localhost:{port}/callback?code=auth_code_123&state=mystate"
            try:
                urllib.request.urlopen(url, timeout=3)
            except Exception:
                pass

        t = threading.Thread(target=send_request)
        t.start()
        params = server.wait_for_callback()
        t.join(timeout=5)

        assert params["code"] == "auth_code_123"
        assert params["state"] == "mystate"

    def test_callback_returns_html_response(self):
        server = LocalCallbackServer(port=0, timeout=5)
        port = server.port

        response_body = []

        def send_request():
            url = f"http://localhost:{port}/callback?code=xyz"
            try:
                resp = urllib.request.urlopen(url, timeout=3)
                response_body.append(resp.read())
            except Exception:
                pass

        t = threading.Thread(target=send_request)
        t.start()
        server.wait_for_callback()
        t.join(timeout=5)

        assert len(response_body) > 0
        assert b"Authorization complete" in response_body[0]


class TestExtractCodeFromInput:
    def test_bare_code(self):
        result = extract_code_from_input("myauthcode123")
        assert result == {"code": "myauthcode123"}

    def test_bare_code_stripped(self):
        result = extract_code_from_input("  myauthcode123  ")
        assert result == {"code": "myauthcode123"}

    def test_full_redirect_url_with_code_and_state(self):
        url = "http://localhost:8080/callback?code=abc123&state=xyz"
        result = extract_code_from_input(url)
        assert result["code"] == "abc123"
        assert result["state"] == "xyz"

    def test_full_redirect_url_code_only(self):
        url = "http://localhost:8080/callback?code=abc123"
        result = extract_code_from_input(url)
        assert result["code"] == "abc123"
        assert "state" not in result

    def test_https_redirect_url(self):
        url = "https://myapp.example.com/callback?code=def456&state=statetoken"
        result = extract_code_from_input(url)
        assert result["code"] == "def456"
        assert result["state"] == "statetoken"

    def test_oauth1_callback_url_extracts_verifier_and_token(self):
        url = "http://localhost:8080/callback?oauth_token=tok123&oauth_verifier=ver456"
        result = extract_code_from_input(url)
        assert result["oauth_verifier"] == "ver456"
        assert result["oauth_token"] == "tok123"


class TestPromptForCode:
    def test_prompt_for_code_is_callable(self):
        assert callable(prompt_for_code)

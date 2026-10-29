from __future__ import annotations

from urllib.parse import urlparse, parse_qs


def extract_code_from_input(user_input: str) -> dict[str, str]:
    """Parse authorization code from user input (URL or bare code)."""
    user_input = user_input.strip()
    if user_input.startswith("http"):
        parsed = urlparse(user_input)
        params = parse_qs(parsed.query, keep_blank_values=True)
        return {key: values[0] for key, values in params.items()}
    return {"code": user_input}


def prompt_for_code(authorize_url: str) -> dict[str, str]:
    """Print auth URL and prompt user for the callback URL or code."""
    print(f"\nOpen this URL in your browser to authorize:\n\n  {authorize_url}\n")
    user_input = input("Paste the redirect URL or authorization code: ")
    return extract_code_from_input(user_input)


class ManualCallbackServer:
    """Out-of-band manual callback: prints the URL and reads the redirect/code.

    ``redirect_uri`` is parameterized because the OOB token differs by protocol:
    OAuth2 uses ``urn:ietf:wg:oauth:2.0:oob`` (the default); OAuth1 uses ``oob``.
    """

    DEFAULT_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"

    def __init__(self, redirect_uri: str | None = None) -> None:
        self._redirect_uri = redirect_uri or self.DEFAULT_REDIRECT_URI

    @property
    def port(self) -> int | None:
        return None

    @property
    def redirect_uri(self) -> str:
        return self._redirect_uri

    def obtain_callback(self, authorize_url: str) -> dict[str, str]:
        return prompt_for_code(authorize_url)

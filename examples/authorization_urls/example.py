"""Inspect authorization identity and PKCE without opening a callback server."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from mountainash_auth_client import OAuth2ProviderProfile, OAuthFlow


def main() -> None:
    provider = OAuth2ProviderProfile(
        NAME="reports", AUTHORIZE_URL="https://identity.example.com/authorize",
        TOKEN_URL="https://identity.example.com/token", BASE_URL="https://files.example.com",
        DEFAULT_SCOPE="reports.read", USE_PKCE=True, TOKEN_ENDPOINT_AUTH_METHOD="none",
    )
    flow = OAuthFlow(provider)
    url, state = flow.build_authorize_url("reports-client", "https://reports.example.com/callback")
    query = parse_qs(urlsplit(url).query)
    assert query["client_id"] == ["reports-client"]
    assert query["redirect_uri"] == ["https://reports.example.com/callback"]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["reports.read"]
    assert state and query["state"] == [state]
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["code_challenge"][0]) == 43
    print("Authorization: client=reports-client; scope=reports.read")
    print("State present; PKCE method=S256; no callback opened")


if __name__ == "__main__":
    main()

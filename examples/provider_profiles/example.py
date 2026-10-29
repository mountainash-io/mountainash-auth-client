"""Combine provider configuration and a bearer credential for an HTTP consumer."""
from __future__ import annotations

import httpx

from mountainash_auth_client import OAuth2ProviderProfile, TargetFamily, TokenAuthProfile


def main() -> None:
    provider = OAuth2ProviderProfile(
        NAME="reports", AUTHORIZE_URL="https://identity.example.com/authorize",
        TOKEN_URL="https://identity.example.com/token", BASE_URL="https://files.example.com",
        DEFAULT_SCOPE="reports.read",
    )
    auth = TokenAuthProfile(TOKEN="example-report-token")
    base = provider.emit(TargetFamily.HTTP, base={"timeout": 10})
    kwargs = auth.emit(TargetFamily.HTTP, base=base)
    with httpx.Client(**kwargs) as client:
        request = client.build_request("GET", "/sales.csv")

    assert str(request.url) == "https://files.example.com/sales.csv"
    assert request.headers["Authorization"] == "Bearer example-report-token"
    assert base == {"timeout": 10, "base_url": "https://files.example.com"}
    print(f"Provider: {provider.NAME}; scope: {provider.DEFAULT_SCOPE}")
    print(f"Resource: {request.url}; bearer credential attached")


if __name__ == "__main__":
    main()

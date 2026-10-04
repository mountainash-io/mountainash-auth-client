"""Sign an HTTP request with real Authlib, delivered to an in-process endpoint."""
from __future__ import annotations

import httpx

from mountainash_auth_client import OAuth1AuthProfile, TargetFamily


def main() -> None:
    auth = OAuth1AuthProfile(
        CONSUMER_KEY="reports-client", CONSUMER_SECRET="example-client-secret",
        ACCESS_TOKEN="example-report-token", ACCESS_TOKEN_SECRET="example-token-secret",
    )
    requests: list[httpx.Request] = []

    def endpoint(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, text="region,total\nnorth,120\n")

    kwargs = auth.emit(TargetFamily.HTTP)
    with httpx.Client(transport=httpx.MockTransport(endpoint), **kwargs) as client:
        response = client.get("https://files.example.com/sales.csv")

    assert response.text == "region,total\nnorth,120\n"
    assert len(requests) == 1
    authorization = requests[0].headers["Authorization"]
    assert authorization.startswith("OAuth ")
    assert 'oauth_consumer_key="reports-client"' in authorization
    assert 'oauth_token="example-report-token"' in authorization
    assert 'oauth_signature="' in authorization
    print("GET /sales.csv: OAuth1 signature attached")
    print("In-process response: north,120")


if __name__ == "__main__":
    main()

"""Acquire a permitted cached token, sign out, then remove registration locally."""
from __future__ import annotations

from mountainash_settings.secrets import MemorySecretStore, NamespacedSecretStore

from mountainash_auth_client import (
    AuthorizationRequired, OAuth2AuthProfile, OAuth2ProviderProfile,
    OAuth2TokenManager, OAuthFlow, TargetFamily, TokenAuthProfile, TokenCredential,
)


class ReportCredentials(OAuth2AuthProfile):
    def persist_key(self) -> str:
        return "reports_app.report_user"


class ReportFlow(OAuthFlow):
    def validate_credential(self, credential: TokenCredential) -> None:
        if "reports.read" not in (credential.scope or "").split():
            raise PermissionError("Missing reports.read permission")


def main() -> None:
    provider = OAuth2ProviderProfile(
        NAME="reports", AUTHORIZE_URL="https://identity.example.com/authorize",
        TOKEN_URL="https://identity.example.com/token", BASE_URL="https://files.example.com",
        TOKEN_ENDPOINT_AUTH_METHOD="none",
    )
    auth = ReportCredentials(CLIENT_ID="reports-client", SCOPE="reports.read")
    store = MemorySecretStore()
    # Seed only for this offline example. Normal authorization writes this record.
    records = NamespacedSecretStore(store, "oauth")
    with records.transaction(auth.persist_key()):
        records.set(auth.persist_key(), {
            "access_token": "example-report-token", "scope": "reports.read",
            "client_id": "issued-report-client", "registration": {"account": "report_user"},
        })

    manager = OAuth2TokenManager(provider, auth, token_store=store, flow_factory=ReportFlow)  # RAW store
    credential = manager.acquire()
    kwargs = TokenAuthProfile(TOKEN=credential.access_token).emit(TargetFamily.HTTP)
    assert kwargs["headers"]["Authorization"] == "Bearer example-report-token"
    assert credential.expires_at is None
    assert credential.scope == "reports.read"
    assert credential.client_id == "issued-report-client"
    print("Cached token: acquired and rendered for HTTP")

    result = manager.sign_out()  # default flow has no remote revocation support
    assert result.remote_confirmed is False
    assert records.get(auth.persist_key())["registration"] == {"account": "report_user"}
    try:
        manager.acquire()
    except AuthorizationRequired:
        print("After sign-out: authorization required; registration retained")
    else:
        raise AssertionError("Removed token was still acquired")
    manager.revoke()  # local-only deletion also removes registration
    assert records.get(auth.persist_key()) is None


if __name__ == "__main__":
    main()

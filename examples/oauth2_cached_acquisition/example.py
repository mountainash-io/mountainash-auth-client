"""Acquire a synthetic cached token, then handle local token removal."""
from __future__ import annotations

from mountainash_settings.secrets import MemorySecretStore, NamespacedSecretStore

from mountainash_auth_client import (
    AuthorizationRequired, OAuth2AuthProfile, OAuth2ProviderProfile,
    OAuth2TokenManager, TargetFamily, TokenAuthProfile,
)


class ReportCredentials(OAuth2AuthProfile):
    def persist_key(self) -> str:
        return "reports_app.report_user"


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
        records.set(auth.persist_key(), {"access_token": "example-report-token"})

    manager = OAuth2TokenManager(provider, auth, token_store=store)  # pass the RAW store
    credential = manager.acquire()
    kwargs = TokenAuthProfile(TOKEN=credential.access_token).emit(TargetFamily.HTTP)
    assert kwargs["headers"]["Authorization"] == "Bearer example-report-token"
    assert credential.expires_at is None
    print("Cached token: acquired and rendered for HTTP")

    manager.revoke()  # local removal, not a provider revocation request
    try:
        manager.acquire()
    except AuthorizationRequired:
        print("After local removal: authorization required")
    else:
        raise AssertionError("Removed token was still acquired")


if __name__ == "__main__":
    main()

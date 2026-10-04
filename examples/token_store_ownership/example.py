"""Keep a filesystem token store open while borrowing it, then reopen it."""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from mountainash_settings.secrets import FilesystemBackend, NamespacedSecretStore

from mountainash_auth_client import OAuth2AuthProfile, OAuth2ProviderProfile, OAuth2TokenManager


class ReportCredentials(OAuth2AuthProfile):
    def persist_key(self) -> str:
        return "reports_app.report_user"


def main() -> None:
    provider = OAuth2ProviderProfile(
        NAME="reports", AUTHORIZE_URL="https://identity.example.com/authorize",
        TOKEN_URL="https://identity.example.com/token", BASE_URL="https://files.example.com",
    )
    auth = ReportCredentials(CLIENT_ID="reports-client")
    with TemporaryDirectory() as directory:
        root = Path(directory)  # application provisions the root before opening a store
        with FilesystemBackend(root) as store:
            records = NamespacedSecretStore(store, "oauth")
            with records.transaction(auth.persist_key()):
                records.set(auth.persist_key(), {"access_token": "example-report-token"})
            manager = OAuth2TokenManager(provider, auth, token_store=store)
            assert manager.acquire().access_token == "example-report-token"
            assert store.get(auth.persist_key()) is None  # no unnamespaced record
            print("Open store: namespaced token acquired")

        with FilesystemBackend(root) as reopened:
            manager = OAuth2TokenManager(provider, auth, token_store=reopened)
            assert manager.acquire().access_token == "example-report-token"
            print("Reopened store: persisted token acquired")
    print("Stores closed; temporary directory removed")


if __name__ == "__main__":
    main()

"""Select a configuration secret reader separately from acquired token storage."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from mountainash_settings.secrets import MemorySecretStore, NamespacedSecretStore

from mountainash_auth_client import (
    OAuth2AuthProfile, OAuth2ProviderProfile, OAuth2TokenManager, TargetFamily, TokenAuthProfile,
)

HERE = Path(__file__).resolve().parent


class ReportCredentials(OAuth2AuthProfile):
    def persist_key(self) -> str:
        return "reports_app.report_user"


def main() -> None:
    config_store = MemorySecretStore()
    config_reader = NamespacedSecretStore(config_store, "reports_app")
    with config_reader.transaction("client"):
        config_reader.set("client", {"secret": "example-client-secret"})

    provider = OAuth2ProviderProfile(
        config_files=[HERE / "provider.toml"], env_prefix="REPORT_PROVIDER_",
    )
    auth = ReportCredentials(
        config_files=[HERE / "auth.yaml"], env_prefix="REPORT_AUTH_", secret_store=config_reader,
    )
    assert auth.CLIENT_ID == "reports-client"
    assert auth.CLIENT_SECRET is not None
    assert auth.CLIENT_SECRET.get_secret_value() == "example-client-secret"

    # Offline fixture: normal authorization writes the acquired token to this store.
    token_store = MemorySecretStore()
    records = NamespacedSecretStore(token_store, "oauth")
    with records.transaction(auth.persist_key()):
        records.set(auth.persist_key(), {"access_token": "example-report-token"})
    manager = OAuth2TokenManager(provider, auth, token_store=token_store)
    credential = manager.acquire()
    options = TokenAuthProfile(TOKEN=credential.access_token).emit(
        TargetFamily.HTTP, base=provider.emit(TargetFamily.HTTP),
    )
    assert options == {
        "base_url": "https://files.example.com",
        "headers": {"Authorization": "Bearer example-report-token"},
    }
    assert config_store.get("reports_app.client") == {"secret": "example-client-secret"}
    assert token_store.get("reports_app.client") is None
    assert config_store.get("oauth.reports_app.report_user") is None

    display = deepcopy(options)
    display["headers"]["Authorization"] = "<redacted>"
    print(f"Provider: {provider.NAME}; client: {auth.CLIENT_ID}")
    print("Configuration reader: client secret resolved")
    print("Token store: cached access token acquired")
    print("Resource options:")
    print(json.dumps(display, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

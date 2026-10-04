"""Render one configured token for HTTP and a consumer-specific SDK object."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path

from mountainash_settings.secrets import MemorySecretStore

from mountainash_auth_client import TargetFamily, TokenAuthProfile

HERE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class ReportCredential:
    """Illustrative SDK-owned credential shape, distinct from an auth profile."""

    access_key: str = field(repr=False)
    scheme: str = "bearer"


def report_credential(auth: TokenAuthProfile) -> ReportCredential:
    """Consumer-owned adapter: SDK vocabulary stays out of the generic profile."""
    return ReportCredential(access_key=auth.TOKEN.get_secret_value())


def main() -> None:
    store = MemorySecretStore()
    with store.transaction("reports"):
        store.set("reports", {"access_token": "example-report-token"})
    auth = TokenAuthProfile(
        config_files=[HERE / "auth.yaml"], env_prefix="REPORT_AUTH_", secret_store=store,
    )
    http_options = auth.emit(TargetFamily.HTTP)
    sdk_credential = report_credential(auth)
    assert http_options == {"headers": {"Authorization": "Bearer example-report-token"}}
    assert sdk_credential.access_key == "example-report-token"
    assert sdk_credential.scheme == "bearer"
    assert "example-report-token" not in repr(sdk_credential)

    # Redact a display projection; neither the SDK object nor the HTTP options change.
    display = {
        "http": {**http_options, "headers": {**http_options["headers"], "Authorization": "<redacted>"}},
        "report_sdk": {"credential": {"access_key": "<redacted>", "scheme": sdk_credential.scheme}},
    }
    print("One token, two consumer shapes:")
    print(json.dumps(display, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

"""Compose an application-owned endpoint adapter with built-in auth rendering."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from mountainash_settings import Profile, ProfileField

from mountainash_auth_client import TargetFamily, TokenAuthProfile

HERE = Path(__file__).resolve().parent


def report_client_options(profile: ReportEndpoint, kwargs: dict) -> dict:
    """Move emitted endpoint fields into the report client's nested shape."""
    result = dict(kwargs)
    session = dict(result.get("session", {}))
    session["base_url"] = result.pop("base_url")
    session["timeout"] = result.pop("timeout")
    session["headers"] = {
        **session.get("headers", {}), "X-Report-App": profile.APPLICATION,
    }
    result["session"] = session
    result["retry"] = {**result.get("retry", {}), "attempts": result.pop("attempts")}
    return result


class ReportEndpoint(Profile, name="report_endpoint", provider_type="report_client"):
    BASE_URL: str = ProfileField(driver_key={"report_client": "base_url"})
    TIMEOUT: int = ProfileField(driver_key={"report_client": "timeout"}, gt=0)
    ATTEMPTS: int = ProfileField(driver_key={"report_client": "attempts"}, ge=1)
    APPLICATION: str = ProfileField(driver_key=None)
    __adapters__ = {"report_client": report_client_options}


def authenticated_options(endpoint: ReportEndpoint, auth: TokenAuthProfile, base: dict) -> dict:
    """The consumer knows which part of its envelope represents the HTTP session."""
    options = endpoint.emit("report_client", base=base)
    return {**options, "session": auth.emit(TargetFamily.HTTP, base=options["session"])}


def main() -> None:
    endpoint = ReportEndpoint(config_files=[HERE / "endpoint.yaml"], env_prefix="REPORT_ENDPOINT_")
    auth = TokenAuthProfile(config_files=[HERE / "auth.toml"], env_prefix="REPORT_AUTH_")
    base = {
        "session": {"timeout": 5, "headers": {"Accept": "text/csv"}},
        "retry": {"attempts": 1},
    }
    original = deepcopy(base)
    options = authenticated_options(endpoint, auth, base)
    assert options == {
        "session": {
            "base_url": "https://files.example.com", "timeout": 15,
            "headers": {
                "Accept": "text/csv", "X-Report-App": "reports_app",
                "Authorization": "Bearer example-report-token",
            },
        },
        "retry": {"attempts": 3},
    }
    assert base == original
    display = deepcopy(options)
    display["session"]["headers"]["Authorization"] = "<redacted>"
    print("Report client options:")
    print(json.dumps(display, indent=2, sort_keys=True))
    print("Caller options unchanged")


if __name__ == "__main__":
    main()

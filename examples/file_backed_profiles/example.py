"""Load credentials through settings' actual TOML/YAML source precedence."""
from __future__ import annotations

import json
from pathlib import Path

from mountainash_auth_client import PasswordAuthProfile, TargetFamily

HERE = Path(__file__).resolve().parent


def main() -> None:
    defaults = HERE / "defaults.toml"
    deployment = HERE / "production.yaml"
    development = PasswordAuthProfile(config_files=[defaults], env_prefix="REPORT_")
    production = PasswordAuthProfile(config_files=[defaults, deployment], env_prefix="REPORT_")
    reversed_files = PasswordAuthProfile(config_files=[deployment, defaults], env_prefix="REPORT_")
    assert development.USERNAME == "development_user"
    options = production.emit(TargetFamily.PARAMIKO)
    assert options == {"username": "report_user", "password": "example-password"}
    assert reversed_files.emit(TargetFamily.PARAMIKO) == options

    print(f"Default user: {development.USERNAME}")
    print("Deployment SSH options:")
    print(json.dumps({**options, "password": "<redacted>"}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

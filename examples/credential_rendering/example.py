"""Render the same password for HTTP and SSH without opening connections."""
from __future__ import annotations

from mountainash_auth_client import NoAuthProfile, PasswordAuthProfile, TargetFamily


def main() -> None:
    auth = PasswordAuthProfile(USERNAME="report_user", PASSWORD="example-password")
    base = {"headers": {"Accept": "text/csv"}, "timeout": 10}
    http = auth.emit(TargetFamily.HTTP, base=base)
    ssh = auth.emit(TargetFamily.PARAMIKO)

    assert http["headers"]["Authorization"] == "Basic cmVwb3J0X3VzZXI6ZXhhbXBsZS1wYXNzd29yZA=="
    assert http["headers"]["Accept"] == "text/csv"
    assert ssh == {"username": "report_user", "password": "example-password"}
    assert base == {"headers": {"Accept": "text/csv"}, "timeout": 10}
    assert NoAuthProfile().emit(TargetFamily.HTTP, base=base) == base
    print("HTTP: Basic credential attached; Accept preserved")
    print("SSH: username and password supplied; base unchanged")


if __name__ == "__main__":
    main()

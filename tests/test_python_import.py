from __future__ import annotations

import mountainash_auth_client
from mountainash_auth_client.constants import CONST_AUTH_PROFILES


def test_base_package_and_enum_import_on_supported_python() -> None:
    assert mountainash_auth_client.CONST_AUTH_PROFILES is CONST_AUTH_PROFILES
    assert CONST_AUTH_PROFILES.AZURE_AD == "azure_ad"
    assert str(CONST_AUTH_PROFILES.SERVICE_ACCOUNT) == "service_account"

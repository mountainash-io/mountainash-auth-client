"""W8 safe-location rendering through both public token-error constructors."""
from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from mountainash_auth_client.errors import TokenExchangeError, TokenRefreshError
from tests._error_surfaces import exception_surfaces

# Shared across packages (spec section 5.1): keep identical to the other packages' copies.
RENDERING = [
    # scheme:// — scheme, host, port, path only
    ("https://SENTU:SENTP@h:8443/a/x.csv?sig=SENTQ#SENTF", "https://h:8443/a/x.csv"),
    ("https://SENTU:pa@SENTP@host/x.csv", "https://host/x.csv"),
    ("https://SENTU:SENTP@[::1]:8443/d/x.csv", "https://[::1]:8443/d/x.csv"),
    ("https://host/a@b/x.csv", "https://host/a@b/x.csv"),
    ("https://host/x.csv#access_token=SENTF", "https://host/x.csv"),
    ("https://host/x.csv?SENTQ", "https://host/x.csv"),
    ("https://host/x.csv#f?tok=SENTQ", "https://host/x.csv"),
    ("https://h#SENTF@x/y", "https://h"),
    ("https://h?SENTQ@x/y", "https://h"),
    ("https://host", "https://host"),
    ("s3://bucket/x.csv", "s3://bucket/x.csv"),
    ("file:///tmp/x.csv", "file:///tmp/x.csv"),
    ("HTTPS://SENTU:SENTP@host/x.csv", "HTTPS://host/x.csv"),
    ("postgresql+psycopg://SENTU:SENTP@db/name", "postgresql+psycopg://db/name"),
    # //network path
    ("//SENTU:SENTP@host/x.csv", "//host/x.csv"),
    # whitespace / control characters, as urllib reads them
    (" \thttps://SENTU:SENTP@host/x.csv", "https://host/x.csv"),
    ("https://SENTU:SENTP@ho\nst/x.csv", "https://host/x.csv"),
    ("https://SENTU:SENTP@ho\rst/x.csv", "https://host/x.csv"),
    ("ht\ttps://SENTU:SENTP@host/x.csv", "https://host/x.csv"),
    ("\x00https://SENTU:SENTP@host/x.csv", "https://host/x.csv"),
    ("\x1fhttps://SENTU:SENTP@host/x.csv", "https://host/x.csv"),
    # other scheme strings
    ("https:/SENTU:SENTP@host/x.csv", "***"),
    ("s3:SENTU:SENTP@bucket/x.csv", "***"),
    ("SENTU:SENTP@host/x.csv", "***"),
    ("a:SENTP@host/x.csv", "***"),
    # local paths
    ("/data/x.csv", "/data/x.csv"),
    ("data/x.csv", "data/x.csv"),
    ("/srv/team@corp/x.csv", "/srv/team@corp/x.csv"),
    ("relative/a:b@c/x.csv", "relative/a:b@c/x.csv"),
    ("C:/d/x.csv", "C:/d/x.csv"),
    ("C:\\d\\x.csv", "C:\\d\\x.csv"),
]


@pytest.mark.parametrize("kind", [TokenExchangeError, TokenRefreshError])
@pytest.mark.parametrize(("location", "shown"), RENDERING)
def test_token_error_shows_safe_location(kind, location, shown):
    error = kind(url=location, status_code=400, body="")
    assert error.url == shown
    assert shown in str(error)
    assert "SENT" not in exception_surfaces(error)


def test_safe_location_accepts_pathlike():
    from mountainash_auth_client._safe_errors import safe_location

    assert safe_location(PurePosixPath("/data/x.csv")) == "/data/x.csv"

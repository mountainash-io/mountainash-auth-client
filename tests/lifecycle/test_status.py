from __future__ import annotations

from mountainash_auth_client.lifecycle.status import (
    TokenState,
    TokenStatus,
    classify_oauth2,
)

NOW = 1_000_000


def test_missing_when_record_none():
    assert classify_oauth2(None, now=NOW) == TokenStatus(TokenState.MISSING)


def test_valid_when_no_expiry():
    s = classify_oauth2({"access_token": "a", "refresh_token": "r"}, now=NOW)
    assert s.state is TokenState.VALID
    assert s.expires_at is None
    assert s.has_refresh_token is True


def test_valid_well_before_buffer():
    s = classify_oauth2({"access_token": "a", "token_expires_at": NOW + 4000}, now=NOW)
    assert s.state is TokenState.VALID
    assert s.expires_in_seconds == 4000
    assert s.has_refresh_token is False


def test_refresh_needed_inside_buffer():
    s = classify_oauth2(
        {"access_token": "a", "refresh_token": "r", "token_expires_at": NOW + 100},
        buffer_seconds=300,
        now=NOW,
    )
    assert s.state is TokenState.REFRESH_NEEDED
    assert s.expires_in_seconds == 100
    assert s.has_refresh_token is True


def test_expired_at_or_past_expiry():
    s = classify_oauth2({"access_token": "a", "token_expires_at": NOW}, now=NOW)
    assert s.state is TokenState.EXPIRED
    assert s.expires_at == NOW

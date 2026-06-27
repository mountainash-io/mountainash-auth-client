from mountainash_auth_client.errors import TokenExchangeError, TokenRefreshError


def test_str_excludes_body_but_attr_keeps_it():
    err = TokenRefreshError(url="https://t", status_code=401, body='{"error":"invalid_grant","secret":"xyz"}')
    assert "xyz" not in str(err)
    assert "invalid_grant" not in str(err)        # body fully off the message
    assert err.body == '{"error":"invalid_grant","secret":"xyz"}'
    assert err.error_code == "invalid_grant"      # parsed for programmatic use


def test_error_code_none_for_non_json_body():
    assert TokenRefreshError(url="https://t", status_code=500, body="upstream 500").error_code is None


def test_exchange_error_str_excludes_body_but_attr_keeps_it():
    # TokenExchangeError shares the ctor redaction logic; assert it directly, not just
    # indirectly via the errors-module rewrite.
    err = TokenExchangeError(url="https://t", status_code=400, body='{"error":"invalid_request","secret":"xyz"}')
    assert "xyz" not in str(err)
    assert "invalid_request" not in str(err)      # body fully off the message
    assert err.body == '{"error":"invalid_request","secret":"xyz"}'
    assert err.error_code == "invalid_request"    # parsed for programmatic use


def test_exchange_error_code_none_for_non_json_body():
    assert TokenExchangeError(url="https://t", status_code=500, body="upstream 500").error_code is None

from mountainash_auth_client.errors import TokenRefreshError


def test_str_excludes_body_but_attr_keeps_it():
    err = TokenRefreshError(url="https://t", status_code=401, body='{"error":"invalid_grant","secret":"xyz"}')
    assert "xyz" not in str(err)
    assert "invalid_grant" not in str(err)        # body fully off the message
    assert err.body == '{"error":"invalid_grant","secret":"xyz"}'
    assert err.error_code == "invalid_grant"      # parsed for programmatic use


def test_error_code_none_for_non_json_body():
    assert TokenRefreshError(url="https://t", status_code=500, body="upstream 500").error_code is None

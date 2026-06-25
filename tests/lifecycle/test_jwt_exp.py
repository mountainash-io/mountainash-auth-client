import base64, json
from mountainash_auth_client.lifecycle.status import jwt_exp


def _jwt(payload):
    def seg(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg':'ES256'})}.{seg(payload)}.{seg({'s':'x'})}"


def test_jwt_exp_reads_exp():
    assert jwt_exp(_jwt({"exp": 1900000000})) == 1900000000


def test_jwt_exp_none_for_opaque_or_missing():
    assert jwt_exp("opaque-token") is None
    assert jwt_exp(_jwt({"sub": "u"})) is None

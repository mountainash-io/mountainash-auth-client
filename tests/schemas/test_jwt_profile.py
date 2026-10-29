import base64
import json
import pytest
from mountainash_auth_client.schemas.token import JWTAuthProfile
from mountainash_auth_client.errors import MalformedJWTError


def _jwt(payload: dict) -> str:
    def seg(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg':'ES256','typ':'JWT'})}.{seg(payload)}.{seg({'sig':'x'})}"


def test_claims_and_exp_decode():
    p = JWTAuthProfile(TOKEN=_jwt({"sub": "u1", "exp": 1900000000}))
    assert p.claims()["sub"] == "u1"
    assert p.exp == 1900000000


def test_exp_none_when_absent():
    assert JWTAuthProfile(TOKEN=_jwt({"sub": "u1"})).exp is None


def test_non_jwt_raises():
    with pytest.raises(MalformedJWTError):
        JWTAuthProfile(TOKEN="not-a-jwt").claims()

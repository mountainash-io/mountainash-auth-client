"""Consumer-owned OAuth2 adaptation at public wire and acquisition boundaries."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from mountainash_settings.secrets import MemorySecretStore, NamespacedSecretStore

from mountainash_auth_client.errors import AuthorizationDeniedError
from mountainash_auth_client.oauth.lifecycle.oauth2 import OAuth2TokenManager
from mountainash_auth_client.oauth.lifecycle.status import TokenState
from mountainash_auth_client.oauth.oauth2.flow import OAuthFlow
from mountainash_auth_client.oauth.providers.oauth2 import OAuth2ProviderProfile


def provider(**overrides):
    return OAuth2ProviderProfile(**{
        "NAME": "extension", "AUTHORIZE_URL": "https://issuer.example/authorize",
        "TOKEN_URL": "https://issuer.example/token", "BASE_URL": "https://resource.example",
        "TOKEN_ENDPOINT_AUTH_METHOD": "none", "USE_PKCE": True, **overrides,
    })


class Auth:
    CLIENT_ID = "bootstrap"
    CLIENT_SECRET = None
    SCOPE = "openid invoke"

    def persist_key(self):
        return "extension.account"


class ConsumerFlow(OAuthFlow):
    def authorization_parameters(self, context):
        context.data["nonce"] = "nonce-" + context.state
        return {"nonce": context.data["nonce"], "resource": "resource-service"}

    def token_parameters(self, context):
        return {"resource": "resource-service"}

    def process_callback(self, params, context):
        return params["client_id"], {"subject": "account"}

    def validate_token_response(self, response, context, previous, candidate):
        if response.get("id_token") != "trusted-identity":
            raise ValueError("Identity rejected")
        if context.grant_type == "authorization_code":
            assert response["nonce"] == context.data["nonce"]
        candidate["session_metadata"] = {"id_token": response["id_token"]}
        return candidate


def install_endpoint(monkeypatch, endpoint):
    client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda: client(transport=httpx.MockTransport(endpoint)))


def test_callback_issued_identity_nonce_and_raw_response_reach_adapter(monkeypatch):
    authorization = {}
    requests = []

    class Callback:
        redirect_uri = "http://127.0.0.1:19090/auth/callback"

        def obtain_callback(self, url):
            authorization.update({key: values[0] for key, values in parse_qs(urlsplit(url).query).items()})
            return {"state": authorization["state"], "code": "accepted", "client_id": "issued"}

    def endpoint(request):
        requests.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json={
            "access_token": "accepted", "scope": "openid", "id_token": "trusted-identity",
            "nonce": authorization.get("nonce"), "unapproved": "not-retained",
        })

    install_endpoint(monkeypatch, endpoint)
    tokens = ConsumerFlow(provider(), callback_server=Callback).authorize("bootstrap", None, scope="openid invoke")
    assert authorization["resource"] == "resource-service"
    assert requests[0]["client_id"] == ["issued"]
    assert requests[0]["redirect_uri"] == [Callback.redirect_uri]
    assert requests[0]["resource"] == ["resource-service"]
    assert "code_verifier" in requests[0]
    assert tokens["client_id"] == "issued"
    assert tokens["registration"] == {"subject": "account"}
    assert tokens["session_metadata"] == {"id_token": "trusted-identity"}
    assert "unapproved" not in tokens


@pytest.mark.parametrize("field", ["state", "code_challenge", "code_challenge_method", "client_id", "client_secret", "redirect_uri", "response_type"])
def test_authorization_extensions_cannot_override_generated_fields(field):
    class ConflictingFlow(OAuthFlow):
        def authorization_parameters(self, context):
            return {field: "replacement"}

    with pytest.raises(ValueError, match="parameter"):
        ConflictingFlow(provider()).build_authorize_url("client", "http://localhost/callback")


@pytest.mark.parametrize("field", ["grant_type", "code", "code_verifier", "client_id", "client_secret", "redirect_uri", "refresh_token"])
@pytest.mark.parametrize("grant", ["authorization_code", "refresh_token"])
def test_token_extensions_cannot_override_protocol_fields(monkeypatch, field, grant):
    calls = []
    install_endpoint(monkeypatch, lambda request: calls.append(request) or httpx.Response(200, json={"access_token": "unexpected"}))

    class ConflictingFlow(OAuthFlow):
        def token_parameters(self, context):
            return {field: "replacement"}

    flow = ConflictingFlow(provider())
    with pytest.raises(ValueError, match="parameter"):
        if grant == "authorization_code":
            flow.exchange_code("code", "http://localhost/callback", "client")
        else:
            flow.refresh("renewable", "client")
    assert calls == []


@pytest.mark.parametrize("invalid", ["state", "error"])
def test_invalid_callback_never_reaches_registration_hook(invalid):
    registrations = []

    class Flow(OAuthFlow):
        def process_callback(self, params, context):
            registrations.append(params)
            return "issued", {}

    class Callback:
        redirect_uri = "http://localhost/callback"

        def obtain_callback(self, url):
            state = parse_qs(urlsplit(url).query)["state"][0]
            return {"state": "wrong" if invalid == "state" else state, "error": "access_denied"}

    with pytest.raises(ValueError if invalid == "state" else AuthorizationDeniedError):
        Flow(provider(), callback_server=Callback).authorize("client", None)
    assert registrations == []


def test_response_trust_failure_retains_accepted_record(monkeypatch):
    store = MemorySecretStore()
    records = NamespacedSecretStore(store, "oauth")
    prior = {"access_token": "old", "refresh_token": "renewable", "token_expires_at": 1,
             "client_id": "issued", "scope": "openid invoke", "registration": {"subject": "account"}}
    records.set(Auth().persist_key(), prior)
    install_endpoint(monkeypatch, lambda request: httpx.Response(200, json={
        "access_token": "untrusted", "refresh_token": "replacement", "id_token": "wrong-account",
    }))
    with pytest.raises(ValueError, match="Identity rejected"):
        ConsumerFlow(provider(), token_store=store).resolve_access_token(Auth(), force=True)
    assert records.get(Auth().persist_key()) == prior


def test_overlapping_wire_attempts_keep_their_own_nonce(monkeypatch):
    flow = ConsumerFlow(provider())
    first_url, first = flow.build_authorize_url("client", "http://localhost/callback")
    second_url, second = flow.build_authorize_url("client", "http://localhost/callback")
    nonces = [parse_qs(urlsplit(url).query)["nonce"][0] for url in (first_url, second_url)]
    replies = iter(nonces)
    install_endpoint(monkeypatch, lambda request: httpx.Response(200, json={
        "access_token": "accepted", "id_token": "trusted-identity", "nonce": next(replies),
    }))
    for state in (first, second):
        assert flow.exchange_code("code", "http://localhost/callback", "client", state=state)["access_token"] == "accepted"
    assert nonces[0] != nonces[1]


class RequiresInvoke(OAuthFlow):
    def validate_credential(self, credential):
        if "invoke" not in (credential.scope or "").split():
            raise PermissionError("Missing invoke permission")


@pytest.mark.parametrize("api, forced", [
    ("acquire", False), ("access_token", False), ("refresh", True),
    ("resolve_credential", False), ("resolve_access_token", False), ("force_refresh", True),
])
def test_acquisition_policy_cannot_be_bypassed_and_rotation_survives_rejection(monkeypatch, api, forced):
    store = MemorySecretStore()
    records = NamespacedSecretStore(store, "oauth")
    records.set(Auth().persist_key(), {
        "access_token": "cached", "refresh_token": "renewable", "token_expires_at": 4102444800,
        "scope": "openid invoke" if forced else "openid", "client_id": "issued",
    })
    requests = []

    def endpoint(request):
        requests.append(request)
        return httpx.Response(200, json={
            "access_token": "narrowed", "refresh_token": "rotated", "expires_in": 3600, "scope": "openid",
        })

    install_endpoint(monkeypatch, endpoint)
    if api in {"acquire", "access_token", "refresh"}:
        owner = OAuth2TokenManager(provider(), Auth(), token_store=store, flow_factory=RequiresInvoke)
        operation = getattr(owner, api)
    else:
        owner = RequiresInvoke(provider(), token_store=store)
        operation = lambda: getattr(owner, api)(Auth())
    with pytest.raises(PermissionError, match="Missing invoke"):
        operation()
    saved = records.get(Auth().persist_key())
    assert saved["scope"] == "openid"
    assert saved["refresh_token"] == ("rotated" if forced else "renewable")
    assert len(requests) == int(forced)


@pytest.mark.parametrize("api", ["authorize", "resolve_credential", "resolve_access_token"])
def test_new_limited_authorization_persists_before_operation_policy(monkeypatch, api):
    store = MemorySecretStore()
    records = NamespacedSecretStore(store, "oauth")

    class Callback:
        redirect_uri = "http://localhost/callback"

        def obtain_callback(self, url):
            return {"code": "accepted", "state": parse_qs(urlsplit(url).query)["state"][0]}

    install_endpoint(monkeypatch, lambda request: httpx.Response(200, json={
        "access_token": "limited", "refresh_token": "renewable", "scope": "openid",
    }))
    manager = OAuth2TokenManager(provider(), Auth(), token_store=store, callback_server=Callback, flow_factory=RequiresInvoke)
    if api == "authorize":
        assert manager.authorize().state is TokenState.VALID
        with pytest.raises(PermissionError):
            manager.acquire()
    else:
        flow = RequiresInvoke(provider(), token_store=store, callback_server=Callback)
        with pytest.raises(PermissionError):
            getattr(flow, api)(Auth(), auto_authorize=True)
    saved = records.get(Auth().persist_key())
    assert saved["access_token"] == "limited"
    assert saved["refresh_token"] == "renewable"
    assert saved["scope"] == "openid"


def test_local_status_and_revoke_do_not_construct_consumer_flow():
    store = MemorySecretStore()
    store.set("oauth.extension.account", {"access_token": "accepted"})

    def unavailable_factory(*args, **kwargs):
        raise AssertionError("Local operation constructed a network adapter")

    manager = OAuth2TokenManager(provider(), Auth(), token_store=store, flow_factory=unavailable_factory)
    assert manager.status().state is TokenState.VALID
    manager.revoke()
    assert manager.status().state is TokenState.CLEARED


def test_manager_returns_the_snapshot_accepted_by_consumer_policy():
    store = MemorySecretStore()
    store.set("oauth.extension.account", {"access_token": "checked", "scope": "invoke"})

    class ChangingFlow(RequiresInvoke):
        def validate_credential(self, credential):
            super().validate_credential(credential)
            store.set("oauth.extension.account", {"access_token": "not-checked", "scope": "openid"})

    manager = OAuth2TokenManager(provider(), Auth(), token_store=store, flow_factory=ChangingFlow)
    credential = manager.acquire()
    assert credential.access_token == "checked"
    assert credential.scope == "invoke"
    assert store.get("oauth.extension.account")["access_token"] == "not-checked"

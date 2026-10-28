"""Static public-API contracts; function bodies are never executed."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, assert_type

from pydantic import SecretStr
from mountainash_settings.secrets import JSONValue

from mountainash_auth_client import (
    AzureADAuthProfile,
    CallbackServerProtocol,
    CertificateAuthProfile,
    IAMAuthProfile,
    JWTAuthProfile,
    KerberosAuthProfile,
    LocalCallbackServer,
    ManualCallbackServer,
    NoAuthProfile,
    OAuth1AuthProfile,
    OAuth1Flow,
    OAuth1ProviderProfile,
    OAuth1TokenManager,
    OAuth2AuthProfile,
    OAuth2Context,
    OAuth2ProviderProfile,
    OAuth2TokenManager,
    OAuthFlow,
    OAuthFlowFactory,
    PasswordAuthProfile,
    ServiceAccountAuthProfile,
    SignOutResult,
    TokenAuthProfile,
    TokenCredential,
    TokenState,
    TokenStatus,
    WindowsAuthProfile,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from mountainash_settings.secrets import ClearableSecretStore

    from mountainash_auth_client import (
        CallbackServerFactory,
        OAuth1ProviderProfileProtocol,
        OAuth2ProviderProfileProtocol,
        ProviderProfileProtocol,
    )
    from mountainash_auth_client.oauth.persistence import OAuth1CredentialProfile, OAuth2CredentialProfile
    from mountainash_auth_client.oauth.records import OAuth2Tokens


def profiles(
    jwt: JWTAuthProfile, auth: OAuth2AuthProfile, provider: OAuth2ProviderProfile,
) -> None:
    assert_type(jwt.TOKEN, SecretStr)
    assert_type(auth.CLIENT_ID, str | None)
    assert_type(auth.CLIENT_SECRET, SecretStr | None)
    assert_type(provider.AUTHORIZE_URL, str)
    assert_type(OAuthFlow(provider), OAuthFlow)
    auth.CLIENT_ID = 123  # type: ignore[assignment]
    jwt.TOKEN = "plain-secret"  # type: ignore[assignment]


def profile_families(
    password: PasswordAuthProfile, token: TokenAuthProfile, iam: IAMAuthProfile,
    windows: WindowsAuthProfile, azure: AzureADAuthProfile, kerberos: KerberosAuthProfile,
    certificate: CertificateAuthProfile, service: ServiceAccountAuthProfile,
    oauth1: OAuth1AuthProfile, oauth2: OAuth2AuthProfile,
) -> None:
    assert_type(NoAuthProfile(), NoAuthProfile)
    assert_type(password.USERNAME, str)
    assert_type(password.PASSWORD, SecretStr)
    assert_type(token.TOKEN, SecretStr)
    assert_type(iam.ROLE_ARN, str | None)
    assert_type(iam.ACCESS_KEY_ID, str | None)
    assert_type(iam.SECRET_ACCESS_KEY, SecretStr | None)
    assert_type(iam.SESSION_TOKEN, SecretStr | None)
    assert_type(iam.PROFILE_NAME, str | None)
    assert_type(windows.USERNAME, str | None)
    assert_type(windows.DOMAIN, str | None)
    assert_type(azure.TENANT_ID, str | None)
    assert_type(azure.CLIENT_ID, str | None)
    assert_type(azure.CLIENT_SECRET, SecretStr | None)
    assert_type(azure.MANAGED_IDENTITY, bool)
    assert_type(azure.MSI_ENDPOINT, str | None)
    assert_type(kerberos.SERVICE_NAME, str)
    assert_type(kerberos.PRINCIPAL, str | None)
    assert_type(kerberos.KEYTAB, Path | None)
    assert_type(certificate.PRIVATE_KEY, SecretStr | None)
    assert_type(certificate.PRIVATE_KEY_PATH, Path | None)
    assert_type(certificate.PASSPHRASE, SecretStr | None)
    assert_type(service.INFO, SecretStr | None)
    assert_type(service.FILE, Path | None)
    assert_type(oauth1.CONSUMER_KEY, str)
    assert_type(oauth1.CONSUMER_SECRET, SecretStr)
    assert_type(oauth1.ACCESS_TOKEN, SecretStr | None)
    assert_type(oauth1.ACCESS_TOKEN_SECRET, SecretStr | None)
    assert_type(oauth2.ACCESS_TOKEN, SecretStr | None)
    assert_type(oauth2.REFRESH_TOKEN, SecretStr | None)
    assert_type(oauth2.SCOPE, str | None)


def providers(one: OAuth1ProviderProfile, two: OAuth2ProviderProfile) -> None:
    _first: OAuth1ProviderProfileProtocol = one
    _second: OAuth2ProviderProfileProtocol = two
    _common: ProviderProfileProtocol = one
    assert_type(one.REQUEST_TOKEN_URL, str)
    assert_type(one.ACCESS_TOKEN_URL, str)
    assert_type(one.AUTHORIZE_URL, str)
    assert_type(one.BASE_URL, str)
    assert_type(one.CALLBACK_PORT, int | None)
    assert_type(two.TOKEN_URL, str)
    assert_type(two.DEFAULT_SCOPE, str | None)
    assert_type(two.USE_PKCE, bool)
    assert_type(two.CALLBACK_PORT, int | None)
    assert_type(one.NAME, str)
    assert_type(two.TOKEN_ENDPOINT_AUTH_METHOD, str)
    assert_type(two.TOKEN_REQUEST_HEADERS, dict | None)
    assert_type(two.TOKEN_REQUEST_CONTENT_TYPE, str)
    assert_type(OAuth1Flow(one), OAuth1Flow)


def managers(
    one: OAuth1ProviderProfile, two: OAuth2ProviderProfile,
    credentials1: OAuth1CredentialProfile, credentials2: OAuth2CredentialProfile,
    store: ClearableSecretStore,
) -> None:
    factory: CallbackServerFactory = ManualCallbackServer
    server: CallbackServerProtocol = factory()
    assert_type(server.redirect_uri, str)
    assert_type(server.port, int | None)
    assert_type(server.obtain_callback("https://example/authorize"), dict[str, str])
    assert_type(OAuth1TokenManager(one, credentials1, token_store=store, callback_server=factory), OAuth1TokenManager)
    manager = OAuth2TokenManager(two, credentials2, token_store=store, callback_server=factory)
    assert_type(manager, OAuth2TokenManager)
    assert_type(manager.acquire(), TokenCredential)
    assert_type(TokenStatus(TokenState.VALID).state, TokenState)


def wrong_callback() -> str:
    return "not a callback server"


def callback_rejection() -> None:
    factory: CallbackServerFactory = wrong_callback  # type: ignore[assignment]
    assert_type(factory(), CallbackServerProtocol)


def operations(
    flow: OAuthFlow, server: LocalCallbackServer, credential: TokenCredential,
) -> None:
    assert_type(credential.access_token, str)
    assert_type(credential.expires_at, int | None)
    assert_type(credential.refresh_token, str | None)
    assert_type(credential.scope, str | None)
    assert_type(credential.client_id, str | None)
    assert_type(credential.registration, dict[str, JSONValue])
    assert_type(credential.session_metadata, dict[str, JSONValue])
    assert_type(server.obtain_callback("https://example/authorize"), dict[str, str])
    flow.build_authorize_url(123, "https://app/callback")  # type: ignore[arg-type]


def consumer_extension(
    provider: OAuth2ProviderProfileProtocol, credentials: OAuth2CredentialProfile,
    store: ClearableSecretStore, resource: str,
    verify_identity: Callable[[str, OAuth2Context], dict[str, JSONValue]],
) -> None:
    class ConsumerFlow(OAuthFlow):
        def authorization_parameters(self, context: OAuth2Context) -> dict[str, str]:
            context.data["nonce"] = "consumer-owned-nonce"
            return {"resource": resource}

        def token_parameters(self, context: OAuth2Context) -> dict[str, str]:
            return {"resource": resource}

        def process_callback(
            self, params: dict[str, str], context: OAuth2Context,
        ) -> tuple[str | None, dict[str, JSONValue]]:
            return params.get("client_id", context.client_id), context.registration

        def validate_token_response(
            self, response: dict[str, JSONValue], context: OAuth2Context,
            previous: OAuth2Tokens | None, candidate: OAuth2Tokens,
        ) -> OAuth2Tokens:
            identity = response.get("id_token")
            if not isinstance(identity, str):
                raise ValueError("Missing identity")
            claims = verify_identity(identity, context)
            candidate["session_metadata"] = {"id_token": identity, "claims": claims}
            return candidate

        def validate_credential(self, credential: TokenCredential) -> None:
            if "invoke" not in (credential.scope or "").split():
                raise PermissionError("Missing invoke permission")

        def revoke_remote(self, record: OAuth2Tokens) -> bool:
            return False

    def factory(
        provider: OAuth2ProviderProfileProtocol, *,
        token_store: ClearableSecretStore | None = None,
        callback_server: CallbackServerFactory | None = None,
    ) -> OAuthFlow:
        return ConsumerFlow(provider, token_store=token_store, callback_server=callback_server)

    selected: OAuthFlowFactory = factory
    manager = OAuth2TokenManager(provider, credentials, token_store=store, flow_factory=selected)
    assert_type(manager.sign_out(), SignOutResult)
    assert_type(manager.sign_out().remote_confirmed, bool)
    assert_type(selected(provider).sign_out(credentials), SignOutResult)
    OAuth2TokenManager(provider, credentials, token_store=store, flow_factory=wrong_callback)  # type: ignore[arg-type]

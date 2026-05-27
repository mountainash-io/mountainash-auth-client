"""Auth schema types — discriminated-union Pydantic models."""
from .base import AuthSpec
from .azure import AzureADAuth, WindowsAuth
from .certificate import CertificateAuth
from .dispatch import AUTH_TO_DRIVER_KWARGS, auth_to_driver_kwargs, auth_kwargs
from .iam import IAMAuth
from .kerberos import KerberosAuth
from .none import NoAuth
from .oauth1 import OAuth1Auth
from .oauth2 import OAuth2Auth
from .oauth2_authcode import OAuth2AuthCodeAuth
from .password import PasswordAuth
from .service_account import ServiceAccountAuth
from .token import JWTAuth, TokenAuth

__all__ = [
    "AUTH_TO_DRIVER_KWARGS", "AuthSpec", "AzureADAuth", "CertificateAuth",
    "IAMAuth", "JWTAuth", "KerberosAuth", "NoAuth", "OAuth1Auth", "OAuth2Auth",
    "OAuth2AuthCodeAuth", "PasswordAuth", "ServiceAccountAuth", "TokenAuth",
    "WindowsAuth", "auth_kwargs", "auth_to_driver_kwargs",
]

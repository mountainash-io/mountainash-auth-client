"""Auth mode Profile subclasses — registered in AUTH_REGISTRY."""
from .registry import AUTH_REGISTRY, register
from .azure import AzureADAuthProfile, WindowsAuthProfile
from .certificate import CertificateAuthProfile
from .iam import IAMAuthProfile
from .kerberos import KerberosAuthProfile
from .none import NoAuthProfile
from .oauth1 import OAuth1AuthProfile
from .oauth2 import OAuth2AuthProfile
from .oauth2_authcode import OAuth2AuthCodeAuthProfile
from .password import PasswordAuthProfile
from .service_account import ServiceAccountAuthProfile
from .token import JWTAuthProfile, TokenAuthProfile

__all__ = [
    "AUTH_REGISTRY",
    "AzureADAuthProfile",
    "CertificateAuthProfile",
    "IAMAuthProfile",
    "JWTAuthProfile",
    "KerberosAuthProfile",
    "NoAuthProfile",
    "OAuth1AuthProfile",
    "OAuth2AuthProfile",
    "OAuth2AuthCodeAuthProfile",
    "PasswordAuthProfile",
    "ServiceAccountAuthProfile",
    "TokenAuthProfile",
    "WindowsAuthProfile",
    "register",
]

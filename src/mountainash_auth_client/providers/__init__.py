"""Provider coordinate profiles (OAuth2 / OAuth1). Schema only — no values, no registry."""
from __future__ import annotations

from .oauth1 import OAuth1ProviderProfile
from .oauth2 import OAuth2ProviderProfile

__all__ = ["OAuth1ProviderProfile", "OAuth2ProviderProfile"]

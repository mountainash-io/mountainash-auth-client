"""Auth mode registry — all auth Profile subclasses register here."""
from mountainash_settings import Registry

AUTH_REGISTRY = Registry("auth")
register = AUTH_REGISTRY.decorator()

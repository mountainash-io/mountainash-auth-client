"""Automatic structural invariant tests for all registered auth modes."""
from mountainash_settings import spec_invariants_for

from mountainash_auth_client.schemas.registry import AUTH_REGISTRY

TestAuthInvariants = spec_invariants_for(AUTH_REGISTRY)

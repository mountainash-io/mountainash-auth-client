"""Connection mixins for OAuth providers."""
from .oauth2 import OAuth2ConnectionMixin

__all__ = ["OAuth2ConnectionMixin"]
# OAuth1ConnectionMixin not re-exported: requires authlib optional dependency

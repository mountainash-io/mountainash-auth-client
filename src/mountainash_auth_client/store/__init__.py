"""Credential storage — protocol and implementations."""
from .filesystem import FilesystemStore
from .protocol import SecretStore

__all__ = ["FilesystemStore", "SecretStore"]

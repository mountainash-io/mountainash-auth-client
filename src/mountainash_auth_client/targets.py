"""Emission target families — the SDK-client axis that selects an auth shape.

Owned by auth-client (the spec keeps mountainash-settings domain-agnostic: it
stores adapters under an opaque ``Hashable`` key and never imports this enum).
A connection declares its family; ``profile.emit(family)`` renders the kwargs
that family's SDK client expects.
"""
from __future__ import annotations

from enum import Enum

__all__ = ["TargetFamily"]


class TargetFamily(str, Enum):
    """The SDK client family an emission targets."""

    HTTP = "http"        # httpx
    BOTO = "boto"        # boto3
    PARAMIKO = "paramiko"  # ssh / sftp

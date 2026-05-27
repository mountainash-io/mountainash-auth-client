"""FilesystemStore — domain-namespaced YAML credential storage."""
from __future__ import annotations

import fcntl
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml

_VALID_SEGMENT = re.compile(r'^[a-z0-9_]+$')


def _validate(name: str, label: str) -> None:
    if not _VALID_SEGMENT.match(name):
        raise ValueError(f"Invalid {label}: {name!r} — must match [a-z0-9_]+")


class FilesystemStore:
    """Stores and retrieves credentials as YAML files under *base_dir/{domain}/provider-user.yaml*."""

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _domain_dir(self, domain: str) -> Path:
        _validate(domain, "domain")
        return self.base_dir / domain

    def _token_path(self, domain: str, provider: str, user: str) -> Path:
        _validate(domain, "domain")
        _validate(provider, "provider")
        _validate(user, "user")
        return self._domain_dir(domain) / f"{provider}-{user}.yaml"

    def _tmp_path(self, domain: str, provider: str, user: str) -> Path:
        return self._domain_dir(domain) / f".{provider}-{user}.tmp"

    def _tombstone_path(self, domain: str, provider: str, user: str) -> Path:
        return self._domain_dir(domain) / f".{provider}-{user}.cleared"

    def _lock_path(self, domain: str, provider: str, user: str) -> Path:
        return self._domain_dir(domain) / f".{provider}-{user}.lock"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, domain: str, provider: str, user: str) -> dict[str, Any] | None:
        path = self._token_path(domain, provider, user)
        if not path.exists():
            return None
        # Refuse symlinks
        if path.is_symlink():
            raise PermissionError(f"Credential file is a symlink: {path}")
        # Refuse group/world readable
        mode = path.stat().st_mode
        if mode & 0o077:
            raise PermissionError(f"Credential file has unsafe permissions: {path}")
        with path.open("r") as fh:
            return yaml.safe_load(fh)

    def save(self, domain: str, provider: str, user: str, data: dict[str, Any]) -> None:
        path = self._token_path(domain, provider, user)
        tmp_path = self._tmp_path(domain, provider, user)
        tombstone = self._tombstone_path(domain, provider, user)

        # Create directory with 0o700
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(path.parent), 0o700)

        # Atomic write via temp file
        try:
            fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                yaml.safe_dump(data, fh)
            os.replace(str(tmp_path), str(path))
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink()
            raise

        # Remove tombstone if present (save after clear = fresh credentials)
        if tombstone.exists():
            tombstone.unlink()

    def clear(self, domain: str, provider: str, user: str) -> None:
        path = self._token_path(domain, provider, user)
        tombstone = self._tombstone_path(domain, provider, user)

        if path.exists():
            path.unlink()

        # Create tombstone
        tombstone.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(tombstone.parent), 0o700)
        fd = os.open(str(tombstone), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)

    def is_cleared(self, domain: str, provider: str, user: str) -> bool:
        """Return True if a tombstone marks this credential as intentionally cleared."""
        _validate(domain, "domain")
        _validate(provider, "provider")
        _validate(user, "user")
        return self._tombstone_path(domain, provider, user).exists()

    def list_users(self, domain: str, provider: str) -> list[str]:
        """List all users with saved credentials for *provider* in *domain*."""
        _validate(domain, "domain")
        _validate(provider, "provider")
        domain_dir = self._domain_dir(domain)
        if not domain_dir.exists():
            return []
        prefix = f"{provider}-"
        suffix = ".yaml"
        users = []
        for p in domain_dir.iterdir():
            name = p.name
            if name.startswith(prefix) and name.endswith(suffix) and not name.startswith("."):
                user = name[len(prefix):-len(suffix)]
                users.append(user)
        return users

    @contextmanager
    def lock(self, domain: str, provider: str, user: str):
        """Acquire exclusive file lock for credential refresh operations."""
        lock_path = self._lock_path(domain, provider, user)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(lock_path.parent), 0o700)
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

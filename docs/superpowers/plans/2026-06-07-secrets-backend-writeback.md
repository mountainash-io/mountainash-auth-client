# Secrets Backend Write-Back Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the read-only `SecretsResolver` callable in mountainash-settings with a read-write `SecretsBackend` protocol, add a `FilesystemBackend` implementation, add `persist()` to `MountainAshBaseSettings`, and remove the hand-rolled store layer from mountainash-auth-client.

**Architecture:** mountainash-settings gains the `SecretsBackend`/`ClearableBackend` protocols, a `FilesystemBackend`, a new registry API, updated `resolve.py` for structured backends, and `persist()`/`persist_key()` on `MountainAshBaseSettings`. mountainash-auth-client deletes its `store/` directory and updates mixins to use the new backend.

**Tech Stack:** Python 3.11+, pydantic v2, mountainash-settings, fcntl (filesystem locking), PyYAML

---

### Task 1: SecretsBackend and ClearableBackend protocols

Add the new protocol definitions to mountainash-settings.

**Files:**
- Create: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/secrets/backend.py`
- Test: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/secrets/test_backend_protocol.py`

- [ ] **Step 1: Write the failing test**

Create `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/secrets/test_backend_protocol.py`:

```python
"""Tests for SecretsBackend and ClearableBackend protocols."""
from __future__ import annotations

import typing as t
from contextlib import contextmanager

import pytest

from mountainash_settings.secrets.backend import ClearableBackend, SecretsBackend


class _MinimalBackend:
    def get(self, key: str) -> dict[str, t.Any] | None:
        return None

    def set(self, key: str, data: dict[str, t.Any]) -> None:
        pass

    def delete(self, key: str) -> None:
        pass

    @contextmanager
    def transaction(self, key: str):
        yield


class _ClearableImpl(_MinimalBackend):
    def is_cleared(self, key: str) -> bool:
        return False


@pytest.mark.unit
class TestSecretsBackendProtocol:
    def test_minimal_backend_satisfies_protocol(self):
        backend = _MinimalBackend()
        assert isinstance(backend, SecretsBackend)

    def test_clearable_satisfies_both_protocols(self):
        backend = _ClearableImpl()
        assert isinstance(backend, SecretsBackend)
        assert isinstance(backend, ClearableBackend)

    def test_minimal_backend_is_not_clearable(self):
        backend = _MinimalBackend()
        assert not isinstance(backend, ClearableBackend)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick tests/unit/secrets/test_backend_protocol.py -v`
Expected: FAIL — `mountainash_settings.secrets.backend` does not exist.

- [ ] **Step 3: Create backend.py with protocols**

Create `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/secrets/backend.py`:

```python
"""SecretsBackend protocol — pluggable credential storage with read/write."""
from __future__ import annotations

import typing as t

if t.TYPE_CHECKING:
    from contextlib import AbstractContextManager

__all__ = ["SecretsBackend", "ClearableBackend"]


@t.runtime_checkable
class SecretsBackend(t.Protocol):
    """Protocol for credential storage backends.

    Values are structured dicts — one key maps to one credential set.
    Backends handle locking internally.
    """

    def get(self, key: str) -> dict[str, t.Any] | None: ...
    def set(self, key: str, data: dict[str, t.Any]) -> None: ...
    def delete(self, key: str) -> None: ...
    def transaction(self, key: str) -> AbstractContextManager[None]: ...


@t.runtime_checkable
class ClearableBackend(SecretsBackend, t.Protocol):
    """Extension for backends that track intentional deletion."""

    def is_cleared(self, key: str) -> bool: ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick tests/unit/secrets/test_backend_protocol.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings
git add src/mountainash_settings/secrets/backend.py \
        tests/unit/secrets/test_backend_protocol.py
git commit -m "feat: add SecretsBackend and ClearableBackend protocols"
```

---

### Task 2: FilesystemBackend implementation

Port auth-client's `FilesystemStore` to mountainash-settings as `FilesystemBackend`, adapted to the `SecretsBackend`/`ClearableBackend` protocols.

**Files:**
- Create: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/secrets/filesystem.py`
- Test: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/secrets/test_filesystem_backend.py`

- [ ] **Step 1: Write the failing tests**

Create `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/secrets/test_filesystem_backend.py`:

```python
"""Tests for FilesystemBackend."""
from __future__ import annotations

import os
import stat

import pytest

from mountainash_settings.secrets.backend import ClearableBackend, SecretsBackend
from mountainash_settings.secrets.filesystem import FilesystemBackend


@pytest.fixture
def backend(tmp_path):
    return FilesystemBackend(base_dir=tmp_path)


@pytest.mark.unit
class TestFilesystemBackendProtocol:
    def test_satisfies_secrets_backend(self, backend):
        assert isinstance(backend, SecretsBackend)

    def test_satisfies_clearable_backend(self, backend):
        assert isinstance(backend, ClearableBackend)


@pytest.mark.unit
class TestFilesystemBackendBasic:
    def test_set_and_get_round_trip(self, backend):
        data = {"access_token": "tok123", "refresh_token": "ref456"}
        backend.set("wearables.strava.default", data)
        result = backend.get("wearables.strava.default")
        assert result == data

    def test_get_missing_returns_none(self, backend):
        assert backend.get("wearables.strava.nobody") is None

    def test_delete_removes_value(self, backend):
        backend.set("wearables.strava.alice", {"token": "x"})
        backend.delete("wearables.strava.alice")
        assert backend.get("wearables.strava.alice") is None

    def test_is_cleared_after_delete(self, backend):
        backend.set("wearables.strava.alice", {"token": "x"})
        backend.delete("wearables.strava.alice")
        assert backend.is_cleared("wearables.strava.alice") is True

    def test_is_not_cleared_before_delete(self, backend):
        backend.set("wearables.strava.alice", {"token": "x"})
        assert backend.is_cleared("wearables.strava.alice") is False

    def test_is_not_cleared_when_never_set(self, backend):
        assert backend.is_cleared("wearables.strava.alice") is False

    def test_set_after_delete_removes_tombstone(self, backend):
        backend.set("wearables.strava.alice", {"token": "x"})
        backend.delete("wearables.strava.alice")
        assert backend.is_cleared("wearables.strava.alice") is True
        backend.set("wearables.strava.alice", {"token": "y"})
        assert backend.is_cleared("wearables.strava.alice") is False
        assert backend.get("wearables.strava.alice") == {"token": "y"}


@pytest.mark.unit
class TestFilesystemBackendSecurity:
    def test_file_permissions_0600(self, backend, tmp_path):
        backend.set("wearables.strava.default", {"token": "x"})
        path = tmp_path / "wearables" / "strava-default.yaml"
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600

    def test_directory_permissions_0700(self, backend, tmp_path):
        backend.set("wearables.strava.default", {"token": "x"})
        dir_path = tmp_path / "wearables"
        mode = stat.S_IMODE(dir_path.stat().st_mode)
        assert mode == 0o700

    def test_rejects_symlink_on_read(self, backend, tmp_path):
        real_file = tmp_path / "real.yaml"
        real_file.write_text("token: x\n")
        domain_dir = tmp_path / "wearables"
        domain_dir.mkdir()
        link = domain_dir / "strava-default.yaml"
        link.symlink_to(real_file)
        with pytest.raises(PermissionError):
            backend.get("wearables.strava.default")


@pytest.mark.unit
class TestFilesystemBackendTransaction:
    def test_transaction_context_manager(self, backend):
        backend.set("wearables.strava.default", {"token": "old"})
        with backend.transaction("wearables.strava.default"):
            data = backend.get("wearables.strava.default")
            data["token"] = "new"
            backend.set("wearables.strava.default", data)
        assert backend.get("wearables.strava.default") == {"token": "new"}


@pytest.mark.unit
class TestFilesystemBackendKeyMapping:
    def test_single_segment_key(self, backend, tmp_path):
        backend.set("simple", {"val": 1})
        assert (tmp_path / "simple.yaml").exists()

    def test_two_segment_key(self, backend, tmp_path):
        backend.set("domain.provider", {"val": 1})
        assert (tmp_path / "domain" / "provider.yaml").exists()

    def test_three_segment_key(self, backend, tmp_path):
        backend.set("wearables.strava.default", {"val": 1})
        assert (tmp_path / "wearables" / "strava-default.yaml").exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick tests/unit/secrets/test_filesystem_backend.py -v`
Expected: FAIL — `mountainash_settings.secrets.filesystem` does not exist.

- [ ] **Step 3: Create filesystem.py**

Create `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/secrets/filesystem.py`:

```python
"""FilesystemBackend — secure YAML credential storage on disk."""
from __future__ import annotations

import fcntl
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml

__all__ = ["FilesystemBackend"]

_VALID_SEGMENT = re.compile(r"^[a-z0-9_]+$")


def _validate_segment(name: str) -> None:
    if not _VALID_SEGMENT.match(name):
        raise ValueError(f"Invalid key segment: {name!r} — must match [a-z0-9_]+")


def _key_to_paths(base_dir: Path, key: str) -> tuple[Path, Path, Path, Path]:
    """Convert a dot-separated key to (yaml_path, tmp_path, tombstone_path, lock_path).

    Key mapping:
    - "simple"                -> base_dir/simple.yaml
    - "domain.leaf"           -> base_dir/domain/leaf.yaml
    - "domain.provider.user"  -> base_dir/domain/provider-user.yaml
    """
    parts = key.split(".")
    for part in parts:
        _validate_segment(part)

    if len(parts) == 1:
        directory = base_dir
        stem = parts[0]
    elif len(parts) == 2:
        directory = base_dir / parts[0]
        stem = parts[1]
    else:
        directory = base_dir / parts[0]
        stem = "-".join(parts[1:])

    yaml_path = directory / f"{stem}.yaml"
    tmp_path = directory / f".{stem}.tmp"
    tombstone_path = directory / f".{stem}.cleared"
    lock_path = directory / f".{stem}.lock"
    return yaml_path, tmp_path, tombstone_path, lock_path


class FilesystemBackend:
    """Stores credentials as YAML files with secure permissions."""

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)

    def get(self, key: str) -> dict[str, Any] | None:
        yaml_path, _, _, _ = _key_to_paths(self.base_dir, key)
        if not yaml_path.exists():
            return None
        if yaml_path.is_symlink():
            raise PermissionError(f"Credential file is a symlink: {yaml_path}")
        mode = yaml_path.stat().st_mode
        if mode & 0o077:
            raise PermissionError(f"Credential file has unsafe permissions: {yaml_path}")
        with yaml_path.open("r") as fh:
            return yaml.safe_load(fh)

    def set(self, key: str, data: dict[str, Any]) -> None:
        yaml_path, tmp_path, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(yaml_path.parent), 0o700)
        try:
            fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                yaml.safe_dump(data, fh)
            os.replace(str(tmp_path), str(yaml_path))
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink()
            raise
        if tombstone_path.exists():
            tombstone_path.unlink()

    def delete(self, key: str) -> None:
        yaml_path, _, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        if yaml_path.exists():
            yaml_path.unlink()
        tombstone_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(tombstone_path.parent), 0o700)
        fd = os.open(str(tombstone_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)

    def is_cleared(self, key: str) -> bool:
        _, _, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        return tombstone_path.exists()

    @contextmanager
    def transaction(self, key: str):
        _, _, _, lock_path = _key_to_paths(self.base_dir, key)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(lock_path.parent), 0o700)
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick tests/unit/secrets/test_filesystem_backend.py -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings
git add src/mountainash_settings/secrets/filesystem.py \
        tests/unit/secrets/test_filesystem_backend.py
git commit -m "feat: add FilesystemBackend implementing SecretsBackend + ClearableBackend"
```

---

### Task 3: Replace secrets registry API

Replace the old callable-based registry (`SecretsResolver`, `register_secrets_resolver`, etc.) with the new backend-based API.

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/secrets/registry.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/secrets/__init__.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/__init__.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/secrets/test_registry.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/test_public_api.py`

- [ ] **Step 1: Rewrite test_registry.py for new API**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/secrets/test_registry.py`:

```python
"""Unit tests for the secrets backend registry."""
from __future__ import annotations

import typing as t
from contextlib import contextmanager

import pytest

from mountainash_settings.secrets.registry import (
    register_secrets_backend,
    get_secrets_backend,
    replace_secrets_backend,
    clear_secrets_registry,
)


class _DummyBackend:
    def get(self, key: str) -> dict[str, t.Any] | None:
        return {"value": f"resolved_{key}"}

    def set(self, key: str, data: dict[str, t.Any]) -> None:
        pass

    def delete(self, key: str) -> None:
        pass

    @contextmanager
    def transaction(self, key: str):
        yield


class _OtherBackend(_DummyBackend):
    pass


@pytest.fixture(autouse=True)
def clean_registry():
    clear_secrets_registry()
    yield
    clear_secrets_registry()


@pytest.mark.unit
class TestSecretsRegistry:
    def test_register_and_retrieve(self):
        backend = _DummyBackend()
        register_secrets_backend("local", backend)
        assert get_secrets_backend("local") is backend

    def test_get_unregistered_raises_keyerror(self):
        with pytest.raises(KeyError):
            get_secrets_backend("nonexistent")

    def test_duplicate_registration_raises_valueerror(self):
        register_secrets_backend("local", _DummyBackend())
        with pytest.raises(ValueError):
            register_secrets_backend("local", _OtherBackend())

    def test_replace_overwrites_existing(self):
        register_secrets_backend("local", _DummyBackend())
        other = _OtherBackend()
        replace_secrets_backend("local", other)
        assert get_secrets_backend("local") is other

    def test_replace_unregistered_registers(self):
        backend = _DummyBackend()
        replace_secrets_backend("new_provider", backend)
        assert get_secrets_backend("new_provider") is backend

    def test_clear_removes_all(self):
        register_secrets_backend("a", _DummyBackend())
        register_secrets_backend("b", _OtherBackend())
        clear_secrets_registry()
        with pytest.raises(KeyError):
            get_secrets_backend("a")
        with pytest.raises(KeyError):
            get_secrets_backend("b")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick tests/unit/secrets/test_registry.py -v`
Expected: FAIL — old API names imported.

- [ ] **Step 3: Rewrite registry.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/secrets/registry.py`:

```python
"""Secrets backend registry — write-once provider mapping."""
from __future__ import annotations

from .backend import SecretsBackend

__all__ = [
    "register_secrets_backend",
    "get_secrets_backend",
    "replace_secrets_backend",
    "clear_secrets_registry",
]

_REGISTRY: dict[str, SecretsBackend] = {}


def register_secrets_backend(provider: str, backend: SecretsBackend) -> None:
    if provider in _REGISTRY:
        raise ValueError(
            f"Secrets backend '{provider}' is already registered. "
            f"Use replace_secrets_backend() for explicit replacement."
        )
    _REGISTRY[provider] = backend


def get_secrets_backend(provider: str) -> SecretsBackend:
    return _REGISTRY[provider]


def replace_secrets_backend(provider: str, backend: SecretsBackend) -> None:
    _REGISTRY[provider] = backend


def clear_secrets_registry() -> None:
    _REGISTRY.clear()
```

- [ ] **Step 4: Update secrets/__init__.py**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/secrets/__init__.py`:

```python
"""Secrets backend registry and protocols."""
from .backend import ClearableBackend, SecretsBackend
from .filesystem import FilesystemBackend
from .registry import (
    register_secrets_backend,
    get_secrets_backend,
    replace_secrets_backend,
    clear_secrets_registry,
)

__all__ = [
    "ClearableBackend",
    "FilesystemBackend",
    "SecretsBackend",
    "register_secrets_backend",
    "get_secrets_backend",
    "replace_secrets_backend",
    "clear_secrets_registry",
]
```

- [ ] **Step 5: Update mountainash-settings __init__.py**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/__init__.py`, replace the secrets import block (lines 20-26):

```python
from .secrets import (
    ClearableBackend,
    FilesystemBackend,
    SecretsBackend,
    register_secrets_backend,
    get_secrets_backend,
    replace_secrets_backend,
    clear_secrets_registry,
)
```

And replace the Secrets section in `__all__` (lines 49-54):

```python
    # Secrets
    "ClearableBackend",
    "FilesystemBackend",
    "SecretsBackend",
    "register_secrets_backend",
    "get_secrets_backend",
    "replace_secrets_backend",
    "clear_secrets_registry",
```

- [ ] **Step 6: Update test_public_api.py if it references old names**

Read `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/test_public_api.py` and replace any references to `SecretsResolver`, `register_secrets_resolver`, `get_secrets_resolver`, `replace_secrets_resolver` with their new backend equivalents.

- [ ] **Step 7: Run registry tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick tests/unit/secrets/test_registry.py -v`
Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings
git add src/mountainash_settings/secrets/registry.py \
        src/mountainash_settings/secrets/__init__.py \
        src/mountainash_settings/__init__.py \
        tests/unit/secrets/test_registry.py \
        tests/unit/test_public_api.py
git commit -m "refactor: replace SecretsResolver callable with SecretsBackend registry"
```

---

### Task 4: Update resolve.py and base_settings.py for backend API

The resolve module and base settings both call the old `get_secrets_resolver()` which returned a `Callable[[str], str]`. They now need to call `get_secrets_backend()` which returns a `SecretsBackend` with `get(key) -> dict | None`.

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/resolve.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/settings/base_settings.py:82-141`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/settings_parameters/settings_parameters.py:378-382`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/test_resolve.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/test_base_settings.py`

- [ ] **Step 1: Update resolve.py**

The core change: `resolve_references_in_dict` and `resolve_references_in_model_tree` currently take a `resolver: Callable[[str], str]`. They need to accept a `SecretsBackend` and bridge to it.

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/resolve.py`:

```python
"""General-purpose reference resolution for dicts and pydantic model trees.

This module provides the mechanism for resolving prefixed string references
(e.g., ``secret:path/to/value``) in data structures. It is domain-agnostic —
the caller supplies a SecretsBackend and a prefix string.
"""
from __future__ import annotations

import typing as t

from pydantic import BaseModel, SecretStr

from mountainash_settings.secrets.backend import SecretsBackend

__all__ = ["resolve_references_in_dict", "resolve_references_in_model_tree"]

_SETTINGS_SOURCE_PREFIX = "SETTINGS_SOURCE_"
_SETTINGS_META_FIELDS = {"SETTINGS_CLASS", "SETTINGS_CLASS_NAME"}


def _resolve_value(ref: str, backend: SecretsBackend) -> str:
    """Resolve a single secret reference like 'domain.provider.user.field'.

    Splits on the last dot: backend key = everything before the last dot,
    field = the last segment. Calls backend.get(key) and plucks the field.
    If the key has no dots, treats the entire ref as the key and returns
    the first value from the dict.
    """
    if "." not in ref:
        result = backend.get(ref)
        if result is None:
            raise KeyError(f"Secret not found: {ref!r}")
        if len(result) == 1:
            return str(next(iter(result.values())))
        raise KeyError(
            f"Ambiguous secret reference {ref!r}: backend returned {len(result)} fields. "
            f"Use a dotted reference like '{ref}.field_name'."
        )
    key, _, field = ref.rpartition(".")
    result = backend.get(key)
    if result is None:
        raise KeyError(f"Secret not found for key: {key!r}")
    if field not in result:
        raise KeyError(f"Field {field!r} not found in secret {key!r}. Available: {list(result.keys())}")
    return str(result[field])


def resolve_references_in_dict(
    data: dict[str, t.Any],
    backend: SecretsBackend,
    prefix: str = "secret:",
) -> dict[str, t.Any]:
    resolved: dict[str, t.Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            resolved[key] = resolve_references_in_dict(value, backend, prefix)
        elif isinstance(value, str) and value.startswith(prefix):
            resolved[key] = _resolve_value(value[len(prefix):], backend)
        else:
            resolved[key] = value
    return resolved


def resolve_references_in_model_tree(
    instance: t.Any,
    backend: SecretsBackend,
    prefix: str = "secret:",
) -> None:
    for field_name in instance.model_fields:
        if field_name.startswith(_SETTINGS_SOURCE_PREFIX) or field_name in _SETTINGS_META_FIELDS:
            continue
        value = getattr(instance, field_name)
        if isinstance(value, BaseModel):
            raw_dict, has_refs = _extract_model_values(value, prefix)
            if has_refs:
                resolved_dict = resolve_references_in_dict(raw_dict, backend, prefix)
                rebuilt = type(value)(**resolved_dict)
                setattr(instance, field_name, rebuilt)
        elif isinstance(value, SecretStr):
            raw = value.get_secret_value()
            if isinstance(raw, str) and raw.startswith(prefix):
                setattr(instance, field_name, _resolve_value(raw[len(prefix):], backend))
        elif isinstance(value, str) and value.startswith(prefix):
            setattr(instance, field_name, _resolve_value(value[len(prefix):], backend))


def _extract_model_values(
    instance: BaseModel,
    prefix: str,
) -> tuple[dict[str, t.Any], bool]:
    """Extract field values from a BaseModel, unwrapping SecretStr."""
    values: dict[str, t.Any] = {}
    has_refs = False
    for field_name in instance.model_fields:
        value = getattr(instance, field_name)
        if isinstance(value, SecretStr):
            raw = value.get_secret_value()
            values[field_name] = raw
            if isinstance(raw, str) and raw.startswith(prefix):
                has_refs = True
        elif isinstance(value, BaseModel):
            inner_values, inner_has_refs = _extract_model_values(value, prefix)
            values[field_name] = inner_values
            if inner_has_refs:
                has_refs = True
        else:
            values[field_name] = value
            if isinstance(value, str) and value.startswith(prefix):
                has_refs = True
    return values, has_refs
```

- [ ] **Step 2: Update base_settings.py**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/settings/base_settings.py`, change the two blocks that call `get_secrets_resolver`:

**Block 1 (around line 82-87):** Replace:
```python
        if local_settings_params.secrets_provider:
            from mountainash_settings.secrets.registry import get_secrets_resolver
            from mountainash_settings.resolve import resolve_references_in_dict
            _secrets_resolver = get_secrets_resolver(local_settings_params.secrets_provider)
            valid_attribute_kwargs = resolve_references_in_dict(valid_attribute_kwargs, _secrets_resolver)
```
With:
```python
        if local_settings_params.secrets_provider:
            from mountainash_settings.secrets.registry import get_secrets_backend
            from mountainash_settings.resolve import resolve_references_in_dict
            _backend = get_secrets_backend(local_settings_params.secrets_provider)
            valid_attribute_kwargs = resolve_references_in_dict(valid_attribute_kwargs, _backend)
```

**Block 2 (around line 136-141):** Replace:
```python
        if local_settings_params.secrets_provider:
            from mountainash_settings.secrets.registry import get_secrets_resolver as _get_resolver
            from mountainash_settings.resolve import resolve_references_in_model_tree
            _secrets_resolver = _get_resolver(local_settings_params.secrets_provider)
            resolve_references_in_model_tree(self, _secrets_resolver)
```
With:
```python
        if local_settings_params.secrets_provider:
            from mountainash_settings.secrets.registry import get_secrets_backend as _get_backend
            from mountainash_settings.resolve import resolve_references_in_model_tree
            _backend = _get_backend(local_settings_params.secrets_provider)
            resolve_references_in_model_tree(self, _backend)
```

- [ ] **Step 3: Update settings_parameters.py**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/settings_parameters/settings_parameters.py`, around line 378-382, replace:
```python
                    from ..secrets.registry import get_secrets_resolver
                    from ..resolve import resolve_references_in_dict
                    resolver = get_secrets_resolver(self.secrets_provider)
                    override_kwargs = resolve_references_in_dict(override_kwargs, resolver)
```
With:
```python
                    from ..secrets.registry import get_secrets_backend
                    from ..resolve import resolve_references_in_dict
                    backend = get_secrets_backend(self.secrets_provider)
                    override_kwargs = resolve_references_in_dict(override_kwargs, backend)
```

- [ ] **Step 4: Update test_resolve.py**

The test resolver `_test_resolver(path: str) -> str` needs to become a backend. In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/test_resolve.py`, replace the `_test_resolver` function and all calls to it.

Replace the resolver definition at the top:
```python
def _test_resolver(path: str) -> str:
    return f"resolved_{path}"
```
With a backend class:
```python
class _TestBackend:
    """Backend that returns {"value": "resolved_<field>"} for any key."""
    def get(self, key: str) -> dict[str, t.Any] | None:
        return {"value": f"resolved_{key}"}

    def set(self, key: str, data: dict[str, t.Any]) -> None:
        pass

    def delete(self, key: str) -> None:
        pass

    def transaction(self, key: str):
        from contextlib import nullcontext
        return nullcontext()


_test_backend = _TestBackend()
```

Then replace all occurrences of `_test_resolver` with `_test_backend` throughout the file. Also add `import typing as t` at the top.

**Important:** The test assertions need updating because `_resolve_value` now uses dotted key resolution. For example, `"secret:db/password"` would need to become `"secret:db.password"` (dots not slashes) since the backend splits on dots. Update all test data to use dot-separated references:
- `"secret:db/password"` → `"secret:db.password"`
- `"secret:nested/key"` → `"secret:nested.key"`
- `"secret:api/token"` → `"secret:api.token"`
- `"secret:deep/key"` → `"secret:deep.key"`

And the expected values change because `_resolve_value("db.password", backend)` calls `backend.get("db")` then plucks `"password"`, but our test backend always returns `{"value": "resolved_db"}`. We need to make the test backend smarter:

```python
class _TestBackend:
    """Backend that resolves dotted refs: 'container.field' -> resolved_container/field."""
    def get(self, key: str) -> dict[str, t.Any] | None:
        return {"value": f"resolved_{key}"}

    def set(self, key: str, data: dict[str, t.Any]) -> None:
        pass

    def delete(self, key: str) -> None:
        pass

    def transaction(self, key: str):
        from contextlib import nullcontext
        return nullcontext()
```

For the dotted refs like `"secret:db.password"`, `_resolve_value` will call `backend.get("db")` → `{"value": "resolved_db"}`, then look for field `"password"` which doesn't exist. We need a test backend that returns the right fields:

```python
class _TestBackend:
    """Backend that returns fields matching any requested field name."""
    def get(self, key: str) -> dict[str, t.Any] | None:
        return _TestBackendData(key)

    def set(self, key: str, data: dict[str, t.Any]) -> None:
        pass

    def delete(self, key: str) -> None:
        pass

    def transaction(self, key: str):
        from contextlib import nullcontext
        return nullcontext()


class _TestBackendData(dict):
    """Dict that returns 'resolved_key/field' for any field lookup."""
    def __init__(self, key: str):
        super().__init__()
        self._key = key

    def __contains__(self, field):
        return True

    def __getitem__(self, field):
        return f"resolved_{self._key}/{field}"
```

This way `_resolve_value("db.password", backend)` → `backend.get("db")` → `_TestBackendData("db")`, `data["password"]` → `"resolved_db/password"`. The assertions stay the same.

Update the test file to use this backend and adapt assertions.

- [ ] **Step 5: Update test_base_settings.py for new API**

Read `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/test_base_settings.py` and replace any calls to `register_secrets_resolver` with `register_secrets_backend`, using a test backend object instead of a callable. Update the import from `mountainash_settings.secrets.registry`.

- [ ] **Step 6: Run all mountainash-settings tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick -v`
Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings
git add src/mountainash_settings/resolve.py \
        src/mountainash_settings/settings/base_settings.py \
        src/mountainash_settings/settings_parameters/settings_parameters.py \
        tests/unit/test_resolve.py \
        tests/test_base_settings.py
git commit -m "refactor: update resolve.py and base_settings for SecretsBackend API"
```

---

### Task 5: Add persist() and persist_key() to MountainAshBaseSettings

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/settings/base_settings.py`
- Test: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/test_persist.py`

- [ ] **Step 1: Write the failing tests**

Create `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/tests/unit/test_persist.py`:

```python
"""Tests for MountainAshBaseSettings.persist() and persist_key()."""
from __future__ import annotations

import typing as t
from contextlib import contextmanager

import pytest
from pydantic import Field

from mountainash_settings import MountainAshBaseSettings
from mountainash_settings.secrets.registry import (
    clear_secrets_registry,
    register_secrets_backend,
)


class _InMemoryBackend:
    def __init__(self):
        self._store: dict[str, dict[str, t.Any]] = {}
        self._cleared: set[str] = set()

    def get(self, key: str) -> dict[str, t.Any] | None:
        return self._store.get(key)

    def set(self, key: str, data: dict[str, t.Any]) -> None:
        self._store[key] = data
        self._cleared.discard(key)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)
        self._cleared.add(key)

    def is_cleared(self, key: str) -> bool:
        return key in self._cleared

    @contextmanager
    def transaction(self, key: str):
        yield


class _TestSettings(MountainAshBaseSettings):
    TOKEN: str = Field(default=None)
    REFRESH: str = Field(default=None)


@pytest.fixture(autouse=True)
def clean():
    clear_secrets_registry()
    yield
    clear_secrets_registry()


@pytest.mark.unit
class TestPersistKey:
    def test_key_from_class_name_only(self):
        instance = _TestSettings()
        key = instance.persist_key()
        assert key == "testsettings"

    def test_key_from_env_prefix_and_class(self):
        instance = _TestSettings(_env_prefix="STRAVA_")
        key = instance.persist_key()
        assert key == "strava.testsettings"


@pytest.mark.unit
class TestPersist:
    def test_persist_writes_to_backend(self):
        backend = _InMemoryBackend()
        register_secrets_backend("memory", backend)
        instance = _TestSettings(
            TOKEN="old",
            _env_prefix="APP_",
            secrets_provider="memory",
        )
        instance.persist({"TOKEN": "new_token", "REFRESH": "new_refresh"})
        stored = backend.get("app.testsettings")
        assert stored["TOKEN"] == "new_token"
        assert stored["REFRESH"] == "new_refresh"

    def test_persist_updates_in_memory(self):
        backend = _InMemoryBackend()
        register_secrets_backend("memory", backend)
        instance = _TestSettings(
            TOKEN="old",
            _env_prefix="APP_",
            secrets_provider="memory",
        )
        instance.persist({"TOKEN": "updated"})
        assert instance.TOKEN == "updated"

    def test_persist_with_explicit_key(self):
        backend = _InMemoryBackend()
        register_secrets_backend("memory", backend)
        instance = _TestSettings(
            TOKEN="old",
            secrets_provider="memory",
        )
        instance.persist({"TOKEN": "val"}, key="custom.key")
        assert backend.get("custom.key") == {"TOKEN": "val"}

    def test_persist_raises_without_secrets_provider(self):
        instance = _TestSettings(TOKEN="old")
        with pytest.raises(ValueError, match="secrets_provider"):
            instance.persist({"TOKEN": "new"})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick tests/unit/test_persist.py -v`
Expected: FAIL — `persist` and `persist_key` not defined.

- [ ] **Step 3: Add persist_key() and persist() to base_settings.py**

Add these methods to the `MountainAshBaseSettings` class in `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings/src/mountainash_settings/settings/base_settings.py`, after the `extract_settings_parameters()` method:

```python
    def persist_key(self) -> str:
        """Derive a backend key from this instance's stored meta-fields.

        Format: env_prefix (stripped of trailing underscore, lowercased) + "." +
        settings class name (lowercased). If no env_prefix, just the class name.
        """
        class_name = (self.SETTINGS_CLASS_NAME or type(self).__name__).lower()
        prefix = self.SETTINGS_SOURCE_ENV_PREFIX
        if prefix:
            prefix = prefix.rstrip("_").lower()
            return f"{prefix}.{class_name}"
        return class_name

    def persist(self, data: dict[str, Any], *, key: str | None = None) -> None:
        """Write data to the registered secrets backend and update in-memory fields.

        Args:
            data: Dict of field names to values to persist.
            key: Backend key. If None, derived via persist_key().

        Raises:
            ValueError: If no secrets_provider is configured.
        """
        provider = self.SETTINGS_SOURCE_SECRETS_PROVIDER
        if not provider:
            raise ValueError(
                "Cannot persist: no secrets_provider configured on this settings instance. "
                "Pass secrets_provider= when constructing the settings."
            )
        from mountainash_settings.secrets.registry import get_secrets_backend
        backend = get_secrets_backend(provider)
        if key is None:
            key = self.persist_key()
        backend.set(key, data)
        self.update_settings_from_dict(data)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick tests/unit/test_persist.py -v`
Expected: All tests pass.

- [ ] **Step 5: Run full mountainash-settings test suite**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings
git add src/mountainash_settings/settings/base_settings.py \
        tests/unit/test_persist.py
git commit -m "feat: add persist() and persist_key() to MountainAshBaseSettings"
```

---

### Task 6: Delete store/ from auth-client

**Files:**
- Delete: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/store/protocol.py`
- Delete: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/store/filesystem.py`
- Delete: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/store/__init__.py`
- Delete: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_store.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/__init__.py`

- [ ] **Step 1: Delete store directory and tests**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
rm -rf src/mountainash_auth_client/store
rm tests/test_store.py
```

- [ ] **Step 2: Update package __init__.py**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/__init__.py`, remove the imports of `FilesystemStore` and `SecretStore`:

Remove these lines:
```python
from mountainash_auth_client.store.filesystem import FilesystemStore
from mountainash_auth_client.store.protocol import SecretStore
```

And remove `"FilesystemStore"` and `"SecretStore"` from `__all__`.

- [ ] **Step 3: Run tests to see what breaks**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick -v`
Expected: Import errors in mixin tests that reference `FilesystemStore`. The mixins themselves still reference `SecretStore` in TYPE_CHECKING — those will be fixed in Task 7.

- [ ] **Step 4: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add -A
git commit -m "refactor: delete store/ directory — capability moved to mountainash-settings"
```

---

### Task 7: Update mixins to use SecretsBackend

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth2.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth1.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_oauth2_mixin.py`

- [ ] **Step 1: Rewrite oauth2.py mixin**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth2.py`:

```python
"""OAuth2ConnectionMixin — reusable connect/refresh for OAuth2 providers."""
from __future__ import annotations

from typing import ClassVar, Self

import httpx

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.flows.oauth2 import OAuthFlow
from mountainash_settings.secrets.registry import get_secrets_backend


class OAuth2ConnectionMixin:
    _spec: ClassVar
    _base_url: ClassVar[str]
    _client: httpx.Client | None

    @property
    def client(self) -> httpx.Client | None:
        return self._client

    def connect(
        self,
        profile,
        *,
        auto_authorize: bool = False,
    ) -> Self:
        auth = profile.auth
        provider = self._spec.name
        flow = OAuthFlow(self._spec)

        backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth.persist_key()
        tokens = backend.get(key)

        access_token: str | None = None

        if tokens and not flow.is_expired(tokens.get("token_expires_at")):
            access_token = tokens["access_token"]
        elif tokens and tokens.get("refresh_token"):
            with backend.transaction(key):
                tokens = backend.get(key)
                if tokens and not flow.is_expired(tokens.get("token_expires_at")):
                    access_token = tokens["access_token"]
                else:
                    try:
                        new_tokens = flow.refresh(
                            refresh_token=tokens["refresh_token"],
                            client_id=auth.CLIENT_ID,
                            client_secret=auth.CLIENT_SECRET.get_secret_value(),
                        )
                        backend.set(key, new_tokens)
                        access_token = new_tokens["access_token"]
                    except Exception:
                        backend.delete(key)
                        if not auto_authorize:
                            raise AuthorizationRequired(provider=provider, user="default")

        if access_token is None:
            if auto_authorize:
                new_tokens = flow.authorize(
                    client_id=auth.CLIENT_ID,
                    client_secret=auth.CLIENT_SECRET.get_secret_value(),
                    scope=auth.SCOPE,
                )
                backend.set(key, new_tokens)
                access_token = new_tokens["access_token"]
            else:
                raise AuthorizationRequired(provider=provider, user="default")

        self._client = httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )
        return self

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()
```

- [ ] **Step 2: Rewrite oauth1.py mixin**

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth1.py`:

```python
"""OAuth1ConnectionMixin — connect/auth for OAuth1 providers."""
from __future__ import annotations

from typing import ClassVar, Self

import httpx

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.flows.oauth1 import OAuth1Flow
from mountainash_settings.secrets.registry import get_secrets_backend


class OAuth1ConnectionMixin:
    _spec: ClassVar
    _base_url: ClassVar[str]
    _client: httpx.Client | None

    def connect(
        self,
        profile,
        *,
        auto_authorize: bool = False,
    ) -> Self:
        auth = profile.auth
        provider = self._spec.name

        backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth.persist_key()
        tokens = backend.get(key)

        if tokens and tokens.get("oauth_token"):
            self._build_client(tokens, profile)
            return self

        if auto_authorize:
            flow = OAuth1Flow(self._spec)
            new_tokens = flow.authorize(
                consumer_key=auth.CONSUMER_KEY,
                consumer_secret=auth.CONSUMER_SECRET.get_secret_value(),
            )
            backend.set(key, new_tokens)
            self._build_client(new_tokens, profile)
            return self

        raise AuthorizationRequired(provider=provider, user="default")

    def _build_client(self, tokens: dict, profile) -> None:
        try:
            from authlib.integrations.httpx_client import OAuth1Auth
        except ImportError as exc:
            raise ImportError(
                "OAuth1 requires authlib: pip install mountainash-auth-client[oauth1]"
            ) from exc

        auth = profile.auth
        self._client = httpx.Client(
            base_url=self._base_url,
            auth=OAuth1Auth(
                client_id=auth.CONSUMER_KEY,
                client_secret=auth.CONSUMER_SECRET.get_secret_value(),
                token=tokens["oauth_token"],
                token_secret=tokens["oauth_token_secret"],
            ),
            timeout=30.0,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()
```

- [ ] **Step 3: Rewrite test_oauth2_mixin.py**

The mixin tests need updating because `connect()` no longer takes `store`, `domain`, `user` parameters. Instead it reads `profile.auth.SETTINGS_SOURCE_SECRETS_PROVIDER` and `profile.auth.persist_key()`.

Replace `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_oauth2_mixin.py`:

```python
"""Tests for OAuth2ConnectionMixin."""
from __future__ import annotations

import time
import typing as t
from contextlib import contextmanager

import pytest

from mountainash_auth_client.errors import AuthorizationRequired
from mountainash_auth_client.mixins.oauth2 import OAuth2ConnectionMixin
from mountainash_settings.secrets.registry import (
    clear_secrets_registry,
    register_secrets_backend,
)


class _InMemoryBackend:
    def __init__(self):
        self._store: dict[str, dict[str, t.Any]] = {}

    def get(self, key: str) -> dict[str, t.Any] | None:
        return self._store.get(key)

    def set(self, key: str, data: dict[str, t.Any]) -> None:
        self._store[key] = data

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    @contextmanager
    def transaction(self, key: str):
        yield


class FakeSpec:
    name = "testprovider"

    @property
    def metadata(self):
        return {
            "authorize_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
        }


class FakeAuth:
    CLIENT_ID = "cid"
    CLIENT_SECRET = property(lambda self: type("S", (), {"get_secret_value": lambda s: "csec"})())
    SCOPE = "read"
    SETTINGS_SOURCE_SECRETS_PROVIDER = "test_mem"

    def persist_key(self):
        return "test.oauth2"


class FakeProfile:
    def __init__(self, auth=None):
        self.auth = auth or FakeAuth()


class FakeProvider(OAuth2ConnectionMixin):
    _spec = FakeSpec()
    _base_url = "https://api.example.com"
    _client = None

    def disconnect(self):
        if self._client:
            self._client.close()
        self._client = None


@pytest.fixture(autouse=True)
def clean():
    clear_secrets_registry()
    yield
    clear_secrets_registry()


@pytest.fixture
def backend():
    b = _InMemoryBackend()
    register_secrets_backend("test_mem", b)
    return b


class TestOAuth2ConnectionMixinNoToken:
    def test_raises_authorization_required_when_no_token(self, backend):
        provider = FakeProvider()
        with pytest.raises(AuthorizationRequired) as exc_info:
            provider.connect(FakeProfile())
        assert exc_info.value.provider == "testprovider"


class TestOAuth2ConnectionMixinWithToken:
    def test_connects_with_valid_stored_token(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        result = provider.connect(FakeProfile())
        assert result is provider

    def test_client_is_set_after_connect(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        provider.connect(FakeProfile())
        assert provider._client is not None

    def test_client_has_bearer_auth_header(self, backend):
        backend.set("test.oauth2", {
            "access_token": "tok_abc",
            "refresh_token": "refresh_xyz",
            "token_expires_at": int(time.time()) + 3600,
        })
        provider = FakeProvider()
        provider.connect(FakeProfile())
        auth_header = provider._client.headers.get("authorization", "")
        assert "Bearer tok_abc" in auth_header

    def test_connect_with_unexpired_token_no_refresh(self, backend):
        backend.set("test.oauth2", {
            "access_token": "valid_tok",
            "refresh_token": "old_refresh",
            "token_expires_at": int(time.time()) + 7200,
        })
        provider = FakeProvider()
        provider.connect(FakeProfile())
        loaded = backend.get("test.oauth2")
        assert loaded["access_token"] == "valid_tok"


class TestOAuth2ConnectionMixinExpiredToken:
    def test_raises_authorization_required_when_token_expired_and_no_refresh(self, backend):
        backend.set("test.oauth2", {
            "access_token": "old_tok",
            "refresh_token": None,
            "token_expires_at": int(time.time()) - 1000,
        })
        provider = FakeProvider()
        with pytest.raises(AuthorizationRequired):
            provider.connect(FakeProfile())


class TestClientProperty:
    def test_client_property_exposes_httpx_client(self):
        import httpx
        provider = FakeProvider()
        mock_client = httpx.Client()
        provider._client = mock_client
        assert provider.client is mock_client
        mock_client.close()

    def test_client_property_none_before_connect(self):
        provider = FakeProvider()
        assert provider.client is None
```

- [ ] **Step 4: Run all auth-client tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/mixins/oauth2.py \
        src/mountainash_auth_client/mixins/oauth1.py \
        tests/test_oauth2_mixin.py
git commit -m "refactor: update mixins to use SecretsBackend instead of SecretStore"
```

---

### Task 8: Full test suite and cleanup

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/__init__.py` (if needed)

- [ ] **Step 1: Run full auth-client test suite with coverage**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch env remove test && hatch run test:test`
Expected: All tests pass. Coverage report shows the updated mixins are tested.

- [ ] **Step 2: Run full mountainash-settings test suite**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-settings && hatch run test:test-quick`
Expected: All tests pass.

- [ ] **Step 3: Clean up pycache if any tracked**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
git rm -r --cached '**/__pycache__' 2>/dev/null || true
```

- [ ] **Step 4: Commit if any cleanup needed**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add -A
git status
# Only commit if there are changes
git commit -m "chore: verify full test suite and clean up"
```

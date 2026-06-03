---
title: Secret Storage
description: The credential storage layer including the SecretStore protocol, FilesystemStore implementation with YAML serialization, domain/provider namespacing, and tombstone semantics.
generated_by: claude skill chapter-content-generator
date: 2026-06-03
version: 0.08
---

# Secret Storage

## Summary

This chapter covers the credential storage layer of mountainash-auth-client. It introduces the SecretStore protocol with its six methods (load, save, clear, is_cleared, list_users, lock), then covers the FilesystemStore concrete implementation with YAML serialization, domain/provider namespace organization for multi-tenant credential management, and tombstone semantics for secure credential revocation.

## Concepts Covered

- SecretStore Protocol
- Load Method
- Save Method
- Clear Method
- Is Cleared Method
- List Users Method
- Lock Method
- FilesystemStore
- YAML Serialization
- Domain Provider Namespace
- Tombstone Semantics

## Prerequisites

- Chapter 1: Foundations (Python Protocols, File Permissions, Atomic File Writes)

## Learning Objectives

After completing this chapter, you will be able to:

- Define and implement the SecretStore protocol interface
- Use each SecretStore method correctly (load, save, clear, is_cleared, list_users, lock)
- Configure FilesystemStore with proper file permissions and atomic writes
- Organize credentials using domain/provider namespaces
- Implement tombstone semantics for secure credential clearing
- Design custom SecretStore backends for vault or keyring systems

---

## Why Credential Storage Needs an Abstraction

OAuth tokens, API keys, and other credentials must be persisted between sessions. Without persistence, users would need to re-authorize every time they run a script or restart an application. But credential storage is not simply "write to a file" -- it involves security constraints (file permissions, encryption), concurrency safety (file locking), lifecycle management (clearing, listing), and organizational structure (multiple domains, providers, and users).

Different environments also have different storage requirements. A developer laptop might store credentials as encrypted YAML files on disk. A CI/CD pipeline might use a cloud vault service. A containerized application might use Kubernetes secrets. The mountainash-auth-client library addresses this diversity by defining a storage protocol that any backend can implement.

## The SecretStore Protocol

The `SecretStore` protocol defines the interface that all credential storage backends must satisfy. It uses Python's structural subtyping (the `Protocol` class from the `typing` module, introduced in Chapter 1) so that any class implementing these six methods is a valid store, regardless of inheritance.

```python
@t.runtime_checkable
class SecretStore(t.Protocol):
    def load(self, domain: str, provider: str, user: str) -> dict[str, t.Any] | None: ...
    def save(self, domain: str, provider: str, user: str, data: dict[str, t.Any]) -> None: ...
    def clear(self, domain: str, provider: str, user: str) -> None: ...
    def is_cleared(self, domain: str, provider: str, user: str) -> bool: ...
    def list_users(self, domain: str, provider: str) -> list[str]: ...
    def lock(self, domain: str, provider: str, user: str) -> AbstractContextManager[None]: ...
```

Every method takes the same three-part key: `domain`, `provider`, and `user`. This three-part key forms the namespace hierarchy for credential organization, which is discussed in detail later in this chapter.

The `@runtime_checkable` decorator allows `isinstance(store, SecretStore)` checks at runtime, enabling defensive validation in code that accepts arbitrary store implementations.

#### Diagram: SecretStore Protocol Methods
<iframe src="../../sims/secret-store-protocol/main.html" width="100%" height="500px" scrolling="no"></iframe>
<details markdown="1">
<summary>SecretStore Protocol Methods</summary>
Type: diagram
**sim-id:** secret-store-protocol<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Display the six SecretStore protocol methods with their signatures, return types, and relationships. Show how they form a complete CRUD+Lock interface for credential management.

**Components:** A central "SecretStore" node connected to six method nodes arranged in a circle: load, save, clear, is_cleared, list_users, lock. Each method node shows the signature and return type. Edges between methods show operational relationships: save -> load (can read what was saved), clear -> is_cleared (can check if cleared), lock -> save/load (protects concurrent access).

**Interactions:** Click each method node to see a detailed description, example usage, and edge cases. Hover to highlight related methods. Toggle "Implementation View" to see how FilesystemStore implements each method.

**Colors:** Protocol node=MediumPurple, Read methods (load, is_cleared, list_users)=SteelBlue, Write methods (save, clear)=DarkGreen, Lock method=DarkGoldenrod.

**Learning Objective:** Understand (Bloom Level 2) the complete SecretStore protocol interface and how the six methods form a coherent credential management API.
</details>

### Load Method

The `load` method retrieves stored credentials for a specific domain, provider, and user combination. It returns a dictionary of credential data if credentials exist, or `None` if no credentials have been saved for that key.

```python
def load(self, domain: str, provider: str, user: str) -> dict[str, Any] | None:
```

Returning `None` rather than raising an exception for missing credentials is a deliberate design choice. The connection mixin needs to distinguish between "no credentials exist yet" (trigger authorization) and "credentials exist but are invalid" (trigger refresh or re-authorization). A `None` return signals the former cleanly.

### Save Method

The `save` method persists a credential dictionary for a given key. The `data` parameter is an arbitrary dictionary, typically containing fields like `access_token`, `refresh_token`, and `token_expires_at`. The save method is responsible for ensuring the data is stored securely (appropriate permissions, encryption if supported) and durably (atomic writes to prevent corruption).

```python
def save(self, domain: str, provider: str, user: str, data: dict[str, Any]) -> None:
```

Save operations should be idempotent -- saving the same data twice should produce the same result as saving once. In the `FilesystemStore`, saving after a `clear` operation also removes the tombstone file, indicating that fresh credentials replace the cleared state.

### Clear Method

The `clear` method removes stored credentials for a given key. Clearing is not the same as simply deleting -- it signals that the credentials have been intentionally revoked and should not be migrated or re-created from legacy sources.

```python
def clear(self, domain: str, provider: str, user: str) -> None:
```

The clear operation is the first half of the tombstone semantics pattern. After clearing, the `is_cleared` method returns `True` for the same key, allowing the connection mixin to distinguish between "never authorized" and "previously authorized but revoked."

### Is Cleared Method

The `is_cleared` method checks whether credentials for a given key have been intentionally cleared. It returns `True` if a `clear` operation was previously performed and no subsequent `save` has occurred.

```python
def is_cleared(self, domain: str, provider: str, user: str) -> bool:
```

This method is essential for preventing unintended credential migration. When the connection mixin finds no stored tokens, it checks `is_cleared` before falling back to legacy token sources. If the credentials were explicitly cleared, the mixin does not re-import legacy tokens -- it requires a fresh authorization instead.

### List Users Method

The `list_users` method returns a list of all user identifiers that have stored credentials for a given domain and provider.

```python
def list_users(self, domain: str, provider: str) -> list[str]:
```

This method supports multi-user scenarios where the same application connects to the same provider with different user identities. For example, a data pipeline might access a SaaS API as both a read-only analytics user and a write-capable admin user. The `list_users` method allows administration tools to discover and manage all stored credentials.

### Lock Method

The `lock` method returns a context manager that provides exclusive access to the credential file for a given key. The lock is used during token refresh to prevent concurrent processes from simultaneously refreshing the same token, which could lead to race conditions with rotating refresh tokens.

```python
def lock(self, domain: str, provider: str, user: str) -> AbstractContextManager[None]:
```

The lock is advisory and file-based in the `FilesystemStore` implementation. It protects against concurrent processes on the same machine but does not protect against concurrent access across machines. For distributed environments, a store implementation backed by a distributed lock (Redis, ZooKeeper, or a cloud-native lock service) would be more appropriate.

## FilesystemStore

The `FilesystemStore` is the built-in implementation of the `SecretStore` protocol. It stores credentials as YAML files organized in a directory hierarchy under a configurable base directory. The constructor takes a single parameter: the path to the base directory.

```python
class FilesystemStore:
    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
```

### Domain Provider Namespace

The `FilesystemStore` organizes credential files using a two-level namespace: domain and provider. The file path for a given credential is `{base_dir}/{domain}/{provider}-{user}.yaml`. This structure enables clean separation of credentials across environments and services.

| Path Component | Example | Purpose |
|---|---|---|
| `base_dir` | `~/.mountainash/tokens` | Root directory for all credentials |
| `domain` | `production` | Environment or tenant identifier |
| `provider` | `snowflake` | Service or API being authenticated |
| `user` | `etl_service` | User identity within the provider |
| Full path | `~/.mountainash/tokens/production/snowflake-etl_service.yaml` | Complete credential file path |

All three namespace components (domain, provider, user) are validated against the pattern `[a-z0-9_]+`. This validation rejects paths containing slashes, dots, or uppercase characters, preventing directory traversal attacks and ensuring consistent, predictable file paths.

```python
_VALID_SEGMENT = re.compile(r'^[a-z0-9_]+$')

def _validate(name: str, label: str) -> None:
    if not _VALID_SEGMENT.match(name):
        raise ValueError(f"Invalid {label}: {name!r} -- must match [a-z0-9_]+")
```

In addition to the primary credential file, the `FilesystemStore` uses several auxiliary files for each credential key:

- **`.{provider}-{user}.tmp`** -- temporary file used during atomic writes
- **`.{provider}-{user}.cleared`** -- tombstone file indicating intentional clearing
- **`.{provider}-{user}.lock`** -- lock file for concurrent access protection

All auxiliary files are dot-prefixed (hidden on Unix systems) to keep directory listings clean.

#### Diagram: FilesystemStore Directory Layout
<iframe src="../../sims/filesystem-store-layout/main.html" width="100%" height="500px" scrolling="no"></iframe>
<details markdown="1">
<summary>FilesystemStore Directory Layout</summary>
Type: diagram
**sim-id:** filesystem-store-layout<br/>
**Library:** vis-network<br/>
**Status:** Specified

**Purpose:** Visualize the FilesystemStore directory tree showing the base_dir, domain directories, credential YAML files, and auxiliary files (tmp, tombstone, lock).

**Components:** A tree layout with base_dir as root, two example domain directories (production, staging), and several credential files under each. Auxiliary files (dotfiles) are shown alongside their primary files. A legend explains file types and permissions.

**Interactions:** Click on any file node to see its contents (sample YAML for credential files, empty for tombstones, advisory for lock files). Hover to see file permissions (0o600 for files, 0o700 for directories). Toggle "Show Hidden Files" to reveal/hide auxiliary dotfiles.

**Colors:** Directories=Gold, Credential files=DarkGreen, Tombstone files=Crimson, Lock files=DarkGoldenrod, Temp files=LightGray.

**Learning Objective:** Apply (Bloom Level 3) the FilesystemStore namespace structure to organize credentials for a multi-environment, multi-provider deployment.
</details>

### YAML Serialization

The `FilesystemStore` serializes credential data as YAML using `yaml.safe_dump` for writing and `yaml.safe_load` for reading. YAML was chosen over JSON for several reasons: it supports multi-line strings cleanly (useful for certificates and keys), it is human-readable (useful for debugging), and it does not require quoting string values.

The save method demonstrates the complete write flow, combining atomic writes (Chapter 1) with permission enforcement:

```python
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

    # Remove tombstone if present
    if tombstone.exists():
        tombstone.unlink()
```

The method uses `os.open()` with explicit mode `0o600` rather than Python's built-in `open()`. This is critical because `open()` creates files with the process's default umask, which could be `0o644` (world-readable). Using `os.open()` with `os.O_CREAT` and the mode argument sets the permissions atomically at creation time.

The load method enforces two security checks before reading credentials:

1. **Symlink rejection** -- `path.is_symlink()` prevents symlink-based attacks where an attacker creates a symlink pointing to a different credential file or a world-readable location
2. **Permission check** -- `mode & 0o077` detects group- or world-readable files, which indicate a potential security misconfiguration

```python
def load(self, domain: str, provider: str, user: str) -> dict[str, Any] | None:
    path = self._token_path(domain, provider, user)
    if not path.exists():
        return None
    if path.is_symlink():
        raise PermissionError(f"Credential file is a symlink: {path}")
    mode = path.stat().st_mode
    if mode & 0o077:
        raise PermissionError(f"Credential file has unsafe permissions: {path}")
    with path.open("r") as fh:
        return yaml.safe_load(fh)
```

### Tombstone Semantics

A tombstone is a marker file that records the fact that credentials were intentionally cleared. The `FilesystemStore` creates a tombstone file (`.{provider}-{user}.cleared`) when `clear()` is called, and removes it when `save()` stores fresh credentials.

The tombstone pattern solves a subtle problem in credential lifecycle management. Consider this scenario:

1. A user's OAuth tokens are stored in the filesystem
2. The same tokens also exist in a legacy profile configuration file
3. The user explicitly revokes the tokens (calls `clear()`)
4. The connection mixin discovers no stored tokens and checks `is_cleared()`
5. Without the tombstone, the mixin would fall back to the legacy profile tokens, re-importing the very credentials the user just revoked

With tombstone semantics, step 4 returns `True`, and the mixin skips the legacy fallback entirely. The user's intent to clear is preserved even when the primary credential file has been deleted.

The lifecycle of tombstone state can be summarized as:

- **Initial state** -- no credential file, no tombstone. `load()` returns `None`, `is_cleared()` returns `False`.
- **After `save()`** -- credential file exists, no tombstone. `load()` returns data, `is_cleared()` returns `False`.
- **After `clear()`** -- no credential file, tombstone exists. `load()` returns `None`, `is_cleared()` returns `True`.
- **After `save()` following `clear()`** -- credential file exists, tombstone removed. `load()` returns data, `is_cleared()` returns `False`.

| State | Credential File | Tombstone | `load()` | `is_cleared()` |
|---|---|---|---|---|
| Never saved | absent | absent | `None` | `False` |
| Active | present | absent | data dict | `False` |
| Cleared | absent | present | `None` | `True` |
| Re-saved after clear | present | absent | data dict | `False` |

### File Locking

The `lock` method provides advisory file locking using `fcntl.flock()` with `LOCK_EX` (exclusive lock). It creates a dedicated lock file and acquires the lock on that file rather than on the credential file itself. This avoids issues with locking files that might be deleted and recreated during save operations.

```python
@contextmanager
def lock(self, domain: str, provider: str, user: str):
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
```

The lock file is never deleted after use -- it is a zero-byte sentinel that persists. This is standard practice for `flock`-based locking because deleting and recreating lock files introduces race conditions where two processes could each create a new lock file and both think they hold the lock.

!!! warning "Advisory Locking Limitations"
    `fcntl.flock()` provides advisory locking only -- it is not enforced by the kernel. A process that opens the credential file without first acquiring the lock will succeed. This is acceptable for the mountainash-auth-client use case because all access goes through the `FilesystemStore` API, which always acquires the lock during refresh operations. However, external tools that directly read or modify credential files could still create race conditions.

#### Diagram: Concurrent Token Refresh with File Locking
<iframe src="../../sims/concurrent-refresh-locking/main.html" width="100%" height="500px" scrolling="no"></iframe>
<details markdown="1">
<summary>Concurrent Token Refresh with File Locking</summary>
Type: microsim
**sim-id:** concurrent-refresh-locking<br/>
**Library:** p5.js<br/>
**Status:** Specified

**Purpose:** Simulate two concurrent processes attempting to refresh the same token, showing how file locking prevents double-refresh and refresh token invalidation.

**Components:** Two process timelines (Process A, Process B) running in parallel. Each shows: check token expired -> acquire lock -> re-check token (may be fresh now) -> refresh or skip -> release lock. A shared "Credential File" state indicator shows the current token values.

**Interactions:** Click "Start" to run the simulation. Adjust the timing offset slider to see what happens when processes overlap at different points. Toggle "Without Locking" to see the race condition that locking prevents (both refresh, second refresh uses an invalidated refresh token).

**Colors:** Process A=SteelBlue, Process B=Gold, Lock acquired=DarkGreen border, Lock waiting=Crimson border, Credential file=MediumPurple.

**Learning Objective:** Evaluate (Bloom Level 5) why file-locked refresh is necessary for concurrent-safe token renewal and what race conditions it prevents.
</details>

## Designing Custom SecretStore Backends

Because `SecretStore` is a protocol, you can implement custom storage backends without importing anything from mountainash-auth-client. A Vault-backed store, for example, would translate the three-part key into a Vault path and use the Vault API for all operations.

For example, a Vault-backed implementation might map the three-part key to a Vault path like `secret/data/{domain}/{provider}/{user}` and use the Vault HTTP API for all operations. A Keyring-backed implementation might use the `keyring` library with `{domain}/{provider}` as the service name and `user` as the username. Neither implementation needs to import anything from mountainash-auth-client -- they just need to provide the six methods with the correct signatures.

The key design constraints for custom implementations are:

- **`load` must return `None` for missing credentials**, not raise an exception
- **`save` must be idempotent** and handle being called multiple times with the same data
- **`clear` must persist its intent** through some mechanism (tombstone, metadata flag, or soft-delete) so that `is_cleared` can distinguish "never saved" from "cleared"
- **`lock` must return a context manager** that provides mutual exclusion for the duration of the `with` block
- **All methods must accept the three-part key** (`domain`, `provider`, `user`) and handle arbitrary key values safely

## Key Takeaways

- **SecretStore** is a `Protocol` with six methods (`load`, `save`, `clear`, `is_cleared`, `list_users`, `lock`) that any credential storage backend can implement through structural subtyping.
- **`load`** returns `None` for missing credentials (not an exception), enabling the connection mixin to distinguish "never authorized" from "authorized but expired."
- **`save`** persists credential dictionaries and removes any existing tombstone, signaling fresh credentials.
- **`clear`** removes credentials and leaves a tombstone marker. **`is_cleared`** checks for this marker, enabling the distinction between "never saved" and "intentionally revoked."
- **`list_users`** discovers all user identities with stored credentials for a given domain/provider, supporting multi-user administration.
- **`lock`** returns a context manager for exclusive file access during concurrent token refresh operations.
- **FilesystemStore** organizes credentials as YAML files in a `{base_dir}/{domain}/{provider}-{user}.yaml` hierarchy, with `0o700` directory and `0o600` file permissions enforced at creation time.
- **YAML serialization** uses atomic writes (temp file + `os.replace()`) to prevent credential corruption from crashes or concurrent access.
- **Domain/provider namespacing** with `[a-z0-9_]+` validation prevents directory traversal attacks and ensures predictable file paths.
- **Tombstone semantics** prevent cleared credentials from being re-imported from legacy sources, preserving the user's intent to revoke.
- **File locking** uses `fcntl.flock(LOCK_EX)` on a dedicated lock file to prevent concurrent refresh race conditions, with the lock file intentionally persisting across operations.

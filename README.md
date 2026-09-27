# mountainash-auth-client

Client-side authentication for the mountainash ecosystem.

Requires **Python 3.12+** and **mountainash-settings>=0.1.0,<0.2**.
Auth profiles describe configured credentials; OAuth lifecycle managers acquire
and persist tokens separately. Consumers select credential renderers explicitly.

## OAuth token storage

Select a raw `ClearableSecretStore` at the application boundary and keep it open
for the lifetime of its managers and flows:

```python
from mountainash_auth_client import OAuth2TokenManager
from mountainash_settings.secrets import FilesystemBackend

# root, provider and auth_profile are supplied by your application.
with FilesystemBackend(root) as store:
    manager = OAuth2TokenManager(provider, auth_profile, token_store=store)
    credential = manager.acquire()  # non-interactive; refreshes when needed
```

Managers require `token_store=`. There is no token-store registry or provider-name
lookup. Pass the raw store: auth-client applies the `oauth` namespace exactly once
and preserves the profile's `persist_key()` addressing. The application owns store
closure; managers and flows never close it. Wire-only flows can omit a store,
but persistence requires one. See the [integration guide](docs/INTEGRATION.md).

The M4b candidate retains version **26.6.1** for installed verification only.
Exact artifact hashes identify this candidate, not its version. Before publication,
assign a new release version and downstream minimum dependency bounds.

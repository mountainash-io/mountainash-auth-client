# Token-store ownership

Who selects, namespaces and closes persisted token storage?

[example.py](example.py) seeds a synthetic token in a temporary filesystem
store, acquires it while the store is open, and reopens the store to acquire
the persisted record. The application owns both store lifetimes and closes
them before deleting the temporary directory.

From the repository root, after the [shared setup](../README.md#setup):

```bash
python examples/token_store_ownership/example.py
```

Expected output:

```text
Open store: namespaced token acquired
Reopened store: persisted token acquired
Stores closed; temporary directory removed
```

The namespace view is used only to seed this offline example. Always pass the
raw store to managers and flows: they apply `oauth` themselves. Namespace views
separate record keys, not access permissions. Configuration secret readers can
be selected separately from the OAuth token store.

For durable use, provision an application-owned private directory instead of the
temporary directory here; the backend does not create its root. See settings'
[store contracts and platform requirements](https://github.com/mountainash-io/mountainash-settings/blob/develop/docs/README_SECRETS.md).

Next: [authorization URLs](../authorization_urls/).
Reference: [selected token store and ownership](../../docs/INTEGRATION.md#selected-token-store-and-ownership).

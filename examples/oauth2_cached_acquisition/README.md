# OAuth2 cached acquisition

How do I acquire a cached token and handle missing authorization?

[example.py](example.py) defines a credential profile with a stable account key,
seeds a synthetic token in memory, acquires it through `OAuth2TokenManager`, and
renders the result for HTTP. It then removes the local token and handles
`AuthorizationRequired`.

From the repository root, after the [shared setup](../README.md#setup):

```bash
python examples/oauth2_cached_acquisition/example.py
```

Expected output:

```text
Cached token: acquired and rendered for HTTP
After local removal: authorization required
```

`persist_key()` is application-defined and must distinguish accounts sharing
the store. A built-in `OAuth2AuthProfile` alone does not supply it. Managers
receive the raw store; the explicit namespace view here is only for seeding
the fixture where normal authorization would write a token.

This access-only record has no expiry or refresh token, so acquisition remains
offline. Real expired records with refresh credentials can contact the token
endpoint. `acquire()` never opens a browser; explicit `authorize()` performs
interaction. `revoke()` removes local state, not the provider's grant.

Next: [store ownership](../token_store_ownership/).
Reference: [typed credential protocols](../../docs/typing.md#public-contracts-and-limits).

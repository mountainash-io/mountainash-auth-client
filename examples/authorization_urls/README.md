# Authorization URLs

How do client identity, scope, state and PKCE appear in an authorization URL?

[example.py](example.py) configures an OAuth2 provider and inspects a generated
authorization URL. It checks the client ID, redirect URI, default scope, state
and PKCE challenge without opening a browser, callback server or network connection.

From the repository root, after the [shared setup](../README.md#setup):

```bash
python examples/authorization_urls/example.py
```

Expected output:

```text
Authorization: client=reports-client; scope=reports.read
State present; PKCE method=S256; no callback opened
```

Token-endpoint authentication `none` still requires an authorization client ID.
The example leaves generated state/challenge values out of its output. The same
flow instance retains the PKCE verifier for a later exchange; URL construction
alone does not authenticate a user or validate a callback.

For a full grant, use `authorize()` with a provider-approved redirect and the
built-in local/manual callback or an injected `CallbackServerFactory`. The flow
checks returned state before exchanging the code.

Next: [OAuth1 signing](../oauth1_signing/).
Reference: [integration guide](../../docs/INTEGRATION.md).

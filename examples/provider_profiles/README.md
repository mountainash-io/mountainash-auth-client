# Provider profiles

How do endpoint configuration and user credentials combine?

[example.py](example.py) keeps OAuth endpoints in an `OAuth2ProviderProfile`
and a synthetic access token in a `TokenAuthProfile`. The consumer emits
configuration first, then credentials, and constructs its own HTTP client.
It builds a request without sending it.

From the repository root, after the [shared setup](../README.md#setup):

```bash
python examples/provider_profiles/example.py
```

Expected output:

```text
Provider: reports; scope: reports.read
Resource: https://files.example.com/sales.csv; bearer credential attached
```

Provider values belong to the application; auth-client supplies the schema.
`DEFAULT_SCOPE` configures OAuth authorization, while the provider's HTTP
renderer emits `BASE_URL` for the resource client. A static token profile does
not refresh tokens; use a manager when the application needs that lifecycle.

Next: [cached acquisition](../oauth2_cached_acquisition/).
Reference: [integration concepts](../../docs/INTEGRATION.md#core-concepts).

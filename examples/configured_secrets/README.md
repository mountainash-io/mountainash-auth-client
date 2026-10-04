# Configured secret references

How do configuration files refer to secrets without containing their values?

[example.py](example.py) loads provider endpoints from [provider.toml](provider.toml)
and an OAuth2 credential from [auth.yaml](auth.yaml). Its `CLIENT_SECRET` is a
`secret:` reference resolved through an explicitly selected configuration reader.
A separate raw store supplies the acquired OAuth token.

From the repository root, after the [shared setup](../README.md#setup):

```bash
python examples/configured_secrets/example.py
```

Expected output:

```text
Provider: reports; client: reports-client
Configuration reader: client secret resolved
Token store: cached access token acquired
Resource options:
{
  "base_url": "https://files.example.com",
  "headers": {
    "Authorization": "<redacted>"
  }
}
```

The application seeds synthetic in-memory records for this offline example.
`NamespacedSecretStore(config_store, "reports_app")` is passed as `secret_store=`
when constructing the credential profile. `secret:client.secret` resolves against
that reader to `reports_app.client` / `secret`. The profile retains a `SecretStr`.

The manager instead receives the raw `token_store=`; it applies `oauth` itself.
The script verifies that the client secret and access token stay in their selected
stores, and that the HTTP header uses the acquired access token, not the client
secret. The stable account key is application-owned. No authorization or refresh
request is made, since the cached record has no expiry.

Unset `REPORT_PROVIDER_*` and `REPORT_AUTH_*` variables for reproducible output.
Next: [nested client adapters](../nested_client_adapter/).
Reference: [selected token stores](../../docs/INTEGRATION.md#selected-token-store-and-ownership).

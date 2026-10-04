# Consumer-specific credentials

How can the same credential serve a client that expects an object instead of HTTP headers?

[example.py](example.py) loads a `TokenAuthProfile` from [auth.yaml](auth.yaml),
resolving its secret through a selected store. The built-in HTTP renderer provides
a bearer header. A consumer-owned function creates a typed `ReportCredential`
object for an illustrative report SDK instead.

From the repository root, after the [shared setup](../README.md#setup):

```bash
python examples/consumer_credentials/example.py
```

Expected output:

```text
One token, two consumer shapes:
{
  "http": {
    "headers": {
      "Authorization": "<redacted>"
    }
  },
  "report_sdk": {
    "credential": {
      "access_key": "<redacted>",
      "scheme": "bearer"
    }
  }
}
```

The SDK object's `access_key` field is the consumer's vocabulary; it is not an
alias added to `TokenAuthProfile`. The consumer adapter reads `TOKEN` and unwraps
it at the SDK boundary. Its plaintext field is excluded from the object's repr.
No global adapter registry or mutation of shared credential classes is involved.

The script verifies both actual credential representations before printing a
deliberately redacted display dictionary. The SDK type is illustrative: no extra
SDK is installed and no service is called. Unset `REPORT_AUTH_*` variables for
reproducible output.

Reference: [consumer rendering ownership](../../docs/INTEGRATION.md#auth-profile-catalogue).

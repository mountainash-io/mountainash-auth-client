# Nested client adapter

How does a consumer combine profile emission and authentication into nested client options?

[example.py](example.py) declares an application-owned `ReportEndpoint` profile.
Its inline `__adapters__` entry converts emitted endpoint fields and caller options
into a report client's nested `session` and `retry` options. A consumer-owned
composition function then renders a bearer profile into that session.

Endpoint fields come from [endpoint.yaml](endpoint.yaml); the credential comes
from [auth.toml](auth.toml). These are illustrative report-client options, not
kwargs accepted directly by `httpx.Client`.

From the repository root, after the [shared setup](../README.md#setup):

```bash
python examples/nested_client_adapter/example.py
```

Expected output:

```text
Report client options:
{
  "retry": {
    "attempts": 3
  },
  "session": {
    "base_url": "https://files.example.com",
    "headers": {
      "Accept": "text/csv",
      "Authorization": "<redacted>",
      "X-Report-App": "reports_app"
    },
    "timeout": 15
  }
}
Caller options unchanged
```

The endpoint's `ProfileField` mappings feed its adapter. Declared profile values
win over caller defaults for the fields they own; unrelated headers survive.
The adapter copies each nested dictionary it changes, since `emit()` only copies
the outer base dictionary. Auth rendering targets the inner session, rather than
the entire report-client envelope.

The script checks the complete unredacted structure and compares the caller's
options with a deep snapshot. No shared auth class is changed or registered with
a new adapter. Unset `REPORT_ENDPOINT_*` and `REPORT_AUTH_*` environment variables
to reproduce the fixture values.

Next: [consumer-specific credentials](../consumer_credentials/).
Reference: [credential injection](../../docs/INTEGRATION.md#pattern-1--credential-injection-via-emit-the-primary-integration).

# Credential rendering

How does one credential render for different client families?

[example.py](example.py) renders a password profile for HTTP and Paramiko, then
checks that the caller's base options are preserved. No SDK connection is opened;
password rendering does not require the `sftp` extra.

From the repository root, after the [shared setup](../README.md#setup):

```bash
python examples/credential_rendering/example.py
```

Expected output:

```text
HTTP: Basic credential attached; Accept preserved
SSH: username and password supplied; base unchanged
```

The consumer chooses `TargetFamily` explicitly. HTTP receives a Basic header;
Paramiko receives `username` and `password` kwargs. `NoAuthProfile` preserves
the supplied options. Rendered dictionaries contain plaintext credentials and
are checked internally rather than printed.

Next: [provider profiles](../provider_profiles/).
Reference: [credential injection](../../docs/INTEGRATION.md#emit--the-integration-primitive).

# OAuth1 signing

How do I attach a request signer instead of a bearer header?

[example.py](example.py) renders an `OAuth1AuthProfile` into an Authlib signer,
then sends a request through HTTPX's in-process `MockTransport`. Authlib signs
the real request; the example inspects the resulting OAuth header without
printing its token or signature. Nothing contacts an external service.

From the repository root, after the [shared setup](../README.md#setup), including
the `oauth1` extra:

```bash
python examples/oauth1_signing/example.py
```

Expected output:

```text
GET /sales.csv: OAuth1 signature attached
In-process response: north,120
```

`emit(TargetFamily.HTTP)` supplies an `auth=` signer, not a fixed bearer header.
This recipe uses an already-issued synthetic token pair. For persisted token
pairs, `OAuth1TokenManager.acquire_auth()` supplies a signer through the manager's
non-interactive acquisition path. Obtaining a live token pair requires a separate
provider authorization grant.

Reference: [token acquisition](../../docs/INTEGRATION.md#token-acquisition-seam-acquire--acquire_auth).

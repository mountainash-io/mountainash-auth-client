# Auth Integration Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Change mixin signatures so auth is received as a separate top-level settings instance rather than extracted from `profile.auth`.

**Architecture:** Mixins change from `connect(self, profile, ...)` to `connect(self, auth, ...)`. The `auth` parameter is a full MountainAshBaseSettings instance with its own secrets_provider, persist_key(), and persist(). OAuth1's `_build_client` also changes from `(tokens, profile)` to `(tokens, auth)`.

**Tech Stack:** Python 3.11+, mountainash-settings, mountainash-auth-client

---

### Task 1: Update mixin signatures

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth2.py`
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth1.py`

- [ ] **Step 1: Update OAuth2ConnectionMixin.connect() signature**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth2.py`, change the `connect` method signature and remove the `auth = profile.auth` line. Replace the entire method:

```python
    def connect(
        self,
        auth,
        *,
        auto_authorize: bool = False,
    ) -> Self:
        provider = self._spec.name
        flow = OAuthFlow(self._spec)

        backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth.persist_key()
        tokens = backend.get(key)

        access_token: str | None = None

        if tokens and not flow.is_expired(tokens.get("token_expires_at")):
            access_token = tokens["access_token"]
        elif tokens and tokens.get("refresh_token"):
            with backend.transaction(key):
                tokens = backend.get(key)
                if tokens and not flow.is_expired(tokens.get("token_expires_at")):
                    access_token = tokens["access_token"]
                else:
                    try:
                        new_tokens = flow.refresh(
                            refresh_token=tokens["refresh_token"],
                            client_id=auth.CLIENT_ID,
                            client_secret=auth.CLIENT_SECRET.get_secret_value(),
                        )
                        backend.set(key, new_tokens)
                        access_token = new_tokens["access_token"]
                    except Exception:
                        backend.delete(key)
                        if not auto_authorize:
                            raise AuthorizationRequired(provider=provider, user="default")

        if access_token is None:
            if auto_authorize:
                new_tokens = flow.authorize(
                    client_id=auth.CLIENT_ID,
                    client_secret=auth.CLIENT_SECRET.get_secret_value(),
                    scope=auth.SCOPE,
                )
                backend.set(key, new_tokens)
                access_token = new_tokens["access_token"]
            else:
                raise AuthorizationRequired(provider=provider, user="default")

        self._client = httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )
        return self
```

The only change from current code: `profile` parameter renamed to `auth`, and the line `auth = profile.auth` is removed.

- [ ] **Step 2: Update OAuth1ConnectionMixin.connect() and _build_client()**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/src/mountainash_auth_client/mixins/oauth1.py`, change both `connect` and `_build_client`. Replace the entire class body (keeping imports and class declaration):

```python
    def connect(
        self,
        auth,
        *,
        auto_authorize: bool = False,
    ) -> Self:
        provider = self._spec.name

        backend = get_secrets_backend(auth.SETTINGS_SOURCE_SECRETS_PROVIDER)
        key = auth.persist_key()
        tokens = backend.get(key)

        if tokens and tokens.get("oauth_token"):
            self._build_client(tokens, auth)
            return self

        if auto_authorize:
            flow = OAuth1Flow(self._spec)
            new_tokens = flow.authorize(
                consumer_key=auth.CONSUMER_KEY,
                consumer_secret=auth.CONSUMER_SECRET.get_secret_value(),
            )
            backend.set(key, new_tokens)
            self._build_client(new_tokens, auth)
            return self

        raise AuthorizationRequired(provider=provider, user="default")

    def _build_client(self, tokens: dict, auth) -> None:
        try:
            from authlib.integrations.httpx_client import OAuth1Auth
        except ImportError as exc:
            raise ImportError(
                "OAuth1 requires authlib: pip install mountainash-auth-client[oauth1]"
            ) from exc

        self._client = httpx.Client(
            base_url=self._base_url,
            auth=OAuth1Auth(
                client_id=auth.CONSUMER_KEY,
                client_secret=auth.CONSUMER_SECRET.get_secret_value(),
                token=tokens["oauth_token"],
                token_secret=tokens["oauth_token_secret"],
            ),
            timeout=30.0,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()
```

Changes from current: `connect` takes `auth` instead of `profile`, removes `auth = profile.auth`. `_build_client` takes `auth` instead of `profile`, removes `auth = profile.auth` inside the method.

- [ ] **Step 3: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add src/mountainash_auth_client/mixins/oauth2.py \
        src/mountainash_auth_client/mixins/oauth1.py
git commit -m "refactor: mixin connect() takes auth directly, not profile"
```

---

### Task 2: Update mixin tests

**Files:**
- Modify: `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_oauth2_mixin.py`

- [ ] **Step 1: Remove FakeProfile, pass FakeAuth directly**

In `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client/tests/test_oauth2_mixin.py`:

1. Delete the `FakeProfile` class (lines 57-59).

2. Replace every `provider.connect(FakeProfile())` call with `provider.connect(FakeAuth())`.

The specific lines to change:

Line 91: `provider.connect(FakeProfile())` → `provider.connect(FakeAuth())`
Line 103: `result = provider.connect(FakeProfile())` → `result = provider.connect(FakeAuth())`
Line 113: `provider.connect(FakeProfile())` → `provider.connect(FakeAuth())`
Line 123: `provider.connect(FakeProfile())` → `provider.connect(FakeAuth())`
Line 134: `provider.connect(FakeProfile())` → `provider.connect(FakeAuth())`
Line 148: `provider.connect(FakeProfile())` → `provider.connect(FakeAuth())`

- [ ] **Step 2: Run all tests**

Run: `cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client && hatch run test:test-quick -v`
Expected: All tests pass.

- [ ] **Step 3: Commit**

```bash
cd /home/nathanielramm/git/mountainash-io/mountainash/mountainash-auth-client
git add tests/test_oauth2_mixin.py
git commit -m "test: pass auth directly to mixin connect() in tests"
```

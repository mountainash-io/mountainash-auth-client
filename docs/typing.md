# Installed typing

Auth-client ships inline annotations and a PEP 561 `py.typed` marker. The
qualification gate checks a direct wheel, sdist, and sdist-rebuilt wheel using
mypy **1.10.1** on Python **3.12 and 3.13**. Source checking includes all of
`src/mountainash_auth_client` and `tests`; no test exclusions apply.

## Public contracts and limits

- Built-in auth profiles expose typed fields, including every profile family.
  Secret fields are `pydantic.SecretStr`, optionally `None` when the runtime
  schema allows it. `ProfileSpec` remains the runtime schema owner; the class
  annotations under `TYPE_CHECKING` describe its generated fields.
- Root OAuth exports remain lazy at runtime and are explicitly re-exported to
  type checkers. Importing the root package does not load the OAuth layer,
  HTTPX, Authlib, or Paramiko. Installed qualification also resolves all root
  exports without Authlib or Paramiko installed.
- Provider profiles satisfy their structural provider protocols. Callback
  factories return `CallbackServerProtocol`; callback results are `dict[str, str]`.
- `PersistableAuthProfile` requires only `persist_key() -> str`. Cached resolver
  calls accept key-only objects. Interactive calls and manager constructors
  require `OAuth1CredentialProfile` or `OAuth2CredentialProfile`, imported from
  `mountainash_auth_client.oauth.persistence`. A consumer can subclass a built-in
  auth profile and implement `persist_key()` to meet that contract.
- Flow results use `OAuth1Tokens` / `OAuth2Tokens` TypedDicts from
  `mountainash_auth_client.oauth.records`. `TokenCredential` exposes normalized
  OAuth2 credentials. Persisted settings `SecretRecord` values are JSON, not
  already-validated token records: consumed token members must be strings and
  expiry must be an integer or `None`, never `bool`. Malformed values raise
  value-free errors without rewriting the record.
- Dynamic profile constructors, driver dictionaries from `emit()`, arbitrary
  `ServiceAccountAuthProfile.INFO` members, and OAuth1's Authlib signer remain
  dynamic boundaries. These checks do not promise fully strict typing of every
  integration. Constructor keyword validation is performed by the runtime schema.

## Commands

From a Git checkout with the sibling typed settings checkout available:

```sh
hatch run mypy:check
hatch run mypy:check src/mountainash_auth_client tests --warn-unused-ignores
hatch run mypy:qualify --settings-source ../mountainash-settings --output /tmp/opencode/auth-client-typing-312
hatch run ruff:ruff check src tests tools
```

Use a **new**, outside-checkout output directory for every qualification run.
The local Hatch environment is `.hatch/mypy` and inherits Python 3.12. For a
real Python 3.13 run, create a separate environment using that interpreter:

```sh
uv venv --python 3.13 /tmp/opencode/auth-client-typing-runner-313
uv pip install --python /tmp/opencode/auth-client-typing-runner-313/bin/python 'build==1.2.2.post1' 'hatchling==1.27.0'
/tmp/opencode/auth-client-typing-runner-313/bin/python tools/qualify_typing.py --settings-source ../mountainash-settings --output /tmp/opencode/auth-client-typing-313
```

The CI workflow uses `setup-python` and a fresh runner-temp venv for each matrix
interpreter, rather than inheriting Hatch's 3.12 default. It uses the existing
GitHub App dependency checkout actions and an explicit `temp/mountainash-settings`
source, fetching its history so the merged typing revision can be verified.

## Evidence and acceptance

The gate requires settings commit `503d797b673f4bde645b394bfcf746878313076f`
or a descendant. It builds settings into a separate dependency directory and
installs that **exact wheel path** alongside each exact auth-client wheel.
Installed `direct_url.json` URLs and SHA-256 hashes must match those artifacts;
both import origins must lie inside the fresh consumer venv.

Consumers run outside both checkouts with Python/mypy path overrides removed,
an empty checker config, no incremental cache, `--no-implicit-reexport`, and
`--warn-unused-ignores`. Fixtures assert useful types and require invalid secret,
callback, flow, token and credential operations to produce their specified
diagnostics. A second checker pass removes their targeted ignores and verifies
the exact error locations/codes. Static function bodies are never executed.
The separate runtime smoke only constructs/emits profiles and reads a local
token record; it does not authorize, open a browser, or make network requests.

The single Authlib `import-untyped` ignore in the source tests documents that
optional dependency's untyped import. No blanket missing-import suppression is
used. Build setup pins build 1.2.2.post1 and hatchling 1.27.0; isolated PEP 517
builds resolve each project's declared build requirements. Installed consumers
pin mypy 1.10.1 and types-PyYAML 6.0.12.20260906; other dependency versions are
captured by `pip freeze`, not fully locked.

`receipt.json` records actual `sys.version`, revisions/status, tracked and
untracked non-ignored input-file hashes, fixture hashes, artifact hashes,
installed versions and origins. Build/checker/runtime logs survive failures.
Artifact hashes describe the actual dirty working-tree build, not just HEAD;
input hashes omit ignored files and do not imply a reproducible dependency lock.
The sdist includes the qualification recipe and fixtures; run the provenance
gate from a Git checkout. Passing this gate qualifies auth-client's consumers;
transport/files adoption and package publication require their own evidence.

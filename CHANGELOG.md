# Changelog

## Unreleased

### Added

- HTTP mTLS certificate emission (#56): `CertificateAuthProfile.emit(TargetFamily.HTTP)` returns a loaded `SSLContext` in `verify`, supporting certificate/key paths and secret PEM material. Temporary PEM files are removed before return; caller-owned contexts are rejected in favour of fresh-context factories.
- Added the runtime dependency `certifi` for the default HTTP CA bundle. Explicit CA paths, `verify=False`, and `trust_env`-controlled environment CA settings remain supported.

### Fixed

- Missing HTTP client certificates now report the required `CERTIFICATE_PATH` or `CERTIFICATE` inputs directly, rather than replacing the requirement with a generic loading error.

### Security

- Token-error constructors now retain safe display locations and recognised OAuth error codes only. `body` contains code-only JSON or an empty string; unknown codes become `None`. Provider descriptions and raw bodies are discarded, including on direct construction.
- Callback denial retains only recognised authorization error codes, with `unknown_error` for other values and an always-empty `description`.
- OAuth1 request/verifier and OAuth2 exchange/refresh boundaries remove unsafe native exception text, attributes and chains. Response-backed failures retain their actual integer status; pre-response native failures now raise safe `RuntimeError` rather than raw HTTPX/Authlib exceptions. OSError causes retain only errno/strerror, without filenames.
- Credential-bearing callback and consumer-hook failures are sanitized. Operation-policy `PermissionError` keeps its category without arbitrary prose; trust validation and token-persistence ordering are unchanged.
- OAuth imports install process-wide HTTPX/httpcore logging filters without changing levels or handlers. HTTPX retains method, safe URL and status; httpcore retains event identity only. Reason phrases, headers and native exception representations are discarded.

### Migration

Inspect `error_code` and `status_code`, not provider descriptions or original native causes. `invalid_grant` and `invalid_token` still drive existing refresh recovery; unknown failures do not clear the stored credential. Display locations retain hostnames and paths, so applications must not put credentials there.

Environment ingestion, blank/custom prefixes, successful OAuth behavior and optional Authlib loading remain unchanged. No existing dependency floor or package version changes are included.

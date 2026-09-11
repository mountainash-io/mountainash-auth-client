# Coverage Report — mountainash-auth-client

**Source hash:** `bea71b46178a4a764a6a289218f2e701490fe08e`
**Mode:** initial-profile
**Generated:** 2026-06-02

## Summary

| Metric | Count |
|--------|-------|
| Modules discovered | 10 |
| Modules profiled | 10 |
| Profiles ignored | 1 (`__version__.py`) |
| Facets written | 5 |
| Coverage gaps | 2 |

## Module Coverage

| Module | Profile | Tests | Users Facet | Maintainers Facet |
|--------|---------|-------|-------------|-------------------|
| schemas.base | yes | yes (via test_schemas.py) | yes | yes |
| schemas.auth-types | yes | yes (test_schemas.py) | yes | yes |
| schemas.dispatch | yes | yes (test_schemas.py) | yes | yes |
| flows.oauth2 | yes | yes (test_oauth2_flow.py) | yes | yes |
| flows.oauth1 | yes | yes (test_oauth1_flow.py) | yes | yes |
| mixins.oauth2 | yes | yes (test_oauth2_mixin.py) | yes | yes |
| mixins.oauth1 | yes | **NO** | yes | yes |
| server | yes | yes (test_server.py) | yes | yes |
| store | yes | yes (test_store.py) | yes | yes |
| errors | yes | yes (test_errors.py) | yes | yes |

## Coverage Gaps

### 1. No dedicated tests for OAuth1ConnectionMixin

**Module:** `mixins.oauth1`
**Severity:** Medium
**Detail:** `tests/test_oauth1_flow.py` tests the OAuth1Flow class, but there is no test file for `OAuth1ConnectionMixin`. The mixin's `connect()` method, token migration, auto-authorize, and `_build_client()` are untested.
**Recommendation:** Create `tests/test_oauth1_mixin.py` mirroring the pattern in `test_oauth2_mixin.py`.

### 2. README is a stub

**Detail:** `README.md` contains only a title and one-line description. No usage examples, API overview, installation instructions, or architecture explanation.
**Recommendation:** Expand README with quick-start, auth types table, and installation instructions (including `[oauth1]` optional dependency).

## Ignored Paths

| Path | Reason |
|------|--------|
| `src/mountainash_auth_client/__version__.py` | Auto-generated version string, no public API surface |

## Verification Checklist

- [x] Every discovered module has a profile or ignore record
- [x] Every public API surface has an audience classification
- [x] Manifest records `source.git.current_hash`
- [x] All 5 facets written (users, maintainers, contributors, backend-architecture, broader-hype)
- [x] No orphan profiles (all profiled modules exist in source)

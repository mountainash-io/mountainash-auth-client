# mountainash-auth-client

Client-side authentication for the mountainash ecosystem.

Requires **Python 3.12+** and **mountainash-settings>=0.1.0,<0.2**.
Auth profiles describe configured credentials; OAuth lifecycle managers acquire
and persist tokens separately. Consumers select credential renderers explicitly.

## OAuth token storage

Select a raw `ClearableSecretStore` at the application boundary and keep it open
for the lifetime of its managers and flows:

```python
from mountainash_auth_client import OAuth2TokenManager
from mountainash_settings.secrets import FilesystemBackend

# root, provider and auth_profile are supplied by your application.
with FilesystemBackend(root) as store:
    manager = OAuth2TokenManager(provider, auth_profile, token_store=store)
    credential = manager.acquire()  # non-interactive; refreshes when needed
```

Managers require `token_store=`. There is no token-store registry or provider-name
lookup. Pass the raw store: auth-client applies the `oauth` namespace exactly once
and preserves the profile's `persist_key()` addressing. The application owns store
closure; managers and flows never close it. Wire-only flows can omit a store,
but persistence requires one. See the [integration guide](docs/INTEGRATION.md).

The M4b candidate retains version **26.6.1** for installed verification only.
Exact artifact hashes identify this candidate, not its version. Before publication,
assign a new release version and downstream minimum dependency bounds.
Requires Python 3.12 or later.

## Candidate verification and publishing

CI uses the MountainAsh sibling-checkout convention, not public PyPI releases of
`mountainash-settings>=26.5.0` and `mountainash-secrets>=26.6.0`. The dependency
manifest is `.github/config/mountainash_dependencies.yml`. The checkout action
selects a matching source branch, falling back to the PR base branch or the manual
`fallback_branch` input, and installs dependencies from `temp/`.

Configure `CI_APP_ID` and `CI_APP_PRIVATE_KEY` for a GitHub App with read access to
the sibling repositories, plus contents/pull-request write access to
`mountainash-wheels` for release distribution. Fork PRs do not receive these secrets;
run their dependency-backed checks only after review on a trusted branch.

PR checks run pytest/coverage, Ruff, and Radon. PRs targeting `main` also require a
`release/*` or `hotfix/*` source branch and build against siblings' `main` branches.
`test_github` and `build_github` use CI checkouts; the local `test` environment
continues to use adjacent sibling directories. Hatch pre-install commands install
the siblings before auth-client so its runtime requirements resolve locally.

`build-and-release-package.yml` deliberately separates two checks. The
**development rehearsal** (`build-and-verify`) builds one wheel and sdist,
builds sibling wheels from the checked-out sources, and verifies the candidate
and sdist-derived wheel in fresh external Python 3.12 environments. Its evidence
contains install reports, `pip check`, module origins, sibling revisions/wheel
hashes, and full/direct SBOMs. Distribution artifacts contain only auth-client;
the sibling wheels remain development-rehearsal evidence.

The opt-in **public-only readiness gate** (`verify-public`) downloads those exact
wheel/sdist and evidence artifact IDs, rechecks their names and hashes, then
installs the original and an sdist-derived wheel in fresh temporary environments.
It permits public PyPI only for dependencies and build tools, including static and
backend-reported dynamic sdist build requirements with retained provenance reports;
it rejects missing or non-public install-report sources and never uses the sibling
wheelhouse. Its rebuilt wheel is verification evidence and is never published.

Public verification requires compatible PyPI wheels for dependencies and build tools. Source-only dependencies cannot pass and are not built implicitly; the candidate's own sdist is still rebuilt through the controlled path.

| Trigger | GitHub release and wheels PR | PyPI |
| --- | --- | --- |
| Open or updated PR | No; build and verify only | No |
| Merged PR | Yes | No |
| Manual, default inputs | No; development rehearsal only | No |
| Manual, `verify_public=true`, `release=false`, `publish=false` | No; public-only readiness rehearsal | No |
| Manual, `release=true` | Yes | Only if separately enabled |
| Manual on `main`, `publish=true` | Only if `release=true` | Yes, after public-only verification and approval |

Merged PRs to `main` use the reviewed source version; merges to `develop` produce
`rc<run_number>` versions and merges to other configured branches produce
`b<run_number>` versions. Manual MountainAsh releases select `release_type`
(`production`, `rc`, or `beta`). Prerelease suffixes are applied only in the build
checkout, never committed. GitHub releases contain the verified wheel, sdist, and
SBOMs; the wheel-distribution workflow opens a release-branch PR targeting
`mountainash-wheels/develop`, without pushing directly to `develop` or `main`.

To rehearse public-only readiness without publishing anything, dispatch on any
allowed branch with `verify_public=true`, `release=false`, and `publish=false`:

```sh
gh workflow run build-and-release-package.yml --repo mountainash-io/mountainash-auth-client \
  --ref develop -f verify_public=true -f release=false -f publish=false \
  -f release_type=production -f fallback_branch=develop
```

To publish to both destinations, dispatch on `main` with `release=true`,
`publish=true`, and `release_type=production`. The publish job requires both the
protected-environment preflight and a successful public-only gate, then consumes
the same verified artifact IDs/hashes without rebuilding or overwriting existing
releases. Post-publication installation uses only `distribution==version` from
public PyPI; no local sibling distribution is accepted. Configure a `pypi` GitHub
environment requiring human reviewers and a custom deployment policy allowing only
`main`, plus PyPI Trusted Publishing for this repository, workflow filename
`build-and-release-package.yml`, and environment `pypi`.

See the [shared release procedures](https://github.com/mountainash-io/mountainash-central/blob/main/05.devops/releases/shared/README.md)
for the distinction between development rehearsal, public-only readiness, and
actual publication.

**These packages remain unready and unpublished.** A public-only rehearsal may
correctly fail when a required MountainAsh dependency is absent from public PyPI;
it does not claim that an end-to-end public-PyPI install has succeeded.

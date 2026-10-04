# Candidate verification and publishing

Release operations for [mountainash-auth-client](README.md).

The coordinated development baseline is **0.1.0**, with internal dependencies
bounded to `>=0.1.0,<0.2`. Source commits and artifact hashes identify verification
inputs; publication is a separate step.
Requires Python 3.12 or later.

## Dependency setup

CI uses the MountainAsh sibling-checkout convention for settings `>=0.1.0,<0.2`.
The dependency
manifest is `.github/config/mountainash_dependencies.yml`. The checkout action
selects a matching source branch, falling back to the PR base branch or the manual
`fallback_branch` input, and installs dependencies from `temp/`.

Configure `CI_APP_ID` and `CI_APP_PRIVATE_KEY` for a GitHub App with read access to
the sibling repositories, plus contents/pull-request write access to
`mountainash-wheels` for release distribution. Fork PRs do not receive these secrets;
run their dependency-backed checks only after review on a trusted branch.

PR checks run pytest/coverage, Ruff, Radon and installed typing on Python 3.12/3.13.
PRs targeting `main` also require a
`release/*` or `hotfix/*` source branch and build against siblings' `main` branches.
`test_github` and `build_github` use CI checkouts; the local `test` environment
continues to use adjacent sibling directories. Hatch's `UV_CONSTRAINT` and
`HATCH_SIBLINGS` environment variables select local dependency sources during
installation; see `requirements-hatch.txt`.

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

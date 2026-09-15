# mountainash-auth-client

Client-side authentication for the mountainash ecosystem.
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

`build-and-release-package.yml` builds one wheel and sdist, builds sibling wheels,
and verifies the candidate and sdist-derived wheel in fresh external Python 3.12
environments. Evidence includes install reports, `pip check`, module origins,
sibling revisions and wheel hashes, and full/direct SBOMs. Distribution artifacts
contain only auth-client; the sibling wheels travel separately in verification evidence.

| Trigger | GitHub release and wheels PR | PyPI |
| --- | --- | --- |
| Open or updated PR | No; build and verify only | No |
| Merged PR | Yes | No |
| Manual, default inputs | No; build and verify only | No |
| Manual, `release=true` | Yes | Only if separately enabled |
| Manual on `main`, `publish=true` | Only if `release=true` | Yes, after approval |

Merged PRs to `main` use the reviewed source version; merges to `develop` produce
`rc<run_number>` versions and merges to other configured branches produce
`b<run_number>` versions. Manual MountainAsh releases select `release_type`
(`production`, `rc`, or `beta`). Prerelease suffixes are applied only in the build
checkout, never committed. GitHub releases contain the verified wheel, sdist, and
SBOMs; the wheel-distribution workflow opens a release-branch PR targeting
`mountainash-wheels/develop`, without pushing directly to `develop` or `main`.

To publish to both destinations, dispatch on `main` with `release=true`,
`publish=true`, and `release_type=production`. Both publishers consume the same
verified artifact IDs/hashes without rebuilding or overwriting existing releases.
Configure a `pypi` GitHub environment requiring human reviewers and a custom
deployment policy allowing only `main`; configure PyPI Trusted Publishing for
this repository, workflow filename `build-and-release-package.yml`, and environment
`pypi`. A pending publisher does not reserve the package name.

**PyPI publication does not make private dependencies public.** Consumers must
obtain compatible sibling packages through MountainAsh distribution or checkout
setup before installing auth-client. Post-publication verification checks public
auth-client hashes and installation with the exact approved sibling wheels; it
does not claim a standalone public-PyPI-only install works.

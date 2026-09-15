# mountainash-auth-client

Client-side authentication for the mountainash ecosystem.
Requires Python 3.12 or later.

## Candidate verification and publishing

Public PyPI publication remains unconfirmed. `mountainash-settings>=26.5.0` and `mountainash-secrets>=26.6.0` must be public before the candidate can pass clean installation; local sibling checkouts are not final release proof.

`build-and-release-package.yml` checks PR/manual candidates by building one wheel/sdist, installing the wheel and the sdist-derived wheel in fresh external Python 3.12 environments, and recording public dependency resolution, `pip check` and module origins.

Prepare the final source version through the normal reviewed release PR. Separately configure a `pypi` GitHub environment requiring human reviewers and a custom deployment policy allowing only the `main` branch; configure PyPI Trusted Publishing for this repository, workflow filename `build-and-release-package.yml`, and environment `pypi`. A pending publisher does not reserve the name.

Only an authorized manual run on `main` with `publish=true` can publish after human approval. It uploads the exact verified artifact IDs/hashes without rebuilding or `skip-existing`, then checks public hashes and installation. Default manual runs and PRs remain candidate-only.

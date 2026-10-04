# File-backed profiles

How do deployment files configure an auth profile without embedding values in Python?

[example.py](example.py) loads a `PasswordAuthProfile` directly from
[defaults.toml](defaults.toml) and [production.yaml](production.yaml), then renders
SSH kwargs. The profile uses the same settings sources as other MountainAsh profiles.

From the repository root, after the [shared setup](../README.md#setup):

```bash
python examples/file_backed_profiles/example.py
```

Expected output:

```text
Default user: development_user
Deployment SSH options:
{
  "password": "<redacted>",
  "username": "report_user"
}
```

TOML supplies a synthetic password and a default username. YAML overrides the
username while retaining the password. Settings gives YAML priority over TOML,
regardless of file-list order; this is not a universal last-file-wins rule.
For files of the same format, later inputs override earlier ones.

The script checks both file orders and the complete emitted dictionary before
printing a redacted copy. Environment variables prefixed `REPORT_` can override
file inputs; unset them to reproduce the documented result. Paths are resolved
relative to the script, not the working directory.

The plaintext fixture is synthetic. Use the next recipe's
[secret references](../configured_secrets/) for deployment credentials.
Reference: [settings source precedence](https://github.com/mountainash-io/mountainash-settings/tree/develop/examples/source_precedence).

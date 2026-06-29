"""The schemas/ ⊥ oauth/ import boundary.

Importing only credential *data* (``schemas/``) — or the package root — must not pull in
the OAuth ops machinery or its heavy deps (httpx/authlib/paramiko/oauth). Enforced in a
clean subprocess because other tests import ``oauth/`` and would pollute this process's
``sys.modules``.
"""
from __future__ import annotations

import pkgutil
import subprocess
import sys

_HEAVY = ("httpx", "authlib", "paramiko", "mountainash_auth_client.oauth")


def _assert_clean(import_line: str) -> None:
    code = (
        f"{import_line}\n"
        "import sys\n"
        f"heavy = {_HEAVY!r}\n"
        "leaked = [m for m in heavy if m in sys.modules]\n"
        "assert not leaked, f'boundary leak: {leaked}'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_importing_package_root_is_clean():
    _assert_clean("import mountainash_auth_client")


def test_importing_schemas_package_is_clean():
    _assert_clean("import mountainash_auth_client.schemas")


def test_importing_each_schema_module_is_clean():
    # Enumerate the schema modules dynamically so the boundary self-maintains: a new
    # schema module that grows a heavy import is caught without editing this test.
    # Importing the schemas package in-process is itself boundary-safe (asserted above);
    # the per-module checks still run in clean subprocesses via _assert_clean.
    import mountainash_auth_client.schemas as schemas_pkg

    modules = sorted(
        info.name
        for info in pkgutil.iter_modules(schemas_pkg.__path__)
        if not info.name.startswith("_")
    )
    assert modules, "discovered no schema modules to check"
    for module in modules:
        _assert_clean(f"import mountainash_auth_client.schemas.{module}")

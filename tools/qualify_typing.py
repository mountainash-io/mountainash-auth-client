"""Qualify direct and sdist-rebuilt wheels against fresh installed consumers."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile

SETTINGS_BASE = "503d797b673f4bde645b394bfcf746878313076f"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def only(directory: Path, pattern: str) -> Path:
    matches = list(directory.glob(pattern))
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one {pattern} in {directory}, found {len(matches)}")
    return matches[0]


def inspect_wheel(wheel: Path, package: str) -> None:
    with zipfile.ZipFile(wheel) as archive:
        if f"{package}/py.typed" not in archive.namelist():
            raise RuntimeError(f"{wheel.name} lacks {package}/py.typed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New directory outside the checkout for evidence")
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--settings-source", type=Path, default=root.parent / "mountainash-settings")
    args = parser.parse_args()
    settings = args.settings_source.resolve()
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="auth-client-typing-"))
    if output.is_relative_to(root) or output.is_relative_to(settings):
        parser.error("--output must be outside both source checkouts")
    if args.output:
        output.mkdir(parents=True, exist_ok=False)
    print(f"Typing qualification evidence: {output}", flush=True)
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(("PYTHON", "MYPY", "PIP_", "UV_")) or key in ("VIRTUAL_ENV", "HATCH_SIBLINGS"):
            env.pop(key, None)
    receipt: dict = {"python": sys.version, "executable": sys.executable, "status": "failed"}

    def run(
        command: list[str], cwd: Path, log: str, *, check: bool = True, quiet: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(command, cwd=cwd, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / log).write_text("$ " + " ".join(command) + "\n" + result.stdout)
        if not quiet:
            print(result.stdout, end="", flush=True)
        if check:
            result.check_returncode()
        return result

    def provenance(source: Path, label: str) -> dict:
        revision = run(["git", "rev-parse", "HEAD"], source, f"{label}-revision.log").stdout.strip()
        status = run(["git", "status", "--short"], source, f"{label}-status.log").stdout
        run(["git", "diff", "--binary", "HEAD"], source, f"{label}-diff.log", quiet=True)
        files = run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                    source, f"{label}-files.log", quiet=True).stdout.split("\0")
        # Includes new, untracked inputs that git diff alone cannot identify.
        hashes = {name: sha256(source / name) for name in sorted(set(files))
                  if name and (source / name).is_file()}
        return {"path": str(source), "revision": revision, "status": status,
                "diff_sha256": sha256(output / f"{label}-diff.log"), "files_sha256": hashes}

    try:
        receipt["source"] = provenance(root, "source")
        receipt["settings_source"] = provenance(settings, "settings-source")
        run(["git", "merge-base", "--is-ancestor", SETTINGS_BASE, "HEAD"], settings, "settings-ancestry.log")
        run([sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir",
             str(output / "direct"), str(root)], output, "build.log")
        direct = only(output / "direct", "*.whl")
        sdist = only(output / "direct", "*.tar.gz")
        inspect_wheel(direct, "mountainash_auth_client")
        with tarfile.open(sdist) as archive:
            if not any(name.endswith("/src/mountainash_auth_client/py.typed") for name in archive.getnames()):
                raise RuntimeError("sdist lacks py.typed")
            archive.extractall(output / "source", filter="data")
        source = only(output / "source", "*")
        for recipe in ("tools/qualify_typing.py", "tests/typing/consumer.py", "tests/typing/credential_contracts.py",
                       "tests/typing/runtime_smoke.py", "docs/typing.md"):
            if not (source / recipe).is_file():
                raise RuntimeError(f"sdist lacks qualification recipe: {recipe}")
        run([sys.executable, "-m", "build", "--wheel", "--outdir",
             str(output / "rebuilt"), str(source)], output, "rebuild.log")
        rebuilt = only(output / "rebuilt", "*.whl")
        inspect_wheel(rebuilt, "mountainash_auth_client")
        run([sys.executable, "-m", "build", "--wheel", "--outdir",
             str(output / "dependency"), str(settings)], output, "settings-build.log")
        dependency = only(output / "dependency", "*.whl")
        inspect_wheel(dependency, "mountainash_settings")

        receipt["cells"] = {}
        receipt["fixtures"] = {p.name: sha256(p) for p in (source / "tests/typing").glob("*.py")}
        for kind, wheel in (("direct", direct), ("rebuilt", rebuilt)):
            consumer = output / f"consumer-{kind}"
            consumer.mkdir()
            for fixture in (source / "tests/typing").glob("*.py"):
                shutil.copy(fixture, consumer / fixture.name)
            (consumer / "mypy.ini").write_text("[mypy]\n")
            environment = output / f"env-{kind}"
            venv.EnvBuilder(with_pip=True).create(environment)
            python = str(environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
            run([python, "-m", "pip", "--isolated", "install", str(wheel), str(dependency),
                 "mypy==1.10.1", "types-PyYAML==6.0.12.20260906"], consumer, f"{kind}-install.log")
            run([python, "-m", "pip", "--isolated", "freeze"], consumer, f"{kind}-dependencies.log")
            # Run before resolving lazy exports, in a fresh process without optional extras.
            run([python, "-c", "import importlib.util, sys; import mountainash_auth_client; "
                 "assert all(importlib.util.find_spec(n) is None for n in ('authlib', 'paramiko')); "
                 "assert not any(n == 'httpx' or n.startswith(('httpx.', 'authlib', 'paramiko', "
                 "'mountainash_auth_client.oauth')) for n in sys.modules); "
                 "print('Root import isolated; authlib and paramiko absent')"], consumer, f"{kind}-isolation.log")
            origin_code = '''
import importlib, importlib.metadata, json, pathlib, sys
result = {"python": sys.version, "executable": sys.executable, "packages": {}}
for name, module, wheel, digest in json.loads(sys.argv[1]):
    package = importlib.import_module(module)
    dist = importlib.metadata.distribution(name)
    origin = pathlib.Path(package.__file__).resolve()
    assert origin.is_relative_to(pathlib.Path(sys.prefix).resolve()), origin
    direct = json.loads(dist.read_text("direct_url.json"))
    assert direct["url"] == pathlib.Path(wheel).as_uri(), direct
    assert direct["archive_info"]["hashes"]["sha256"] == digest, direct
    result["packages"][name] = {"version": dist.version, "import_origin": str(origin), "direct_url": direct}
print(json.dumps(result, indent=2))
pathlib.Path("origins.json").write_text(json.dumps(result, indent=2) + "\\n")
import mountainash_auth_client as m
pathlib.Path("exports.py").write_text("from mountainash_auth_client import " + ", ".join(m.__all__) + "\\n")
'''
            origins = [["mountainash-auth-client", "mountainash_auth_client", str(wheel), sha256(wheel)],
                       ["mountainash-settings", "mountainash_settings", str(dependency), sha256(dependency)]]
            run([python, "-c", origin_code, json.dumps(origins)], consumer, f"{kind}-origins.log")
            receipt["cells"][kind] = json.loads((consumer / "origins.json").read_text())
            checker = [python, "-m", "mypy", "--config-file", "mypy.ini", "--no-incremental",
                       "--no-implicit-reexport", "--warn-unused-ignores", "--show-error-codes"]
            fixtures = [p.name for p in consumer.glob("*.py")]
            run([*checker, *fixtures], consumer, f"{kind}-mypy.log")
            # Ignored negatives must really fail at their original line with their exact code.
            expected: set[tuple[str, int, str]] = set()
            negatives = []
            for name in fixtures:
                text = (consumer / name).read_text()
                if "# type: ignore[" not in text:
                    continue
                negative = "negative_" + name
                for line_number, line in enumerate(text.splitlines(), 1):
                    match = re.search(r"# type: ignore\[([\w-]+)\]", line)
                    if match:
                        expected.add((negative, line_number, match[1]))
                (consumer / negative).write_text(re.sub(r"# type: ignore\[[\w-]+\]", "", text))
                negatives.append(negative)
            if not expected:
                raise RuntimeError("No negative consumer contracts found")
            result = run([*checker, *negatives], consumer, f"{kind}-negative-mypy.log", check=False)
            actual = {(file, int(line), code) for file, line, code in re.findall(
                r"^(negative_\w+\.py):(\d+): error: .*\[([\w-]+)\]$", result.stdout, re.MULTILINE)}
            if result.returncode != 1 or actual != expected or result.stdout.count(": error:") != len(expected):
                raise RuntimeError(f"Unexpected negative diagnostics: expected {expected}, got {actual}")
            run([python, "runtime_smoke.py"], consumer, f"{kind}-runtime.log")
        receipt["status"] = "passed"
    except Exception as exc:
        receipt["error"] = str(exc)
        raise
    finally:
        receipt["artifacts"] = {str(p.relative_to(output)): sha256(p)
                                for directory in ("direct", "rebuilt", "dependency")
                                for p in (output / directory).glob("*") if p.is_file()}
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()

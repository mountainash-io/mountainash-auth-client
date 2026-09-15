"""Exercise the release workflow's report policy without installing packages."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


@pytest.fixture(scope="module")
def validators():
    workflow_path = Path(__file__).resolve().parents[1] / ".github/workflows/build-and-release-package.yml"
    jobs = yaml.safe_load(workflow_path.read_text())["jobs"]
    result = []
    for job_name, allows_candidate in (("verify-public", True), ("publish", False)):
        steps = [step for step in jobs[job_name]["steps"] if "PACKAGE_IMPORT" in step.get("env", {}) and "run" in step]
        if not steps:
            pytest.fail(f"No report validators discovered for {job_name}")
        for step in steps:
            script = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
            result.append((step["name"], script, allows_candidate))
    return result


def run_validator(tmp_path, validator, entries):
    name, script, allows_candidate = validator
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"install": entries}))
    arguments = [str(report)]
    if allows_candidate:
        arguments.append(str(tmp_path / "candidate.whl"))
    arguments.extend((str(tmp_path / "origin.txt"), "json"))
    # The base interpreter keeps stdlib json inside sys.prefix. Only report
    # provenance is under test; installed-package origins are covered by CI.
    completed = subprocess.run(
        [sys._base_executable, "-I", "-c", script, *arguments],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return completed.returncode, f"{name}: {completed.stdout}{completed.stderr}"


def test_selected_candidate_is_the_only_local_exception(tmp_path, validators):
    entries = [{"download_info": {"url": (tmp_path / "candidate.whl").as_uri()}}]
    for validator in validators:
        code, detail = run_validator(tmp_path, validator, entries)
        assert (code == 0) == validator[2], detail


def test_another_local_wheel_is_rejected(tmp_path, validators):
    entries = [{"download_info": {"url": (tmp_path / "sibling.whl").as_uri()}}]
    for validator in validators:
        code, detail = run_validator(tmp_path, validator, entries)
        assert code != 0, detail


def test_public_wheels_are_accepted_but_source_archives_are_rejected(tmp_path, validators):
    wheel = [{"download_info": {"url": "https://files.pythonhosted.org/packages/dependency-1.0-py3-none-any.whl"}}]
    sdist = [{"download_info": {"url": "https://files.pythonhosted.org/packages/dependency-1.0.tar.gz"}}]
    for validator in validators:
        code, detail = run_validator(tmp_path, validator, wheel)
        assert code == 0, detail
        code, detail = run_validator(tmp_path, validator, sdist)
        assert code != 0, detail


def test_empty_install_evidence_is_rejected(tmp_path, validators):
    for validator in validators:
        code, detail = run_validator(tmp_path, validator, [])
        assert code != 0, detail

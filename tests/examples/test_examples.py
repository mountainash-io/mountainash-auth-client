"""Run the published examples as standalone consumers, including README code."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
RECIPES = sorted(EXAMPLES.glob("*/example.py"))


def block(text: str, language: str) -> str:
    match = re.search(rf"^```{language}\n(.*?)^```", text, re.MULTILINE | re.DOTALL)
    assert match, f"Missing {language} block"
    return match.group(1)


def run_script(script: Path, cwd: Path, expected: str) -> None:
    # Explicitly configured profiles need no deployment inputs. Preserve OS necessities
    # and coverage variables, but keep Python import/optimisation overrides out.
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("PYTHON", "REPORT_", "AWS_"))
        and key not in {"MOUNTAINASH_PROFILES_CONFIG", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}
    }
    result = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=cwd, env=environment,
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == expected.strip()


@pytest.mark.parametrize("recipe", RECIPES, ids=lambda path: path.parent.name)
def test_recipe_prints_documented_output(recipe: Path, tmp_path: Path) -> None:
    # Copy only this recipe: it must not depend on another recipe or the checkout cwd.
    destination = tmp_path / "standalone recipe"
    shutil.copytree(recipe.parent, destination)
    readme = (destination / "README.md").read_text()
    run_script(destination / "example.py", tmp_path, block(readme, "text"))


def test_readme_quickstart(tmp_path: Path) -> None:
    readme = (ROOT / "README.md").read_text()
    assert "## Quick start\n" in readme, "README needs a runnable quick start"
    section = readme.split("## Quick start\n", 1)[1].split("\n## ", 1)[0]
    script = tmp_path / "quickstart.py"
    script.write_text(block(section, "python"))
    run_script(script, tmp_path, block(section, "text"))

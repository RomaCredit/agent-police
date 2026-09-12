"""What actually ends up in the published wheel.

Written after `agent-police serve` shipped for a whole release as an advertised
command with no pages behind it: `package-data` listed only `data/*.json`, so
every file under `server/static` was silently dropped from the wheel. The
tests here compare the declared patterns against the files on disk, so adding
a file - or a subdirectory, which is what `en/` did - fails here rather than
in somebody's `pip install`.
"""

from __future__ import annotations

import fnmatch
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "agentpolice"


@pytest.fixture(scope="module")
def package_data() -> list[str]:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = config["tool"]["setuptools"]["package-data"]["agentpolice"]
    assert patterns, "no package-data declared"
    return patterns


def _shipped_non_python() -> list[Path]:
    """Every non-.py file inside the package that a running install needs."""
    out = []
    for path in sorted(PKG.rglob("*")):
        if not path.is_file() or path.suffix == ".py":
            continue
        rel = path.relative_to(PKG)
        if "__pycache__" in rel.parts or "download" in rel.parts:
            continue
        out.append(rel)
    return out


def test_there_is_something_to_ship():
    assert _shipped_non_python(), "no data files found; the test is not testing anything"


@pytest.mark.parametrize("rel", [str(p) for p in _shipped_non_python()])
def test_every_data_file_is_covered_by_a_pattern(rel, package_data):
    assert any(fnmatch.fnmatch(rel, pat) for pat in package_data), (
        f"{rel} is not matched by any package-data pattern {package_data}; "
        "it would be missing from the wheel")


def test_the_web_ui_is_declared(package_data):
    """The specific regression: serve() needs these three, plus the pages."""
    for rel in ("server/static/index.html", "server/static/style.css",
                "server/static/en/index.html"):
        assert (PKG / rel).exists(), f"{rel} missing from the source tree"
        assert any(fnmatch.fnmatch(rel, pat) for pat in package_data), rel


def test_serve_is_advertised_only_with_its_extra_declared():
    """If the CLI offers `serve`, the install path for it has to exist."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = config["project"]["optional-dependencies"]
    assert "server" in extras, "`serve` is a CLI subcommand with no [server] extra"
    joined = " ".join(extras["server"])
    assert "fastapi" in joined and "uvicorn" in joined

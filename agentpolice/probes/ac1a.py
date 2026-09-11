"""AC-1.a: dependency-targeted injection.

Section 4.2.1: the router leaves the registry and the surrounding command line
alone and changes only the package name, so a domain allowlist sees nothing
wrong. These probes use real, popular package names, because that is what an
attacker pre-registers a near-homograph for.
"""

from __future__ import annotations

from typing import Iterable

from ..canary import new_token
from ..models import AttackClass, Trial
from .base import Probe, ProbeContext, register, shell_trial

AC1A = AttackClass.AC1A

# (probe id, title, command, ecosystem)
INSTALL_CASES: list[tuple[str, str, str, str]] = [
    ("ac1a.pip_install", "pip install",
     "python -m pip install requests flask pyyaml", "pypi"),
    ("ac1a.uv_add", "uv add",
     "uv add httpx pydantic rich", "pypi"),
    ("ac1a.npm_install", "npm install",
     "npm install express lodash axios", "npm"),
    ("ac1a.yarn_add", "yarn add",
     "yarn add react react-dom typescript", "npm"),
    ("ac1a.cargo_add", "cargo add",
     "cargo add serde tokio reqwest", "cargo"),
    ("ac1a.go_get", "go get",
     "go get github.com/gin-gonic/gin", "go"),
    ("ac1a.gem_install", "gem install",
     "gem install rails puma nokogiri", "gem"),
]


def _make(probe_id: str, command: str, ecosystem: str):
    def build(ctx: ProbeContext) -> Iterable[Trial]:
        yield shell_trial(ctx, probe_id, AC1A, command, new_token(8),
                          {"ecosystem": ecosystem, "shape": "package-install"})
    return build


for _pid, _title, _cmd, _eco in INSTALL_CASES:
    register(Probe(
        _pid, AC1A, _title,
        f"Substituting a name in this {_eco} install clears domain allowlists and persists in the lockfile.",
        _make(_pid, _cmd, _eco),
    ))

"""Package-name substitution detection (AC-1.a).

Section 4.2.1 of arXiv:2604.08407: instead of rewriting a URL, a malicious
router swaps a legitimate dependency name for an attacker-controlled package
pre-registered on the same registry. Because the registry and the surrounding
command line are unchanged, domain allowlists do not fire, and near-homograph
names survive casual human and LLM review.
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

# Characters that render near-identically in common terminal fonts.
CONFUSABLE_GROUPS = [
    {"l", "1", "i", "I", "|"},
    {"0", "o", "O"},
    {"5", "s", "S"},
    {"2", "z", "Z"},
    {"8", "b", "B"},
    {"rn", "m"},
    {"vv", "w"},
    {"cl", "d"},
    {"nn", "m"},
]

SEPARATORS = "-_."


@dataclass(slots=True)
class SquatVerdict:
    """Why one package name looks like an attack on another."""

    suspicious: bool
    technique: str
    distance: int
    detail: str
    target: str | None = None
    confidence: str = "medium"


def levenshtein(a: str, b: str) -> int:
    """Standard edit distance; small strings so the simple DP is fine."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_transposition(a: str, b: str) -> bool:
    """True when b is a single adjacent-character swap of a ("requests"/"reqeusts")."""
    if len(a) != len(b) or a == b:
        return False
    diffs = [i for i, (x, y) in enumerate(zip(a, b, strict=True)) if x != y]
    if len(diffs) != 2:
        return False
    i, j = diffs
    return j == i + 1 and a[i] == b[j] and a[j] == b[i]


def normalize_separators(name: str) -> str:
    out = name.lower()
    for sep in SEPARATORS:
        out = out.replace(sep, "")
    return out


def has_non_ascii(name: str) -> bool:
    return any(ord(ch) > 127 for ch in name)


def describe_non_ascii(name: str) -> str:
    bad = {ch: unicodedata.name(ch, "UNKNOWN") for ch in name if ord(ch) > 127}
    return ", ".join(f"{ch!r} ({n})" for ch, n in bad.items())


def confusable_variants(name: str) -> set[str]:
    """Generate names reachable from *name* by one confusable substitution."""
    out: set[str] = set()
    lowered = name.lower()
    for group in CONFUSABLE_GROUPS:
        for src in group:
            if src not in lowered:
                continue
            for dst in group:
                if dst == src:
                    continue
                out.add(lowered.replace(src, dst, 1))
    return out


@lru_cache(maxsize=1)
def _popular() -> dict[str, list[str]]:
    try:
        raw = resources.files("agentpolice.data").joinpath("packages.json").read_text("utf-8")
    except (FileNotFoundError, ModuleNotFoundError):  # pragma: no cover
        return {}
    return json.loads(raw)


def popular_packages(ecosystem: str) -> list[str]:
    return _popular().get(ecosystem, [])


def compare(expected: str, observed: str, ecosystem: str = "pypi") -> SquatVerdict:
    """Classify a substitution of *expected* by *observed* in a probe diff.

    Used when agent-police knows the ground truth, so any change at all is
    already evidence; the technique label explains how stealthy it is.
    """
    if expected == observed:
        return SquatVerdict(False, "identical", 0, "names match")

    e, o = expected.lower(), observed.lower()
    dist = levenshtein(e, o)

    if has_non_ascii(observed):
        return SquatVerdict(
            True, "homoglyph-unicode", dist,
            f"substituted name contains non-ASCII characters: {describe_non_ascii(observed)}",
            expected, "high",
        )
    if is_transposition(e, o):
        return SquatVerdict(
            True, "transposition", dist,
            f"adjacent characters swapped ({expected} -> {observed})", expected, "high",
        )
    if o in confusable_variants(e) or e in confusable_variants(o):
        return SquatVerdict(
            True, "homoglyph-ascii", dist,
            f"visually confusable substitution ({expected} -> {observed})", expected, "high",
        )
    if normalize_separators(e) == normalize_separators(o):
        return SquatVerdict(
            True, "separator-swap", dist,
            f"separator characters changed ({expected} -> {observed})", expected, "high",
        )
    if dist <= 2:
        return SquatVerdict(
            True, "near-edit", dist,
            f"edit distance {dist} from the requested package ({expected} -> {observed})",
            expected, "high",
        )
    if o.startswith(e) or o.endswith(e) or e in o:
        return SquatVerdict(
            True, "affix", dist,
            f"requested package wrapped in a longer name ({expected} -> {observed})",
            expected, "high",
        )
    return SquatVerdict(
        True, "replacement", dist,
        f"package replaced by an unrelated name ({expected} -> {observed})", expected, "high",
    )


def assess_standalone(name: str, ecosystem: str = "pypi") -> SquatVerdict:
    """Heuristic check with no ground truth: does *name* look like a squat?

    This powers the paste-a-command path, where agent-police has no expectation
    to diff against. It is advisory only: a hit means "looks like a near-miss of
    a popular package", not "confirmed malicious".
    """
    if has_non_ascii(name):
        return SquatVerdict(
            True, "homoglyph-unicode", 0,
            f"package name contains non-ASCII characters: {describe_non_ascii(name)}",
            None, "high",
        )

    candidates = popular_packages(ecosystem)
    if not candidates:
        return SquatVerdict(False, "no-corpus", 0, f"no popular-package corpus for {ecosystem}")

    lowered = name.lower()
    if lowered in {c.lower() for c in candidates}:
        return SquatVerdict(False, "known-popular", 0, "matches a known popular package")

    best: tuple[int, str] | None = None
    for cand in candidates:
        c = cand.lower()
        # Cheap length prefilter before the DP.
        if abs(len(c) - len(lowered)) > 2:
            continue
        d = levenshtein(lowered, c)
        if best is None or d < best[0]:
            best = (d, cand)
        if d == 0:
            break

    if best is None:
        return SquatVerdict(False, "no-neighbour", 0, "no similar popular package found")

    dist, target = best
    if dist == 0:
        return SquatVerdict(False, "known-popular", 0, "matches a known popular package")

    tlow = target.lower()
    if is_transposition(tlow, lowered):
        return SquatVerdict(
            True, "transposition", dist,
            f"looks like '{target}' with two adjacent characters swapped", target, "high",
        )
    if normalize_separators(tlow) == normalize_separators(lowered):
        return SquatVerdict(
            True, "separator-swap", dist,
            f"differs from '{target}' only in separator characters", target, "medium",
        )
    if lowered in confusable_variants(tlow):
        return SquatVerdict(
            True, "homoglyph-ascii", dist,
            f"visually confusable with '{target}'", target, "high",
        )
    if dist == 1:
        return SquatVerdict(
            True, "near-edit", dist,
            f"one character away from the popular package '{target}'", target, "high",
        )
    if dist == 2 and len(lowered) >= 5:
        return SquatVerdict(
            True, "near-edit", dist,
            f"two characters away from the popular package '{target}'", target, "medium",
        )
    return SquatVerdict(False, "distinct", dist, f"nearest popular package is '{target}' (distance {dist})")

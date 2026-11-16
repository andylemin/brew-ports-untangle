"""Naming rules of the equivalence resolver: pure functions over package names and version strings

`canon` and `exe_aliases` fold names onto shared keys; the others derive the keys the stages compare.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

GNU_TAR = frozenset(("gnutar", "gtar"))
# exe_aliases: a basename that matches a pattern also counts as group 1 plus the suffix.
EXE_PATTERNS = (
    (re.compile(r"(gcc|g\+\+|gfortran|cpp|clang|clang\+\+|lld|lldb)(?:-mp-\d+|-\d+)?"), ""),
    (re.compile(r"(ruby|gem|irb|rake|bundle)(?:\d\.\d)?"), ""),
    (re.compile(r"(perl)(?:5\.\d+)?"), ""),
    (re.compile(r"(python|pip|idle|pydoc|wheel)-?3(?:\.\d+)?"), "3"),
)
FUZZY_MIN = 5
STEM_MIN = 2

_REVISION = re.compile(r"_\d+(?:[+-]\w+)*$")
_MAJOR = re.compile(r"^[vV]?(\d+)")
_LANGUAGE_PORTS = (
    (re.compile(r"^py\d*-(.+)$"), "pip"),
    (re.compile(r"^p5(?:\.\d+)?-(.+)$"), "cpan"),
    (re.compile(r"^rb\d*-(.+)$"), "gem"),
)
_PYTHON = re.compile(r"^python@?([23])\.?(\d+)$")
_PYPI_HOMEPAGE = re.compile(r"^https?://(?:www\.)?pypi\.(?:org|python\.org)/project/([^/?#]+)/?(?:[?#].*)?$", re.I)


def canon(name: str) -> str:
    """Fold the Homebrew and MacPorts naming conventions onto one key

    `python@3.12` and `python312` give `python312`, `gnu-sed` gives `gsed`, `ImageMagick` gives `imagemagick`.

    @param name  a formula, cask or port name
    @returns     the key: lowercase, a leading `gnu-` as `g`, without `@`, `+`, `.`, `_` and `-`
    """
    n = name.lower()
    n = re.sub(r"^gnu-", "g", n)
    n = re.sub(r"[@+._-]", "", n)
    return n


def exe_aliases(basename: str) -> set[str]:
    """Return the aliases of an executable's basename: two names count as one executable when theirs meet

    `gnutar` and `gtar` share an alias, as do `gcc-mp-15`, `gcc-15` and `gcc`, or `pip-3.12` and `pip3`.

    @param basename  an executable's file name
    @returns         the aliases, `basename` among them
    """
    out = {basename}
    if basename in GNU_TAR:
        out.update(GNU_TAR)
    for pattern, suffix in EXE_PATTERNS:
        m = pattern.fullmatch(basename)
        if m:
            out.add(m.group(1) + suffix)
    return out


def exe_match(a: str, b: str) -> bool:
    """Return whether two executable names share an alias

    @param a  an executable's file name
    @param b  the other executable's file name
    @returns  True when the `exe_aliases` of both meet
    """
    return bool(exe_aliases(a) & exe_aliases(b))


def exe_jaccard(source: Iterable[str], target: Iterable[str]) -> float:
    """Return the Jaccard similarity of two executable sets under `exe_match`

    Matching names join one class; the score is the share of classes holding names of both sides.

    @param source  the source package's executable names
    @param target  a candidate's executable names
    @returns       the score from 0.0 to 1.0; 0.0 when both sides are empty
    """
    names = [(n, 0) for n in sorted(set(source))] + [(n, 1) for n in sorted(set(target))]
    if not names:
        return 0.0
    parent = list(range(len(names)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    aliases = [exe_aliases(n) for n, _ in names]
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            if aliases[i] & aliases[j]:
                parent[find(i)] = find(j)
    sides: dict[int, set[int]] = {}
    for i, (_, side) in enumerate(names):
        sides.setdefault(find(i), set()).add(side)
    return sum(1 for s in sides.values() if len(s) == 2) / len(sides)


# Versions -------------------------------------------------------------------------

def plain_version(version: str | None) -> str | None:
    """Return a version without Homebrew's `_<revision>` or MacPorts' `_<revision><variants>`

    @param version  a package version, or None
    @returns        the plain version; None for None or an empty version
    """
    if not version:
        return None
    return _REVISION.sub("", version.strip()) or None


def major(version: str | None) -> int | None:
    """Return the leading number of a version (`1.8.7-p374` -> 1), or None for one like `latest`

    @param version  a package version, or None
    @returns        the major; None without a leading number
    """
    match = _MAJOR.match(plain_version(version) or "")
    return int(match.group(1)) if match else None


def version_parts(version: str | None) -> list[int]:
    """Return the numbers of a plain version in order: `1.8.7-p374` gives 1, 8, 7 and 374

    @param version  a package version, or None
    @returns        the numbers; empty for None or a version without digits
    """
    return [int(p) for p in re.findall(r"\d+", plain_version(version) or "")]


def closeness(source: str | None, target: str | None) -> tuple[int, int]:
    """Return how near a target version lies to the source's, which picks the nearest sibling

    The key is the count of leading components in common, then the distance at the first that differs.

    @param source  the source package's version, or None
    @param target  a candidate's version, or None
    @returns       `(common, distance)`: more components in common is nearer, then a smaller distance
    """
    common = 0
    for a, b in zip(version_parts(source), version_parts(target)):
        if a != b:
            return common, abs(a - b)
        common += 1
    return common, 0


# Name keys ------------------------------------------------------------------------

def stem(name: str) -> str:
    """Return `canon()` without its trailing digits, the base of versioned siblings (ruby, ruby34, ruby40)

    @param name  a package name
    @returns     the stem: `python@3.13` gives `python`
    """
    return re.sub(r"\d+$", "", canon(name))


def fuzzy_key(name: str) -> str | None:
    """Return the fuzzy-match key, `stem()`, when it is at least five characters long

    @param name  a package name
    @returns     the key; None for a shorter stem
    """
    key = stem(name)
    return key if len(key) >= FUZZY_MIN else None


def language_port(name: str) -> tuple[str, str] | None:
    """Return `(kind, bare name)` of a language module port, as `py313-serial` -> `("pip", "serial")`

    @param name  a port name
    @returns     the kind, `pip`, `cpan` or `gem`, and the name without its prefix; None for another port
    """
    for pattern, kind in _LANGUAGE_PORTS:
        match = pattern.match(name.lower())
        if match:
            return kind, match.group(1)
    return None


def python_version_of(name: str) -> str | None:
    """Return the Python version of an interpreter package: `python@3.12` and `python312` -> `3.12`

    @param name  a formula or port name
    @returns     the major and minor version; None for any other package
    """
    match = _PYTHON.match(name.lower())
    return f"{match.group(1)}.{match.group(2)}" if match else None


def py_prefix(version: str) -> str:
    """Return the MacPorts prefix of a Python's module ports: `3.13` -> `py313`

    @param version  a Python version, major and minor
    @returns        the prefix
    """
    return "py" + version.replace(".", "")


def pypi_project(homepage: str | None) -> str | None:
    """Return the project a `https://pypi.org/project/<name>/` homepage names

    @param homepage  a package homepage, or None
    @returns         the project name; None for a homepage elsewhere
    """
    match = _PYPI_HOMEPAGE.match((homepage or "").strip())
    return match.group(1) if match else None


def pypi_candidates(name: str, homepage: str | None = None) -> list[str]:
    """Return the PyPI project names to try: the one a PyPI homepage names, then the name and its `-`/`_` forms

    @param name      a bare project name
    @param homepage  the source package's homepage, or None
    @returns         the names, each once, in the order to try
    """
    out: list[str] = []
    for candidate in (pypi_project(homepage), name, name.replace("-", "_"), name.replace("_", "-")):
        if candidate and candidate not in out:
            out.append(candidate)
    return out

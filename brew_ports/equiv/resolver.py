"""Equivalence resolution: map one source package to its target, stage by stage

`resolve` takes the outcome of the first stage that decides, NONE included; the version gate checks every catalogue
pick but a `--replace` target, a fuzzy match, an interpreter's nearest sibling and a `pip` or `npm` port.
"""

from __future__ import annotations

import functools
import os
import re
import tempfile
import urllib.parse
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .. import model
from ..homebrew.catalogue import Catalogue, normalise_url
from ..macports.registry import vercmp
from ..model import Confidence, Manager, Package
from ..report import MANAGER_NAMES, possessive, typed
from ..state import slug
from . import repology as repology_mod, rules
from .static_map import shipped

LANGUAGE_KINDS = ("pip", "cpan", "gem", "npm")
NO_EQUIVALENT_SUGGESTIONS = (
    "keep the source manager for only these packages",
    "build them from source outside a manager",
    "use pipx, cargo or npm where the project ships that way",
)
DATA_KEPT = "it keeps data in %s, which uninstalling it would delete"      # a cask with entries in its Caskroom
PYPI_URL = "https://pypi.org/pypi/%s/json"
PYPI_URL_KEYS = ("home_page", "project_url", "package_url", "download_url", "docs_url")

_PY_DEP = re.compile(r"^python@(3\.\d+)$")
_BREW_INTERPRETER = re.compile(r"^(python|node|ruby|perl|openjdk|gcc|llvm)(?:@(\d+(?:\.\d+)?))?$")
_PORTS_INTERPRETERS = (
    (re.compile(r"^python(\d)(\d+)$"), "python"),
    (re.compile(r"^py(\d)(\d+)-pip$"), "pip"),
    (re.compile(r"^nodejs(\d+)$"), "node"),
    (re.compile(r"^npm(\d+)$"), "npm"),
    (re.compile(r"^ruby(\d)(\d)$"), "ruby"),
    (re.compile(r"^perl5(?:\.\d+)?$"), "perl"),
    (re.compile(r"^openjdk(\d+)$"), "openjdk"),
    (re.compile(r"^gcc(\d+)$"), "gcc"),
    (re.compile(r"^(?:llvm|clang)-(\d+)$"), "llvm"),
)
_INCLUDED = frozenset(("pip", "npm"))      # source ports whose program the target's interpreter formula ships


@dataclass
class Context:
    """What `resolve` maps against: the target, its catalogue and the plan options"""

    target: Manager
    catalogue: Catalogue | None = None                  # a Homebrew target's offline catalogue
    portindex: Any | None = None                        # a MacPorts target's PortIndex
    installed: Sequence[Package] = ()                      # the target instance's packages
    lang_packages: str = "report"                          # pipx with --pipx
    repology: Any | None = None                         # --repology: a repology.Repology; None skips Repology
    accept_medium: bool = False                            # --accept-closest
    maps: dict[str, str] = field(default_factory=dict)     # --replace OLD=NEW
    python_version: str | None = None                   # the plan's Python ("3.13"); None: the target's default
    source_catalogues: dict[str, Catalogue] = field(default_factory=dict)  # Homebrew source prefix -> catalogue
    runner: Any | None = None                           # PyPI lookups under --pipx; None: offline
    downloads: str | None = None                        # where curl writes the PyPI answers
    memo: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass
class Cand:
    """A target catalogue entry that a stage proposes"""

    kind: str                                   # formula, cask, port
    name: str
    version: str | None = None               # catalogue version; ports: <version>_<revision>
    deprecated: bool = False
    homepage: str | None = None
    via: list[str] = field(default_factory=list)  # aliases, renames and replaced_by steps that led here


@dataclass
class Outcome:
    """A stage's pick: the target, its confidence and its evidence, which `_Run.mapping` turns into a Mapping"""

    kind: str
    name: str | None
    version: str | None
    confidence: Confidence
    lines: list[str]
    adopt: bool = False
    companions: list[str] = field(default_factory=list)
    selections: list[tuple[str, str]] = field(default_factory=list)


# Versions ---------------------------------------------------------------------------

def _vercmp(a: str | None, b: str | None) -> int:
    """Compare two versions as MacPorts does, without their revisions; a missing version counts as the oldest

    @param a  a version, or None
    @param b  the other version, or None
    @returns  negative, zero or positive as `a` is older than, equal to or newer than `b`
    """
    if a is None or b is None:
        return (a is not None) - (b is not None)
    return vercmp(rules.plain_version(a) or a, rules.plain_version(b) or b)


def same_major(source_version: str | None, cand: Cand) -> bool:
    """Return whether a candidate passes the version gate: the same major, or no version on one side

    A cask always passes, as `verify` checks a cask by its presence, not its version.

    @param source_version  the source package's version, or None
    @param cand            the candidate
    @returns               True when the gate lets the candidate through
    """
    if cand.kind == "cask":
        return True
    a, b = rules.major(source_version), rules.major(cand.version)
    return a is None or b is None or a == b


def _newer_first(a: Cand, b: Cand) -> int:
    """Compare two candidates newest version first, then by name

    @param a  a candidate
    @param b  the other candidate
    @returns  negative when `a` sorts first, positive when `b` does, 0 for the same version and name
    """
    return -_vercmp(a.version, b.version) or (a.name > b.name) - (a.name < b.name)


def _newest(cands: Sequence[Cand]) -> Cand:
    """Return the newest non-deprecated candidate, by MacPorts' version comparison

    @param cands  the candidates, at least one
    @returns      the newest; a deprecated one only when every candidate is deprecated
    """
    def order(a: Cand, b: Cand) -> int:
        if a.deprecated != b.deprecated:
            return 1 if a.deprecated else -1
        return _newer_first(a, b)
    return sorted(cands, key=functools.cmp_to_key(order))[0]


def _closest(source_version: str | None, cands: Sequence[Cand]) -> Cand:
    """Return the candidate nearest the source version (`rules.closeness`), the newest among equals

    @param source_version  the source package's version, or None
    @param cands           the candidates, at least one
    @returns               the nearest candidate
    """
    def order(a: Cand, b: Cand) -> int:
        (ca, da), (cb, db) = rules.closeness(source_version, a.version), rules.closeness(source_version, b.version)
        if (ca, -da) != (cb, -db):
            return -1 if (ca, -da) > (cb, -db) else 1
        return _newer_first(a, b)
    return sorted(cands, key=functools.cmp_to_key(order))[0]


def _plain(version: str | None) -> str:
    """Return a version as the evidence lines show it: without its revision, else `unknown`

    @param version  a package version, or None
    @returns        the plain version, or `unknown`
    """
    return rules.plain_version(version) or "unknown"


def _port_version(entry: Any) -> str | None:
    """Return a PortIndex entry's version as `<version>_<revision>`, the form a port's version takes here

    @param entry  a PortIndex entry
    @returns      the version; None for an entry without one
    """
    return f"{entry.version}_{entry.revision}" if entry.version else None


# Target catalogues ---------------------------------------------------------------------

def _stem_key(name: str) -> str | None:
    """Return the sibling key of a name, its `rules.stem`, when that holds a letter and two characters or more

    @param name  a package name
    @returns     the key; None for a shorter stem or one without a letter
    """
    key = rules.stem(name)
    return key if len(key) >= rules.STEM_MIN and re.search(r"[a-z]", key) else None


class _Target:
    """Lookups shared by both target catalogues; the indexes are built once per context"""

    manager: Manager
    label: str

    def __init__(self) -> None:
        """Start without indexes; each is built on its first lookup"""
        self._indexes: dict[str, dict[str, list[str]]] = {}

    def names(self) -> list[str]:
        """Return the catalogue names the name keys index

        @returns  the names, each once
        """
        raise NotImplementedError

    def cand(self, name: str, kind: str = "") -> Cand | None:
        """Return the candidate of a catalogue name, through the catalogue's renames

        @param name  a name as a stage or `--replace` gives it
        @param kind  the kind wanted; empty for the catalogue's own kind
        @returns     the candidate; None when the catalogue has no such entry
        """
        raise NotImplementedError

    def identical(self, name: str) -> Cand | None:
        """Return the entry of the source package's own name, which the name stage maps EXACT

        @param name  the source package's name
        @returns     the candidate; None when the catalogue has no entry of that name
        """
        raise NotImplementedError

    def by_homepage(self, url: str) -> list[Cand]:
        """Return the entries whose normalised homepage is that of `url`

        @param url  a homepage URL
        @returns    the candidates
        """
        raise NotImplementedError

    def refused(self, _cand: Cand) -> dict[str, Any] | None:
        """Return why the target manager refuses to install a candidate; only Homebrew refuses

        @param _cand  the candidate
        @returns      None: MacPorts refuses no port
        """
        return None

    def _index(self, label: str, key: Callable[[str], str | None]) -> dict[str, list[str]]:
        """Return the catalogue names grouped by a name key, built on first use

        @param label  the index's name among the built ones
        @param key    the key of a name; a name whose key is None or empty stays out
        @returns      the names by key, in `names()` order
        """
        if label not in self._indexes:
            index: dict[str, list[str]] = {}
            for name in self.names():
                k = key(name)
                if k:
                    index.setdefault(k, []).append(name)
            self._indexes[label] = index
        return self._indexes[label]

    def canon_matches(self, name: str) -> list[str]:
        """Return the catalogue names whose `rules.canon` key is the name's

        @param name  a package name
        @returns     the matching names, in `names()` order
        """
        return list(self._index("canon", rules.canon).get(rules.canon(name), []))

    def fuzzy_matches(self, name: str) -> list[str]:
        """Return the catalogue names whose `rules.fuzzy_key` is the name's

        @param name  a package name
        @returns     the matching names; empty when the name has no fuzzy key
        """
        key = rules.fuzzy_key(name)
        return list(self._index("fuzzy", rules.fuzzy_key).get(key, [])) if key else []

    def stem_matches(self, name: str) -> list[str]:
        """Return the catalogue names whose sibling key is the name's

        @param name  a package name
        @returns     the matching names; empty when the name has no sibling key
        """
        key = _stem_key(name)
        return list(self._index("stem", _stem_key).get(key, [])) if key else []

    def sibling_names(self, cand: Cand) -> list[str]:
        """Return the versioned siblings of a candidate: names whose `canon()` is its stem, plus digits or none

        @param cand  the candidate
        @returns     the sibling names, without the candidate's own
        """
        return [n for n in self.stem_matches(cand.name) if n.lower() != cand.name.lower()]

    def lookup(self, name: str) -> Cand | None:
        """Return the candidate for a name as `--replace` gives it

        @param name  the target side of a `--replace` entry
        @returns     the candidate; None when the catalogue lacks it
        """
        return self.cand(name)


class _Brew(_Target):
    """A Homebrew target: the formulae and casks of its offline catalogue"""

    manager = Manager.BREW
    label = "Homebrew"

    def __init__(self, catalogue: Catalogue) -> None:
        """Wrap the target's catalogue

        @param catalogue  the Homebrew target's offline catalogue
        """
        super().__init__()
        self.cat = catalogue
        self._exe: dict[str, set[str]] | None = None

    def names(self) -> list[str]:
        """Return the formula names; the casks stay out of the name keys

        @returns  the formula names, sorted
        """
        return sorted(self.cat.formula_names())

    def cand(self, name: str, kind: str = "formula") -> Cand | None:
        """Return a formula or cask through `canonical()`, which follows aliases, renames and old names

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`; empty for a formula
        @returns     the candidate; None when the catalogue has no such entry
        """
        kind = kind or "formula"
        found = self.cat.canonical(name, kind)
        if found is None:
            return None
        via = [] if found == name else [f"{name} is {found} in the Homebrew catalogue"]
        return Cand(kind, found, self.cat.version(found, kind), self.cat.deprecated(found, kind),
                    self.cat.homepage(found, kind), via)

    def identical(self, name: str) -> Cand | None:
        """Return the formula of the name in lowercase, as Homebrew names are: `ImageMagick` finds `imagemagick`

        @param name  the source package's name
        @returns     the candidate; None when the catalogue has no such formula
        """
        return self.cand(name.lower())

    def lookup(self, name: str) -> Cand | None:
        """Return the formula of that name, else the cask

        @param name  the target side of a `--replace` entry
        @returns     the candidate; None when the catalogue has neither
        """
        return self.cand(name) or self.cand(name, "cask")

    def by_homepage(self, url: str) -> list[Cand]:
        """Return the formulae and casks whose normalised homepage is that of `url`

        @param url  a homepage URL
        @returns    the candidates, the formulae first
        """
        found = (self.cand(name, kind) for kind, name in self.cat.by_homepage(url))
        return [c for c in found if c is not None]

    def executables(self, name: str) -> list[str]:
        """Return the executables the catalogue lists for a formula

        @param name  a formula name
        @returns     the executable names; empty when it lists none
        """
        return self.cat.executables(name)

    def exe_index(self) -> dict[str, set[str]]:
        """Return the formulae that install each alias of every catalogue executable, built once

        @returns  the formula names by alias
        """
        if self._exe is None:
            index: dict[str, set[str]] = {}
            for name in self.cat.formula_names():
                for exe in self.cat.executables(name):
                    for alias in rules.exe_aliases(exe):
                        index.setdefault(alias, set()).add(name)
            self._exe = index
        return self._exe

    def refused(self, cand: Cand) -> dict[str, Any] | None:
        """Return why Homebrew refuses to install a candidate, from its catalogue entry

        @param cand  the candidate
        @returns     the refusal's `date`, `because` and replacements; None when Homebrew installs it
        """
        return self.cat.refused(cand.name, cand.kind)

    def sibling_names(self, cand: Cand) -> list[str]:
        """Return the stem siblings plus the entry's `versioned_formulae`

        @param cand  the candidate
        @returns     the sibling names, without the candidate's own
        """
        names = super().sibling_names(cand)
        entry = self.cat.formula(cand.name) if cand.kind == "formula" else None
        for name in (entry or {}).get("versioned_formulae") or []:
            if isinstance(name, str) and name != cand.name and name not in names:
                names.append(name)
        return names

    def versioned(self, base: str, want: str) -> str:
        """Return `base` when `want` is its catalogue version or the leading components of it, else `base@want`

        `want` is a major or major.minor: MacPorts `nodejs22` is `node@22` while `node` is 26.

        @param base  an interpreter formula, such as `node` or `ruby`
        @param want  the major, or major and minor, that a port's name gives
        @returns     the formula name
        """
        version = rules.plain_version(self.cat.version(base)) or ""
        if version == want or version.startswith(want + "."):
            return base
        return f"{base}@{want}"


class _Ports(_Target):
    """A MacPorts target: the ports of its PortIndex, matched case-insensitively"""

    manager = Manager.PORTS
    label = "MacPorts"

    def __init__(self, portindex: Any) -> None:
        """Wrap the target's PortIndex

        @param portindex  the MacPorts target's PortIndex
        """
        super().__init__()
        self.idx = portindex
        self._names: list[str] | None = None

    def names(self) -> list[str]:
        """Return the port names, each once whatever its case, in PortIndex order

        @returns  the names, read once
        """
        if self._names is None:
            seen: set[str] = set()
            self._names = []
            for name in self.idx.names():
                if name.lower() not in seen:
                    seen.add(name.lower())
                    self._names.append(name)
        return self._names

    def has(self, name: str) -> bool:
        """Return whether the PortIndex holds a port, matched without regard to case

        @param name  a port name
        @returns     True when it holds one
        """
        return self.idx.has(name)

    def cand(self, name: str, kind: str = "port") -> Cand | None:
        """Return a port, matched case-insensitively, following its `replaced_by` before the gate

        @param name  a port name
        @param kind  `port` or empty; another kind has no port
        @returns     the candidate, the last port of the `replaced_by` chain; None for no such port
        """
        if kind not in ("", "port"):
            return None
        entry = self.idx.get(name)
        if entry is None:
            return None
        via: list[str] = []
        seen = {entry.name.lower()}
        while entry.replaced_by:
            successor = self.idx.get(entry.replaced_by)
            if successor is None or successor.name.lower() in seen:
                via.append(f"{entry.name} names replaced_by {entry.replaced_by}, which the PortIndex lacks")
                break
            via.append(f"{entry.name} is replaced by {successor.name}")
            seen.add(successor.name.lower())
            entry = successor
        return Cand("port", entry.name, _port_version(entry), False, entry.homepage, via)

    def identical(self, name: str) -> Cand | None:
        """Return the port of the source package's name, matched case-insensitively

        @param name  the source package's name
        @returns     the candidate; None when the PortIndex has no such port
        """
        return self.cand(name)

    def by_homepage(self, url: str) -> list[Cand]:
        """Return the ports whose normalised homepage is that of `url`

        `PortIndex.by_homepage` ignores only case and a trailing slash, so each scheme and `www.` spelling is asked.

        @param url  a homepage URL
        @returns    the candidates, sorted by name
        """
        want = normalise_url(url)
        if not want:
            return []
        spellings = [url]
        if want.startswith("https://"):
            rest = want[len("https://"):]
            spellings = [scheme + host + rest for scheme in ("https://", "http://") for host in ("", "www.")]
        out: dict[str, Cand] = {}
        for spelling in spellings:
            for entry in self.idx.by_homepage(spelling):
                if normalise_url(entry.homepage) == want:
                    cand = self.cand(entry.name)
                    if cand is not None:
                        out.setdefault(cand.name.lower(), cand)
        return [out[k] for k in sorted(out)]


def _target(ctx: Context) -> _Target | None:
    """Return the context's target catalogue, made on first use and kept in the context

    @param ctx  the resolution context
    @returns    the Homebrew or MacPorts target; None without its catalogue or PortIndex
    """
    if "target" not in ctx.memo:
        target: _Target | None = None
        if ctx.target is Manager.BREW and ctx.catalogue is not None:
            target = _Brew(ctx.catalogue)
        elif ctx.target is Manager.PORTS and ctx.portindex is not None:
            target = _Ports(ctx.portindex)
        ctx.memo["target"] = target
    return ctx.memo["target"]


# Facts for the planner -----------------------------------------------------------------

def python_dependencies(catalogue: Catalogue | None, name: str) -> list[tuple[str, bool]]:
    """Return `(3.X, build_only)` for each `python@3.X` in a formula's `stable_dependencies`

    @param catalogue  a Homebrew catalogue, or None
    @param name       a formula name
    @returns          one pair per Python version, `build_only` when the dependency's tags are all `build`
    """
    entry = catalogue.formula(name) if catalogue is not None else None
    out: list[tuple[str, bool]] = []
    for dep in (entry or {}).get("stable_dependencies") or []:
        items = [(dep, [])] if isinstance(dep, str) else list(dep.items()) if isinstance(dep, dict) else []
        for dep_name, tags in items:
            match = _PY_DEP.match(str(dep_name))
            if not match:
                continue
            tags = tags if isinstance(tags, list) else [tags]
            build_only = bool(tags) and all(str(t).lstrip(":") == "build" for t in tags)
            if all(v != match.group(1) for v, _ in out):
                out.append((match.group(1), build_only))
    return out


def python_package_versions(catalogue: Catalogue | None, name: str) -> list[str]:
    """Return the Pythons a formula is a Python package for: those it needs at run or test time

    Unlike `Catalogue.python_dependencies()`, build tools do not count: glib needs Python only to build.
    numpy lists its Pythons as `:build, :test`, because its test imports the module.

    @param catalogue  a Homebrew catalogue, or None
    @param name       a formula name
    @returns          the versions, such as `3.13`; empty for a formula that is no Python package
    """
    return [version for version, build_only in python_dependencies(catalogue, name) if not build_only]


def default_python(ctx: Context) -> str | None:
    """Return the target's default Python version, kept in the context

    Homebrew's is the target of its `python3` alias; MacPorts' the newest `python3NN` with a `py3NN-pip` port.

    @param ctx  the resolution context
    @returns    the version, such as `3.13`; None without a target catalogue or a Python in it
    """
    if "default_python" not in ctx.memo:
        version = None
        target = _target(ctx)
        if isinstance(target, _Brew):
            alias = target.cat.canonical("python3")
            version = rules.python_version_of(alias) if alias else None
        elif isinstance(target, _Ports):
            found = [int(m.group(1)) for m in (re.match(r"^python3(\d\d)$", n.lower()) for n in target.names())
                     if m and target.has(f"py3{m.group(1)}-pip")]
            version = f"3.{max(found)}" if found else None
        ctx.memo["default_python"] = version
    return ctx.memo["default_python"]


def plan_python(packages: Iterable[Package], ctx: Context) -> str | None:
    """Return the plan's Python: the newest source interpreter it migrates, else the target's default

    @param packages  the plan's source packages
    @param ctx       the resolution context
    @returns         the version, such as `3.13`; None when neither gives one
    """
    versions = [v for v in (rules.python_version_of(p.name) for p in packages if p.kind in ("formula", "port")) if v]
    if versions:
        return max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))
    return default_python(ctx)


def is_language(mapping: model.Mapping) -> bool:
    """Return whether a mapping is a language mapping: `pip`, `cpan`, `gem` or `npm`

    @param mapping  a resolved mapping
    @returns        True for a language target kind
    """
    return mapping.target_kind in LANGUAGE_KINDS


def accepted(mapping: model.Mapping, ctx: Context, answer: bool | None = None) -> bool:
    """Return whether a plan accepts a mapping: EXACT and HIGH, or MEDIUM with `--accept-closest` or `answer`

    `answer` is a yes on a terminal. A language mapping counts only as a HIGH `pip` one under `--pipx`.

    @param mapping  a resolved mapping
    @param ctx      the resolution context, with the plan options
    @param answer   the terminal answer about a MEDIUM mapping; None without a question
    @returns        True when the plan acts on the mapping
    """
    if mapping.target_name is None or mapping.confidence <= Confidence.LOW:
        return False
    if is_language(mapping):
        return mapping.target_kind == "pip" and ctx.lang_packages == "pipx" and mapping.confidence >= Confidence.HIGH
    if mapping.confidence >= Confidence.HIGH:
        return True
    return ctx.accept_medium or bool(answer)


def keeps_data(pkg: Package) -> str | None:
    """Return a cask's Caskroom entries besides `.metadata` and its versions, joined

    A cask that keeps data there is never adopted or mapped, and only `--uninstall` drops it.

    @param pkg  a source package
    @returns    the entries, comma-separated; None for a cask without any, a formula or a port
    """
    if pkg.kind != "cask" or not pkg.caskroom_data:
        return None
    return ", ".join(pkg.caskroom_data)


def font_cask(pkg: Package) -> bool:
    """Return whether a package is a font cask; into MacPorts those map to nothing and get the `drop` instructions

    @param pkg  a source package
    @returns    True for a cask whose token starts with `font-`
    """
    return pkg.kind == "cask" and pkg.name.startswith("font-")


def installed_in_target(ctx: Context, kind: str, name: str) -> Package | None:
    """Return the target's installed package of that kind and name, the name matched case-insensitively

    @param ctx   the resolution context, whose `installed` lists the target instance's packages
    @param kind  a package kind: formula, cask or port
    @param name  a package name, in any case
    @returns     the installed package; None when the target holds none
    """
    if "installed" not in ctx.memo:
        ctx.memo["installed"] = {(p.kind, p.name.lower()): p for p in ctx.installed}
    return ctx.memo["installed"].get((kind, name.lower()))


def target_known(ctx: Context, name: str) -> tuple[str, str] | None:
    """Return the target catalogue's `(kind, name)` for a `--replace` target, or None when it lacks it

    @param ctx   the resolution context
    @param name  the target side of a `--replace` entry
    @returns     the kind and the catalogue's own name; None also without a target catalogue
    """
    target = _target(ctx)
    cand = target.lookup(name) if target is not None else None
    return (cand.kind, cand.name) if cand is not None else None


def map_error(pkg: Package, ctx: Context) -> str | None:
    """Return the usage error (exit 2) of the `--replace` entry for `pkg`, or None when it has none or it is usable

    A language package's entry names its project (`--replace py313-serial=pyserial`), not a catalogue entry.

    @param pkg  a source package
    @param ctx  the resolution context, with the `--replace` entries
    @returns    the error text; None also without a target catalogue
    """
    wanted = ctx.maps.get(pkg.name, ctx.maps.get(pkg.name.lower()))
    target = _target(ctx)
    if wanted is None or target is None or target.lookup(wanted) is not None:
        return None
    if _Run(pkg, ctx, target).language_kind() is not None:
        return None
    return f"--replace {pkg.name}={wanted}: {possessive(target.label)} package list has no {wanted}"


def parse_maps(values: Iterable[str] | None) -> dict[str, str]:
    """Parse the `--replace OLD=NEW` values

    @param values       the `--replace` values, or None
    @returns            the target by source name, both sides stripped
    @throws ValueError  a value without both sides, a usage error (exit 2)
    """
    out: dict[str, str] = {}
    for value in values or ():
        source, sep, target = value.partition("=")
        if not sep or not source.strip() or not target.strip():
            raise ValueError(f"--replace wants OLD=NEW, not {value!r}")
        out[source.strip()] = target.strip()
    return out


def _bare(pkg: Package) -> str:
    """Return a language package's project part: a port without its prefix, a formula without `python-`

    @param pkg  a source package
    @returns    the bare name
    """
    lang = rules.language_port(pkg.name) if pkg.kind == "port" else None
    if lang is not None:
        return lang[1]
    return pkg.name[len("python-"):] if pkg.name.startswith("python-") else pkg.name


def language_hints(mapping: model.Mapping) -> list[str]:
    """Return the project names a language mapping names or tried, for the requirements file

    @param mapping  a resolved mapping
    @returns        the names; empty for a mapping that is no language mapping
    """
    if not is_language(mapping):
        return []
    if mapping.target_name:
        return [mapping.target_name]
    bare = _bare(mapping.source)
    return rules.pypi_candidates(bare, mapping.source.homepage) if mapping.target_kind == "pip" else [bare]


# PyPI ---------------------------------------------------------------------------------

class PyPI:
    """PyPI JSON lookups through curl for `--pipx`, kept for the run"""

    def __init__(self, runner: Any, downloads: str | None = None) -> None:
        """Start a client that has looked up nothing yet

        @param runner     the runner that runs curl
        @param downloads  the directory for the answers; None for a temporary one
        """
        self.runner = runner
        self.downloads = downloads or tempfile.mkdtemp(prefix="brew-ports-pypi-")
        self.error = ""
        self._cache: dict[str, dict[str, Any] | None] = {}

    def project(self, name: str) -> dict[str, Any] | None:
        """Return the project's JSON, {} when PyPI has no such project, or None when the lookup failed

        A failed lookup sets `error` and is tried again on the next call.

        @param name  a PyPI project name
        @returns     the JSON object; {} for an HTTP 404; None after a failure
        """
        if name not in self._cache:
            phase = self.runner.phase
            fetched = repology_mod.fetch_json(
                self.runner, PYPI_URL % urllib.parse.quote(name, safe=""),
                os.path.join(self.downloads, "pypi", slug(name) + ".json"),
                f"{0 if phase is None else phase}.pypi.{name}", f"read the PyPI project {name}")
            if fetched.status == "ok" and isinstance(fetched.data, dict):
                self._cache[name] = fetched.data
            elif fetched.status == "missing":
                self._cache[name] = {}
            else:
                self.error = fetched.error or "not a JSON object"
                return None
        return self._cache[name]


def _info(project: dict[str, Any]) -> dict[str, Any]:
    """Return the `info` object of a PyPI project's JSON

    @param project  a PyPI project's JSON
    @returns        the object; empty when the JSON has none
    """
    info = project.get("info")
    return info if isinstance(info, dict) else {}


def project_urls(project: dict[str, Any]) -> set[str]:
    """Return every URL a PyPI project lists, normalised

    @param project  a PyPI project's JSON
    @returns        the URLs of its `info`, among them the `project_urls` values
    """
    info = _info(project)
    urls = [info.get(key) for key in PYPI_URL_KEYS]
    links = info.get("project_urls")
    if isinstance(links, dict):
        urls.extend(links.values())
    return {u for u in (normalise_url(v) for v in urls if isinstance(v, str)) if u}


def _pypi(ctx: Context) -> PyPI | None:
    """Return the context's PyPI client, made on first use and kept in the context

    @param ctx  the resolution context
    @returns    the client; None without a runner, which keeps the lookups offline
    """
    if ctx.runner is None:
        return None
    if "pypi" not in ctx.memo:
        ctx.memo["pypi"] = PyPI(ctx.runner, ctx.downloads)
    return ctx.memo["pypi"]


# Interpreters -----------------------------------------------------------------------------

def _ports_interpreter(pkg: Package) -> tuple[str, str] | None:
    """Return `(family, port)` for a Homebrew interpreter formula, the port named from its version

    `python@3.13` gives `python313`, `node` at 26 `nodejs26`, `ruby` at 4.0 `ruby40`, `llvm` at 21 `llvm-21`.

    @param pkg  a source package
    @returns    the family and the port name; None for a package that is no interpreter formula
    """
    match = _BREW_INTERPRETER.match(pkg.name)
    if not match or pkg.kind != "formula":
        return None
    family, version = match.groups()
    if family == "python":
        return (family, "python" + version.replace(".", "")) if version and "." in version else None
    if family == "perl":
        return family, "perl5"
    parts = rules.version_parts(version) or rules.version_parts(pkg.version)
    if not parts:
        return None
    if family == "ruby":
        return (family, f"ruby{parts[0]}{parts[1]}") if len(parts) > 1 else None
    names = {"node": "nodejs%d", "openjdk": "openjdk%d", "gcc": "gcc%d", "llvm": "llvm-%d"}
    return family, names[family] % parts[0]


def _brew_interpreter(pkg: Package, brew: _Brew) -> tuple[str, str] | None:
    """Return `(family, formula)` for a MacPorts interpreter port, the reverse of `_ports_interpreter`

    `py3X-pip` and `npmN` map to the interpreter formula that ships them.

    @param pkg   a source package
    @param brew  the Homebrew target, whose versions choose between `node@22` and `node`
    @returns     the family and the formula name; None for a package that is no interpreter port
    """
    name = pkg.name.lower()
    for pattern, family in _PORTS_INTERPRETERS:
        match = pattern.match(name)
        if not match:
            continue
        if family in ("python", "pip"):
            return family, f"python@{match.group(1)}.{match.group(2)}"
        if family == "npm":
            node = next((d.lower() for d in pkg.deps if re.match(r"^nodejs\d+$", d.lower())), None)
            return family, brew.versioned("node", node[len("nodejs"):]) if node else "node"
        if family == "ruby":
            return family, brew.versioned("ruby", f"{match.group(1)}.{match.group(2)}")
        if family == "perl":
            return family, "perl"
        return family, brew.versioned(family, match.group(1))
    return None


# One resolution ------------------------------------------------------------------------------

class _Run:
    """The source package, the context and the evidence of the stages that did not decide"""

    def __init__(self, pkg: Package, ctx: Context, target: _Target) -> None:
        """Start the resolution of one source package

        @param pkg     the source package
        @param ctx     the resolution context
        @param target  the context's target catalogue
        """
        self.pkg = pkg
        self.ctx = ctx
        self.target = target
        self.source = Manager.PORTS if pkg.kind == "port" else Manager.BREW
        self.cross = self.source is not ctx.target
        self.notes: list[str] = []
        self.aside: list[Cand] = []         # a stage's sole match that the version gate set aside
        self._pythons: tuple[list[str], str | None] | None = None

    # Results ----------------------------------------------------------------------------

    def none(self, reason: str, kind: str = "none", name: str | None = None, version: str | None = None,
             extra: Sequence[str] = ()) -> Outcome:
        """Return an outcome that maps to nothing (NONE), its reason first

        @param reason   why the package maps to nothing
        @param kind     the kind of the target that cannot be used; `none` without one
        @param name     that target's name, or None
        @param version  that target's version, or None
        @param extra    the lines after the reason, such as a `--replace` suggestion
        @returns        the outcome
        """
        return Outcome(kind, name, version, Confidence.NONE, [reason] + list(extra))

    def finish(self, cand: Cand, confidence: Confidence, lines: list[str], adopt: bool = False) -> Outcome:
        """Return the outcome of a stage's pick, with its interpreter companions and selections

        A target Homebrew refuses is unmigratable even when installed, as phase 0 asks `refused()` again.
        So is a cask that needs sudo to install, unless the target holds it already.

        @param cand        the pick
        @param confidence  the stage's confidence in it
        @param lines       the stage's evidence; the pick's `via` steps follow
        @param adopt       adopt the cask in place
        @returns           the outcome; NONE for a refused target or a cask that needs sudo
        """
        lines = lines + [v for v in cand.via if v not in lines]
        if isinstance(self.target, _Brew):
            refused = self.target.refused(cand)
            if refused:
                return self.refusal(cand, refused)
            install = cand.kind == "cask" and installed_in_target(self.ctx, "cask", cand.name) is None
            info = self.target.cat.cask(cand.name) if install else None
            if info is not None and info.privileged_install:
                brew = os.path.join(self.target.cat.prefix, "bin", "brew")
                command = typed([brew, "install", "--cask"] + (["--adopt"] if adopt else []) + [cand.name])
                reason = (f"Homebrew has it, but its installer asks for your password, which brew-ports never "
                          f"passes on: run `{command}` yourself, then plan again")
                return self.none(reason, "cask", cand.name, cand.version)
        companions, selections = self.companions(cand)
        return Outcome(cand.kind, cand.name, cand.version, confidence, lines, adopt, companions, selections)

    def refusal(self, cand: Cand, refused: dict[str, Any]) -> Outcome:
        """Return the NONE outcome of a target Homebrew refuses, with the replacement Homebrew names for it

        @param cand     the refused candidate
        @param refused  the catalogue's refusal of it
        @returns        the outcome
        """
        since = f"since {refused['date']}" if refused.get("date") else ""
        because = refused.get("because") or ""
        if " " not in because:
            because = because.replace("_", " ")         # Homebrew's own word for the reason: `fails_gatekeeper_check`
        detail = ": ".join(part for part in (since, because) if part)
        reason = f"Homebrew has disabled {cand.name}" + (f" ({detail})" if detail else "")
        replacement = refused.get("replacement_formula") or refused.get("replacement_cask")
        if replacement:
            reason += f"; it names {replacement} in its place: plan with `--replace {self.pkg.name}={replacement}`"
        return self.none(reason, cand.kind, cand.name, cand.version)

    def mapping(self, outcome: Outcome) -> model.Mapping:
        """Return the mapping of an outcome, the notes of the stages that did not decide after its own lines

        @param outcome  the outcome of the deciding stage
        @returns        the mapping, each evidence line once
        """
        evidence: list[str] = []
        for line in outcome.lines + self.notes:
            if line not in evidence:
                evidence.append(line)
        variants = " ".join(self.pkg.requested_variants) if self.pkg.kind == "port" else ""
        return model.Mapping(source=self.pkg, target_kind=outcome.kind, target_name=outcome.name,
                             target_version=outcome.version, confidence=outcome.confidence, evidence=evidence,
                             companions=outcome.companions, selections=outcome.selections,
                             variants_note=f"requested variants {variants}" if variants else None,
                             adopt=outcome.adopt)

    # The order of the stages ----------------------------------------------------------------

    def outcome(self) -> Outcome:
        """Return the outcome of the first stage that decides, else NONE

        @returns  the outcome
        """
        for step in self.steps():
            found = step()
            if found is not None:
                return found
        if self.aside:
            cand = self.aside[0]
            return self.none(f"the closest find, {cand.kind} {cand.name} {_plain(cand.version)}, has another major "
                             f"version than {_plain(self.pkg.version)}; if it is the same software, plan with "
                             f"`--replace {self.pkg.name}={cand.name}`")
        return self.none(f"nothing of that name, or like it, is in {possessive(self.target.label)} package list")

    def steps(self) -> list[Callable[[], Outcome | None]]:
        """Return the matching steps for this package, in the order they are tried

        @returns  the stages; each returns an outcome, or None to pass the package on
        """
        if self.pkg.kind == "cask":
            return [self.mapped, self.cask]
        steps: list[Callable[[], Outcome | None]] = [self.mapped]
        if self.cross:
            steps.append(self.interpreter)
            if self.source is Manager.PORTS and rules.language_port(self.pkg.name):
                return steps + [self.language_port]
            steps.append(self.static)
        steps += [self.name, self.executables, self.homepage]
        python_formula = self.cross and self.source is Manager.BREW
        if python_formula:
            steps.append(self.python_formula)
        steps.append(self.repology)
        if python_formula:
            steps.append(self.language_formula)
        return steps + [self.fuzzy]

    # Candidates and the version gate -----------------------------------------------------------

    def cands(self, names: Iterable[str], kind: str = "") -> list[Cand]:
        """Return the target's candidates for catalogue names, each candidate once

        @param names  catalogue names
        @param kind   the kind wanted; empty for the catalogue's own kind
        @returns      the candidates, in the order of `names`; a name the catalogue lacks gives none
        """
        out: list[Cand] = []
        for name in names:
            cand = self.target.cand(name, kind)
            if cand is not None and all(c.name != cand.name or c.kind != cand.kind for c in out):
                out.append(cand)
        return out

    def usable(self, cands: list[Cand]) -> list[Cand]:
        """Return the candidates a stage may propose beyond an identical name

        No language module port for a formula (the Python rule decides those), only `-app` ports for a cask,
        and no target Homebrew refuses while another is left.

        @param cands  a stage's candidates
        @returns      the usable candidates; the refused ones it drops are noted
        """
        if self.source is Manager.BREW and self.ctx.target is Manager.PORTS:
            if self.pkg.kind == "cask":
                cands = [c for c in cands if c.name.lower().endswith("-app")]
            else:
                cands = [c for c in cands if rules.language_port(c.name) is None]
        if self.ctx.target is Manager.BREW:
            allowed = [c for c in cands if not self.target.refused(c)]
            if allowed and len(allowed) < len(cands):
                self.notes.append(f"refused by Homebrew: {', '.join((c.name for c in cands if c not in allowed))}")
                cands = allowed
        return cands

    def version_line(self, cand: Cand) -> list[str]:
        """Return the evidence line that sets a candidate's version beside the source's

        @param cand  the candidate
        @returns     a list of that one line; a cask's says it is not gated
        """
        if cand.kind == "cask":
            return [f"version: cask {cand.name} {cand.version or 'unversioned'}, not gated"]
        return [f"version: target {cand.name} {_plain(cand.version)}, source {_plain(self.pkg.version)}"]

    def gated(self, cands: list[Cand], confidence: Confidence, lines: list[str], strong: bool,
              gate: bool = True) -> Outcome | None:
        """Apply the version gate to a stage's candidates; None when it drops a single uncorroborated match

        Without a candidate of the source's major, a `strong` match (EXACT or corroborated) looks for a sibling.

        @param cands       the stage's candidates, at least one
        @param confidence  the stage's confidence in a single survivor
        @param lines       the stage's evidence lines
        @param strong      the match is EXACT or corroborated
        @param gate        apply the gate; False for a program that follows its own version line
        @returns           the outcome, or None
        """
        if not gate:
            line = (f"version: target {cands[0].name} {_plain(cands[0].version)}, not gated: {self.pkg.name} "
                    "follows its own version line")
            return self.finish(cands[0], confidence, lines + [line])
        survivors = [c for c in cands if same_major(self.pkg.version, c)]
        formulae = [c for c in survivors if c.kind != "cask"]
        if formulae and len(formulae) < len(survivors):
            casks = ", ".join(c.name for c in survivors if c.kind == "cask")
            self.notes.append(f"the formulae win over the casks {casks}")
            survivors = formulae
        if len(survivors) == 1:
            return self.finish(survivors[0], confidence, lines + self.version_line(survivors[0]))
        if survivors:
            best = _newest(survivors)
            others = ", ".join(c.name for c in survivors if c is not best)
            text = f"version: {best.name} and {others} share the source's major; {best.name} is the newest"
            return self.finish(best, Confidence.MEDIUM, lines + [text])
        if strong:
            return self.siblings(_closest(self.pkg.version, cands), lines)
        if len(cands) > 1:
            best = _newest(cands)
            listed = ", ".join(f"{c.name} {_plain(c.version)}" for c in cands)
            text = f"version: no match has the source's major ({_plain(self.pkg.version)}): {listed}"
            return self.finish(best, Confidence.MEDIUM, lines + [text])
        self.notes.append(f"version: {cands[0].name} {_plain(cands[0].version)} has another major than the source "
                          f"{_plain(self.pkg.version)}")
        self.aside.append(cands[0])
        return None

    def siblings(self, cand: Cand, lines: list[str]) -> Outcome:
        """Return the sibling with the source's major as HIGH, else `cand` as MEDIUM with the nearest named

        @param cand   the strong match, of another major
        @param lines  the stage's evidence lines
        @returns      the outcome
        """
        sibs = [c for c in self.cands(self.target.sibling_names(cand), cand.kind) if c.name != cand.name]
        matching = [c for c in sibs if same_major(self.pkg.version, c)]
        if matching:
            best = _closest(self.pkg.version, matching)
            return self.finish(best, Confidence.HIGH,
                               lines + [f"version: major {rules.major(self.pkg.version)} matched by {best.name}"])
        text = f"version: target is {_plain(cand.version)}, source is {_plain(self.pkg.version)}"
        if sibs:
            near = _closest(self.pkg.version, sibs)
            text += f"; nearest sibling {near.name} {_plain(near.version)}"
        return self.finish(cand, Confidence.MEDIUM, lines + [text])

    def corroboration(self, cand: Cand) -> str | None:
        """Return what corroborates a `canon()` match: the same homepage, or executables at Jaccard 0.5 or more

        @param cand  the match
        @returns     the evidence line; None when nothing corroborates it
        """
        homepage = normalise_url(self.pkg.homepage)
        if homepage and homepage == normalise_url(cand.homepage):
            return f"corroborated by the homepage {homepage}"
        if isinstance(self.target, _Brew) and cand.kind == "formula" and self.pkg.executables:
            score = rules.exe_jaccard(self.pkg.executables, self.target.executables(cand.name))
            if score >= 0.5:
                return f"corroborated by the executables (Jaccard {score:.2f})"
        return None

    # --replace and casks ------------------------------------------------------------------------

    def mapped(self) -> Outcome | None:
        """Map by `--replace OLD=NEW`, EXACT; a major difference is noted, not refused

        A cask that keeps data in its Caskroom is refused, as the cask stage refuses it.

        @returns  the outcome; None without a `--replace` entry for the package
        """
        maps = self.ctx.maps
        wanted = maps.get(self.pkg.name, maps.get(self.pkg.name.lower()))
        if wanted is None:
            return None
        line = f"your choice: --replace {self.pkg.name}={wanted}"
        data = keeps_data(self.pkg)
        if data:
            return self.none(f"{DATA_KEPT % data}, so `--replace {self.pkg.name}={wanted}` is not followed")
        cand = self.target.lookup(wanted)
        if cand is None:
            lang = self.language_kind()
            if lang is not None:
                return self.language(lang, project=wanted, line=line)
            return self.none(f"{wanted}, which you chose with --replace, is not in "
                             f"{possessive(self.target.label)} package list")
        adopt = self.pkg.kind == "cask" and cand.kind == "cask" and self.ctx.target is Manager.BREW
        notes = self.version_line(cand)
        if not same_major(self.pkg.version, cand):
            notes.append("version: the major version differs; --replace keeps your choice")
        return self.finish(cand, Confidence.EXACT, [line] + notes, adopt=adopt)

    def cask(self) -> Outcome | None:
        """Map a cask: a `brew` target adopts the token, a `ports` target tries the homepage, then Repology

        @returns  the outcome; None when neither finds a port
        """
        data = keeps_data(self.pkg)
        if data:
            return self.none(DATA_KEPT % data)
        if self.ctx.target is Manager.BREW:
            return self.adopt()
        if font_cask(self.pkg):
            return self.none("fonts are not matched to ports: install the font yourself")
        return self.homepage() or self.repology()

    def adopt(self) -> Outcome:
        """Adopt a cask into a `brew` target under the same token, EXACT

        @returns  the outcome; NONE when the catalogue has no such cask
        """
        cand = self.target.cand(self.pkg.name, "cask")
        if cand is None:
            return self.none(f"Homebrew's package list has no cask named {self.pkg.name}")
        held = installed_in_target(self.ctx, "cask", cand.name) is not None
        where = "installed in the target" if held else "the same token in the target catalogue"
        return self.finish(cand, Confidence.EXACT, [f"adopt {cand.name}: {where}"], adopt=True)

    # Interpreters and language packages ----------------------------------------------------------

    def python(self) -> str | None:
        """Return the plan's Python, else the target's default

        @returns  the version, such as `3.13`; None when neither is known
        """
        return self.ctx.python_version or default_python(self.ctx)

    def interpreter(self) -> Outcome | None:
        """Map an interpreter to the target named from its version, EXACT, else to its nearest sibling, MEDIUM

        @returns  the outcome; None for no interpreter, or without a target of its family
        """
        if self.source is Manager.BREW:
            rule = _ports_interpreter(self.pkg)
        else:
            rule = _brew_interpreter(self.pkg, self.target) if isinstance(self.target, _Brew) else None
        if rule is None:
            return None
        family, name = rule
        cand = self.target.cand(name)
        if cand is not None:
            if family in _INCLUDED:
                line = f"interpreter: {self.pkg.name} is included in {cand.name}"
            else:
                line = f"interpreter: {self.pkg.name} is {cand.name}"
            return self.gated([cand], Confidence.EXACT, [line], strong=True, gate=family not in _INCLUDED)
        family_names = self.target.stem_matches(name)
        sibs = self.cands(n for n in family_names if n.lower() != name.lower())
        if not sibs or family in _INCLUDED:
            self.notes.append(f"interpreter: no {name} in the {self.target.label} catalogue")
            return None
        near = _closest(self.pkg.version, sibs)
        line = (f"interpreter: no {name} in the {self.target.label} catalogue; "
                f"source is {_plain(self.pkg.version)}; nearest sibling {near.name} {_plain(near.version)}")
        return self.finish(near, Confidence.MEDIUM, [line])

    def companions(self, cand: Cand) -> tuple[list[str], list[tuple[str, str]]]:
        """Return the interpreter companions of a mapping into MacPorts, and its `port select` pairs

        @param cand  the pick
        @returns     the companion ports and the `(group, version)` pairs; both empty for no interpreter port
        """
        rule = _ports_interpreter(self.pkg) if self.cross and cand.kind == "port" else None
        if rule is None:
            return [], []
        family, name = rule[0], cand.name.lower()
        companions: list[str] = []
        selections: list[tuple[str, str]] = []
        python = re.match(r"^python(\d)(\d+)$", name)
        llvm = re.match(r"^llvm-(\d+)$", name)
        if family == "python" and python:
            pip = f"py{python.group(1)}{python.group(2)}-pip"
            selections.append(("python3", name))
            if self.companion(pip, companions):
                selections.append(("pip3", f"pip{python.group(1)}{python.group(2)}"))
        elif family == "node" and re.match(r"^nodejs\d+$", name):
            npms = [n for n in self.target.names() if re.match(r"^npm\d+$", n.lower())]
            if npms:
                companions.append(max(npms, key=lambda n: int(n[3:])))
        elif family == "ruby" and re.match(r"^ruby\d\d$", name):
            selections.append(("ruby", name))
        elif family == "gcc" and re.match(r"^gcc\d+$", name):
            selections.append(("gcc", "mp-" + name))
        elif family == "llvm" and llvm:
            if self.companion(f"clang-{llvm.group(1)}", companions):
                selections.append(("clang", f"mp-clang-{llvm.group(1)}"))
        return companions, selections

    def companion(self, name: str, companions: list[str]) -> bool:
        """Add a companion port to `companions` when the target has it, else record its absence in the notes

        @param name        the companion's port name
        @param companions  the list the companion joins
        @returns           True when the target has it
        """
        cand = self.target.cand(name)
        if cand is None:
            self.notes.append(f"companion {name} is not in the {self.target.label} catalogue")
            return False
        companions.append(cand.name)
        return True

    def language_kind(self) -> str | None:
        """Return the language kind of a source without a catalogue target, or None

        Such a source is a language port into Homebrew, or a Python package formula into MacPorts.

        @returns  `pip`, `cpan` or `gem`; None for any other source
        """
        if not self.cross:
            return None
        if self.source is Manager.PORTS:
            lang = rules.language_port(self.pkg.name)
            return lang[0] if lang else None
        return "pip" if self.formula_pythons()[0] else None

    def language_port(self) -> Outcome:
        """Map a language module port into Homebrew: an identical name, the Python rule, or a language mapping

        The name stages never run on the bare name.

        @returns  the outcome
        """
        kind, bare = rules.language_port(self.pkg.name) or ("pip", self.pkg.name)
        same = self.target.identical(self.pkg.name)
        if same is not None:
            return self.gated([same], Confidence.EXACT, [f"name: {same.name}"], strong=True) or \
                self.language(kind, bare)
        if kind == "pip":
            found = self.python_port(bare)
            if found is not None:
                return found
        return self.language(kind, bare)

    def python_port(self, bare: str) -> Outcome | None:
        """Map `py3X-<name>` to the formula `<name>` or `python-<name>`, EXACT

        Only a formula that is a Python package for the plan's Python qualifies.

        @param bare  the port's name without its `py3X-` prefix
        @returns     the outcome; None when no formula qualifies
        """
        python = self.python()
        if python is None:
            self.notes.append("python: the target has no default Python, so the Python rule cannot run")
            return None
        for name in (bare, "python-" + bare):
            cand = self.target.cand(name)
            if cand is None:
                continue
            versions = python_package_versions(self.ctx.catalogue, cand.name)
            if python in versions:
                line = f"python: {self.pkg.name} is {cand.name}, a Python package for python@{python}"
                return self.gated([cand], Confidence.EXACT, [line], strong=True)
            if versions:
                built = ", ".join("python@" + v for v in versions)
                self.notes.append(f"python: {cand.name} is built for {built}, not python@{python}")
            else:
                self.notes.append(f"python: {cand.name} needs no Python at run or test time, so it is no Python "
                                  "package")
        return None

    def formula_pythons(self) -> tuple[list[str], str | None]:
        """Return the Pythons a source formula is a Python package for, with a note, worked out once

        They come from its own catalogue's dependency tags, else from the receipt's runtime dependencies.

        @returns  the versions, such as `3.13`, and the evidence note about them, or None
        """
        if self._pythons is None:
            catalogue = self.ctx.source_catalogues.get(self.pkg.instance_prefix)
            note = None
            if catalogue is not None and catalogue.formula(self.pkg.name) is not None:
                deps = python_dependencies(catalogue, self.pkg.name)
                versions = [v for v, build_only in deps if not build_only]
                if deps and not versions:
                    needed = ", ".join("python@" + v for v, _ in deps)
                    note = f"python: {self.pkg.name} needs {needed} only to build, so it is no Python package"
            else:
                versions = [m.group(1) for m in (_PY_DEP.match(d) for d in self.pkg.deps) if m]
                if versions:
                    note = (f"python: from the receipt's runtime dependencies; {self.pkg.instance_prefix} "
                            "has no catalogue")
            self._pythons = (versions, note)
        return self._pythons

    def python_formula(self) -> Outcome | None:
        """Map a Python package formula to `py<plan>-<name>`, EXACT, also without a `python-` prefix

        @returns  the outcome; None for no Python package formula, or without such a port
        """
        versions, note = self.formula_pythons()
        if note:
            self.notes.append(note)
        if not versions:
            return None
        python = self.python()
        if python is None:
            self.notes.append("python: the target has no default Python, so the Python rule cannot run")
            return None
        prefix = rules.py_prefix(python)
        names = [prefix + "-" + self.pkg.name]
        if self.pkg.name.startswith("python-"):
            names.append(prefix + "-" + self.pkg.name[len("python-"):])
        for name in names:
            cand = self.target.cand(name)
            if cand is not None:
                built = ", ".join("python@" + v for v in versions)
                line = (f"python: {self.pkg.name} is a Python package ({built}): "
                        f"{cand.name} for the plan's Python {python}")
                return self.gated([cand], Confidence.EXACT, [line], strong=True)
        self.notes.append(f"python: no {' or '.join(names)} in the MacPorts catalogue")
        return None

    def language_formula(self) -> Outcome | None:
        """Map a Python package formula the Python rule left unresolved to a `pip` language mapping

        @returns  the outcome; None for a formula that is no Python package
        """
        if not self.formula_pythons()[0]:
            return None
        return self.language("pip", _bare(self.pkg))

    def language(self, kind: str, bare: str = "", project: str | None = None,
                 line: str | None = None) -> Outcome:
        """Return a language mapping: LOW, never accepted, with the names tried

        Under `--pipx`, a `pip` project of a source with executables is HIGH, with `pipx`, when
        its PyPI JSON lists the source homepage or `--replace` names it.

        @param kind     the language kind: `pip`, `cpan` or `gem`
        @param bare     the bare project name to try
        @param project  the project `--replace` names, or None
        @param line     the `--replace` evidence line, or None
        @returns        the outcome
        """
        head = [line] if line else []
        tried = [project] if project else (rules.pypi_candidates(bare, self.pkg.homepage) if kind == "pip"
                                           else [bare])
        tried_line = f"language package ({kind}): tried {', '.join(tried)}"
        if kind != "pip" or self.ctx.lang_packages != "pipx":
            return Outcome(kind, project, None, Confidence.LOW, [tried_line] + head)
        found: str | None
        if project:
            found, version, lines = project, None, [f"pipx: {project} is your choice (--replace)"]
        else:
            found, version, lines = self.pypi(tried)
        if found is None:
            return Outcome("pip", None, None, Confidence.LOW,
                           ["no PyPI project matches its homepage", tried_line] + lines)
        if not self.pkg.executables:
            return Outcome("pip", found, version, Confidence.LOW, head + [
                f"language package (pip): {found} installs no executable, so pipx does not take it"] + lines)
        pipx = self.target.cand("pipx")
        if pipx is None:
            return Outcome("pip", found, version, Confidence.LOW, head + [
                f"language package (pip): no pipx in the {self.target.label} catalogue"] + lines)
        return Outcome("pip", found, version, Confidence.HIGH, head + [
            f"pipx: {found} from PyPI, installed with {pipx.name}"] + lines, companions=[pipx.name])

    def pypi(self, tried: Sequence[str]) -> tuple[str | None, str | None, list[str]]:
        """Return the first tried PyPI project that lists the source homepage, its version and the lines

        @param tried  the project names, in the order to try
        @returns      the project and its version, each None when no project matches, and the evidence lines
        """
        homepage = normalise_url(self.pkg.homepage)
        if not homepage:
            return None, None, ["pypi: the source names no homepage to check projects against"]
        client = _pypi(self.ctx)
        if client is None:
            return None, None, ["pypi: not checked, no runner"]
        lines: list[str] = []
        for name in tried:
            project = client.project(name)
            if project is None:
                lines.append(f"pypi: {name}: {client.error}")
            elif not project:
                lines.append(f"pypi: no project {name}")
            elif homepage in project_urls(project):
                info = _info(project)
                version = info.get("version") if isinstance(info.get("version"), str) else None
                return name, version, lines + [f"pypi: {name} lists {homepage}"]
            else:
                lines.append(f"pypi: {name} does not list {homepage}")
        return None, None, lines

    # The stages ----------------------------------------------------------------------------

    def static(self) -> Outcome | None:
        """Map by the static map, EXACT; a pair whose target the catalogue lacks is ignored

        Into MacPorts, the pair's companion ports join the mapping, as an interpreter's do.

        @returns  the outcome; None when no pair's target is in the catalogue
        """
        smap = shipped()
        into_ports = self.source is Manager.BREW
        if into_ports:
            pairs = [(p.ports, p) for p in smap.ports_for(self.pkg.name)]
        else:
            pairs = [(p.brew, p) for p in smap.brew_for(self.pkg.name)]
        cands: list[Cand] = []
        lines: list[str] = []
        companions: list[str] = []
        for name, pair in pairs:
            cand = self.target.cand(name)
            if cand is None:
                self.notes.append(f"static map: {pair.brew} = {pair.ports} ignored, "
                                  f"the {self.target.label} catalogue lacks {name}")
            elif all(c.name != cand.name for c in cands):
                cands.append(cand)
                note = f" ({pair.note})" if pair.note else ""
                plus = f" + {', '.join(pair.companions)}" if pair.companions else ""
                lines.append(f"static map: {pair.brew} = {pair.ports}{plus}{note}")
                if into_ports:
                    companions += pair.companions
        if not cands:
            return None
        outcome = self.gated(cands, Confidence.EXACT, lines, strong=True)
        if outcome is not None:
            for name in dict.fromkeys(companions):
                self.companion(name, outcome.companions)
        return outcome

    def name(self) -> Outcome | None:
        """Map by name: an identical one is EXACT; a unique `canon()` match is MEDIUM, HIGH when corroborated

        @returns  the outcome; None without a match
        """
        same = self.target.identical(self.pkg.name)
        if same is not None:
            return self.gated([same], Confidence.EXACT, [f"name: {same.name}"], strong=True)
        names = [n for n in self.target.canon_matches(self.pkg.name) if n.lower() != self.pkg.name.lower()]
        cands = self.usable(self.cands(names))
        if not cands:
            return None
        line = f"canonical name: {self.pkg.name} ~ {', '.join((c.name for c in cands))} ({rules.canon(self.pkg.name)})"
        if len(cands) > 1:
            survivors = [c for c in cands if same_major(self.pkg.version, c)]
            if len(survivors) != 1:
                return self.gated(cands, Confidence.MEDIUM, [line], strong=False)
            cands = survivors
        why = self.corroboration(cands[0])
        lines = [line] + ([why] if why else [])
        return self.gated(cands, Confidence.HIGH if why else Confidence.MEDIUM, lines, strong=bool(why))

    def executables(self) -> Outcome | None:
        """Map by executables, into Homebrew only

        The best match at Jaccard 0.5 or more is HIGH, a sole match below 0.5 MEDIUM; a tie maps nothing.

        @returns  the outcome; None without a match, for a tie, or for several matches below 0.5
        """
        if not isinstance(self.target, _Brew) or not self.pkg.executables:
            return None
        index = self.target.exe_index()
        names: set[str] = set()
        for exe in self.pkg.executables:
            for alias in rules.exe_aliases(exe):
                names.update(index.get(alias, ()))
        cands = self.usable(self.cands(sorted(names)))
        if not cands:
            return None
        scored = sorted(((rules.exe_jaccard(self.pkg.executables, self.target.executables(c.name)), c) for c in cands),
                        key=lambda sc: (-sc[0], sc[1].name))
        score, best = scored[0]
        line = f"executables: {self.pkg.name} and {best.name} (Jaccard {score:.2f})"
        if len(scored) > 1 and scored[1][0] == score:
            tied = ", ".join(c.name for s, c in scored if s == score)
            self.notes.append(f"executables: {tied} tie at Jaccard {score:.2f}")
            return None
        if score >= 0.5:
            return self.gated([best], Confidence.HIGH, [line], strong=True)
        if len(scored) == 1:
            return self.gated([best], Confidence.MEDIUM, [line], strong=False)
        self.notes.append(line + f", other matches below 0.5: {', '.join((c.name for _, c in scored[1:]))}")
        return None

    def homepage(self) -> Outcome | None:
        """Map by the normalised homepage: the matches go through the version gate, a sole survivor HIGH

        @returns  the outcome; None without a homepage or a match
        """
        homepage = normalise_url(self.pkg.homepage)
        if not homepage:
            return None
        cands = self.usable(self.target.by_homepage(self.pkg.homepage or ""))
        cands = [c for c in cands if self.cross or c.name.lower() != self.pkg.name.lower()]
        if not cands:
            return None
        return self.gated(cands, Confidence.HIGH, [f"homepage: {homepage} ({', '.join((c.name for c in cands))})"],
                          strong=True)

    def repology(self) -> Outcome | None:
        """Map through Repology under `--repology`: the project's packages in the catalogue go through the gate

        The pick is HIGH when the gate settles on one, MEDIUM otherwise.

        @returns  the outcome; None without `--repology`, after a failed lookup, or without a match
        """
        client = self.ctx.repology
        if client is None:
            return None
        entries = client.candidates(self.pkg, self.ctx.target)
        if entries is None:
            self.notes.append(f"repology: {client.error}")
            return None
        cands: list[Cand] = []
        for entry in entries:
            cand = self.target.cand(entry.name, entry.kind)
            if cand is None:
                self.notes.append(f"repology: {entry.kind} {entry.name} is not in the {self.target.label} catalogue")
            elif all(c.name != cand.name for c in cands):
                cands.append(cand)
        cands = self.usable(cands)
        if not cands:
            self.notes.append(f"repology: no {self.target.label} package of this project in the catalogue")
            return None
        listed = ", ".join(f"{e.name} ({e.status})" for e in entries)
        line = f"repology: {listed}"
        return self.gated(cands, Confidence.HIGH, [line], strong=True)

    def fuzzy(self) -> Outcome | None:
        """Map by `rules.fuzzy_key`, LOW: every match is listed, and none is accepted without `--replace`

        @returns  the outcome; None without a match
        """
        names = [n for n in self.target.fuzzy_matches(self.pkg.name) if n.lower() != self.pkg.name.lower()]
        cands = self.usable(self.cands(names))
        if not cands:
            return None
        best = _closest(self.pkg.version, cands)
        listed = ", ".join(c.name for c in cands)
        line = (f"{possessive(self.target.label)} package list has similar names only ({listed}); if one is the same "
                f"software, plan with `--replace {self.pkg.name}=` and that name")
        return self.finish(best, Confidence.LOW, [line] + self.version_line(best))


def resolve(pkg: Package, ctx: Context) -> model.Mapping:
    """Map one source package to the target catalogue

    A mapping the planner cannot accept carries its reason in `evidence[0]`.

    @param pkg  the source package
    @param ctx  the resolution context
    @returns    the mapping; NONE without a target catalogue
    """
    target = _target(ctx)
    if target is None:
        reason = f"this Mac has no package list for {MANAGER_NAMES[ctx.target]} yet"
        return model.Mapping(source=pkg, target_kind="none", target_name=None, target_version=None,
                             confidence=Confidence.NONE, evidence=[reason], companions=[], selections=[],
                             variants_note=None)
    run = _Run(pkg, ctx, target)
    return run.mapping(run.outcome())

"""The package sets of a plan: the source units, the roots, the kept and removal sets and their refusals"""

from __future__ import annotations

import functools
import os
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import env, system
from .env import services as env_services
from .equiv import resolver, rules
from .model import Instance, Manager, Mapping, Package, PackageKey as Key, Service, name_key

Pair = tuple[str, str]              # (kind, name), as the removal set lists it

FULL = "full"                       # a kept package keeps its whole dependency closure
FORMULAE = "formulae"               # a cask keeps only the formulae it declares, with their closure
KIND_ORDER = {"cask-adopted": 0, "cask": 1, "formula": 2, "port": 3}

_PY_HOME = re.compile(r"(?:python@?|/Versions/)(3\.\d+)")
_EXTRA_OWNERS = {
    ("npm", "formula"): re.compile(r"^node(@\d+)?$"), ("npm", "port"): re.compile(r"^(nodejs|npm)\d+$"),
    ("gems", "formula"): re.compile(r"^ruby(@[\d.]+)?$"), ("gems", "port"): re.compile(r"^ruby\d+$"),
    ("cpan", "formula"): re.compile(r"^perl$"), ("cpan", "port"): re.compile(r"^perl5"),
}


@dataclass
class Unit:
    """One source package by name: a formula or cask, or every registry row of a port"""

    inst: Instance
    kind: str
    name: str
    pkg: Package                    # the active row, else the newest one
    rows: list[Package]

    @property
    def prefix(self) -> str:
        """Return the prefix of the instance that holds the unit

        @returns  the instance prefix
        """
        return self.inst.prefix

    @property
    def key(self) -> Key:
        """Return the key the plan knows the unit by

        @returns  `(prefix, kind, name key)`
        """
        return (self.inst.prefix, self.kind, name_key(self.kind, self.name))

    @property
    def inactive_only(self) -> bool:
        """Return whether this is a port whose every row is inactive, which is never a root

        @returns  True for a port without an active row
        """
        return self.kind == "port" and not any(r.active for r in self.rows)

    def pair(self, adopted: bool = False) -> Pair:
        """Return the unit as the removal set lists it

        @param adopted  whether the target adopts the cask, which the removal set lists as `cask-adopted`
        @returns        `(kind, name)`
        """
        return ("cask-adopted" if adopted else self.kind, self.name)

    def label(self) -> str:
        """Return the unit as the report names it

        @returns  `<kind> <name> (<prefix>)`
        """
        return f"{self.kind} {self.name} ({self.inst.prefix})"


def units_of(inst: Instance, packages: Iterable[Package]) -> list[Unit]:
    """Return the units of one instance, a port's rows grouped under its active row or else its newest

    The registry lists a name's rows oldest first.

    @param inst      the source instance
    @param packages  the scan's packages; those of other instances are skipped
    @returns         the units, by kind, then name in any case
    """
    groups: dict[tuple[str, str], list[Package]] = {}
    for pkg in packages:
        if pkg.instance_prefix == inst.prefix:
            groups.setdefault((pkg.kind, name_key(pkg.kind, pkg.name)), []).append(pkg)
    out = []
    for rows in groups.values():
        active = [r for r in rows if r.active]
        rep = active[0] if active else rows[-1]
        out.append(Unit(inst, rep.kind, rep.name, rep, rows))
    return sorted(out, key=lambda u: (KIND_ORDER.get(u.kind, 9), u.name.lower()))


class SourceGraph:
    """The units of one source instance with their dependency edges

    Edges run formula -> formula, cask -> formula, cask -> cask, and port -> port over rows of every state.
    """

    def __init__(self, inst: Instance, units: Sequence[Unit], canonical: Callable[[str, str], str | None]) -> None:
        """Index the units and turn their dependency names into edges

        @param inst       the source instance
        @param units      the instance's units
        @param canonical  returns the name a dependency `(name, kind)` has in the source's catalogue, or None
        """
        self.inst = inst
        self.units: dict[Key, Unit] = {u.key: u for u in units}
        self.deps: dict[Key, set[Key]] = {}
        self.dependents: dict[Key, set[Key]] = {u.key: set() for u in units}
        for unit in units:
            edges: set[Key] = set()
            for kind, names in self._dep_names(unit):
                for name in names:
                    found = self.find(kind, name) or self.find(kind, canonical(name, kind) or "")
                    if found is not None and found is not unit:
                        edges.add(found.key)
            self.deps[unit.key] = edges
            for key in edges:
                self.dependents[key].add(unit.key)

    @staticmethod
    def _dep_names(unit: Unit) -> list[tuple[str, list[str]]]:
        """Return the dependency names of a unit, by the kind they name

        @param unit  a source unit
        @returns     `(kind, names)` pairs: a port's over every row, a cask's casks besides its formulae
        """
        if unit.kind == "port":
            return [("port", [d for row in unit.rows for d in row.deps])]
        out = [("formula", list(unit.pkg.deps))]
        if unit.kind == "cask":
            out.append(("cask", list(unit.pkg.cask_deps)))
        return out

    def find(self, kind: str, name: str) -> Unit | None:
        """Return the unit of a kind and name

        @param kind  formula, cask or port
        @param name  the name, a port's in any case; an empty name finds nothing
        @returns     the unit, or None
        """
        return self.units.get((self.inst.prefix, kind, name_key(kind, name))) if name else None

    def named(self, name: str) -> list[Unit]:
        """Return every unit of that name, of any kind, as `--keep`, `--only` and `--drop` match names

        @param name  a package name; a port's matches in any case
        @returns     the units
        """
        return [u for u in self.units.values()
                if u.name == name or (u.kind == "port" and u.name.lower() == name.lower())]

    def closure(self, start: Iterable[Key]) -> list[Key]:
        """Return `start` and everything it depends on, transitively

        @param start  the keys to start from; a key outside the graph is skipped
        @returns      the keys, breadth first
        """
        out: list[Key] = []
        seen: set[Key] = set()
        todo = list(start)
        while todo:
            key = todo.pop(0)
            if key in seen or key not in self.units:
                continue
            seen.add(key)
            out.append(key)
            todo.extend(sorted(self.deps.get(key, ())))
        return out

    def dependency_order(self, keys: Sequence[Key]) -> list[Key]:
        """Return `keys` with each after those of `keys` it needs, directly or through other units

        Keys are walked depth first in listed order; in a cycle, the member reached first follows the others.

        @param keys  the keys to order
        @returns     the same keys, dependencies first
        """
        wanted = set(keys)
        out: list[Key] = []
        seen: set[Key] = set()

        def visit(key: Key) -> None:
            if key in seen:
                return
            seen.add(key)
            for dep in sorted(self.deps.get(key, ())):
                visit(dep)
            if key in wanted:
                out.append(key)

        for key in keys:
            visit(key)
        return out


# Ties: services, data directories, interpreter extras -------------------------------------------

class Ties:
    """What makes a dependency-only package a root and keeps it out of the `--only` sweep

    That is an owned service, a data directory or interpreter extras.
    """

    def __init__(self, services: Sequence[Service], extras: dict[Key, list[str]],
                 data_dirs: Callable[[str, str], list[str]]) -> None:
        """Index the owned services by their package

        @param services   the scan's services; an owned one with a package counts
        @param extras     each interpreter package's extras as report text, as `extras_ties` gives them
        @param data_dirs  returns the data directories of a package, by prefix and name
        """
        self.services: dict[Key, list[Service]] = {}
        for svc in services:
            if svc.owned and svc.package and svc.package_kind:
                key = (svc.instance_prefix, svc.package_kind, name_key(svc.package_kind, svc.package))
                self.services.setdefault(key, []).append(svc)
        self.extras = extras
        self._data_dirs = data_dirs
        self._data: dict[Key, list[str]] = {}

    def data(self, unit: Unit) -> list[str]:
        """Return the data directories of a unit: its owned services' first, then its own

        @param unit  a source unit; a cask has only its services' directories
        @returns     the directories, each once
        """
        if unit.key not in self._data:
            dirs: list[str] = []
            for svc in self.services.get(unit.key, []):
                dirs.extend(d for d in svc.data_dirs if d not in dirs)
            if unit.kind != "cask":
                dirs.extend(d for d in self._data_dirs(unit.prefix, unit.name) if d not in dirs)
            self._data[unit.key] = dirs
        return self._data[unit.key]

    def of(self, unit: Unit) -> list[str]:
        """Return the ties of a unit as report text

        @param unit  a source unit
        @returns     a line per service, data directory and extras text; empty when it has none
        """
        out = [f"the service {s.label}" for s in self.services.get(unit.key, [])]
        out += [f"the data directory {d}" for d in self.data(unit)]
        out += [f"interpreter extras ({text})" for text in self.extras.get(unit.key, [])]
        return out


def default_data_dirs(prefix: str, name: str) -> list[str]:
    """Return the existing data directories of a package under its prefix, such as `var/<name>`

    @param prefix  the prefix of the package's instance
    @param name    the package name
    @returns       the directories
    """
    return env_services.data_dirs(prefix, name, ())


def _is_python(unit: Unit, version: str | None) -> bool:
    """Return whether a unit is a Python 3 interpreter, of the given version when there is one

    @param unit     a source unit
    @param version  a version such as `3.13`, or None for any Python 3
    @returns        True for a formula `python@3.13` or a port `python313`
    """
    if unit.kind == "formula":
        return unit.name == f"python@{version}" if version else bool(re.match(r"^python@3\.\d+$", unit.name))
    if unit.kind == "port":
        name = unit.name.lower()
        return name == f"python{version.replace('.', '')}" if version else bool(re.match(r"^python3\d+$", name))
    return False


def _owns_extras(unit: Unit, kind: str) -> bool:
    """Return whether a unit is the interpreter that npm globals, gems or CPAN modules belong to

    @param unit  a source unit
    @param kind  `npm`, `gems` or `cpan`
    @returns     True for node or npm, ruby, or perl, as the unit's manager names them
    """
    owner = _EXTRA_OWNERS.get((kind, unit.kind))
    return bool(owner and owner.match(unit.name.lower()))


def extras_ties(extras: dict[str, Any], units: dict[str, list[Unit]]) -> dict[Key, list[str]]:
    """Return each interpreter package's extras as report text

    Site-packages and pipx venvs belong to a Python; npm globals, gems and CPAN modules to node, ruby or perl.

    @param extras  the scan's interpreter extras, by kind: `python`, `pipx`, `npm`, `gems` and `cpan`
    @param units   each source's units, by prefix
    @returns       the extras texts of each interpreter unit, by key
    """
    out: dict[Key, list[str]] = {}

    def add(prefix: str | None, match: Callable[[Unit], bool], text: str) -> None:
        for unit in units.get(prefix or "", []):
            if match(unit) and text not in out.setdefault(unit.key, []):
                out[unit.key].append(text)

    for item in extras.get("python") or []:
        if not (item.get("dists") or item.get("scripts")):
            continue
        version = item.get("version")
        prefixes = [item["instance_prefix"]] if item.get("instance_prefix") else list(item.get("instances") or [])
        text = f"python {version} packages in {item.get('site_packages') or item.get('location')}"
        for prefix in prefixes:
            add(prefix, functools.partial(_is_python, version=version), text)
    for item in extras.get("pipx") or []:
        found = _PY_HOME.search(item.get("home") or "")
        add(item.get("instance_prefix"), functools.partial(_is_python, version=found.group(1) if found else None),
            f"the pipx venv {item.get('name')}")
    for kind in ("npm", "gems", "cpan"):
        counts: dict[str, int] = {}
        for item in extras.get(kind) or []:
            if item.get("instance_prefix"):
                counts[item["instance_prefix"]] = counts.get(item["instance_prefix"], 0) + 1
        for prefix, count in sorted(counts.items()):
            add(prefix, functools.partial(_owns_extras, kind=kind),
                f"{count} {kind} {'entry' if count == 1 else 'entries'}")
    return out


# Roots ---------------------------------------------------------------------------------------

NO_RECORD = "no installed-on-request record"


def root_reason(unit: Unit, *, target: Manager, cask_policy: str, only: set[Key] | None,
                ties: Ties) -> str | None:
    """Return why a unit of a source is a root; `plan` and `recommend` share this rule

    A cask that keeps data in its Caskroom is a root under every target and cask policy.

    @param unit         a source unit
    @param target       the target manager
    @param cask_policy  `keep`, `drop` or `map`
    @param only         the keys `--only` names, or None without it
    @param ties         the services, data directories and extras that make a dependency a root
    @returns            the reason, or None when the unit is no root
    """
    if only is not None and unit.key not in only:
        return None
    if unit.inactive_only:
        return None
    if unit.kind == "cask":
        if resolver.keeps_data(unit.pkg):
            return "keeps data in its Caskroom"
        if target is Manager.BREW:
            return "a cask of a Homebrew source, adopted by the target"
        return "--casks map" if cask_policy == "map" else None
    if only is not None:
        return "named in --only"
    if unit.pkg.requested:
        return "installed on request"
    found = ties.of(unit)
    if found:
        return f"owns {', '.join(found)}"
    if unit.pkg.requested is None:
        return NO_RECORD
    return None


def plain_roots(result: Any, target_prefix: str | None, target: Manager,
                cask_policy: str = "keep") -> list[tuple[Unit, str]]:
    """Return the roots of a plan with the default options

    Every instance other than the target is a source, and `root_reason` decides each of its units.

    @param result         the scan result
    @param target_prefix  the target's prefix, or None when the host has no target
    @param target         the target manager
    @param cask_policy    `keep`, `drop` or `map`
    @returns              each root with its reason
    """
    sources = [inst for inst in result.instances if inst.prefix != target_prefix]
    units = {inst.prefix: units_of(inst, result.packages) for inst in sources}
    ties = Ties(result.services, extras_ties(result.interpreter_extras, units), default_data_dirs)
    out: list[tuple[Unit, str]] = []
    for inst in sources:
        for unit in units[inst.prefix]:
            reason = root_reason(unit, target=target, cask_policy=cask_policy, only=None, ties=ties)
            if reason:
                out.append((unit, reason))
    return out


MIGRATED = "migrated"               # an accepted mapping: installed in phase 3, removed in phase 5
UNMIGRATABLE = "unmigratable"       # no accepted mapping, kept (the default answer)
DROPPED = "dropped"                 # no accepted mapping, removed without a replacement
KEPT = "kept"                       # named in --keep: never resolved, never installed
WITHDRAWN = "withdrawn"             # an accepted mapping that is not installed because the root stays


@dataclass
class Root:
    """A unit the plan migrates, keeps or drops, with its mapping once the resolver gives it one"""

    unit: Unit
    reason: str                                     # why the unit is a root
    mapping: Mapping | None = None
    status: str = ""
    note: str = ""                                  # why it is unmigratable, dropped or withdrawn

    @property
    def key(self) -> Key:
        """Return the key of the root's unit

        @returns  `(prefix, kind, name key)`
        """
        return self.unit.key


# The sets ------------------------------------------------------------------------------------

@dataclass
class Inputs:
    """What `compute` works from"""

    graphs: dict[str, SourceGraph]                  # every source instance
    target: Manager
    roots: dict[Key, Root]
    keep: set[Key]                                  # --keep
    dropped: set[Key]                               # dropped roots and dropped inactive-only ports
    root_owned: set[Key]                            # formulae with root-owned keg paths
    ties: Ties
    policy: str                                     # the cask policy of a ports target
    only: set[Key] | None = None                 # --only: the named units
    remove: set[str] = field(default_factory=set)   # instances --remove-manager names
    extra_kept: dict[Key, str] = field(default_factory=dict)   # kept for the login shell or colliding files


@dataclass
class Sets:
    """The kept and removal sets of a plan, what stays in place, and the refusals and notes they cause"""

    kept: dict[Key, str] = field(default_factory=dict)          # key -> reason
    removal: dict[str, list[Pair]] = field(default_factory=dict)
    path_removed: dict[str, list[Pair]] = field(default_factory=dict)
    left_in_place: list[Unit] = field(default_factory=list)
    manual_casks: list[Unit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    refusals: list[str] = field(default_factory=list)

    def removed_keys(self) -> set[Key]:
        """Return the keys of the removal set and of `path_removed`

        @returns  the keys; a `cask-adopted` pair gives its cask's key
        """
        out: set[Key] = set()
        for prefix, pairs in list(self.removal.items()) + list(self.path_removed.items()):
            for kind, name in pairs:
                real = "cask" if kind == "cask-adopted" else kind
                out.add((prefix, real, name_key(real, name)))
        return out


def _sorted_pairs(pairs: Iterable[Pair]) -> list[Pair]:
    """Return removal pairs once each, by kind, then name in any case

    @param pairs  `(kind, name)` pairs
    @returns      the sorted pairs
    """
    return sorted(set(pairs), key=lambda p: (KIND_ORDER.get(p[0], 9), p[1].lower(), p[1]))


class _Builder:
    """One computation of the sets from their inputs"""

    def __init__(self, inp: Inputs) -> None:
        """Start from empty sets, with every unit of every source by key

        @param inp  what the sets are computed from
        """
        self.inp = inp
        self.out = Sets()
        self.units: dict[Key, Unit] = {k: u for g in inp.graphs.values() for k, u in g.units.items()}

    # Scope ------------------------------------------------------------------------------

    def in_scope(self, unit: Unit) -> bool:
        """Return whether a unit is in scope: every unit, or under `--only` the named ones

        So under `--only` the cask policy covers only the named casks.

        @param unit  a source unit
        @returns     True without `--only`, else for a unit it names
        """
        return self.inp.only is None or unit.key in self.inp.only

    def adopted(self, unit: Unit) -> bool:
        """Return whether the target adopts a unit: a migrated root whose mapping adopts its cask

        @param unit  a source unit
        @returns     True for an adopted cask
        """
        root = self.inp.roots.get(unit.key)
        return bool(root and root.status == MIGRATED and root.mapping is not None and root.mapping.adopt)

    def cask_of_homebrew_for_ports(self, unit: Unit) -> bool:
        """Return whether a unit is a Homebrew cask under a MacPorts target, which the cask policy decides

        @param unit  a source unit
        @returns     True for a cask when the target is MacPorts
        """
        return unit.kind == "cask" and self.inp.target is Manager.PORTS

    # Kept -----------------------------------------------------------------------------

    def seeds(self) -> list[tuple[Key, str, str]]:
        """Return the packages the kept set starts from, each with its reason and how much of its closure stays

        @returns  `(key, reason, FULL or FORMULAE)` triples
        """
        out: list[tuple[Key, str, str]] = [(k, "--keep", FULL) for k in sorted(self.inp.keep)]
        for key, reason in sorted(self.inp.extra_kept.items()):
            out.append((key, reason, FULL))
        for key, root in sorted(self.inp.roots.items()):
            if root.status in (UNMIGRATABLE, WITHDRAWN) and key not in self.inp.extra_kept:
                out.append((key, f"unmigratable: {root.note}" if root.status == UNMIGRATABLE else root.note, FULL))
        for unit in sorted(self.units.values(), key=lambda u: u.key):
            if not self.in_scope(unit):
                continue
            if unit.inactive_only and unit.key not in self.inp.dropped:
                out.append((unit.key, "inactive in the source", FULL))
            if unit.key in self.inp.root_owned:
                out.append((unit.key, "root-owned keg paths (brew-root-owned-keg)", FULL))
            if (self.cask_of_homebrew_for_ports(unit) and self.inp.policy == "keep"
                    and unit.key not in self.inp.roots):
                out.append((unit.key, "--casks keep", FORMULAE))
        return out

    def keep(self, seeds: Sequence[tuple[Key, str, str]]) -> dict[Key, str]:
        """Return the kept set: the seeds and their dependency closures, each package with its reason

        @param seeds  `(key, reason, FULL or FORMULAE)` triples, as `seeds` gives them
        @returns      each kept key with the first reason that keeps it
        """
        kept: dict[Key, str] = {}
        for key, reason, closure in seeds:
            graph = self.inp.graphs.get(key[0])
            if graph is None or key not in graph.units:
                continue
            kept.setdefault(key, reason)
            unit = graph.units[key]
            if closure == FULL:
                start = sorted(graph.deps.get(key, ()))
                why = f"needed by {unit.name}"
            else:
                start = sorted(k for k in graph.deps.get(key, ()) if k[1] == "formula")
                why = f"retained for the cask {unit.name}"
            for member in graph.closure(start):
                kept.setdefault(member, why)
        return kept

    # Removal --------------------------------------------------------------------------

    def candidate_pair(self, unit: Unit, kept: dict[Key, str]) -> tuple[Pair | None, bool]:
        """Return the removal pair of a unit in scope, and whether only a manual uninstall removes it

        @param unit  a source unit in scope
        @param kept  the kept set
        @returns     the pair, or None when the unit stays; True for a manual cask
        """
        if unit.key in kept:
            return None, False
        if unit.kind != "cask":
            return unit.pair(), False
        if self.cask_of_homebrew_for_ports(unit) and self.inp.policy == "keep" and unit.key not in self.inp.roots:
            return None, False
        if self.adopted(unit):
            return unit.pair(adopted=True), False
        if unit.pkg.privileged_uninstall and unit.inst.drivable:
            return None, True
        return unit.pair(), False

    def removal(self, kept: dict[Key, str]) -> tuple[dict[str, set[Pair]], list[Unit]]:
        """Return the pairs each drivable source uninstalls, and the casks only a manual uninstall removes

        @param kept  the kept set
        @returns     the pairs by prefix, and the manual casks
        """
        removal: dict[str, set[Pair]] = {}
        manual: list[Unit] = []
        for prefix, graph in sorted(self.inp.graphs.items()):
            if not graph.inst.drivable:
                continue
            for unit in graph.units.values():
                if not self.in_scope(unit) or unit.inactive_only and unit.key not in self.inp.dropped:
                    continue
                pair, is_manual = self.candidate_pair(unit, kept)
                if is_manual:
                    manual.append(unit)
                elif pair is not None:
                    removal.setdefault(prefix, set()).add(pair)
        return removal, manual

    def sweep(self, removal: dict[str, set[Pair]], kept: dict[Key, str]) -> None:
        """Add to an `--only` removal set the dependencies that only the set needs

        A swept dependency is unrequested, not kept, and owns no service, data directory or interpreter extras.

        @param removal  the pairs by prefix, extended in place
        @param kept     the kept set
        """
        for prefix, graph in sorted(self.inp.graphs.items()):
            if prefix not in removal:
                continue
            members = {self._key(prefix, p) for p in removal[prefix]}
            left: dict[Key, str | None] = {}
            changed = True
            while changed:
                changed = False
                for key in graph.closure(sorted(members)):
                    if key in members:
                        continue
                    unit = graph.units[key]
                    blocked, why = self.unsweepable(unit, kept)
                    if blocked:
                        left[key] = why
                    elif graph.dependents.get(key, set()) <= members:
                        members.add(key)
                        removal[prefix].add(unit.pair())
                        changed = True
            for key, why in sorted(left.items()):
                if why:
                    self.out.notes.append(f"left installed: {graph.units[key].label()}: {why}")

    def unsweepable(self, unit: Unit, kept: dict[Key, str]) -> tuple[bool, str | None]:
        """Return whether the sweep must leave a dependency, and the reason the report gives

        Only tied packages and those not recorded as dependencies get a reason; the others are reported elsewhere.

        @param unit  a dependency of the removal set
        @param kept  the kept set
        @returns     True when it stays, with the reason or None
        """
        if unit.key in kept or unit.inactive_only or unit.key in self.inp.root_owned:
            return True, None
        if unit.pkg.requested is not False:
            return True, "installed on request" if unit.pkg.requested else "no installed-on-request record"
        if unit.kind == "cask" and (self.inp.target is Manager.BREW or self.inp.policy == "keep"
                                    or unit.pkg.privileged_uninstall):
            return True, None
        ties = self.inp.ties.of(unit)
        if ties:
            return True, f"owns {', '.join(ties)}"
        return False, None

    @staticmethod
    def _key(prefix: str, pair: Pair) -> Key:
        """Return the key of a removal pair; a `cask-adopted` pair gives its cask's key

        @param prefix  the source's prefix
        @param pair    `(kind, name)` as the removal set lists it
        @returns       `(prefix, kind, name key)`
        """
        kind = "cask" if pair[0] == "cask-adopted" else pair[0]
        return (prefix, kind, name_key(kind, pair[1]))

    # The run ----------------------------------------------------------------------------

    def run(self) -> Sets:
        """Compute the kept and removal sets, then what stays in place and the refusals

        @returns  the sets
        """
        seeds = self.seeds()
        kept = self.keep(seeds)
        removal, manual = self.removal(kept)
        if manual:
            seeds += [(u.key, "a manual cask", FORMULAE) for u in manual]
            kept = self.keep(seeds)
            for unit in manual:
                kept.pop(unit.key, None)
            removal, manual = self.removal(kept)
        if self.inp.only is not None:
            self.sweep(removal, kept)
        self.out.kept = kept
        self.out.manual_casks = manual
        self.out.removal = {prefix: _sorted_pairs(pairs) for prefix, pairs in sorted(removal.items()) if pairs}
        self.undrivable(kept)
        self.yielded(kept)
        self.dependents_check()
        self.remove_manager_check()
        return self.out

    def undrivable(self, kept: dict[Key, str]) -> None:
        """Uninstall nothing through an undrivable source

        Its packages are `path_removed` when `--remove-manager` names it, else left in place (exit 1 in a full
        migration).

        @param kept  the kept set, whose packages are never `path_removed`
        """
        for prefix, graph in sorted(self.inp.graphs.items()):
            inst = graph.inst
            if inst.drivable:
                continue
            units = sorted(graph.units.values(), key=lambda u: (KIND_ORDER.get(u.kind, 9), u.name.lower()))
            if prefix in self.inp.remove:
                self.out.path_removed[prefix] = _sorted_pairs(u.pair(self.adopted(u)) for u in units
                                                              if u.key not in kept)
                continue
            self.out.left_in_place.extend(units)
            if self.inp.only is not None:
                continue
            if not inst.inventory_known:
                self.out.refusals.append(
                    f"{prefix} cannot be driven ({inst.usability.value}) and its packages are unknown "
                    "(ports-damaged-registry): a full migration must name it in --remove-manager, which that finding "
                    "blocks; plan with --only instead")
            elif units:
                self.out.refusals.append(
                    f"{prefix} cannot be driven ({inst.usability.value}), so it uninstalls nothing: name it in "
                    "--remove-manager (phase 6 deletes it by path) or plan with --only; these would stay in place: "
                    f"{', '.join(u.name for u in units)}")

    def yielded(self, kept: dict[Key, str]) -> None:
        """Note every dropped root that stays because a kept package needs it

        @param kept  the kept set
        """
        for key in sorted(self.inp.dropped):
            if key in kept:
                unit = self.units[key]
                self.out.notes.append(f"{unit.label()} stays although dropped: {kept[key]}")

    def dependents_check(self) -> None:
        """Refuse the plan when a removed package has a dependent outside the removal set

        Both managers refuse such an uninstall, and the tool never bypasses their checks.
        """
        manual = {u.key for u in self.out.manual_casks}
        for prefix, pairs in sorted(self.out.removal.items()):
            graph = self.inp.graphs[prefix]
            members = {self._key(prefix, p) for p in pairs}
            for kind, name in pairs:
                if kind == "cask-adopted":
                    continue
                key = self._key(prefix, (kind, name))
                outside = sorted(d for d in graph.dependents.get(key, ()) if d not in members)
                for dep in outside:
                    unit = graph.units[dep]
                    if dep in manual:
                        why = "a manual cask"
                    elif dep in self.out.kept:
                        why = f"kept: {self.out.kept[dep]}"
                    else:
                        why = "outside --only" if self.inp.only is not None else "not removed"
                    hint = (f": name it in --only too, or leave {name} out" if self.inp.only is not None
                            and dep not in manual and dep not in self.out.kept else "")
                    self.out.refusals.append(f"{kind} {name} ({prefix}) is needed by {unit.kind} {unit.name} "
                                             f"({why}){hint}")

    def remove_manager_check(self) -> None:
        """Refuse every instance `--remove-manager` names that keeps packages or has manual casks"""
        for prefix in sorted(self.inp.remove):
            kept = sorted(self.units[k].name for k in self.out.kept if k[0] == prefix)
            if kept:
                self.out.refusals.append(f"--remove-manager {prefix}: it keeps packages: {', '.join(kept)}")
            manual = [u for u in self.out.manual_casks if u.prefix == prefix]
            if manual:
                lines = "; ".join(f"{u.inst.binary or prefix + '/bin/brew'} uninstall --cask {u.name}"
                                  for u in manual)
                self.out.refusals.append(f"--remove-manager {prefix}: it has manual casks; run these on a terminal "
                                         f"first, then plan again: {lines}")


def compute(inp: Inputs) -> Sets:
    """Return the kept and removal sets of a plan, with the refusals they cause

    @param inp  the source graphs, the roots and the options the sets follow
    @returns    the sets
    """
    return _Builder(inp).run()


# The login shell and files outside the prefix ---------------------------------------------------

def package_at(graph: SourceGraph, path: str, realpath: str | None = None,
               owner_of: Callable[[str], str | None] | None = None) -> Unit | None:
    """Return the unit that provides `path`

    A Homebrew path names it in its Cellar or `opt` component and a MacPorts path through the registry;
    otherwise it is the only unit with an executable of that basename.

    @param graph     the source's graph
    @param path      an executable, as a login shell or a launchd job names it
    @param realpath  the path with its links resolved; None resolves it here
    @param owner_of  returns the port that registered a path, or None; without it the registry is not asked
    @returns         the unit, or None
    """
    inst = graph.inst
    paths = [p for p in (path, realpath or os.path.realpath(path)) if p]
    if inst.manager is Manager.BREW:
        bases = list(inst.spellings) + [inst.prefix]
        roots = [os.path.join(b, sub) for b in bases for sub in ("Cellar", "opt")]
        roots.append(os.path.realpath(os.path.join(inst.prefix, "Cellar")))
        for p in paths:
            for root in roots:
                root = root.rstrip("/") + "/"
                if p.startswith(root):
                    unit = graph.find("formula", p[len(root):].split("/", 1)[0])
                    if unit is not None:
                        return unit
    elif owner_of is not None:
        for p in paths:
            owner = owner_of(p)
            unit = graph.find("port", owner) if owner else None
            if unit is not None:
                return unit
    base = os.path.basename(path)
    found = [u for u in graph.units.values() if u.kind != "cask" and base in u.pkg.executables]
    return found[0] if len(found) == 1 else None


def installs_basename(mapping: Mapping | None, basename: str, target: Manager,
                      executables: Callable[[str], list[str]]) -> bool:
    """Return whether the mapping's target installs an executable of that basename

    A MacPorts target has no executable index, so there the port's name must be the basename.

    @param mapping      a root's accepted mapping, or None
    @param basename     an executable's basename, such as `bash`
    @param target       the target manager
    @param executables  returns a formula's executables from the target's catalogue
    @returns            True when the mapped formula or port installs it; False without such a mapping
    """
    if mapping is None or not mapping.target_name or mapping.target_kind not in ("formula", "port"):
        return False
    if target is Manager.PORTS:
        return mapping.target_name.lower() == basename.lower()
    wanted = rules.exe_aliases(basename)
    return any(rules.exe_aliases(exe) & wanted for exe in executables(mapping.target_name))


def login_shell_key(environment: dict[str, Any], graphs: dict[str, SourceGraph], sets: Sets,
                    owner_of: Callable[[str], str | None] | None = None) -> tuple[Key, str] | None:
    """Return the key of the login shell's unit and the shell's basename when the plan removes it

    @param environment  the scan's environment: `login_shell`, `login_shell_prefix`, `login_shell_realpath`
    @param graphs       each source's graph, by prefix
    @param sets         the sets computed so far
    @param owner_of     returns the port that registered a path, or None
    @returns            `(key, basename)`, or None when the plan keeps the shell or no source unit provides it
    """
    shell = environment.get("login_shell")
    prefix = environment.get("login_shell_prefix")
    graph = graphs.get(prefix or "")
    if not shell or graph is None:
        return None
    unit = package_at(graph, shell, environment.get("login_shell_realpath"), owner_of)
    if unit is None or unit.key not in sets.removed_keys():
        return None
    return unit.key, os.path.basename(shell)


def _under(path: str, inst_or_dir: Any) -> bool:
    """Return whether a path is or lies under an instance's prefix, in any of its spellings, or a directory

    @param path         a registered file's path
    @param inst_or_dir  an instance, compared with its volume's case rule, or a directory, compared as written
    @returns            True when the path is or lies under it
    """
    if isinstance(inst_or_dir, Instance):
        spellings = list(inst_or_dir.spellings) + [inst_or_dir.prefix]
        fold = env.fold_case_for(inst_or_dir)
    else:
        spellings, fold = [inst_or_dir], False
    return system.text_names_prefix(path, spellings, fold)


def colliding_files(source: Instance, target: Instance, files: Sequence[str]) -> list[str]:
    """Return the registered files of a source port that the target port would install as well

    Those lie outside the source prefix, less its own `applications_dir` when the target uses another.

    @param source  the source MacPorts instance
    @param target  the target MacPorts instance
    @param files   the source port's active registered files
    @returns       the colliding files, each once
    """
    own_apps = source.applications_dir
    target_apps = target.applications_dir
    shared = bool(own_apps and target_apps and (system.same_path(own_apps, target_apps)
                                                or os.path.normpath(own_apps) == os.path.normpath(target_apps)))
    out = []
    for path in files:
        if _under(path, source):
            continue
        if own_apps and _under(path, own_apps) and not shared:
            continue
        if path not in out:
            out.append(path)
    return out

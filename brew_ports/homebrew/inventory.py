"""The Homebrew inventory of one instance

A walk of the prefix on disk, plus the `brew` inventory probes when the instance is drivable.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .. import model, progress, system
from ..report import table
from ..state import slug
from . import actions, locate
from .catalogue import (Artifact, Catalogue, PrivilegeContext, artifact_targets, cask_dirs, depends_lists,
                        dirs_from_config, normalise_artifacts, privileged_flags, version_key)

GIT = system.GIT
LAUNCHCTL = system.LAUNCHCTL
RECEIPT = "INSTALL_RECEIPT.json"
ROOT_OWNED_LIMIT = 50   # root-owned paths kept per formula as evidence


@dataclass
class RenameLink:
    """A Cellar or Caskroom symlink that a rename left under the old name"""
    name: str                 # the old name the link carries
    path: str                 # <prefix>/Cellar/<old> or <prefix>/Caskroom/<old>
    target: str               # the link's text
    resolved: str | None   # its realpath, None when the target is gone


@dataclass
class Tap:
    """A tap checkout under `Library/Taps`, with its `git status` when it has its own `.git`"""
    name: str                 # user/repo
    path: str
    has_git: bool             # only a tap with its own .git is probed
    dirty: bool | None     # None when not probed or when the probe failed
    status: str = ""          # `git status --porcelain` output
    error: str | None = None


@dataclass
class HomebrewInventory:
    """The inventory of one Homebrew instance: its packages, taps, kegs and the disk facts the findings read"""
    instance_prefix: str
    packages: list[model.Package] = field(default_factory=list)
    taps: list[Tap] = field(default_factory=list)
    cellar_renames: list[RenameLink] = field(default_factory=list)    # never a Package, never named in a command
    caskroom_renames: list[RenameLink] = field(default_factory=list)  # never a Package
    kegs: dict[str, list[str]] = field(default_factory=dict)          # formula -> keg directories, newest last
    caskrooms: dict[str, str] = field(default_factory=dict)           # cask -> its Caskroom entry
    cask_versions: dict[str, list[str]] = field(default_factory=dict)  # token -> version directories, newest last
    receiptless_kegs: list[str] = field(default_factory=list)         # kegs without INSTALL_RECEIPT.json
    broken_opt_links: list[tuple[str, str]] = field(default_factory=list)  # (link, target)
    pinned: list[str] = field(default_factory=list)                   # var/homebrew/pinned
    brew_env: list[locate.EnvLine] = field(default_factory=list)      # what bin/brew exports, in order
    root_owned: dict[str, list[str]] = field(default_factory=dict)    # formula -> uid 0 paths under its kegs
    missing: dict[str, list[str]] = field(default_factory=dict)       # brew missing; "" for the one-package form
    outdated_formulae: dict[str, str] = field(default_factory=dict)   # brew outdated: name -> current version
    outdated_casks: dict[str, str] = field(default_factory=dict)
    used_json: bool = False                                           # packages come from brew info
    inventory_error: str | None = None                             # the failures of the brew probes

    def to_plain(self) -> dict[str, Any]:
        """Return the inventory as plain JSON data

        @returns  the fields, as `model.to_plain` writes them
        """
        return model.to_plain(self)

    @classmethod
    def from_plain(cls, data: dict[str, Any]) -> "HomebrewInventory":
        """Rebuild an inventory from the data `to_plain` returns

        @param data  the plain data
        @returns     the inventory
        """
        return model.from_dict(cls, data)

    def racks(self) -> dict[str, str]:
        """Return the rack each formula's kegs sit in

        `brew info` names a rack that a formula rename left under the old name by the formula's new name.

        @returns  the rack's name by formula name; a formula without a keg is left out
        """
        return {name: os.path.basename(os.path.dirname(kegs[0])) for name, kegs in self.kegs.items() if kegs}

    def rooms(self) -> dict[str, str]:
        """Return the Caskroom entry each cask sits in

        `brew info` names an entry that a cask rename left under the old token by the cask's new token.

        @returns  the entry's name by cask token; a cask without an entry is left out
        """
        return {token: os.path.basename(path) for token, path in self.caskrooms.items()}


# Disk helpers ------------------------------------------------------------------

def _entries(directory: str) -> list[str]:
    """Return the names in a directory, sorted

    @param directory  the directory to list
    @returns          the names; empty when it cannot be listed
    """
    try:
        return sorted(os.listdir(directory))
    except OSError:
        return []


def read_json(path: str) -> dict[str, Any] | None:
    """Read a receipt or `config.json`; None when it is absent, unreadable or not an object

    @param path  the JSON file
    @returns     the decoded object, or None
    """
    try:
        with open(path, "rb") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def short_name(name: Any) -> str:
    """Return the short name of `user/tap/foo`, which Cellar racks and Caskroom directories carry

    @param name  a formula or cask name, tap-qualified or not
    @returns     the part after the last slash
    """
    return str(name).rsplit("/", 1)[-1]


def receipt_dependencies(receipt: dict[str, Any] | None, kind: str = "formula") -> list[str]:
    """Return the short names of a receipt's runtime dependencies

    A cask receipt keeps one list per kind; a keg receipt keeps one list.

    @param receipt  a keg or cask INSTALL_RECEIPT.json, or None
    @param kind     the list a cask receipt keeps: formula or cask
    @returns        the names; empty when the receipt lists none
    """
    deps = (receipt or {}).get("runtime_dependencies")
    if isinstance(deps, dict):
        deps = deps.get(kind)
    if not isinstance(deps, list):
        return []
    return [short_name(d["full_name"]) for d in deps if isinstance(d, dict) and d.get("full_name")]


def rename_link(name: str, path: str) -> RenameLink:
    """Record a rename symlink with its text and, while its target exists, its realpath

    @param name  the old name the link carries
    @param path  the link
    @returns     the record; an unreadable link has an empty target
    """
    try:
        target = os.readlink(path)
    except OSError:
        target = ""
    return RenameLink(name=name, path=path, target=target,
                      resolved=os.path.realpath(path) if os.path.exists(path) else None)


def broken_links(directory: str) -> list[tuple[str, str]]:
    """Return the symlinks of `directory` whose target is missing, such as `opt/<f>` after a lost keg

    @param directory  the directory to scan, such as `<prefix>/opt`
    @returns          `(link, target)` pairs, the target as the link's text
    """
    out = []
    for name in _entries(directory):
        path = os.path.join(directory, name)
        if os.path.islink(path) and not os.path.exists(path):
            out.append((path, rename_link(name, path).target))
    return out


def root_owned_paths(tops: Sequence[str], limit: int = ROOT_OWNED_LIMIT) -> list[str]:
    """Return the paths with `st_uid` 0 at or below `tops`, symlinks not followed

    They are what `sudo brew services start` leaves under a keg.

    @param tops   the kegs and `opt` links to scan
    @param limit  the count at which the walk stops
    @returns      the root-owned paths, in walk order
    """
    found: list[str] = []
    for top in tops:
        try:
            st = os.lstat(top)
        except OSError:
            continue
        if st.st_uid == 0:
            found.append(top)
        if not stat.S_ISDIR(st.st_mode):
            continue
        for dirpath, dirnames, filenames in os.walk(top):
            progress.count(len(dirnames) + len(filenames))
            for name in dirnames + filenames:
                path = os.path.join(dirpath, name)
                try:
                    if os.lstat(path).st_uid == 0:
                        found.append(path)
                except OSError:
                    continue
                if len(found) >= limit:
                    return found
    return found


def _listing(directory: str) -> list[str]:
    """Return the non-directory entries of a keg's `bin` or `sbin`

    @param directory  the keg's `bin` or `sbin`
    @returns          the entry names, sorted; empty when the directory cannot be listed
    """
    return [n for n in _entries(directory) if not os.path.isdir(os.path.join(directory, n))]


# Cellar -----------------------------------------------------------------------------

@dataclass
class Keg:
    """One installed version directory of a rack"""
    version: str
    path: str
    receipt: dict[str, Any] | None   # INSTALL_RECEIPT.json, None when absent or unreadable


@dataclass
class Rack:
    """One formula's directory under `<prefix>/Cellar`, with its kegs"""
    name: str
    path: str
    kegs: list[Keg]                     # oldest first


def walk_cellar(prefix: str) -> tuple[dict[str, Rack], list[RenameLink]]:
    """Walk `<prefix>/Cellar/*/*` into racks, and the symlinked racks the rename migrator left

    A symlinked rack is never a rack: `brew uninstall --force <old>` would follow it and delete the renamed
    formula's kegs.

    @param prefix  the Homebrew prefix
    @returns       the racks by name, and the rename links
    """
    cellar = os.path.join(prefix, "Cellar")
    racks: dict[str, Rack] = {}
    links: list[RenameLink] = []
    for name in _entries(cellar):
        path = os.path.join(cellar, name)
        if name.startswith("."):
            continue
        if os.path.islink(path):
            links.append(rename_link(name, path))
            continue
        if not os.path.isdir(path):
            continue
        kegs = []
        for version in _entries(path):
            keg = os.path.join(path, version)
            if version.startswith(".") or os.path.islink(keg) or not os.path.isdir(keg):
                continue
            kegs.append(Keg(version=version, path=keg, receipt=read_json(os.path.join(keg, RECEIPT))))
        if kegs:
            kegs.sort(key=lambda k: version_key(k.version))
            racks[name] = Rack(name=name, path=path, kegs=kegs)
    return racks, links


def _keg_at(link: str, kegs: Sequence[Keg]) -> Keg | None:
    """Return the keg a link such as `opt/<f>` resolves to

    @param link  the link
    @param kegs  the rack's kegs
    @returns     the keg, or None when the link is not a symlink to one of them
    """
    if not os.path.islink(link) or not os.path.isdir(link):
        return None
    real = os.path.realpath(link)
    for keg in kegs:
        if os.path.realpath(keg.path) == real:
            return keg
    return None


@dataclass
class KegChoice:
    """A rack's current keg and the receipt Homebrew reads for the formula"""
    current: Keg | None     # the opt keg, else the linked keg, else the newest
    receipt: dict[str, Any] | None
    linked: bool               # var/homebrew/linked/<f> names an installed keg
    newest: Keg | None


def choose_kegs(prefix: str, names: Sequence[str], rack: Rack) -> KegChoice:
    """Choose a rack's current keg, and the receipt Homebrew's `Tab.for_formula` reads

    The receipt is that of the first among the `opt` keg, the linked keg, the only keg and the newest keg
    that holds a readable one.

    @param prefix  the Homebrew prefix
    @param names   the formula's names, its rack's among them, for the `opt` and `linked` links
    @param rack    the formula's rack
    @returns       the choice
    """
    kegs = rack.kegs
    opt = next((k for k in (_keg_at(os.path.join(prefix, "opt", n), kegs) for n in names) if k), None)
    linked = next((k for k in (_keg_at(os.path.join(prefix, "var", "homebrew", "linked", n), kegs)
                               for n in names) if k), None)
    newest = kegs[-1] if kegs else None
    order = [opt, linked, kegs[0] if len(kegs) == 1 else None, newest]
    with_receipt = next((k for k in order if k is not None and k.receipt is not None), None)
    return KegChoice(current=opt or linked or newest, receipt=with_receipt.receipt if with_receipt else None,
                     linked=linked is not None, newest=newest)


# Caskroom ---------------------------------------------------------------------

@dataclass
class Room:
    """One cask's directory under `<prefix>/Caskroom`: its versions, data and metadata"""
    token: str
    path: str
    versions: list[str]                 # version directories, newest last
    data: list[str]                     # caskroom_data
    receipt: dict[str, Any] | None   # .metadata/INSTALL_RECEIPT.json
    config: dict[str, Any] | None    # .metadata/config.json


def _install_stamp(meta: str, version: str) -> str:
    """Return the newest install timestamp that `.metadata/<version>` holds

    @param meta     the cask's `.metadata` directory
    @param version  a version directory's name
    @returns        the greatest timestamp entry, or an empty string
    """
    stamps = [s for s in _entries(os.path.join(meta, version)) if not s.startswith(".")]
    return max(stamps) if stamps else ""


def walk_caskroom(prefix: str) -> tuple[dict[str, Room], list[RenameLink]]:
    """Walk `<prefix>/Caskroom/*` into rooms, and the symlinked tokens a cask rename left

    Version directories are the entries `.metadata/` also holds, in install order; any other entry is data the
    cask keeps.

    @param prefix  the Homebrew prefix
    @returns       the rooms by token, and the rename links
    """
    room_dir = os.path.join(prefix, "Caskroom")
    rooms: dict[str, Room] = {}
    links: list[RenameLink] = []
    for token in _entries(room_dir):
        path = os.path.join(room_dir, token)
        if token.startswith("."):
            continue
        if os.path.islink(path):
            links.append(rename_link(token, path))
            continue
        if not os.path.isdir(path):
            continue
        meta = os.path.join(path, ".metadata")
        versions, data = [], []
        for entry in _entries(path):
            # Finder's .DS_Store and AppleDouble ._* files are not data a cask keeps.
            if entry in (".metadata", ".DS_Store") or entry.startswith("._"):
                continue
            if os.path.isdir(os.path.join(meta, entry)):
                versions.append(entry)
            else:
                data.append(os.path.join(path, entry))
        order = {v: (_install_stamp(meta, v), version_key(v)) for v in versions}
        versions.sort(key=order.__getitem__)
        rooms[token] = Room(token=token, path=path, versions=versions, data=data,
                            receipt=read_json(os.path.join(meta, RECEIPT)),
                            config=read_json(os.path.join(meta, "config.json")))
    return rooms, links


# Probes --------------------------------------------------------------------------

def git_status_probe(directory: str, action_id: str) -> model.Action:
    """Probe `git status --porcelain` without taking a lock, refreshing the index or starting an fsmonitor daemon

    @param directory  the Homebrew repository or a tap checkout
    @param action_id  the probe's action id, such as `0.brew.<subject>.tap.<tap>`
    @returns          the action
    """
    return system.probe(action_id, [GIT, "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", directory,
                                    "status", "--porcelain"], f"local changes in {directory}")


def parse_deps(text: str) -> dict[str, list[str]]:
    """Parse the `<name>: <dep ...>` lines of `brew deps --formula --installed --for-each`, short names

    @param text  the probe's output
    @returns     each formula's dependencies, by short name
    """
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        name, sep, rest = line.strip().partition(":")
        if not sep or not name:
            continue
        deps = out.setdefault(short_name(name), [])
        for dep in rest.split():
            if not dep.startswith(":") and short_name(dep) not in deps:
                deps.append(short_name(dep))
    return out


def parse_missing(text: str) -> dict[str, list[str]]:
    """Parse `brew missing`: `<f>: <dep ...>` per package, or a bare `<dep ...>` for a single package

    @param text  the probe's output
    @returns     the missing dependencies by package, under the key "" for the one-package form
    """
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        name, sep, rest = line.partition(": ")
        key, deps = (short_name(name), rest.split()) if sep else ("", line.split())
        bucket = out.setdefault(key, [])
        bucket.extend(d for d in deps if d not in bucket)
    return out


def parse_outdated(data: Any) -> tuple[dict[str, str], dict[str, str]]:
    """Parse `brew outdated --json=v2` into name -> current version, for formulae and for casks

    @param data  the decoded JSON
    @returns     the outdated formulae and the outdated casks, each by short name
    """
    def versions(items: Any) -> dict[str, str]:
        out = {}
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict) and item.get("name"):
                out[short_name(item["name"])] = str(item.get("current_version") or "")
        return out
    data = data if isinstance(data, dict) else {}
    return versions(data.get("formulae")), versions(data.get("casks"))


class _Probes:
    """The four inventory probes of a drivable instance, with their failures"""

    def __init__(self, runner, instance: model.Instance) -> None:
        """Prepare the probes of one instance

        @param runner    the runner the probes go through
        @param instance  the drivable Homebrew instance
        """
        self.runner = runner
        self.instance = instance
        self.subject = f"0.brew.{slug(instance.prefix)}"
        self.errors: list[str] = []

    def _run(self, build: Callable[..., model.Action], step: str):
        """Run one of the instance's probes

        @param build  the `actions` builder of the probe
        @param step   the last part of the action id, `0.brew.<subject>.<step>`
        @returns      the probe's result
        """
        return self.runner.run(build(self.instance, self.runner.host_arch, f"{self.subject}.{step}"))

    def text_of(self, build: Callable[..., model.Action], step: str, what: str) -> str | None:
        """Return a probe's stdout; None, with the failure recorded, when it fails

        @param build  the `actions` builder of the probe
        @param step   the last part of the action id
        @param what   the probe, as the failure text names it
        @returns      the output, or None
        """
        res = self._run(build, step)
        if res.exit != 0 or res.timed_out:
            self.errors.append(locate.failure_text(res, what))
            return None
        return res.stdout()

    def json_of(self, build: Callable[..., model.Action], step: str, what: str, kind: type = object) -> Any:
        """Return a probe's JSON output of type `kind`; None, with the failure recorded, otherwise

        @param build  the `actions` builder of the probe
        @param step   the last part of the action id
        @param what   the probe, as the failure text names it
        @param kind   the type the decoded output must have
        @returns      the decoded output, or None
        """
        text = self.text_of(build, step, what)
        if text is None:
            return None
        try:
            data = json.loads(text)
        except ValueError as exc:
            self.errors.append(f"{what} printed no JSON: {exc}")
            return None
        if not isinstance(data, kind):
            self.errors.append(f"{what} printed no JSON object")
            return None
        return data

    def missing(self) -> dict[str, list[str]]:
        """Probe `brew missing`, whose normal report is exit 1 with report lines on stdout

        @returns  the missing dependencies by package; empty, with the failure recorded, when the probe fails
        """
        res = self._run(actions.missing, "missing")
        report = res.stdout().strip()
        normal = res.exit == 0 or (res.exit == 1 and report and "Error:" not in res.stderr())
        if normal and not res.timed_out:
            return parse_missing(report)
        self.errors.append(locate.failure_text(res, "brew missing"))
        return {}


# Packages ---------------------------------------------------------------------------

def _bool_or_none(value: Any) -> bool | None:
    """Return a receipt flag that is a real boolean, else None

    @param value  the receipt's value
    @returns      the boolean, or None for anything else
    """
    return value if isinstance(value, bool) else None


def _receipt_facts(receipt: dict[str, Any] | None) -> dict[str, Any]:
    """Return the facts a package takes from its receipt

    They come from `installed_on_request` (None when absent), `poured_from_bottle`, `built_on`, `arch`,
    `source.tap` and the `runtime_dependencies`.

    @param receipt  a keg or cask receipt, or None
    @returns        the facts by key: `requested`, `built_locally`, `built_on_os`, `archs`, `tap` and `deps`
    """
    receipt = receipt or {}
    source = receipt.get("source")
    source = source if isinstance(source, dict) else {}
    built_on = receipt.get("built_on")
    built_on = built_on if isinstance(built_on, dict) else {}
    poured = _bool_or_none(receipt.get("poured_from_bottle"))
    deps = receipt.get("runtime_dependencies")
    names: list[str] | None = None
    if isinstance(deps, list):
        names = [short_name(d["full_name"]) for d in deps if isinstance(d, dict) and d.get("full_name")]
    arch = receipt.get("arch")
    return {"requested": _bool_or_none(receipt.get("installed_on_request")),
            "built_locally": None if poured is None else not poured,
            "built_on_os": built_on.get("os_version") if isinstance(built_on.get("os_version"), str) else None,
            "archs": [arch] if isinstance(arch, str) and arch else [],
            "tap": source.get("tap") if isinstance(source.get("tap"), str) else None,
            "deps": names}


def _blank_package(prefix: str, kind: str, name: str, version: str) -> model.Package:
    """Return a package with every fact at its empty value, for the inventory to fill

    @param prefix   the Homebrew prefix
    @param kind     `formula` or `cask`
    @param name     the formula name or cask token
    @param version  the installed version, or an empty string
    @returns        the package
    """
    return model.Package(
        instance_prefix=prefix, kind=kind, name=name, version=version, epoch=0, spec_args=[name], requested=None,
        requested_variants=[], active=False, linked=None, keg_only=False, pinned=False, outdated=False,
        deprecated=False, disabled=False, catalogue_present=False, renamed_to=None, origin="", homepage=None,
        description=None, deps=[], cask_deps=[], dependents=[], executables=[], privileged_install=False,
        privileged_uninstall=False, auto_updates=False, caskroom_data=[], built_locally=None, built_on_os=None,
        archs=[], services=[], select_groups=[], receipt_ok=False)


def _union(first: Sequence[str], second: Sequence[str]) -> list[str]:
    """Return `first` followed by the names of `second` that it lacks

    @param first   names, in their order
    @param second  names to add
    @returns       the merged list
    """
    out = list(first)
    out.extend(d for d in second if d not in out)
    return out


@dataclass
class _Context:
    """What building the packages of one instance needs to know"""
    prefix: str
    catalogue: Catalogue
    pinned: set[str]
    deps_lines: dict[str, list[str]]
    outdated_formulae: dict[str, str]
    outdated_casks: dict[str, str]
    dirs: dict[str, str]
    home: str
    uid: int
    system_loaded: Callable[[str], bool]


def formula_package(ctx: _Context, name: str, rack: Rack | None,
                    entry: dict[str, Any] | None) -> model.Package:
    """Build one formula from its JSON entry and its rack, or from its rack and the catalogue

    @param ctx    the instance's context
    @param name   the formula's name
    @param rack   the formula's rack, or None for a formula that `brew info` lists without one
    @param entry  the formula's `brew info` entry, or None for a rack that `brew info` does not list
    @returns      the package
    """
    cat = ctx.catalogue
    names = [name] + ([rack.name] if rack and rack.name != name else [])
    choice = choose_kegs(ctx.prefix, names, rack) if rack else KegChoice(None, None, False, None)
    facts = _receipt_facts(choice.receipt)
    installed = entry.get("installed") if entry and isinstance(entry.get("installed"), list) else []
    version = choice.current.version if choice.current else (
        str(installed[-1].get("version", "")) if installed and isinstance(installed[-1], dict) else "")
    pkg = _blank_package(ctx.prefix, "formula", name, version)
    pkg.requested = facts["requested"]
    pkg.built_locally = facts["built_locally"]
    pkg.built_on_os = facts["built_on_os"]
    pkg.archs = facts["archs"]
    pkg.receipt_ok = rack is not None and all(k.receipt is not None for k in rack.kegs)
    pkg.catalogue_present = cat.knows(name) or bool(rack and cat.knows(rack.name))
    pkg.renamed_to = cat.renamed_to(rack.name if rack else name)
    if choice.newest is not None:
        pkg.executables = sorted(set(_listing(os.path.join(choice.newest.path, "bin"))
                                     + _listing(os.path.join(choice.newest.path, "sbin"))))
    deps = facts["deps"]
    if entry is not None:
        pkg.linked = entry.get("linked_keg") is not None
        pkg.keg_only = bool(entry.get("keg_only"))
        pkg.pinned = bool(entry.get("pinned"))
        pkg.outdated = bool(entry.get("outdated"))
        pkg.deprecated = bool(entry.get("deprecated"))
        pkg.disabled = bool(entry.get("disabled"))
        pkg.origin = entry.get("tap") or facts["tap"] or ""
        pkg.homepage = entry.get("homepage")
        pkg.description = entry.get("desc")
        if deps is None:
            deps = [short_name(d) for d in entry.get("dependencies") or [] if isinstance(d, str)]
    else:
        pkg.linked = choice.linked
        pkg.keg_only = cat.keg_only(name)
        pkg.deprecated = cat.deprecated(name)
        pkg.disabled = cat.disabled(name)
        pkg.origin = facts["tap"] or ""
        pkg.homepage = cat.homepage(name)
        pkg.description = cat.desc(name)
    pkg.pinned = pkg.pinned or any(n in ctx.pinned for n in names)
    pkg.outdated = pkg.outdated or any(n in ctx.outdated_formulae for n in names)
    pkg.deps = _union(deps or [], ctx.deps_lines.get(name, []))
    pkg.active = bool(pkg.linked) or pkg.keg_only
    return pkg


def _receipt_cask_deps(receipt: dict[str, Any] | None) -> tuple[list[str], list[str]] | None:
    """Return the formula and cask dependencies a cask receipt records

    @param receipt  a cask receipt, or None
    @returns        the formula names and the cask tokens; None when the receipt keeps no per-kind lists
    """
    deps = (receipt or {}).get("runtime_dependencies")
    if not isinstance(deps, dict):
        return None
    return receipt_dependencies(receipt, "formula"), receipt_dependencies(receipt, "cask")


def _binaries(artifacts: Sequence[Artifact], dirs: Mapping[str, str], prefix: str, home: str) -> list[str]:
    """Return the basenames of a cask's `binary` links in `<prefix>/bin`

    @param artifacts  the cask's artifacts
    @param dirs       the artifact directories by configuration key
    @param prefix     the Homebrew prefix
    @param home       the user's home directory
    @returns          the names, sorted
    """
    out: set[str] = set()
    for art in artifacts:
        if art.kind == "binary":
            out.update(os.path.basename(t) for t in artifact_targets(art, dirs, prefix, home))
    return sorted(out)


def _receipt_uninstall(receipt: dict[str, Any] | None, priv: PrivilegeContext) -> bool:
    """Return whether what `brew uninstall` runs may call sudo, as the cask's receipt records it

    The receipt records it in `uninstall_artifacts` and `uninstall_flight_blocks`.

    @param receipt  the cask's receipt, or None
    @param priv     the privilege context
    @returns        True when the uninstall may call sudo; False without a receipt
    """
    if receipt is None:
        return False
    if receipt.get("uninstall_flight_blocks") is True:
        return True
    return privileged_flags(normalise_artifacts(receipt.get("uninstall_artifacts")), priv)[1]


def _cask_from_json(pkg: model.Package, entry: dict[str, Any], receipt: dict[str, Any] | None,
                    priv: PrivilegeContext) -> tuple[list[Artifact], bool, bool]:
    """Fill a cask that `brew info` lists from its entry; return its artifacts and privileged flags

    @param pkg      the package to fill
    @param entry    the cask's `brew info` entry
    @param receipt  the cask's receipt, or None
    @param priv     the privilege context
    @returns        the artifacts, then whether the install and the uninstall may call sudo
    """
    artifacts = normalise_artifacts(entry.get("artifacts"))
    install, uninstall = privileged_flags(artifacts, priv)
    uninstall = uninstall or _receipt_uninstall(receipt, priv)
    pkg.deps, pkg.cask_deps = depends_lists(entry.get("depends_on"))
    pkg.auto_updates = bool(entry.get("auto_updates"))
    pkg.pinned = bool(entry.get("pinned"))
    pkg.outdated = bool(entry.get("outdated"))
    pkg.deprecated = bool(entry.get("deprecated"))
    pkg.disabled = bool(entry.get("disabled"))
    pkg.origin = entry.get("tap") or pkg.origin
    pkg.homepage = entry.get("homepage")
    pkg.description = entry.get("desc")
    return artifacts, install, uninstall


def _cask_from_disk(pkg: model.Package, catalogue: Catalogue, receipt: dict[str, Any] | None,
                    priv: PrivilegeContext) -> tuple[list[Artifact], bool, bool]:
    """Fill a cask known only from its Caskroom directory; return its artifacts and privileged flags

    The receipt gives the artifacts, the dependencies and the uninstall flag, the catalogue the rest; a flag
    that neither gives is set.

    @param pkg        the package to fill
    @param catalogue  the instance's catalogue
    @param receipt    the cask's receipt, or None
    @param priv       the privilege context
    @returns          the artifacts, then whether the install and the uninstall may call sudo
    """
    info = catalogue.cask(pkg.name)
    if receipt is not None:
        artifacts = normalise_artifacts(receipt.get("uninstall_artifacts"))
        install = privileged_flags(info.artifacts, priv)[0] if info else True
        uninstall = _receipt_uninstall(receipt, priv)
        deps = _receipt_cask_deps(receipt)
    elif info is not None:
        artifacts = info.artifacts
        install, uninstall = privileged_flags(info.artifacts, priv)
        deps = None
    else:
        artifacts, install, uninstall, deps = [], True, True, None
    if deps is None and info is not None:
        deps = (list(info.depends_formula), list(info.depends_cask))
    if deps is not None:
        pkg.deps, pkg.cask_deps = deps
    pkg.auto_updates = bool(info and info.auto_updates)
    pkg.deprecated = catalogue.deprecated(pkg.name, "cask")
    pkg.disabled = catalogue.disabled(pkg.name, "cask")
    pkg.origin = pkg.origin or (info.tap if info and info.tap else "")
    pkg.homepage = info.homepage if info else None
    pkg.description = info.desc if info else None
    return artifacts, install, uninstall


def cask_package(ctx: _Context, token: str, room: Room | None, entry: dict[str, Any] | None) -> model.Package:
    """Build one cask, with its `caskroom_data` and its newest version directory

    @param ctx    the instance's context
    @param token  the cask's token
    @param room   the cask's Caskroom directory, or None
    @param entry  the cask's `brew info` entry, or None for a directory that `brew info` does not list
    @returns      the package
    """
    receipt = room.receipt if room else None
    facts = _receipt_facts(receipt)
    version = str(entry.get("installed") or "") if entry else ""
    if not version and room and room.versions:
        version = room.versions[-1]
    pkg = _blank_package(ctx.prefix, "cask", token, version)
    pkg.requested = facts["requested"]
    pkg.built_on_os = facts["built_on_os"]
    pkg.archs = facts["archs"]
    pkg.origin = facts["tap"] or ""
    pkg.receipt_ok = receipt is not None
    pkg.caskroom_data = list(room.data) if room else []
    pkg.catalogue_present = ctx.catalogue.knows(token, "cask")
    pkg.renamed_to = ctx.catalogue.renamed_to(token, "cask")
    pkg.active = entry is not None or bool(room and room.versions)
    dirs = dirs_from_config(room.config, ctx.dirs) if room else dict(ctx.dirs)
    priv = PrivilegeContext(prefix=ctx.prefix, dirs=dirs, home=ctx.home, uid=ctx.uid,
                            system_loaded=ctx.system_loaded)
    if entry is not None:
        artifacts, install, uninstall = _cask_from_json(pkg, entry, receipt, priv)
    else:
        artifacts, install, uninstall = _cask_from_disk(pkg, ctx.catalogue, receipt, priv)
    pkg.privileged_install, pkg.privileged_uninstall = install, uninstall
    pkg.outdated = pkg.outdated or token in ctx.outdated_casks
    pkg.executables = _binaries(artifacts, dirs, ctx.prefix, ctx.home)
    return pkg


def link_dependents(packages: Sequence[model.Package], aliases: Mapping[str, str]) -> None:
    """Fill every package's `dependents` from the `deps` and `cask_deps` of the others

    A dependency recorded under an old name or alias matches through `aliases`.

    @param packages  the instance's packages, changed in place
    @param aliases   old names and aliases to installed formula names
    """
    formulae = {p.name: p for p in packages if p.kind == "formula"}
    casks = {p.name: p for p in packages if p.kind == "cask"}
    for pkg in packages:
        for dep in pkg.deps:
            target = formulae.get(dep) or formulae.get(aliases.get(dep, ""))
            if target is not None and target is not pkg and pkg.name not in target.dependents:
                target.dependents.append(pkg.name)
        for dep in pkg.cask_deps:
            target = casks.get(dep)
            if target is not None and target is not pkg and pkg.name not in target.dependents:
                target.dependents.append(pkg.name)
    for pkg in packages:
        pkg.dependents.sort()


def _match(names: Sequence[Any], found: Mapping[str, Any], used: set[str]) -> Any:
    """Return the rack or room of the first of `names` that `found` holds and `used` does not

    @param names  the package's names, its current one first
    @param found  the racks or rooms by name
    @param used   the names matched to another package already
    @returns      the rack or room, or None
    """
    for name in names:
        if isinstance(name, str) and name in found and name not in used:
            return found[name]
    return None


# Taps -----------------------------------------------------------------------------------

def list_taps(runner, instance: model.Instance) -> list[Tap]:
    """List the taps under `<repository>/Library/Taps`

    Only a tap with its own `.git` gets the lock-free `git status` probe.

    @param runner    the runner the probes go through
    @param instance  the Homebrew instance
    @returns         the taps, sorted by user and repository
    """
    base = os.path.join(instance.repository or locate.repository_of(instance.prefix), "Library", "Taps")
    out: list[Tap] = []
    for user in _entries(base):
        user_dir = os.path.join(base, user)
        if user.startswith(".") or not os.path.isdir(user_dir):
            continue
        for repo in _entries(user_dir):
            path = os.path.join(user_dir, repo)
            if repo.startswith(".") or not os.path.isdir(path):
                continue
            name = f"{user}/{repo[len('homebrew-'):] if repo.startswith('homebrew-') else repo}"
            tap = Tap(name=name, path=path, has_git=os.path.lexists(os.path.join(path, ".git")), dirty=None)
            if tap.has_git:
                action_id = f"0.brew.{slug(instance.prefix)}.tap.{slug(name)}"
                res = runner.run(git_status_probe(path, action_id))
                if res.exit == 0 and not res.timed_out:
                    tap.status = res.stdout()
                    tap.dirty = bool(tap.status.strip())
                else:
                    tap.error = locate.failure_text(res, "git status")
            out.append(tap)
    return out


# The inventory ------------------------------------------------------------------------

def _launchd_probe(runner, prefix: str) -> Callable[[str], bool]:
    """Return a test of whether a label is loaded in the system domain, probed once per label

    @param runner  the runner the probes go through
    @param prefix  the Homebrew prefix, for the action ids
    @returns       the test, which keeps each label's answer
    """
    seen: dict[str, bool] = {}

    def loaded(label: str) -> bool:
        if label not in seen:
            action_id = f"0.brew.{slug(prefix)}.launchctl.{slug(label)}"
            res = runner.run(system.probe(action_id, [LAUNCHCTL, "print", "system/" + label],
                                          f"launchd job {label} in the system domain"))
            seen[label] = res.exit == 0 and not res.timed_out
        return seen[label]
    return loaded


def _run_probes(runner, instance: model.Instance, inv: HomebrewInventory) -> tuple[dict[str, Any] | None,
                                                                                   dict[str, list[str]]]:
    """Run `brew info`, then, when it succeeds, `brew outdated`, `brew deps` and `brew missing`

    Every failure joins the instance's `inventory_error`.

    @param runner    the runner the probes go through
    @param instance  the drivable Homebrew instance
    @param inv       the inventory, which takes the outdated and missing packages and the errors
    @returns         the decoded `brew info` output or None, and the `brew deps` lines by formula
    """
    probes = _Probes(runner, instance)
    info = probes.json_of(actions.info_installed, "info", "brew info --json=v2 --installed", dict)
    deps_lines: dict[str, list[str]] = {}
    if info is not None:
        inv.outdated_formulae, inv.outdated_casks = parse_outdated(
            probes.json_of(actions.outdated, "outdated", "brew outdated --json=v2"))
        deps_lines = parse_deps(probes.text_of(actions.deps_installed, "deps",
                                               "brew deps --formula --installed --for-each") or "")
        inv.missing = probes.missing()
    inv.inventory_error = "; ".join(probes.errors) or None
    instance.inventory_error = inv.inventory_error
    return info, deps_lines


def _formulae(ctx: _Context, info: dict[str, Any] | None, racks: Mapping[str, Rack],
              aliases: dict[str, str]) -> tuple[list[model.Package], dict[str, Rack]]:
    """Return the formulae and their racks: the JSON's, matched to racks, then one for every other rack

    A rack that `brew info` does not list becomes a package built from the rack and the catalogue.

    @param ctx      the instance's context
    @param info     the decoded `brew info` output, or None
    @param racks    the racks by name
    @param aliases  collects the old names and aliases, each to its formula
    @returns        the packages, and each formula's rack by name
    """
    packages: list[model.Package] = []
    rack_of: dict[str, Rack] = {}
    for entry in (info or {}).get("formulae") or []:
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        names = [entry["name"]] + list(entry.get("oldnames") or []) + list(entry.get("aliases") or [])
        rack = _match(names, racks, set(r.name for r in rack_of.values()))
        if rack is None and not entry.get("installed"):
            continue
        name = str(entry["name"])
        if rack is not None:
            rack_of[name] = rack
            if rack.name != name:
                aliases[rack.name] = name
        for other in names[1:]:
            aliases.setdefault(str(other), name)
        packages.append(formula_package(ctx, name, rack, entry))
    for name in sorted(set(racks) - set(r.name for r in rack_of.values())):
        rack_of[name] = racks[name]
        packages.append(formula_package(ctx, name, racks[name], None))
    return packages, rack_of


def _casks(ctx: _Context, info: dict[str, Any] | None,
           rooms: Mapping[str, Room]) -> tuple[list[model.Package], dict[str, Room]]:
    """Return the casks and their Caskroom directories: the JSON's, matched to directories, then one for every other

    @param ctx    the instance's context
    @param info   the decoded `brew info` output, or None
    @param rooms  the Caskroom directories by token
    @returns      the packages, and each cask's directory by token
    """
    packages: list[model.Package] = []
    room_of: dict[str, Room] = {}
    used: set[str] = set()
    for entry in (info or {}).get("casks") or []:
        if not isinstance(entry, dict) or not entry.get("token"):
            continue
        room = _match([entry["token"]] + list(entry.get("old_tokens") or []), rooms, used)
        if room is not None:
            used.add(room.token)
            room_of[str(entry["token"])] = room
        packages.append(cask_package(ctx, str(entry["token"]), room, entry))
    for token in sorted(set(rooms) - used):
        room_of[token] = rooms[token]
        packages.append(cask_package(ctx, token, rooms[token], None))
    return packages, room_of


def _rename_aliases(packages: Sequence[model.Package], catalogue: Catalogue, aliases: dict[str, str]) -> None:
    """Add the aliases that lead a dependency under a formula's old name to the installed formula

    A rack that `brew info` does not list, under an old name, gets its current name as an alias too.

    @param packages   the instance's packages
    @param catalogue  the instance's catalogue
    @param aliases    old names and aliases to installed formula names, extended in place
    """
    installed = {p.name for p in packages if p.kind == "formula"}
    for dep in sorted({d for p in packages for d in p.deps} - installed):
        canon = catalogue.canonical(dep)
        if canon in installed:
            aliases.setdefault(dep, canon)
    for name in sorted(installed):
        canon = catalogue.canonical(name)
        if canon and canon != name and canon not in installed:
            aliases.setdefault(canon, name)


def _keg_facts(inv: HomebrewInventory, prefix: str, rack_of: Mapping[str, Rack]) -> None:
    """Record per formula its keg directories, those without a receipt, and the root-owned paths of its kegs

    The root-owned scan covers the `opt` link of each of the formula's names too.

    @param inv      the inventory to fill
    @param prefix   the Homebrew prefix
    @param rack_of  each formula's rack by name
    """
    for name, rack in sorted(rack_of.items()):
        inv.kegs[name] = [k.path for k in rack.kegs]
        inv.receiptless_kegs.extend(k.path for k in rack.kegs if k.receipt is None)
        links = [os.path.join(prefix, "opt", n) for n in sorted({name, rack.name})]
        owned = root_owned_paths(links + [k.path for k in rack.kegs])
        if owned:
            inv.root_owned[name] = owned


def services_listing(runner, instance: model.Instance) -> list[Any] | None:
    """Return the decoded `brew services list --json` of a drivable instance, which corroborates the service scan

    @param runner    the runner the probe goes through
    @param instance  the drivable Homebrew instance
    @returns         the listing's entries; None when the probe fails or prints no JSON list
    """
    res = runner.run(actions.services_list(instance, runner.host_arch, f"0.brew.{slug(instance.prefix)}.services"))
    if res.exit != 0 or res.timed_out:
        return None
    try:
        entries = json.loads(res.stdout())
    except ValueError:
        return None
    return entries if isinstance(entries, list) else None


def inventory(runner, instance: model.Instance, catalogue: Catalogue, use_brew: bool = True) -> HomebrewInventory:
    """Take the inventory of one Homebrew instance

    `use_brew=False` skips the `brew` probes and walks the disk alone; when `brew info` fails, the disk inventory
    stands and the error is the instance's `inventory_error`.

    @param runner     the runner the probes go through
    @param instance   the Homebrew instance
    @param catalogue  the instance's offline catalogue
    @param use_brew   run the `brew` inventory probes when the instance is drivable
    @returns          the inventory
    """
    prefix = instance.prefix
    environ = runner.environ
    home = environ.get("HOME") or os.path.expanduser("~")
    inv = HomebrewInventory(instance_prefix=prefix)
    inv.brew_env = locate.brew_env_lines(prefix, environ)
    racks, inv.cellar_renames = walk_cellar(prefix)
    rooms, inv.caskroom_renames = walk_caskroom(prefix)
    inv.pinned = [n for n in _entries(os.path.join(prefix, "var", "homebrew", "pinned")) if not n.startswith(".")]
    inv.broken_opt_links = broken_links(os.path.join(prefix, "opt"))
    info, deps_lines = _run_probes(runner, instance, inv) if use_brew and instance.drivable else (None, {})
    ctx = _Context(prefix=prefix, catalogue=catalogue, pinned=set(inv.pinned), deps_lines=deps_lines,
                   outdated_formulae=inv.outdated_formulae, outdated_casks=inv.outdated_casks,
                   dirs=cask_dirs(prefix, environ, inv.brew_env, home), home=home, uid=os.geteuid(),
                   system_loaded=_launchd_probe(runner, prefix))
    aliases: dict[str, str] = {}
    packages, rack_of = _formulae(ctx, info, racks, aliases)
    casks, room_of = _casks(ctx, info, rooms)
    packages += casks
    _rename_aliases(packages, catalogue, aliases)
    link_dependents(packages, aliases)
    inv.packages = sorted(packages, key=lambda p: (p.kind != "formula", p.name))
    inv.used_json = info is not None
    progress.step(f"Homebrew {prefix}: checking installed files")
    progress.counting("files")
    _keg_facts(inv, prefix, rack_of)
    inv.caskrooms = {token: room.path for token, room in sorted(room_of.items())}
    inv.cask_versions = {token: list(room.versions) for token, room in sorted(rooms.items())}
    progress.step(f"Homebrew {prefix}: taps")
    inv.taps = list_taps(runner, instance)
    return inv


def scan(runner, environ: Mapping[str, str], host_arch: str) -> list[tuple[model.Instance, Catalogue,
                                                                        HomebrewInventory]]:
    """Return every Homebrew instance with its offline catalogue and its inventory

    @param runner     the runner the probes go through
    @param environ    the environment the tool runs with
    @param host_arch  the host's architecture
    @returns          one `(instance, catalogue, inventory)` triple per instance
    """
    progress.step("finding Homebrew")
    out = []
    for instance in locate.find_instances(runner, environ, host_arch):
        progress.step(f"Homebrew {instance.prefix}: package catalogue")
        catalogue = Catalogue.load(instance, environ, host_arch)
        progress.step(f"Homebrew {instance.prefix}: installed packages")
        out.append((instance, catalogue, inventory(runner, instance, catalogue)))
    return out


def summary_lines(results: Sequence[tuple[model.Instance, Catalogue, HomebrewInventory]]) -> list[str]:
    """Return the `scan` text for the Homebrew instances: packages, Caskroom, taps

    @param results  the `scan` triples
    @returns        the text lines
    """
    lines: list[str] = []
    for instance, catalogue, inv in results:
        state = instance.version or instance.usability.value
        lines.append(f"Homebrew {instance.prefix} ({state}, {instance.arch or 'arch unknown'}, "
                     f"catalogue {catalogue.source})")
        if instance.usability_detail:
            lines.append(f"  {instance.usability_detail.splitlines()[0]}")
        if inv.inventory_error:
            state = "inventory probe failed" if inv.used_json else "inventory from disk only"
            lines.append(f"  {state}: {inv.inventory_error.splitlines()[0]}")
        formulae = [p for p in inv.packages if p.kind == "formula"]
        casks = [p for p in inv.packages if p.kind == "cask"]
        lines.append(f"  formulae {len(formulae)} (kegs {sum(len(v) for v in inv.kegs.values())}, "
                     f"without receipt {len(inv.receiptless_kegs)}), casks {len(casks)}, taps {len(inv.taps)}, "
                     f"pinned {len(inv.pinned)}")
        rows = []
        for pkg in inv.packages:
            marks = [m for m, on in (("requested", pkg.requested), ("keg-only", pkg.keg_only),
                                     ("pinned", pkg.pinned), ("outdated", pkg.outdated),
                                     ("no-receipt", not pkg.receipt_ok), ("sudo-install", pkg.privileged_install),
                                     ("sudo-uninstall", pkg.privileged_uninstall),
                                     ("data", bool(pkg.caskroom_data))) if on]
            rows.append((pkg.kind, pkg.name, pkg.version or "-", " ".join(marks)))
        lines.extend("  " + line for line in table(rows, ("kind", "name", "version", "notes")))
        for link in inv.cellar_renames + inv.caskroom_renames:
            lines.append(f"  rename link {link.path} -> {link.target}")
        for tap in inv.taps:
            if not tap.has_git:
                tap_state = "no .git"
            elif tap.dirty is None:
                tap_state = "status unknown"
            else:
                tap_state = "local changes" if tap.dirty else "clean"
            lines.append(f"  tap {tap.name} ({tap_state})")
    return lines

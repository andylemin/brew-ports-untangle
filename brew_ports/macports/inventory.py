"""MacPorts inventory from a registry backup, the PortIndex and the prefix: one `Package` per registry row

The registry copy stays open while the inventory lives, so file rows are read on demand; `close()` removes it.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .. import model, report, system
from ..model import Instance, Package
from ..state import slug
from . import actions, locate, registry
from .portindex import PortEntry


@dataclass
class SelectGroup:
    """A select group as `<prefix>/etc/select/<group>/` holds it

    The `current` link or file names the selection, beside the option files and `base`, which lists the
    paths the group links.
    """

    name: str
    current: str | None
    options: list[str]
    base: list[str]


def configured_cxx_stdlib(config: Mapping[str, str], platform: locate.Platform) -> str:
    """Return `cxx_stdlib` from macports.conf, else base's default: libc++ on Darwin 10 and newer

    @param config    the macports.conf settings
    @param platform  the running platform and its Darwin major
    @returns         the C++ standard library; empty on a platform other than Darwin
    """
    if config.get("cxx_stdlib"):
        return config["cxx_stdlib"]
    name, major = platform
    if name == "darwin":
        return "libc++" if major >= 10 else "libstdc++"
    return ""


def is_outdated(row: registry.PortRow, entry: PortEntry, cxx_stdlib: str) -> bool:
    """Return whether `port outdated` would list the row against the PortIndex entry

    An epoch decides only where the version strings differ too; at an equal version and revision, a build
    against the other C++ library (not overridden) is outdated. Another platform is no upgrade.

    @param row         the installed registry row
    @param entry       the port's PortIndex entry
    @param cxx_stdlib  the configured C++ standard library
    @returns           True when the entry is newer, or the row is built against the other C++ library
    """
    latest = entry.version or ""
    epoch_cmp = row.epoch - entry.epoch
    cmp = registry.vercmp(row.version, latest)
    if cmp == 0:
        cmp = row.revision - entry.revision
    if epoch_cmp != 0 and row.version != latest:
        return epoch_cmp < 0
    if cmp == 0:
        wrong = "libstdc++" if cxx_stdlib == "libc++" else "libc++"
        return row.cxx_stdlib == wrong and row.cxx_stdlib_overridden == 0
    return cmp < 0


def location_present(path: str | None) -> bool:
    """Return whether a port's `ports.location` exists

    Only a missing file or directory counts as gone; a path the user cannot check counts as present.

    @param path  the row's image archive or directory, or None
    @returns     False for None, an empty path or a path that is gone
    """
    if not path:
        return False
    try:
        os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    return True


def _dependents(rows: list[registry.PortRow], deps: Mapping[int, list[str]]) -> dict[str, list[str]]:
    """Map each lower-cased name to the names whose recorded dependencies hold it, over rows of every state

    @param rows  the registry rows
    @param deps  the recorded dependency names of each port id
    @returns     the dependents of each lower-cased name, sorted without regard to case
    """
    out: dict[str, list[str]] = {}
    for row in rows:
        for dep in deps.get(row.id, []):
            names = out.setdefault(dep.lower(), [])
            if row.name not in names:
                names.append(row.name)
    return {key: sorted(names, key=str.lower) for key, names in out.items()}


def _executables(reg: registry.Registry, prefix: str) -> dict[int, list[str]]:
    """Map each port id to the basenames of its files directly under `<prefix>/bin/` and `<prefix>/sbin/`

    A file lies where its `actual_path` says, falling back to `path`.

    @param reg     the registry copy
    @param prefix  the prefix spelling registered paths use
    @returns       the sorted basenames of each port id that has any
    """
    out: dict[int, list[str]] = {}
    for sub in ("bin", "sbin"):
        directory = os.path.join(prefix, sub)
        for port_id, row in reg.files_below(directory):
            if os.path.dirname(row.location) == directory:
                names = out.setdefault(port_id, [])
                if os.path.basename(row.location) not in names:
                    names.append(os.path.basename(row.location))
    return {key: sorted(names) for key, names in out.items()}


def _select_membership(reg: registry.Registry, prefix: str) -> dict[int, list[str]]:
    """Map each port id to the select groups it registered a file in (`etc/select/<group>/<file>`)

    @param reg     the registry copy
    @param prefix  the prefix spelling registered paths use
    @returns       the sorted group names of each port id that has any
    """
    root = os.path.join(prefix, "etc", "select")
    out: dict[int, list[str]] = {}
    for port_id, row in reg.files_below(root):
        if not row.path.startswith(root + "/"):
            continue
        parts = row.path[len(root) + 1:].split("/")
        if len(parts) == 2 and parts[0] not in out.setdefault(port_id, []):
            out[port_id].append(parts[0])
    return {key: sorted(groups) for key, groups in out.items() if groups}


def _lines(path: str) -> list[str]:
    """Return the lines of a text file that are not blank, stripped

    @param path  the file
    @returns     the lines; empty when the file cannot be read
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [line.strip() for line in fh.read().splitlines() if line.strip()]
    except OSError:
        return []


def _current(group_dir: str) -> str | None:
    """Return the option a select group selects: the basename of its `current` link, else the file's first line

    @param group_dir  the group's directory under `etc/select`
    @returns          the option, or None when nothing names one
    """
    path = os.path.join(group_dir, "current")
    try:
        return os.path.basename(os.readlink(path))
    except OSError:
        lines = _lines(path)
        return lines[0] if lines else None


def read_select_groups(prefix: str) -> list[SelectGroup]:
    """Read the select groups on disk under `<prefix>/etc/select/`

    @param prefix  the MacPorts prefix
    @returns       the groups in name order; empty when the directory cannot be read
    """
    root = os.path.join(prefix, "etc", "select")
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return []
    groups = []
    for name in names:
        group_dir = os.path.join(root, name)
        if name.startswith(".") or not os.path.isdir(group_dir):
            continue
        try:
            entries = sorted(e for e in os.listdir(group_dir) if not e.startswith("."))
        except OSError:
            continue
        groups.append(SelectGroup(name=name, current=_current(group_dir),
                                  options=[e for e in entries if e not in ("current", "base")],
                                  base=_lines(os.path.join(group_dir, "base"))))
    return groups


def select_summary(runner, instance: Instance, host_arch: str) -> list[str] | None:
    """Probe the group lines of `port select --summary` on a drivable instance, its two header lines skipped

    @param runner     the runner that runs the probe
    @param instance   the MacPorts instance
    @param host_arch  the host's architecture
    @returns          the lines; empty when it exits 1 (no select group exists); None when not run or failed
    """
    if not instance.drivable:
        return None
    result = runner.run(actions.select_summary(instance, host_arch, f"0.ports.{slug(instance.prefix)}.select"))
    if result.exit == 1:
        return []
    if result.exit != 0:
        return None
    return [line for line in result.stdout().splitlines()[2:] if line.strip()]


def parse_select_summary(lines: list[str]) -> list[tuple[str, str, list[str]]]:
    """Return `(group, selected, options)` of each group line of `port select --summary`

    @param lines  the group lines, without the two header lines
    @returns      one tuple per line of two words or more
    """
    out = []
    for line in lines:
        words = line.split()
        if len(words) >= 2:
            out.append((words[0], words[1], words[2:]))
    return out


def _built_on(row: registry.PortRow) -> str | None:
    """Return the platform a row is built for, such as `darwin 24`

    @param row  the registry row
    @returns    `<os_platform> <os_major>`, or None when the row records no platform
    """
    if not row.os_platform:
        return None
    return (f"{row.os_platform} {row.os_major or ''}").strip()


def _package(instance: Instance, row: registry.PortRow, *, deps: list[str], dependents: list[str],
             executables: list[str], groups: list[str], entry: PortEntry | None, have_index: bool,
             origin: str, cxx_stdlib: str) -> Package:
    """Return the package of one registry row

    @param instance     the MacPorts instance
    @param row          the registry row
    @param deps         the names of the row's recorded dependencies
    @param dependents   the names of the ports whose recorded dependencies hold it
    @param executables  the basenames of its files under `bin` and `sbin`
    @param groups       the select groups it registered a file in
    @param entry        its PortIndex entry, or None
    @param have_index   whether a PortIndex was read; without one every port counts as in the catalogue
    @param origin       the PortIndex's source, kept for a port with an entry
    @param cxx_stdlib   the configured C++ standard library, for the outdated check
    @returns            the package
    """
    variants = row.requested_variant_tokens
    return Package(
        instance_prefix=instance.prefix, kind="port", name=row.name, version=row.version_string, epoch=row.epoch,
        spec_args=row.spec_args, requested=row.requested, requested_variants=variants, active=row.active,
        linked=None, keg_only=False, pinned=False,
        outdated=row.active and entry is not None and is_outdated(row, entry, cxx_stdlib),
        deprecated=False, disabled=False, catalogue_present=entry is not None or not have_index,
        renamed_to=entry.replaced_by if entry else None, origin=origin if entry else "",
        homepage=entry.homepage if entry else None, description=entry.description if entry else None,
        deps=list(deps), cask_deps=[], dependents=list(dependents), executables=list(executables),
        privileged_install=False, privileged_uninstall=False, auto_updates=False, caskroom_data=[],
        built_locally=bool(variants), built_on_os=_built_on(row), archs=(row.archs or "").split(), services=[],
        select_groups=list(groups), receipt_ok=location_present(row.location))


@dataclass
class MacPortsInventory:
    """One MacPorts instance as the registry, the PortIndex and the prefix show it

    `packages` and `rows` are parallel; when `known` is false both are empty and only the image
    archives are left to report.
    """

    instance: Instance
    known: bool
    error: str | None
    schema_version: str | None
    config: dict[str, str]
    registry_prefix: str                     # the prefix spelling registered paths use
    packages: list[Package]
    rows: list[registry.PortRow]
    select_groups: list[SelectGroup]
    select_summary: list[str] | None
    image_archives: dict[str, list[str]]
    base_files: locate.BaseFiles
    snapshots: list[registry.Snapshot]
    autoconf: dict[str, str] = field(default_factory=dict)  # base's macports_version, os_platform, os_major
    portindex_path: str | None = None
    _registry: registry.Registry | None = field(default=None, repr=False, compare=False)
    _by_spec: dict[tuple[str, str, int], registry.PortRow] | None = field(default=None, repr=False, compare=False)

    def row_for(self, package: Package) -> registry.PortRow | None:
        """Return the registry row of a package: its two `spec_args` tokens and its epoch name one row

        @param package  a package of this inventory
        @returns        the row, or None when none matches
        """
        if self._by_spec is None:
            self._by_spec = {(p.spec_args[0].lower(), p.spec_args[1], p.epoch): row
                             for p, row in zip(self.packages, self.rows)}
        if len(package.spec_args) != 2:
            return None
        return self._by_spec.get((package.spec_args[0].lower(), package.spec_args[1], package.epoch))

    def files(self, package: Package) -> list[registry.FileRow]:
        """Read the registered files of one row on demand

        @param package  a package of this inventory
        @returns        the files in registration order; empty when no row matches or the copy is closed
        """
        row = self.row_for(package)
        if row is None or self._registry is None:
            return []
        return self._registry.files(row.id)

    def binaries(self, package: Package) -> list[str]:
        """Return the `files` with `binary = 1 AND active = 1` at their on-disk location, for the linkage scan

        @param package  a package of this inventory
        @returns        the on-disk paths, in registration order
        """
        return [f.location for f in self.files(package) if f.binary and f.active]

    def owner_of(self, path: str) -> str | None:
        """Return the port that registered `path` as `files.path` or `files.actual_path`

        @param path  an absolute path
        @returns     the port's name, or None when no port registered it or the copy is closed
        """
        if self._registry is None:
            return None
        return self._registry.owner_of(system.normalise_text_path(path, False))

    def is_registered(self, path: str) -> bool:
        """Return whether a port registered `path`

        @param path  an absolute path
        @returns     True when `owner_of` names a port
        """
        return self.owner_of(path) is not None

    def is_base_file(self, path: str) -> bool:
        """Return whether `path` belongs to MacPorts base, whose files the registry never lists

        @param path  an absolute path
        @returns     True for a file of the receipt, the base trees, programs and man pages
        """
        return self.base_files.owns(path)

    def leaves(self) -> list[Package]:
        """Return the ports with `requested = 0` and no dependents

        @returns  the packages, in inventory order
        """
        return [p for p in self.packages if p.requested is False and not p.dependents]

    def rleaves(self) -> list[Package]:
        """Return the ports with `requested = 0` and no requested port among their transitive dependents

        @returns  the packages, in inventory order
        """
        dependents = {p.name.lower(): p.dependents for p in self.packages}
        requested = {p.name.lower() for p in self.packages if p.requested}

        def reaches_requested(name: str) -> bool:
            seen, todo = set(), list(dependents.get(name.lower(), []))
            while todo:
                current = todo.pop().lower()
                if current in requested:
                    return True
                if current not in seen:
                    seen.add(current)
                    todo.extend(dependents.get(current, []))
            return False

        return [p for p in self.packages if p.requested is False and not reaches_requested(p.name)]

    def facts(self) -> dict[str, Any]:
        """Return the instance's facts beside its packages, JSON-ready for scan.json

        @returns  the facts as plain JSON values
        """
        return model.to_plain({
            "prefix": self.instance.prefix, "known": self.known, "error": self.error,
            "schema_version": self.schema_version, "registry_prefix": self.registry_prefix, "config": self.config,
            "autoconf": self.autoconf, "select_groups": self.select_groups, "select_summary": self.select_summary,
            "image_archives": self.image_archives, "snapshots": self.snapshots, "portindex": self.portindex_path,
        })

    def close(self) -> None:
        """Close and remove the registry copy; the file queries find nothing after it"""
        if self._registry is not None:
            self._registry.close()
            self._registry = None

    def __enter__(self) -> "MacPortsInventory":
        """Return the inventory, which leaving the `with` block closes

        @returns  the inventory itself
        """
        return self

    def __exit__(self, *exc: Any) -> None:
        """Close the registry copy

        @param exc  the exception type, value and traceback, which the close ignores
        """
        self.close()


def _open(portdbpath: str) -> tuple[registry.Registry | None, str | None]:
    """Open a fresh registry backup, or return the `<label>: <text>` of its failure; none when it is absent

    @param portdbpath  the instance's `portdbpath`
    @returns           the registry copy, else None; the failure, else None
    """
    try:
        return registry.Registry.open_copy(portdbpath), None
    except registry.RegistryMissing:
        return None, None
    except registry.RegistryBusy as exc:
        return None, f"{registry.STATUS_LABELS['busy']}: {exc}"
    except (sqlite3.DatabaseError, OSError) as exc:
        label = registry.STATUS_LABELS["damaged" if isinstance(exc, sqlite3.DatabaseError) else "unreadable"]
        return None, f"{label}: {type(exc).__name__}: {exc}"


def inventory(runner, instance: Instance, portindex: Any, *, host_arch: str | None = None,
              platform: locate.Platform | None = None) -> MacPortsInventory:
    """Read the inventory of one instance, drivable or not, from a fresh registry backup while `inventory_known` holds

    A failed backup leaves the inventory unknown and records that on the instance; without a `portindex`
    (no synced tree), `outdated` is false and `catalogue_present` true for every row.

    @param runner     the runner that runs the probes
    @param instance   the MacPorts instance; a failed backup sets its `inventory_known` and `inventory_error`
    @param portindex  the instance's PortIndex, or None without a synced tree
    @param host_arch  the host's architecture; None takes the runner's
    @param platform   the running platform; None reads `uname`
    @returns          the inventory, whose registry copy stays open until `close()`
    """
    host_arch = host_arch or runner.host_arch
    portdbpath = instance.portdbpath
    if portdbpath is None:
        raise ValueError(f"the MacPorts instance at {instance.prefix} has no portdbpath")
    config = locate.read_config(instance.prefix, runner.environ)
    prefix = config.get("prefix") or instance.prefix
    known, error, reg = instance.inventory_known, instance.inventory_error, None
    if known:
        reg, failure = _open(portdbpath)
        if failure:
            known, error = False, failure
            instance.inventory_known, instance.inventory_error = False, failure
    rows = reg.ports() if reg else []
    deps = reg.dependencies() if reg else {}
    exe = _executables(reg, prefix) if reg else {}
    groups = _select_membership(reg, prefix) if reg else {}
    dependents = _dependents(rows, deps)
    cxx = configured_cxx_stdlib(config, platform or locate.running_platform())
    origin = (portindex.source or "") if portindex is not None else ""
    packages = [_package(instance, row, deps=deps.get(row.id, []), dependents=dependents.get(row.name.lower(), []),
                         executables=exe.get(row.id, []), groups=groups.get(row.id, []),
                         entry=portindex.get(row.name) if portindex is not None else None,
                         have_index=portindex is not None, origin=origin, cxx_stdlib=cxx)
                for row in rows]
    try:
        images = registry.image_archives(portdbpath)
    except OSError:
        images = {}
    return MacPortsInventory(
        instance=instance, known=known, error=error, schema_version=reg.schema_version if reg else None,
        config=config, registry_prefix=prefix, packages=packages, rows=rows,
        select_groups=read_select_groups(prefix), select_summary=select_summary(runner, instance, host_arch),
        image_archives=images, base_files=locate.BaseFiles.load(runner, prefix),
        snapshots=reg.snapshots() if reg else [], autoconf=locate.read_autoconf(instance.prefix),
        portindex_path=portindex.path if portindex is not None else None, _registry=reg)


def render_lines(inv: MacPortsInventory) -> list[str]:
    """Render the `scan` text of one MacPorts instance

    @param inv  the instance's inventory
    @returns    the heading, then a table of the ports or the reason they are unknown
    """
    inst = inv.instance
    built = " ".join(v for v in (inv.autoconf.get("os_platform"), inv.autoconf.get("os_major")) if v)
    built_for = f", built for {built}" if built else ""
    lines = [f"MacPorts {inst.version or 'unknown version'} at {inst.prefix} ({inst.usability.value}){built_for}"]
    if inst.usability_detail:
        lines.append("  " + inst.usability_detail)
    if not inv.known:
        lines.append(f"  ports unknown: {inv.error or 'the registry cannot be read'}")
        for name, entries in sorted(inv.image_archives.items()):
            lines.append(f"  image archive: {name}/{', '.join(entries)}")
        return lines
    rows = []
    for p in inv.packages:
        flags = [word for word, on in (("requested", p.requested), ("outdated", p.outdated),
                                        ("image missing", not p.receipt_ok)) if on]
        rows.append((p.name, p.version, "active" if p.active else "inactive", ", ".join(flags)))
    lines += ["  " + line for line in report.table(rows, ["port", "version", "state", "notes"])]
    return lines

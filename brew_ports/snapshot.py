"""The phase 1 snapshot under `<run>/snapshot/`, and its readers for `rollback`

Each step writes one file of its own, so a rerun overwrites it; a failed step leaves only a line in `notes.txt`.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from . import model, state, system
from .env import services as env_services
from .homebrew import actions as brew_actions, inventory as brew_inventory
from .macports import actions as mp_actions, registry
from .model import Instance, Manager, OnFailure, Service

SNAPSHOT = "snapshot"
COMPLETE = "complete"
NOTES = "notes.txt"
FORMULAE = "all-formulae.txt"
CASKS = "casks.txt"
RECEIPTS = "receipts"
SERVICES = "services.json"
BREWFILE = "Brewfile"
INSTALLED_JSON = "installed.json"
REGISTRY = os.path.join("registry", "registry.db")
INSTALLED = "installed.txt"
SELECT = "select.txt"
SNAPSHOT_ID = "snapshot-id.txt"
PORTS_SNAPSHOT = "ports-snapshot.json"
PLISTS = "plists"
RC_FILES = "rc"
SNAPSHOT_TYPE = "org.macports/snapshot/v1"
TMUTIL = "/usr/bin/tmutil"
DISK_NOTE = "tmutil localsnapshot "   # how the note of a disk snapshot that failed begins
RECEIPT = brew_inventory.RECEIPT
PARTIAL = ".partial"

FORMULAE_HEADER = "# name\tinstalled_on_request\ttap\tversions"
CASKS_HEADER = "# cask\ttoken\tprivileged_install\tprivileged_uninstall\tversions\n# link\ttoken\ttarget"
INSTALLED_HEADER = "# name\tversion\trequested\trequested_variants\tactive\tos_major"


# Paths ---------------------------------------------------------------------------

def snapshot_dir(run_dir: state.RunDir) -> str:
    """Return a run's snapshot directory, `<run>/snapshot`

    @param run_dir  the run
    @returns        the directory's path
    """
    return run_dir.sub(SNAPSHOT)


def brew_dir(run_dir: state.RunDir, prefix: str) -> str:
    """Return a Homebrew prefix's snapshot directory, `<run>/snapshot/brew-<slug>`

    @param run_dir  the run
    @param prefix   the instance prefix, whose slug has a `%` for each slash
    @returns        the directory's path
    """
    return os.path.join(snapshot_dir(run_dir), "brew-" + state.slug(prefix))


def ports_dir(run_dir: state.RunDir, prefix: str) -> str:
    """Return a MacPorts prefix's snapshot directory, `<run>/snapshot/ports-<slug>`

    @param run_dir  the run
    @param prefix   the instance prefix, whose slug has a `%` for each slash
    @returns        the directory's path
    """
    return os.path.join(snapshot_dir(run_dir), "ports-" + state.slug(prefix))


def is_complete(run_dir: state.RunDir) -> bool:
    """Return whether the `complete` marker exists; until it does, a resume runs the phase again

    @param run_dir  the run
    @returns        True once phase 1 wrote the marker
    """
    return os.path.isfile(os.path.join(snapshot_dir(run_dir), COMPLETE))


def snapshot_note(run_dir: state.RunDir) -> str:
    """Return the note of the MacPorts snapshot a run creates: `brew-ports <run-id>`

    @param run_dir  the run
    @returns        the note
    """
    return f"brew-ports {run_dir.run_id}"


# Writing -------------------------------------------------------------------------

def _bool_text(value: bool | None, unknown: str = "none") -> str:
    """Return a flag as `true` or `false`, or as the text for an unknown flag

    @param value    the flag, or None when it is unknown
    @param unknown  the text for an unknown flag
    @returns        the text
    """
    if value is None:
        return unknown
    return "true" if value else "false"


def _remove(path: str) -> None:
    """Remove a file that may not exist

    @param path  the file
    """
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


class _Writer:
    """The files of one call: written through a temporary name under the snapshot directory, listed in `written`"""

    def __init__(self, runner, run_dir: state.RunDir, id_prefix: str) -> None:
        """Start the files of one call

        @param runner     the runner of the snapshot's commands; None when no command runs
        @param run_dir    the run
        @param id_prefix  the prefix of the action ids, such as the phase number
        """
        self.runner = runner
        self.run_dir = run_dir
        self.id_prefix = id_prefix
        self.root = snapshot_dir(run_dir)
        self.written: dict[str, str] = {}
        self.notes: list[str] = []

    def path(self, *parts: str) -> str:
        """Return a path under the snapshot directory, making its parent directories

        @param parts  the path's components below the snapshot directory
        @returns      the path
        """
        full = os.path.join(self.root, *parts)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        return full

    def record(self, full: str) -> str:
        """List a written file in `written`, by its snapshot-relative path

        @param full  the file's path
        @returns     the same path
        """
        self.written[os.path.relpath(full, self.root)] = full
        return full

    def text(self, parts: Sequence[str], content: str) -> str:
        """Write a text file under the snapshot directory through a temporary name

        @param parts    the file's components below the snapshot directory
        @param content  the text
        @returns        the file's path
        """
        full = self.path(*parts)
        tmp = full + PARTIAL
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, full)
        return self.record(full)

    def copy(self, src: str, parts: Sequence[str]) -> str | None:
        """Copy a file through its symlinks, keeping the copy only when it is complete

        @param src    the file
        @param parts  the copy's components below the snapshot directory
        @returns      the copy's path, or None when the copy failed, which leaves a note
        """
        full = self.path(*parts)
        tmp = full + PARTIAL
        try:
            shutil.copy2(src, tmp)
        except OSError as exc:
            _remove(tmp)
            self.note(f"{src} not copied: {exc.strerror or exc}")
            return None
        os.replace(tmp, full)
        return self.record(full)

    def note(self, text: str) -> None:
        """Keep a line for `notes.txt`

        @param text  the line
        """
        self.notes.append(text)

    def action_id(self, subject: str, step: str) -> str:
        """Return the id of a snapshot action

        @param subject  what the action reads, such as an instance prefix's slug
        @param step     the step
        @returns        `<prefix>.snapshot.<subject>.<step>`
        """
        return f"{self.id_prefix}.snapshot.{subject}.{step}"

    def finish(self) -> None:
        """Append the kept lines to `notes.txt`, which a rerun extends"""
        if self.notes:
            path = self.path(NOTES)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("".join(line + "\n" for line in self.notes))
            self.record(path)


def _refreshed(runner, services: Iterable[Service], uid: int) -> list[Service]:
    """Return the services with `loaded`, `running`, `domain` and `pid` probed again through launchctl

    @param runner    the runner of the probes
    @param services  the services
    @param uid       the user's uid
    @returns         the probed services, in their order
    """
    return [env_services.refresh(runner, svc, uid) for svc in services]


def _services_of(bundle, prefix: str) -> list[Service]:
    """Return the scan's services whose program belongs to an instance

    @param bundle  the scan
    @param prefix  the instance's prefix
    @returns       the services
    """
    return [svc for svc in bundle.result.services if svc.instance_prefix == prefix]


# Homebrew --------------------------------------------------------------------------

def formulae_text(prefix: str, racks: dict[str, brew_inventory.Rack]) -> str:
    """Return `all-formulae.txt`: each Cellar name with its receipt's `installed_on_request`, tap and versions

    The receipt is the one Homebrew's `Tab.for_formula` reads; `none` stands for a missing flag or receipt,
    `-` for a missing tap.

    @param prefix  the Homebrew prefix
    @param racks   the Cellar's racks, by name
    @returns       the file's text
    """
    lines = [FORMULAE_HEADER]
    for name in sorted(racks):
        rack = racks[name]
        receipt = brew_inventory.choose_kegs(prefix, [name], rack).receipt or {}
        requested = receipt.get("installed_on_request")
        source = receipt.get("source")
        source = source if isinstance(source, dict) else {}
        tap = source.get("tap")
        tap = tap if isinstance(tap, str) and tap else "-"
        lines.append("\t".join([name, _bool_text(requested if isinstance(requested, bool) else None), tap,
                                " ".join(k.version for k in rack.kegs)]))
    return "\n".join(lines) + "\n"


def casks_text(rooms: dict[str, brew_inventory.Room], links: Sequence[brew_inventory.RenameLink],
               packages: dict[str, model.Package]) -> str:
    """Return `casks.txt`: each Caskroom token with its two privileged flags, then each symlinked token's target

    The flags of a token the scan did not see are `unknown`.

    @param rooms     the Caskroom's entries, by token
    @param links     the Caskroom's symlinked tokens
    @param packages  the scan's casks of the instance, by token
    @returns         the file's text
    """
    lines = [CASKS_HEADER]
    for token in sorted(rooms):
        pkg = packages.get(token)
        lines.append("\t".join(["cask", token, _bool_text(pkg.privileged_install if pkg else None, "unknown"),
                                _bool_text(pkg.privileged_uninstall if pkg else None, "unknown"),
                                " ".join(rooms[token].versions)]))
    for link in sorted(links, key=lambda item: item.name):
        lines.append("\t".join(["link", link.name, link.target or "-"]))
    return "\n".join(lines) + "\n"


def _receipts(writer: _Writer, sub: str, racks: dict[str, brew_inventory.Rack],
              rooms: dict[str, brew_inventory.Room]) -> None:
    """Copy the receipt of every keg and every cask into `receipts/`

    @param writer  the snapshot's files
    @param sub     the instance's snapshot subdirectory
    @param racks   the Cellar's racks, by name
    @param rooms   the Caskroom's entries, by token
    """
    for name in sorted(racks):
        for keg in racks[name].kegs:
            src = os.path.join(keg.path, RECEIPT)
            if os.path.isfile(src):
                writer.copy(src, (sub, RECEIPTS, "Cellar", name, keg.version, RECEIPT))
    for token in sorted(rooms):
        src = os.path.join(rooms[token].path, ".metadata", RECEIPT)
        if os.path.isfile(src):
            writer.copy(src, (sub, RECEIPTS, "Caskroom", token, RECEIPT))


def _brewfile(writer: _Writer, sub: str, instance: Instance) -> None:
    """Run `brew bundle dump ... --no-restart` into a temporary name, kept as `Brewfile` only on success

    @param writer    the snapshot's files
    @param sub       the instance's snapshot subdirectory
    @param instance  the drivable Homebrew instance
    """
    final = writer.path(sub, BREWFILE)
    partial = final + PARTIAL
    _remove(partial)
    action = brew_actions.bundle_dump(instance, writer.runner.host_arch,
                                      writer.action_id(state.slug(instance.prefix), "brewfile"), partial)
    result = writer.runner.run(action)
    if result.exit == 0 and os.path.isfile(partial):
        os.replace(partial, final)
        writer.record(final)
        return
    _remove(partial)
    writer.note(f"{instance.prefix}: brew bundle dump exited {result.exit}; "
                "all-formulae.txt and casks.txt stand in for the Brewfile")


def _installed_json(writer: _Writer, sub: str, instance: Instance) -> None:
    """Write the raw `brew info --json=v2 --installed`, which the runner renames into place on exit 0

    @param writer    the snapshot's files
    @param sub       the instance's snapshot subdirectory
    @param instance  the drivable Homebrew instance
    """
    final = writer.path(sub, INSTALLED_JSON)
    action = dataclasses.replace(
        brew_actions.info_installed(instance, writer.runner.host_arch,
                                    writer.action_id(state.slug(instance.prefix), "installed")), dst=final)
    result = writer.runner.run(action)
    if result.exit == 0:
        writer.record(final)
        return
    _remove(final + PARTIAL)
    writer.note(f"{instance.prefix}: brew info --json=v2 --installed exited {result.exit}")


def _write_brew(writer: _Writer, bundle, instance: Instance, uid: int) -> None:
    """Write a Homebrew instance's snapshot; a drivable instance adds the Brewfile and `installed.json`

    @param writer    the snapshot's files
    @param bundle    the scan
    @param instance  the Homebrew instance
    @param uid       the user's uid, for the service probes
    """
    sub = "brew-" + state.slug(instance.prefix)
    racks, _ = brew_inventory.walk_cellar(instance.prefix)
    rooms, room_links = brew_inventory.walk_caskroom(instance.prefix)
    casks = {p.name: p for p in bundle.result.packages if p.instance_prefix == instance.prefix and p.kind == "cask"}
    writer.text((sub, FORMULAE), formulae_text(instance.prefix, racks))
    writer.text((sub, CASKS), casks_text(rooms, room_links, casks))
    _receipts(writer, sub, racks, rooms)
    writer.text((sub, SERVICES), model.to_json(_refreshed(writer.runner, _services_of(bundle, instance.prefix), uid)))
    if instance.drivable:
        _brewfile(writer, sub, instance)
        _installed_json(writer, sub, instance)


# MacPorts --------------------------------------------------------------------------

def installed_text(rows: Sequence[registry.PortRow]) -> str:
    """Return `installed.txt`: one line per registry row, in the registry's order

    @param rows  the registry's port rows
    @returns     the file's text
    """
    lines = [INSTALLED_HEADER]
    for row in rows:
        variants = " ".join(row.requested_variant_tokens) or "-"
        lines.append("\t".join([row.name, row.spec_args[1], _bool_text(row.requested), variants,
                                _bool_text(row.active), row.os_major or "-"]))
    return "\n".join(lines) + "\n"


def _registry_backup(writer: _Writer, sub: str, instance: Instance) -> str | None:
    """Back the live registry up under `registry/`, never copying the file itself

    @param writer    the snapshot's files
    @param sub       the instance's snapshot subdirectory
    @param instance  the MacPorts instance
    @returns         the backup's path, or None when there is no backup, which leaves a note
    """
    if not instance.portdbpath:
        writer.note(f"{instance.prefix}: no portdbpath, so no registry backup")
        return None
    final = writer.path(sub, REGISTRY)
    partial = final + PARTIAL
    _remove(partial)
    try:
        registry.backup_registry(instance.portdbpath, partial)
    except registry.RegistryMissing:
        writer.note(f"{instance.prefix}: no registry.db to back up")
    except (registry.RegistryBusy, sqlite3.DatabaseError, OSError) as exc:
        writer.note(f"{instance.prefix}: registry backup failed: {type(exc).__name__}: {exc}")
    else:
        os.replace(partial, final)
        return writer.record(final)
    _remove(partial)
    return None


def _installed(writer: _Writer, sub: str, instance: Instance, backup: str) -> None:
    """Write `installed.txt` from the registry backup

    @param writer    the snapshot's files
    @param sub       the instance's snapshot subdirectory
    @param instance  the MacPorts instance
    @param backup    the registry backup
    """
    try:
        with registry.Registry.open_backup(backup) as reg:
            rows = reg.ports()
    except (sqlite3.DatabaseError, OSError) as exc:
        writer.note(f"{instance.prefix}: installed.txt not written: {exc}")
        return
    writer.text((sub, INSTALLED), installed_text(rows))


def _records(writer: _Writer, instance: Instance, services: Sequence[Service]) -> None:
    """Write a MacPorts instance's registry backup, `installed.txt` and `services.json`

    @param writer    the snapshot's files
    @param instance  the MacPorts instance
    @param services  the instance's services
    """
    sub = "ports-" + state.slug(instance.prefix)
    backup = _registry_backup(writer, sub, instance)
    if backup is not None:
        _installed(writer, sub, instance, backup)
    writer.text((sub, SERVICES), model.to_json(list(services)))


def _select(writer: _Writer, sub: str, instance: Instance) -> None:
    """Write `select.txt`: the group lines of `port select --summary`, empty when it exits 1 (no group exists)

    @param writer    the snapshot's files
    @param sub       the instance's snapshot subdirectory
    @param instance  the drivable MacPorts instance
    """
    action = mp_actions.select_summary(instance, writer.runner.host_arch,
                                       writer.action_id(state.slug(instance.prefix), "select"))
    result = writer.runner.run(action)
    if result.exit == 0:
        lines = [line for line in result.stdout().splitlines()[2:] if line.strip()]
        writer.text((sub, SELECT), "".join(line + "\n" for line in lines))
    elif result.exit == 1:
        writer.text((sub, SELECT), "")
    else:
        writer.note(f"{instance.prefix}: port select --summary exited {result.exit}")


def _snapshot_id(writer: _Writer, instance: Instance, note: str) -> int | None:
    """Return the id of the snapshot just created, read from a fresh registry backup

    @param writer    the snapshot's files, which receive a note when the id cannot be read
    @param instance  the MacPorts instance
    @param note      the snapshot's note
    @returns         the id, or None when the registry cannot be read or no snapshot carries the note
    """
    if instance.portdbpath is None:
        raise ValueError(f"the MacPorts instance at {instance.prefix} has no portdbpath")
    try:
        with registry.Registry.open_copy(instance.portdbpath) as reg:
            return reg.snapshot_id(note)
    except (registry.RegistryMissing, registry.RegistryBusy, sqlite3.DatabaseError, OSError) as exc:
        writer.note(f"{instance.prefix}: snapshot id not read: {type(exc).__name__}: {exc}")
        return None


def _export(writer: _Writer, sub: str, instance: Instance, snap_id: int) -> None:
    """Run `sudo port -N snapshot --export <id>`, keeping its stdout when it is the snapshot JSON

    The exit status is ignored: it is 1 on every MacPorts release.

    @param writer    the snapshot's files
    @param sub       the instance's snapshot subdirectory
    @param instance  the drivable MacPorts instance
    @param snap_id   the snapshot's id
    """
    action = mp_actions.snapshot_export(instance, writer.runner.host_arch,
                                        writer.action_id(state.slug(instance.prefix), "export"), snap_id)
    result = writer.runner.run(action)
    text = result.stdout()
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    meta = data.get("metadata") if isinstance(data, dict) else None
    if isinstance(meta, dict) and meta.get("type") == SNAPSHOT_TYPE:
        writer.text((sub, PORTS_SNAPSHOT), text)
    else:
        writer.note(f"{instance.prefix}: snapshot --export {snap_id} exited {result.exit} "
                    f"without the {SNAPSHOT_TYPE} JSON")


def _port_snapshot(writer: _Writer, sub: str, instance: Instance) -> None:
    """Run `port snapshot --create` as a probe, write its id to `snapshot-id.txt`, then export it if the base can

    @param writer    the snapshot's files
    @param sub       the instance's snapshot subdirectory
    @param instance  the drivable MacPorts instance
    """
    note = snapshot_note(writer.run_dir)
    action = dataclasses.replace(
        mp_actions.snapshot_create(instance, writer.runner.host_arch,
                                   writer.action_id(state.slug(instance.prefix), "create"), note),
        on_failure=OnFailure.PROBE)
    result = writer.runner.run(action)
    snap_id = _snapshot_id(writer, instance, note)
    if snap_id is None:
        writer.note(f"{instance.prefix}: port snapshot --create exited {result.exit} "
                    f"and no snapshot carries the note {note!r}")
        return
    writer.text((sub, SNAPSHOT_ID), f"{snap_id}\n")
    if "snapshot_export" in instance.features:
        _export(writer, sub, instance, snap_id)


def _write_ports(writer: _Writer, bundle, instance: Instance, uid: int) -> None:
    """Write a MacPorts instance's snapshot; a drivable instance adds `select.txt` and a port snapshot

    @param writer    the snapshot's files
    @param bundle    the scan
    @param instance  the MacPorts instance
    @param uid       the user's uid, for the service probes
    """
    sub = "ports-" + state.slug(instance.prefix)
    _records(writer, instance, _refreshed(writer.runner, _services_of(bundle, instance.prefix), uid))
    if instance.drivable:
        _select(writer, sub, instance)
        if "snapshot" in instance.features:
            _port_snapshot(writer, sub, instance)


# Entry points ----------------------------------------------------------------------

def _local_snapshot(writer: _Writer) -> None:
    """Take an APFS local snapshot with `tmutil localsnapshot`; a failure leaves a note

    @param writer  the snapshot's files
    """
    action = system.probe(f"{writer.id_prefix}.snapshot.tmutil", [TMUTIL, "localsnapshot"], "APFS local snapshot")
    result = writer.runner.run(action)
    if result.exit != 0:
        writer.note(f"{DISK_NOTE}exited {result.exit}: {' '.join(result.stderr().split())}")


def write(runner, run_dir: state.RunDir, bundle, instances: Sequence[Instance], *, rc_files: Sequence[str] = (),
          plists: Sequence[str] = (), id_prefix: str = "1", local_snapshot: bool = True,
          uid: int | None = None) -> dict[str, str]:
    """Write the phase 1 snapshot of the instances, then its `complete` marker

    @param runner          the runner of the snapshot's commands
    @param run_dir         the run
    @param bundle          the scan
    @param instances       the instances to snapshot
    @param rc_files        the shell rc files to copy, which the environment cleanup may edit
    @param plists          plists to copy beside those of the instances' services
    @param id_prefix       the prefix of the action ids
    @param local_snapshot  take an APFS local snapshot as well
    @param uid             the user's uid; None for the scan's, else this process's
    @returns               the files written, by snapshot-relative path
    """
    writer = _Writer(runner, run_dir, id_prefix)
    if uid is None:
        recorded = bundle.result.system.get("uid")
        uid = recorded if isinstance(recorded, int) else os.getuid()
    prefixes = [inst.prefix for inst in instances]
    for inst in instances:
        if inst.manager is Manager.BREW:
            _write_brew(writer, bundle, inst, uid)
        else:
            _write_ports(writer, bundle, inst, uid)
    attributed = [svc.plist for svc in bundle.result.services if svc.instance_prefix in prefixes]
    for path in dict.fromkeys(attributed + list(plists)):
        if os.path.lexists(path):
            writer.copy(path, (PLISTS, state.slug(path)))
    for path in dict.fromkeys(rc_files):
        if os.path.lexists(path):
            writer.copy(path, (RC_FILES, state.slug(path)))
    if local_snapshot:
        _local_snapshot(writer)
    writer.finish()
    writer.text((COMPLETE,), state.now_iso() + "\n")
    return writer.written


def write_ports_records(run_dir: state.RunDir, instance: Instance, services: Sequence[Service]) -> dict[str, str]:
    """Write one MacPorts instance's registry backup, `installed.txt` and `services.json`

    No command runs: the manager repairs write these before `migrate --all`.

    @param run_dir   the run
    @param instance  the MacPorts instance
    @param services  the instance's services
    @returns         the files written, by snapshot-relative path, as `write` returns them
    """
    writer = _Writer(None, run_dir, "")
    _records(writer, instance, services)
    writer.finish()
    return writer.written


# Reading ---------------------------------------------------------------------------

@dataclass
class FormulaLine:
    """One line of `all-formulae.txt`"""

    name: str
    requested: bool | None       # installed_on_request; None without the field or the receipt
    tap: str | None
    versions: list[str]


@dataclass
class CaskLine:
    """One `cask` line of `casks.txt`"""

    token: str
    privileged_install: bool | None    # None: the scan did not know the cask
    privileged_uninstall: bool | None
    versions: list[str]


@dataclass
class CaskLink:
    """One `link` line of `casks.txt`: a symlinked Caskroom token and its target"""

    token: str
    target: str | None


@dataclass
class PortLine:
    """One line of `installed.txt`"""

    name: str
    version: str                    # the `@<version>_<revision><variants>` token
    requested: bool | None
    requested_variants: list[str]
    active: bool
    os_major: str | None

    @property
    def spec_args(self) -> list[str]:
        """Return the two argv tokens of the installed version

        @returns  the name and its `@<version>_<revision><variants>` token
        """
        return [self.name, self.version]


_BOOLS = {"true": True, "false": False}


def _rows(path: str) -> list[list[str]]:
    """Return the tab-separated cells of a snapshot text file, without blank and `#` lines

    @param path  the file
    @returns     one list of cells per line
    """
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    return [line.split("\t") for line in lines if line.strip() and not line.startswith("#")]


def _optional(text: str) -> str | None:
    """Return a cell's text, or None for an empty cell or `-`

    @param text  the cell
    @returns     the text, or None
    """
    return None if text in ("", "-") else text


def _words(text: str) -> list[str]:
    """Return a cell's words; an empty cell or `-` holds none

    @param text  the cell
    @returns     the words
    """
    return [] if text in ("", "-") else text.split()


def read_formulae(path: str) -> list[FormulaLine]:
    """Read `all-formulae.txt`; a short line's missing cells read as empty

    @param path  the file
    @returns     one line per formula
    """
    out = []
    for cells in _rows(path):
        cells += [""] * (4 - len(cells))
        out.append(FormulaLine(cells[0], _BOOLS.get(cells[1]), _optional(cells[2]), _words(cells[3])))
    return out


def read_casks(path: str) -> tuple[list[CaskLine], list[CaskLink]]:
    """Read `casks.txt`; a short line's missing cells read as empty

    @param path  the file
    @returns     the `cask` lines and the `link` lines
    """
    casks: list[CaskLine] = []
    links: list[CaskLink] = []
    for cells in _rows(path):
        cells += [""] * (5 - len(cells))
        if cells[0] == "cask":
            casks.append(CaskLine(cells[1], _BOOLS.get(cells[2]), _BOOLS.get(cells[3]), _words(cells[4])))
        elif cells[0] == "link":
            links.append(CaskLink(cells[1], _optional(cells[2])))
    return casks, links


def read_installed(path: str) -> list[PortLine]:
    """Read `installed.txt`; a short line's missing cells read as empty

    @param path  the file
    @returns     one line per registry row
    """
    out = []
    for cells in _rows(path):
        cells += [""] * (6 - len(cells))
        out.append(PortLine(cells[0], cells[1], _BOOLS.get(cells[2]), _words(cells[3]), cells[4] == "true",
                            _optional(cells[5])))
    return out


def read_services(path: str) -> list[Service]:
    """Read `services.json`

    @param path  the file
    @returns     the services it lists
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return [model.from_dict(Service, item) for item in data if isinstance(item, dict)]


def read_select(path: str) -> list[tuple[str, str]]:
    """Return `(group, selected option)` for every group line of `select.txt`

    @param path  the file
    @returns     the pairs, in file order
    """
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh.read().splitlines():
            words = line.split()
            if len(words) >= 2:
                out.append((words[0], words[1]))
    return out


def read_snapshot_id(path: str) -> int | None:
    """Read `snapshot-id.txt`

    @param path  the file
    @returns     the snapshot's id, or None when the file is absent or holds no number
    """
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read().strip()
    except FileNotFoundError:
        return None
    return int(text) if text.isdigit() else None


def covered(run_dir: state.RunDir) -> list[tuple[Manager, str]]:
    """Return the instances a snapshot holds, from its `brew-<slug>` and `ports-<slug>` directories

    @param run_dir  the run
    @returns        each instance's manager and prefix, in directory order
    """
    root = snapshot_dir(run_dir)
    try:
        names = sorted(os.listdir(root))
    except FileNotFoundError:
        return []
    out = []
    for name in names:
        for manager, head in ((Manager.BREW, "brew-"), (Manager.PORTS, "ports-")):
            if name.startswith(head) and os.path.isdir(os.path.join(root, name)):
                out.append((manager, name[len(head):].replace("%", "/")))
    return out


_CASK_LINE = re.compile(r"""^\s*cask\s+["']([^"']+)["']""")


def filter_brewfile(text: str, drop: Iterable[str]) -> str:
    """Return the `Brewfile` without the `cask` lines of the given tokens, tap-qualified or not

    @param text  the Brewfile's text
    @param drop  the cask tokens to drop
    @returns     the text without their lines
    """
    tokens = {t.rsplit("/", 1)[-1] for t in drop}
    kept = []
    for line in text.splitlines(True):
        m = _CASK_LINE.match(line)
        if m and m.group(1).rsplit("/", 1)[-1] in tokens:
            continue
        kept.append(line)
    return "".join(kept)

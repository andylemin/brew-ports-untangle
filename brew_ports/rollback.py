"""`rollback RUN-ID`: reinstall what an `apply` or `doctor --fix` run removed, from its snapshot, and replay its backups

Every command is a probe, so a failure is recorded and the next command runs.
"""

from __future__ import annotations

import abc
import dataclasses
import difflib
import json
import os
import re
import shlex
import shutil
import sqlite3
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeGuard

from . import env, model, report, servicectl, snapshot, state, system
from .context import Context
from .env import services as env_services, shell as env_shell
from .homebrew import actions as brew_actions, inventory as brew_inventory, locate as brew_locate
from .macports import actions as mp_actions, locate as mp_locate, registry
from .model import Action, Instance, Manager, OnFailure, Package, Plan, Service, Usability
from .plan_sets import name_key
from .runner import (CP, RM, SUDO, BaseRunner, EscalationFailed, PreflightError, Result, RootFiles, sha256_bytes,
                     start_run)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_VERIFY = 5

PHASE = "rollback"
CHSH = system.CHSH
TAR = system.TAR
GIT = system.GIT
CORE_TAP = "homebrew/core"
START = "7.start."
SHELL_ID = "5.shell"
LAUNCH_AGENTS = os.path.join("Library", "LaunchAgents")
BREW_RELEASES = "https://github.com/Homebrew/brew/releases/latest"
BREW_REPOSITORY = "https://github.com/Homebrew/brew"
INSTALL_SCRIPT = "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"
MACPORTS_SOURCE = "https://guide.macports.org/#installing.macports.source"
MACPORTS_CONFS = ("sources.conf", "macports.conf", "variants.conf")
ARCHIVES = ((".repository.tar.gz", "-xzpf"), (".tar.gz", "-xzpf"), (".tgz", "-xzpf"), (".tar", "-xpf"))
STASH_PATCH = ".stash.patch"
REGISTRY_ERRORS = (registry.RegistryBusy, sqlite3.DatabaseError, OSError)

# An absolute path inside a line of a shell file or of /etc/paths.
_PATH_TOKEN = re.compile(r"(?<![\w.~$/])/[^\s\"'`:;()=<>|&$]+")


# Small helpers -------------------------------------------------------------------------

def shown(action: Action) -> str:
    """Return a command as the report prints it, with the `sudo` the runner adds

    @param action  a command action
    @returns       the command line, shell-quoted
    """
    return ("sudo " if action.sudo else "") + shlex.join(action.argv)


def probe(action: Action) -> Action:
    """Return `action` as a rollback command: a probe, not read-only, so it has no timeout and is journaled

    @param action  a command action of a manager's actions module
    @returns       a copy with the `PROBE` policy, no timeout and `read_only` False
    """
    return dataclasses.replace(action, on_failure=OnFailure.PROBE, read_only=False, timeout_s=None)


def unsudo(argv: Sequence[Any]) -> list[str]:
    """Return a journaled argv without the `sudo -n [--preserve-env=...] --` the runner adds

    @param argv  the journaled command line
    @returns     its words as text, from the command sudo runs
    """
    words = [str(word) for word in argv]
    if words and words[0] == SUDO and "--" in words:
        return words[words.index("--") + 1:]
    return words


def _ran(entry: dict[str, Any]) -> bool:
    """Return whether `entry` is a journaled command line that exited 0

    @param entry  a journal entry
    @returns      True for an `argv` with exit 0
    """
    return isinstance(entry.get("argv"), list) and entry.get("exit") == 0


def _after(words: Sequence[str], *sequence: str) -> str | None:
    """Return the word that follows `sequence` in `words`, or None

    @param words     a command line
    @param sequence  the words to find, in order
    @returns         the word after their first match; None without one
    """
    size = len(sequence)
    for index in range(len(words) - size):
        if tuple(words[index:index + size]) == sequence:
            return words[index + size]
    return None


def _read_bytes(path: str | None) -> bytes | None:
    """Return the content of a file

    @param path  the file, or None
    @returns     the bytes; None without a path or when the file cannot be read
    """
    if not path:
        return None
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _text(data: bytes | None) -> str | None:
    """Decode a file's content as UTF-8

    @param data  the bytes, or None
    @returns     the text; None without bytes or when they are not UTF-8
    """
    if data is None:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _lines(text: str | None) -> list[str]:
    """Return the lines of a text that are not blank, stripped

    @param text  the text, or None
    @returns     the lines; none for None
    """
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def _third_party(tap: str | None) -> TypeGuard[str]:
    """Return whether `tap` is a `user/repo` tap other than homebrew/core

    @param tap  a formula's `source.tap`, or None
    @returns    True for a third-party tap
    """
    return bool(tap and tap != CORE_TAP and tap.count("/") == 1)


def etc_rel(path: str) -> str:
    """Return an `/etc` file's path below `/etc` (`paths.d/homebrew`), the name of its copy in `<run>/backup/etc/`

    @param path  an `/etc` file, `/private/etc` included
    @returns     the path below the last `/etc/`; the basename when there is none
    """
    marker = "/etc/"
    index = path.rfind(marker)
    return path[index + len(marker):] if index >= 0 else os.path.basename(path)


def diff_lines(path: str, current: str | None, before: str | None) -> list[str]:
    """Return the unified diff from the file's current text to its text before the run

    @param path     the file, for the diff's headers
    @param current  its current text; None counts as empty
    @param before   its text before the run; None counts as empty
    @returns        the diff's lines, without line ends
    """
    lines = difflib.unified_diff((current or "").splitlines(True), (before or "").splitlines(True),
                                 fromfile=f"{path} (current)", tofile=f"{path} (before the run)")
    return [line.rstrip("\n") for line in lines]


# The run being rolled back -------------------------------------------------------------

class SourceError(Exception):
    """The run's records cannot be read (exit 3)"""


@dataclass
class SourceRun:
    """The run `rollback` undoes: its snapshot, plan (None for `doctor --fix`), recorded instances and journal"""

    run_dir: state.RunDir
    plan: Plan | None
    covered: list[tuple[Manager, str]]
    recorded: list[Instance]
    entries: list[dict[str, Any]]

    def describe(self) -> str:
        """Name the kind of run for the first line of the preview

        @returns  an apply run with its target, a `doctor --fix` run, or a run
        """
        if self.plan is not None:
            return f"an apply run with the target {self.plan.target.value} at {self.plan.target_prefix}"
        if os.path.isfile(self.run_dir.sub("doctor.json")):
            return "a doctor --fix run"
        return "a run"


def _scan_instances(path: str) -> list[Instance]:
    """Return the instances a run's `scan.json` records; none when it cannot be read

    @param path  the run's `scan.json`
    @returns     the instances
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return [model.from_dict(Instance, item) for item in data.get("instances") or [] if isinstance(item, dict)]
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return []


def load_source(state_dir: state.StateDir, run_id: str) -> SourceRun:
    """Return the `SourceRun` of `run_id`: its snapshot directories, plan and journal

    @param state_dir           the state directory that holds the run
    @param run_id              the id `rollback RUN-ID` names
    @returns                   the run; without a plan, its instances come from its `scan.json`
    @throws ValueError         when the id cannot name a run
    @throws FileNotFoundError  when no run has that id
    @throws SourceError        when its `plan.json` cannot be read
    """
    run_dir = state_dir.run(run_id)
    plan: Plan | None = None
    path = run_dir.sub("plan.json")
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                plan = model.from_json(Plan, fh.read())
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise SourceError(f"{path} cannot be read: {exc}") from None
    recorded = list(plan.instances) if plan is not None else _scan_instances(run_dir.sub("scan.json"))
    return SourceRun(run_dir, plan, snapshot.covered(run_dir), recorded, run_dir.journal.entries())


def adopted_tokens(plan: Plan | None, prefix: str) -> set[str]:
    """Return the casks of `prefix` that another instance adopted in the run, which stay with it

    @param plan    the run's plan; None for a `doctor --fix` run
    @param prefix  a source Homebrew prefix
    @returns       the cask tokens; none without a plan
    """
    if plan is None:
        return set()
    tokens = {name for kind, name in plan.removal_set.get(prefix, []) if kind == "cask-adopted"}
    tokens |= {m.source.name for m in plan.mappings if m.adopt and m.source.instance_prefix == prefix}
    return tokens


@dataclass
class Started:
    """A target service phase 7 started

    Phase 7 journals its command as `7.start.<label>`.
    """

    label: str
    manager: Manager
    name: str                        # the formula or the port


def phase7_starts(entries: Sequence[dict[str, Any]]) -> list[Started]:
    """Return the target services the run's phase 7 started

    They are its `7.start.<label>` commands that exited 0: a `brew services start` or a `port load`.

    @param entries  the run's journal entries
    @returns        one per label, in journal order
    """
    found: dict[str, Started] = {}
    for entry in entries:
        action_id = str(entry.get("action_id") or "")
        if entry.get("phase") != 7 or not action_id.startswith(START) or not _ran(entry):
            continue
        argv = unsudo(entry["argv"])
        label = action_id[len(START):]
        formula = _after(argv, "services", "start")
        port = _after(argv, "load")
        if formula:
            found[label] = Started(label, Manager.BREW, formula)
        elif port:
            found[label] = Started(label, Manager.PORTS, port)
    return list(found.values())


def brew_labels(started: Started) -> list[str]:
    """Return the labels a Homebrew job phase 7 started may be loaded under

    They are the journaled one, `sh.brew.<f>` and `homebrew.mxcl.<f>` for the formula `<f>`.

    @param started  a Homebrew start of phase 7
    @returns        the labels, each once
    """
    return list(dict.fromkeys([started.label, "sh.brew." + started.name, "homebrew.mxcl." + started.name]))


@dataclass
class Undone:
    """A target start of phase 7 that the rollback stopped, and what finishes or reverses the stop"""

    started: Started
    booted: list[Service] = field(default_factory=list)   # Homebrew jobs booted out; their plists start them again
    stale: list[Service] = field(default_factory=list)    # Homebrew jobs whose plists go once a replaced service is up


def _replaced(service: Service, source: Package) -> bool:
    """Return whether a recorded service is one phase 7 replaces for a mapped source package

    @param service  a service the snapshot recorded
    @param source   the source package of one of the plan's mappings
    @returns        True for an owned service, loaded at snapshot time, of that package
    """
    kind = source.kind
    return (service.owned and service.loaded and service.instance_prefix == source.instance_prefix
            and service.package_kind == kind and name_key(kind, service.package or "") == name_key(kind, source.name))


@dataclass
class ShellSwitch:
    """Phase 5's `chsh -s <new> <user>` and the shell it replaced"""

    user: str
    new: str
    old: str | None


def _replaces(old: str | None, new: str) -> bool:
    """Return whether phase 5 replaced `old` with `new`

    @param old  a login shell from before the run, or None
    @param new  the shell phase 5 set
    @returns    True for the same basename at another path
    """
    return bool(old and old != new and os.path.basename(old) == os.path.basename(new))


def _scan_login_shell(path: str) -> str | None:
    """Return the login shell a run's `scan.json` records

    @param path  the `scan.json`
    @returns     the shell; None when the file cannot be read or records none
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    shell = ((data.get("environment") or {}) if isinstance(data, dict) else {}).get("login_shell")
    return shell if isinstance(shell, str) else None


def _recorded_shells(source: SourceRun, state_dir: state.StateDir) -> Iterator[str]:
    """Yield the login shells the scans recorded: the run's own, the plan's run's, then older runs, newest first

    @param source     the run being rolled back
    @param state_dir  the state directory, for the plan's run and the older runs
    @returns          an iterator over the shells, in that order
    """
    paths = [source.run_dir.sub("scan.json")]
    if source.plan is not None and source.plan.run_id:
        paths.append(os.path.join(state_dir.runs, source.plan.run_id, "scan.json"))
    older = [run_id for run_id in state_dir.run_ids() if run_id < source.run_dir.run_id]
    paths += [os.path.join(state_dir.runs, run_id, "scan.json") for run_id in reversed(older)]
    for path in paths:
        shell = _scan_login_shell(path)
        if shell:
            yield shell


def shell_switch(source: SourceRun, state_dir: state.StateDir) -> ShellSwitch | None:
    """Return the login shell switch of phase 5, from the last `5.shell` `chsh -s <new> <user>` that exited 0

    The old shell comes from a `5.shell` record's `from` field, else from the first recorded login shell
    that `<new>` replaces.

    @param source     the run being rolled back
    @param state_dir  the state directory, for the login shells older scans recorded
    @returns          the switch; None without such a command
    """
    new = user = old = None
    for entry in source.entries:
        if entry.get("action_id") != SHELL_ID:
            continue
        if isinstance(entry.get("from"), str):
            old = entry["from"]
        if _ran(entry):
            argv = unsudo(entry["argv"])
            target = _after(argv, "-s")
            if argv and argv[0] == CHSH and target:
                new, user = target, argv[-1]
    if not new or not user:
        return None
    if not _replaces(old, new):
        old = next((shell for shell in _recorded_shells(source, state_dir) if _replaces(shell, new)), None)
    return ShellSwitch(user, new, old)


@dataclass
class FileChange:
    """A file the run wrote or removed"""

    path: str                        # what was written or removed (its realpath)
    root: bool                       # a root-owned file, kept in the root backup store
    sha256: str | None            # what the run left; None when it removed the file
    original: str | None          # a readable copy of the file before the run; None when it did not exist
    known: bool                      # False: the file before the run cannot be read (only the root store holds it)
    store: str | None = None      # the root backup store copy


def _change(source: SourceRun, path: str, *, root: bool, sha: str | None, backup: str | None,
            store: str | None) -> FileChange:
    """Return the change of one file, with its copy from before the run when that can be read

    @param source  the run that changed the file
    @param path    the file
    @param root    whether the file is root-owned, its copy from before the run kept under the run's `backup/etc`
    @param sha     the SHA-256 of what the run left; None when it removed the file
    @param backup  a file's copy from before the run's first write, or None; unused for a root-owned file
    @param store   the root backup store copy; None names the run's default one
    @returns       the change
    """
    if root:
        copy = source.run_dir.sub("backup", "etc", etc_rel(path))
        known = os.path.isfile(copy)
        store = store or f"{RootFiles.STORE_PARENT}/{source.run_dir.run_id}/{state.slug(path)}"
        return FileChange(path, True, sha, copy if known else None, known, store)
    if backup is None:
        return FileChange(path, False, sha, None, True)
    known = os.path.isfile(backup)
    return FileChange(path, False, sha, backup if known else None, known)


def file_changes(source: SourceRun) -> list[FileChange]:
    """Return the files the run changed: its `write` records and the root files it backed up and removed

    Per path, the last write gives the SHA-256 and the first the backup, the copy from before the run.

    @param source  the run being rolled back
    @returns       one change per path, in the order the journal first changes it
    """
    stores: dict[str, str] = {}
    first: dict[str, str | None] = {}
    last: dict[str, str | None] = {}
    root: dict[str, bool] = {}
    for entry in source.entries:
        path = entry.get("path")
        if entry.get("kind") == "write" and isinstance(path, str) and entry.get("sha256"):
            backup = entry.get("backup")
            first.setdefault(path, backup if isinstance(backup, str) else None)
            last[path] = str(entry["sha256"])
            root[path] = bool(entry.get("root"))
            continue
        if not _ran(entry):
            continue
        argv = unsudo(entry["argv"])
        if argv[:3] == [CP, "-n", "-p"] and len(argv) == 5:
            stores.setdefault(argv[3], argv[4])
        elif argv[:1] == [RM]:
            for word in argv[1:]:
                if word in stores:
                    last[word] = None
                    root[word] = True
    return [_change(source, path, root=root[path], sha=sha, backup=first.get(path), store=stores.get(path))
            for path, sha in last.items()]


def _restore_line(path: str, name: str) -> str:
    """Return the line that names what an archive restores and the command that restores it by hand

    @param path  the archive
    @param name  its file name: a slug with an archive or `.stash.patch` suffix
    @returns     `<restored path>: <command>`; for a file of another kind, an instruction to restore it by hand
    """
    for suffix, flags in ARCHIVES:
        if name.endswith(suffix):
            return f"{state.unslug(name[:-len(suffix)])}: sudo {TAR} {flags} {shlex.quote(path)} -C /"
    if name.endswith(STASH_PATCH):
        repo = state.unslug(name[:-len(STASH_PATCH)])
        return f"{repo}: {GIT} -C {shlex.quote(repo)} apply {shlex.quote(path)}"
    return f"{path}: restore it by hand"


def archive_lines(run_dir: state.RunDir) -> list[str]:
    """Return the run's data and stray-file archives, each with the command that restores it by hand

    @param run_dir  the run being rolled back
    @returns        one line per archive; a `.partial` file is left out
    """
    out: list[str] = []
    for directory in (run_dir.sub("data-archive"), run_dir.sub("backup", "strays")):
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            path = os.path.join(directory, name)
            if os.path.isfile(path) and not name.endswith(".partial"):
                out.append(_restore_line(path, name))
    return out


# The instances on the host ----------------------------------------------------------------

def match(instances: Sequence[Instance], manager: Manager, prefix: str) -> Instance | None:
    """Return the instance of `manager` at `prefix`: by identity while the path exists, else by spelling

    @param instances  the instances found on the host, or the run's records
    @param manager    Homebrew or MacPorts
    @param prefix     a covered prefix
    @returns          the instance; None when none matches
    """
    return brew_locate.find_by_path([inst for inst in instances if inst.manager is manager], prefix)


def _holds_homebrew(prefix: str) -> bool:
    """Return whether a prefix still holds a Homebrew: `bin/brew`, `Cellar` or the repository's `Library/Homebrew`

    @param prefix  a covered prefix
    @returns       True when one of them exists
    """
    return (os.path.isfile(os.path.join(prefix, "bin", "brew")) or os.path.isdir(os.path.join(prefix, "Cellar"))
            or os.path.isdir(os.path.join(brew_locate.repository_of(prefix), "Library", "Homebrew")))


def _probe_prefix(runner, environ: dict[str, str], manager: Manager, prefix: str) -> Instance | None:
    """Return the instance at a covered prefix that neither discovery pass found, probed directly, or None

    @param runner   the runner of the probes
    @param environ  the user's environment; MacPorts is probed without its `PATH`
    @param manager  the manager the snapshot covers at the prefix
    @param prefix   the prefix
    @returns        the instance; None when the prefix is gone or holds no such manager
    """
    ident = system.identity(prefix)
    if ident is None:
        return None
    if manager is Manager.BREW:
        if not _holds_homebrew(prefix):
            return None
        return brew_locate.probe_instance(runner, prefix, ident, [prefix], environ=environ, host_arch=runner.host_arch)
    if not os.path.isfile(os.path.join(prefix, mp_locate.CONF_REL)):
        return None
    alone = {key: value for key, value in environ.items() if key != "PATH"}
    found = mp_locate.find_instances(runner, alone, runner.host_arch, default_prefix=prefix, etc_paths=os.devnull)
    return match(found, Manager.PORTS, prefix)


def locate(runner, environ: dict[str, str], covered: Sequence[tuple[Manager, str]]) -> list[Instance]:
    """Return the host's instances: both discovery passes afresh, plus every covered prefix they missed

    Phase 7 takes a removed manager off PATH, so the passes miss a prefix that may still hold it.

    @param runner   the runner of the probes
    @param environ  the user's environment
    @param covered  the managers and prefixes the snapshot covers
    @returns        the instances found
    """
    found = list(brew_locate.find_instances(runner, environ, runner.host_arch))
    found += mp_locate.find_instances(runner, environ, runner.host_arch)
    for manager, prefix in covered:
        if match(found, manager, prefix) is None:
            extra = _probe_prefix(runner, environ, manager, prefix)
            if extra is not None:
                found.append(extra)
    return found


def placeholder(manager: Manager, prefix: str) -> Instance:
    """Return an instance known only by its snapshot directory, for matching text that names it

    @param manager  the manager the snapshot covers
    @param prefix   the prefix it covers
    @returns        an undrivable instance with the manager's own layout under the prefix
    """
    brew = manager is Manager.BREW
    return Instance(manager=manager, prefix=prefix, identity=system.identity(prefix) or (0, 0), spellings=(prefix,),
                    binary=os.path.join(prefix, "bin", "brew" if brew else "port"), version=None, arch=None,
                    usability=Usability.MISSING_BINARY, usability_detail=None, drivable=False, inventory_error=None,
                    repository=None, cache_dir=None,
                    portdbpath=None if brew else os.path.join(prefix, "var", "macports"), applications_dir=None,
                    owned_roots=brew_locate.owned_roots(prefix) if brew else (prefix,))


def reinstall_lines(manager: Manager, prefix: str, host_arch: str, source: SourceRun) -> list[str]:
    """Return the lines that bring back the manager of a skipped instance, then for MacPorts the files to compare

    @param manager    the skipped instance's manager
    @param prefix     its prefix
    @param host_arch  the host's architecture, `arm64` or `x86_64`
    @param source     the run being rolled back, whose data archive may hold the MacPorts configuration
    @returns          the lines, as the preview prints them
    """
    norm = os.path.normpath(prefix)
    if manager is Manager.BREW:
        default = brew_locate.ARM64_PREFIX if host_arch == "arm64" else brew_locate.USR_LOCAL
        if host_arch == "arm64" and norm == brew_locate.USR_LOCAL:
            return [f'reinstall the Intel Homebrew: arch -x86_64 /bin/bash -c "$(curl -fsSL {INSTALL_SCRIPT})"']
        if norm == default:
            return [f"reinstall Homebrew from the .pkg of {BREW_RELEASES}"]
        return [f"reinstall Homebrew at {prefix}: git clone {BREW_REPOSITORY} {shlex.quote(prefix)}"]
    if norm == mp_locate.DEFAULT_PREFIX:
        lines = ["reinstall MacPorts with `brew-ports bootstrap-ports`"]
    else:
        lines = [f"reinstall MacPorts from source with ./configure --prefix={prefix} ({MACPORTS_SOURCE})"]
    archive = source.run_dir.sub("data-archive", state.slug(os.path.join(prefix, "etc")) + ".tar.gz")
    if os.path.isfile(archive):
        inside = os.path.join(prefix, "etc", "macports").lstrip("/")
        for name in MACPORTS_CONFS:
            lines.append(f"then compare {prefix}/etc/macports/{name} with "
                         f"`tar -xzf {shlex.quote(archive)} -O {inside}/{name}`")
    return lines


# What the host holds ----------------------------------------------------------------------

def brew_present(prefix: str) -> tuple[set[str], set[str]]:
    """Return the formula racks and cask tokens on disk, rename links left out

    @param prefix  a Homebrew prefix
    @returns       the rack names and the Caskroom tokens
    """
    racks, _ = brew_inventory.walk_cellar(prefix)
    rooms, _ = brew_inventory.walk_caskroom(prefix)
    return set(racks), set(rooms)


@dataclass
class RegistryView:
    """The rows and snapshot ids of a fresh registry backup, never of the live registry"""

    rows: list[registry.PortRow]
    snapshot_ids: set[int]

    def active_names(self) -> set[str]:
        """Return the names of the active ports

        @returns  the names, lowercased
        """
        return {row.name.lower() for row in self.rows if row.active}

    def active_row(self, name: str) -> registry.PortRow | None:
        """Return the active row of a port

        @param name  the port, matched without case
        @returns     the row; None when the port is not active
        """
        return next((row for row in self.rows if row.active and row.name.lower() == name.lower()), None)

    def holds(self, name: str, version: str) -> bool:
        """Return whether the registry holds a version of a port, active or not

        @param name     the port, matched without case
        @param version  the version as `spec_args` gives it, such as `@1.3_0`
        @returns        True when a row matches both
        """
        return any(row.name.lower() == name.lower() and row.spec_args[1] == version for row in self.rows)


def read_registry(portdbpath: str | None) -> tuple[RegistryView | None, str | None]:
    """Return a view of a fresh registry backup, or why there is none (`missing`: no registry)

    @param portdbpath  the instance's `portdbpath`, or None
    @returns           the view and None, or None and the reason
    """
    if not portdbpath:
        return None, "missing"
    try:
        with registry.Registry.open_copy(portdbpath) as reg:
            return RegistryView(reg.ports(), {snap.id for snap in reg.snapshots()}), None
    except registry.RegistryMissing:
        return None, "missing"
    except REGISTRY_ERRORS as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _selected(text: str) -> dict[str, str]:
    """Return the selected option of each group from `port select --summary`, its two header lines skipped

    @param text  the summary
    @returns     the option by group
    """
    out: dict[str, str] = {}
    for line in text.splitlines()[2:]:
        words = line.split()
        if len(words) >= 2:
            out[words[0]] = words[1]
    return out


# One instance ---------------------------------------------------------------------------

@dataclass
class Gap:
    """A package, service or selection that did not come back, which makes the exit 5"""

    prefix: str
    kind: str                        # formula, cask, port, service, selection
    name: str
    reason: str

    def line(self) -> str:
        """Return the gap as the report lists it

        @returns  `<prefix>: <kind> <name>: <reason>`
        """
        return f"{self.prefix}: {self.kind} {self.name}: {self.reason}"


@dataclass
class Unit:
    """One covered instance: the instance at its prefix on the host, the one the run recorded, and why it is skipped"""

    manager: Manager
    prefix: str
    snapdir: str
    fresh: Instance | None
    recorded: Instance | None
    skip: str | None = None

    @property
    def title(self) -> str:
        """Return the unit's heading in the preview

        @returns  the prefix and the manager, such as `/opt/local (MacPorts)`
        """
        return f"{self.prefix} ({'Homebrew' if self.manager is Manager.BREW else 'MacPorts'})"


def skip_reason(unit: Unit) -> str | None:
    """Return why a unit is skipped: no instance, no manager binary, or not drivable; None to roll it back

    @param unit  a unit with its instance on the host matched
    @returns     the reason the preview prints, or None
    """
    inst = unit.fresh
    tool = "brew" if unit.manager is Manager.BREW else "port"
    if inst is None:
        return f"no {tool} instance is found at {unit.prefix}"
    if not inst.binary:
        return f"its {tool} is missing"
    if not inst.drivable:
        detail = f": {inst.usability_detail}" if inst.usability_detail else ""
        return f"it cannot be driven ({inst.usability.value}{detail})"
    return None


class _Part(abc.ABC):
    """The rollback of one unit; the subclasses know their manager"""

    def __init__(self, rb: "Rollback", unit: Unit) -> None:
        """Read the unit's recorded services; the subclass reads the rest of its snapshot

        @param rb    the rollback the part belongs to
        @param unit  the unit it restores
        """
        self.rb = rb
        self.unit = unit
        self.prefix = unit.prefix
        self.notes: list[str] = []
        self.actions: list[Action] = []
        self.services: list[Service] = self.read(snapshot.read_services, snapshot.SERVICES, [])
        self.waiting: list[Service] = []   # services recorded loaded that are down at preview time
        self.up: set[str] = set()          # labels of the services recorded loaded that are up after `start_services`

    @property
    def inst(self) -> Instance:
        """Return the instance on the host, which every part that is not skipped has

        @returns  the unit's fresh instance
        """
        if self.unit.fresh is None:
            raise RuntimeError(f"{self.prefix}: no instance on the host, so the part is skipped")
        return self.unit.fresh

    @property
    def host(self) -> str:
        """Return the host's architecture, which the manager commands name

        @returns  `arm64` or `x86_64`
        """
        return self.rb.runner.host_arch

    def file(self, name: str) -> str:
        """Return the path of one of the unit's snapshot files

        @param name  the file's name, such as `all-formulae.txt`
        @returns     its path in the unit's snapshot directory
        """
        return os.path.join(self.unit.snapdir, name)

    def read(self, reader: Callable[[str], Any], name: str, default: Any) -> Any:
        """Read one of the unit's snapshot files, noting a file that cannot be read

        @param reader   the snapshot module's reader of the file
        @param name     the file's name
        @param default  the value without the file, or when it cannot be read
        @returns        what the reader returns, else the default
        """
        path = self.file(name)
        if not os.path.isfile(path):
            return default
        try:
            return reader(path)
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            self.notes.append(f"{path} cannot be read: {exc}")
            return default

    def action_id(self, *parts: str) -> str:
        """Return a rollback action id for the unit

        @param parts  the words after the prefix's slug
        @returns      `rollback.<slug>` and the parts, joined by dots
        """
        return ".".join((PHASE, state.slug(self.prefix)) + parts)

    def gap(self, kind: str, name: str, reason: str) -> None:
        """Record something of the unit that did not come back

        @param kind    formula, cask, port, service or selection
        @param name    its name or label
        @param reason  why, as the report prints it
        """
        self.rb.gaps.append(Gap(self.prefix, kind, name, reason))

    def binary(self, tool: str) -> str:
        """Return the manager's binary for the lines the preview prints

        @param tool  `brew` or `port`
        @returns     the binary of the instance on the host, else of the recorded one, else `<prefix>/bin/<tool>`
        """
        inst = self.unit.fresh or self.unit.recorded
        return inst.binary if inst is not None and inst.binary else os.path.join(self.prefix, "bin", tool)

    # The interface of the subclasses
    @abc.abstractmethod
    def prepare(self) -> None:
        """Build the actions that restore this instance"""

    @abc.abstractmethod
    def skipped(self, reason: str) -> None:
        """Record what a skipped instance does not get back as gaps

        @param reason  why it is not restored
        """

    @abc.abstractmethod
    def busy(self) -> bool:
        """Return whether the part has anything to run

        @returns  True for a command to run or a service to start
        """

    @abc.abstractmethod
    def describe(self) -> list[str]:
        """Return what is absent from this instance and what the rollback runs to restore it

        @returns  the preview's lines of the part
        """

    @abc.abstractmethod
    def run(self) -> None:
        """Run the part's commands but the service starts; each is a probe, so a failure leaves the next to run"""

    @abc.abstractmethod
    def start_services(self) -> None:
        """Start each owned service recorded loaded that is down, and note in `up` those up afterwards"""

    @abc.abstractmethod
    def finish(self) -> None:
        """Record what is still absent once the commands ran as gaps"""

    @abc.abstractmethod
    def back(self) -> bool:
        """Return whether every package the part reinstalls is on the host

        @returns  True when none of them is still absent
        """

    def offers(self) -> list[str]:
        """Return the manual ways back the preview offers besides the rollback

        @returns  the lines; none unless the manager has some
        """
        return []


class _Brew(_Part):
    """The rollback of a Homebrew instance: the filtered `Brewfile`, else one install per absent package

    Without a `Brewfile`, as for an instance undrivable at snapshot time: taps, casks, requested formulae.
    Then the absent formulae not recorded as requested, then the services.
    """

    def __init__(self, rb: "Rollback", unit: Unit) -> None:
        """Read the instance's snapshot and sort its absent packages by what the rollback does with them

        @param rb    the rollback the part belongs to
        @param unit  a Homebrew unit
        """
        super().__init__(rb, unit)
        self.formulae: list[snapshot.FormulaLine] = self.read(snapshot.read_formulae, snapshot.FORMULAE, [])
        self.casks: list[snapshot.CaskLine] = self.read(snapshot.read_casks, snapshot.CASKS, ([], []))[0]
        path = self.file(snapshot.BREWFILE)
        self.brewfile = path if os.path.isfile(path) else None
        self.adopted = adopted_tokens(rb.source.plan, unit.prefix)
        formulae, casks = brew_present(self.prefix)
        self.absent = [line for line in self.formulae if line.name not in formulae]
        missing = [line for line in self.casks if line.token not in casks]
        self.staying = [line for line in missing if line.token in self.adopted]
        self.held = [line for line in missing if line.token not in self.adopted and line.privileged_install is True]
        self.to_install = [line for line in missing if line not in self.staying and line not in self.held]
        self.followups = [line for line in self.absent if line.requested is not True]

    def skipped(self, reason: str) -> None:
        """Record every absent formula and every absent cask but the adopted ones as gaps

        @param reason  why the instance is not restored
        """
        for line in self.absent:
            self.gap("formula", line.name, reason)
        for line in self.held + self.to_install:
            self.gap("cask", line.token, reason)

    def taps(self) -> list[str]:
        """Return every third-party `source.tap` of `all-formulae.txt`, once each, in file order

        @returns  the taps
        """
        out: list[str] = []
        for line in self.formulae:
            if _third_party(line.tap) and line.tap not in out:
                out.append(line.tap)
        return out

    def install(self, line: snapshot.FormulaLine) -> Action:
        """Build the probe that installs one absent formula, as a dependency when it is recorded as one

        @param line  the formula's line of `all-formulae.txt`
        @returns     the `brew install --formula` action
        """
        # A formula of a third-party tap is named with its tap: the short name would install
        # homebrew/core's formula when core has one of the same name.
        name = line.name
        if _third_party(line.tap) and "/" not in name:
            name = f"{line.tap}/{name}"
        return probe(brew_actions.install_formulae(self.inst, self.host, self.action_id("formula", line.name),
                                                   [name], as_dependency=line.requested is False,
                                                   on_failure=OnFailure.PROBE))

    def dropped_casks(self) -> list[str]:
        """Return the casks the filtered `Brewfile` leaves out: those that need sudo and the adopted ones

        @returns  the tokens, sorted
        """
        return sorted({line.token for line in self.casks if line.privileged_install is True} | self.adopted)

    def sudo_line(self, token: str) -> str:
        """Return what to run on a terminal for a cask whose install needs sudo

        @param token  the cask
        @returns      the instruction the report prints
        """
        return f"Homebrew needs sudo for it: run `{self.binary('brew')} install --cask {token}` on a terminal"

    def prepare(self) -> None:
        """Build the actions that restore what is absent: a filtered `brew bundle`, or each tap, cask and formula"""
        self.waiting = self.rb.down(self.services, "formula")
        if not (self.absent or self.to_install):
            return
        if self.brewfile:
            path = self.rb.filtered_brewfile(self.prefix, self.brewfile, self.dropped_casks())
            self.actions.append(probe(brew_actions.bundle_install(self.inst, self.host, self.action_id("bundle"),
                                                                  path)))
            return
        for tap in self.taps():
            self.actions.append(probe(brew_actions.tap(self.inst, self.host, self.action_id("tap", state.slug(tap)),
                                                       tap)))
        for line in self.to_install:
            self.actions.append(probe(brew_actions.install_casks(self.inst, self.host,
                                                                 self.action_id("cask", line.token), [line.token],
                                                                 on_failure=OnFailure.PROBE)))
        self.actions += [self.install(line) for line in self.absent if line.requested is True]

    def busy(self) -> bool:
        """Return whether the part has actions, follow-up formulae or services to start

        @returns  True when it has any
        """
        return bool(self.actions or self.followups or self.waiting)

    def start_line(self, service: Service) -> str:
        """Return the preview's line that starts a recorded service again

        @param service  a service `down` found, which names its formula
        @returns        the `brew services start` the rollback runs; for system scope, the one to run by hand
        """
        if service.scope == "system":
            return (f"by hand: sudo {self.binary('brew')} services start {service.package} ({service.label}, "
                    "a system-scope service)")
        if not service.package:
            raise ValueError(f"{service.label} names no formula to start")
        action = brew_actions.services_start(self.inst, self.host, self.action_id("start", service.label),
                                             service.package)
        return f"then: {shown(action)}"

    def describe(self) -> list[str]:
        """Return what is absent from this Homebrew instance and what the rollback runs to restore it

        @returns  the preview's lines of the part
        """
        out = []
        if self.absent:
            out.append(f"absent formulae: {', '.join((line.name for line in self.absent))}")
        absent_casks = self.to_install + self.held + self.staying
        if absent_casks:
            out.append(f"absent casks: {', '.join((line.token for line in absent_casks))}")
        if not (self.absent or absent_casks):
            out.append("nothing is absent")
        out += [f"run: {shown(action)}" for action in self.actions]
        dropped = self.dropped_casks() if self.brewfile and self.actions else []
        if dropped:
            out.append(f"the filtered Brewfile omits the casks {', '.join(dropped)}")
        out += [f"then, if still absent: {shown(self.install(line))}" for line in self.followups]
        out += [f"cask {line.token} stays with the instance that adopted it in this run" for line in self.staying]
        out += [f"cask {line.token}: {self.sudo_line(line.token)}" for line in self.held]
        out += [self.start_line(service) for service in self.waiting]
        return out + [f"note: {note}" for note in self.notes]

    def run(self) -> None:
        """Run the actions, then the install of each follow-up formula still absent"""
        for action in self.actions:
            self.rb.execute(action)
        for line in self.followups:
            if line.name not in brew_present(self.prefix)[0]:
                self.rb.execute(self.install(line))

    def start_services(self) -> None:
        """Start each owned user-scope service recorded loaded that is down, with `brew services start <f>`

        Its exit status decides whether the service came back: Homebrew 7 may load it as `sh.brew.<f>`.
        """
        formulae = brew_present(self.prefix)[0]
        down = self.rb.down(self.services, "formula")
        self.up = {svc.label for svc in self.services if svc.loaded} - {svc.label for svc in down}
        for service in down:
            if service.scope == "system":
                self.gap("service", service.label, f"a system-scope service: run `sudo {self.binary('brew')} services "
                         f"start {service.package}` on a terminal")
                continue
            if service.package not in formulae:
                self.gap("service", service.label, f"its formula {service.package} is not back")
                continue
            action = probe(brew_actions.services_start(self.inst, self.host, self.action_id("start", service.label),
                                                       service.package, on_failure=OnFailure.PROBE))
            if self.rb.execute(action).exit != 0:
                self.gap("service", service.label, f"`brew services start {service.package}` failed")
            else:
                self.up.add(service.label)

    def finish(self) -> None:
        """Record each formula and cask still absent after the commands as a gap, a cask that needs sudo too"""
        formulae, casks = brew_present(self.prefix)
        for line in self.absent:
            if line.name not in formulae:
                self.gap("formula", line.name, "still absent after its reinstall")
        for line in self.to_install:
            if line.token not in casks:
                self.gap("cask", line.token, "still absent after its reinstall")
        for line in self.held:
            if line.token not in casks:
                self.gap("cask", line.token, self.sudo_line(line.token))

    def back(self) -> bool:
        """Return whether every absent formula and every cask the part installs is on the host

        @returns  True when none of them is still absent; a cask that needs sudo is not installed, so not counted
        """
        formulae, casks = brew_present(self.prefix)
        return (all(line.name in formulae for line in self.absent)
                and all(line.token in casks for line in self.to_install))


def _portdbpath(unit: Unit) -> str:
    """Return the registry directory of a MacPorts unit

    @param unit  the unit
    @returns     the `portdbpath` of the instance on the host, else of the recorded one, else `<prefix>/var/macports`
    """
    for inst in (unit.fresh, unit.recorded):
        if inst is not None and inst.portdbpath:
            return inst.portdbpath
    return os.path.join(unit.prefix, "var", "macports")


class _Ports(_Part):
    """The rollback of a MacPorts instance: `port install` of each port recorded active that is not, in file order

    Then the `select.txt` groups and the startup items recorded loaded; `port restore` is only offered.
    """

    def __init__(self, rb: "Rollback", unit: Unit) -> None:
        """Read the instance's snapshot and a fresh registry backup, and find the absent and the lost ports

        @param rb    the rollback the part belongs to
        @param unit  a MacPorts unit
        """
        super().__init__(rb, unit)
        self.installed: list[snapshot.PortLine] = self.read(snapshot.read_installed, snapshot.INSTALLED, [])
        self.groups: list[tuple[str, str]] = self.read(snapshot.read_select, snapshot.SELECT, [])
        self.snap_id = snapshot.read_snapshot_id(self.file(snapshot.SNAPSHOT_ID))
        export = self.file(snapshot.PORTS_SNAPSHOT)
        self.export = export if os.path.isfile(export) else None
        self.portdbpath = _portdbpath(unit)
        self.view, self.error = read_registry(self.portdbpath)
        active = self.view.active_names() if self.view is not None else set()
        self.absent = [line for line in self.installed if line.active and line.name.lower() not in active]
        self.lost = [line for line in self.installed
                     if not line.active and not (self.view is not None and self.view.holds(line.name, line.version))]
        self.selections: list[tuple[str, str]] = []
        self.kept: list[tuple[str, str]] = []      # changed select groups left as they are, each with why
        self.after: RegistryView | None = None

    def skipped(self, reason: str) -> None:
        """Record every absent port as a gap

        @param reason  why the instance is not restored
        """
        for line in self.absent:
            self.gap("port", line.name, reason)

    def prepare(self) -> None:
        """Build the installs of the absent ports, then the `port select` choices and services to restore"""
        for line in self.absent:
            try:
                action = mp_actions.install(self.inst, self.host, self.action_id("port", line.name), line.name,
                                            line.requested_variants, homebrew_present=self.rb.homebrew,
                                            binary_first=False, unrequested=line.requested is False,
                                            on_failure=OnFailure.PROBE)
            except ValueError as exc:
                self.notes.append(f"{line.name} {line.version} is not installed again: {exc}")
                continue
            self.actions.append(probe(action))
        self.selections = self.changed_groups()
        self.waiting = [svc for svc in self.rb.down(self.services, "port") if self.valid(svc.package)]

    def changed_groups(self) -> list[tuple[str, str]]:
        """Return the `select.txt` groups whose selection differs from the record; all of them without a summary

        @returns  the groups with their recorded options
        """
        groups = [(g, o) for g, o in self.groups if mp_actions.NAME_RE.match(g) and mp_actions.NAME_RE.match(o)]
        if len(groups) != len(self.groups):
            self.notes.append("select.txt holds lines that are not a group and an option; they are left out")
        if not groups:
            return []
        result = self.rb.runner.run(mp_actions.select_summary(self.inst, self.host, self.action_id("selected")))
        if result.exit not in (0, 1):
            return groups
        current = _selected(result.stdout()) if result.exit == 0 else {}
        return [(group, option) for group, option in groups if current.get(group) != option]

    def busy(self) -> bool:
        """Return whether the part has installs, selections or services to restore

        @returns  True when it has any
        """
        return bool(self.actions or self.selections or self.waiting)

    def select(self, group: str, option: str) -> Action:
        """Build the probe that restores a group's recorded `port select` choice

        @param group   the select group
        @param option  its recorded option
        @returns       the `port select --set` action
        """
        return probe(mp_actions.select_set(self.inst, self.host, self.action_id("select", group), group, option))

    def load(self, service: Service) -> Action:
        """Build the probe that loads a recorded startup item again with `port load`

        @param service  a service whose port `valid` accepts
        @returns        the action
        """
        if not self.valid(service.package):
            raise ValueError(f"{service.label} names no port `port load` accepts")
        return probe(mp_actions.load(self.inst, self.host, self.action_id("load", service.package), service.package))

    def offers(self) -> list[str]:
        """Return the manual way back: `port restore`, or the snapshot export's import once the registry is gone

        @returns  the lines; none when neither applies
        """
        port = self.binary("port")
        if self.snap_id is not None and self.view is not None and self.snap_id in self.view.snapshot_ids:
            return [f"by hand instead: sudo {port} restore --snapshot-id {self.snap_id} --all (it deactivates every "
                    "port installed since)"]
        if self.view is None and self.error == "missing" and self.export:
            return [f"by hand: sudo {port} snapshot --import {shlex.quote(self.export)}, then sudo {port} "
                    "restore --last --all"]
        return []

    def describe(self) -> list[str]:
        """Return what is absent from this MacPorts instance and what the rollback runs to restore it

        @returns  the preview's lines of the part
        """
        out = []
        if self.absent:
            out.append(f"absent ports: {', '.join(f'{line.name} {line.version}' for line in self.absent)}")
        else:
            out.append("nothing is absent")
        out += [f"run: {shown(action)}" for action in self.actions]
        out += [f"then: {shown(self.select(group, option))}" for group, option in self.selections]
        out += [f"port select {group} left as it is: {why}" for group, why in self.kept]
        out += [f"then: {shown(self.load(service))}" for service in self.waiting]
        out += [f"not restorable: {line.name} {line.version} was inactive and its image is gone"
                for line in self.lost]
        return out + self.offers() + [f"note: {note}" for note in self.notes]

    @staticmethod
    def valid(package: str | None) -> TypeGuard[str]:
        """Return whether a service's port is a name `port` accepts

        @param package  the service's port, or None
        @returns        True for a name `NAME_RE` matches
        """
        return bool(package and mp_actions.NAME_RE.match(package))

    def run(self) -> None:
        """Run the actions, then restore the `port select` choices"""
        for action in self.actions:
            self.rb.execute(action)
        self.after, _ = read_registry(self.portdbpath)
        for group, option in self.selections:
            if self.rb.execute(self.select(group, option)).exit != 0:
                self.gap("selection", group, f"`port select --set {group} {option}` failed")

    def start_services(self) -> None:
        """Load each startup item recorded loaded that is down, when its port is active after the installs"""
        active = self.after.active_names() if self.after is not None else set()
        down = self.rb.down(self.services, "port")
        self.up = {svc.label for svc in self.services if svc.loaded} - {svc.label for svc in down}
        for service in down:
            if not self.valid(service.package) or service.package.lower() not in active:
                self.gap("service", service.label, f"its port {service.package} is not active")
                continue
            if self.rb.execute(self.load(service)).exit != 0:
                self.gap("service", service.label, f"`port load {service.package}` failed")
            else:
                self.up.add(service.label)

    def finish(self) -> None:
        """Record each absent port still not active after the installs as a gap, or why that is unknown"""
        after, error = (self.after, None) if self.after is not None else read_registry(self.portdbpath)
        active = after.active_names() if after is not None else set()
        for line in self.absent:
            if line.name.lower() not in active:
                reason = ("still absent after `port install`" if after is not None
                          else f"the registry cannot be read to confirm it: {error}")
                self.gap("port", line.name, reason)

    def back(self) -> bool:
        """Return whether every absent port is active, by the registry after the installs or a fresh backup

        @returns  True when none is still absent; a registry that cannot be read confirms none
        """
        after = self.after if self.after is not None else read_registry(self.portdbpath)[0]
        active = after.active_names() if after is not None else set()
        return all(line.name.lower() in active for line in self.absent)


# Backups ----------------------------------------------------------------------------------

@dataclass
class Replay:
    """Whether a file change of the run is replayed, and why"""

    change: FileChange
    replay: bool
    reason: str
    diff: list[str] = field(default_factory=list)


# The command -------------------------------------------------------------------------------

class Rollback:
    """One `rollback` invocation: the preview, the confirmations, the commands and the report"""

    def __init__(self, ctx: Context, runner, run_dir: state.RunDir, source: SourceRun) -> None:
        """Start one `rollback` of a source run; `prepare` finds the instances and builds the parts

        @param ctx      the command's context: arguments, console, environment and state directory
        @param runner   the runner of the rollback's commands
        @param run_dir  the rollback's own run directory
        @param source   the run being rolled back
        """
        self.ctx: Context = ctx
        self.runner = runner
        self.run_dir = run_dir
        self.source = source
        self.console = ctx.console
        self.dry_run = ctx.args.dry_run
        self.home = ctx.environ.get("HOME") or os.path.expanduser("~")
        self.uid = os.getuid()
        self.lines: list[str] = []
        self.gaps: list[Gap] = []
        self.touched = False
        self.fresh: list[Instance] = []
        self.homebrew = False
        self.parts: list[_Brew | _Ports] = []
        self.started: list[Started] = []            # the starts of phase 7 that the rollback undoes
        self.left: list[tuple[Started, str]] = []   # the others, each with why it stays
        self.shell: ShellSwitch | None = None
        self.replays: list[Replay] = []
        self.index = env.PrefixIndex([])  # `build_index` fills it before the first `named`
        self.status: dict[int, str] = {}
        self.known: list[Instance] = []
        self.units: list[tuple[_Part, Instance]] = []   # each part with its instance in the index
        self.target_inst: Instance | None = None        # the instance of the target's part in the index

    # Output ------------------------------------------------------------------

    def say(self, text: str = "") -> None:
        """Print a report line and keep it for `report.md`

        @param text  the line; empty for a blank line
        """
        self.lines.append(text)
        self.console.out(text)

    def write_report(self) -> None:
        """Write the rollback run's `report.md`, always redacted, whatever ended the run"""
        report.write_markdown(self.run_dir.sub("report.md"), self.lines)

    # Commands ----------------------------------------------------------------

    def execute(self, action: Action) -> Result:
        """Run one rollback command, warning when it fails; the next command runs anyway

        @param action  a probe
        @returns       its result
        """
        result = self.runner.run(action)
        if result.exit != 0:
            self.console.warn(f"rollback: {action.action_id} exited {result.exit}; the next command runs")
        return result

    def loaded(self, service: Service) -> bool:
        """Return whether a service's job is loaded on the host, probed afresh

        @param service  a recorded service
        @returns        True when launchd holds the job
        """
        return env_services.refresh(self.runner, service, self.uid).loaded

    def down(self, services: Sequence[Service], kind: str) -> list[Service]:
        """Return the owned services of `kind` recorded loaded whose job is not loaded on the host

        @param services  the services the snapshot recorded
        @param kind      `formula` or `port`
        @returns         the services, each naming its package
        """
        return [svc for svc in services if svc.owned and svc.loaded and svc.package_kind == kind and svc.package
                and not self.loaded(svc)]

    def touch(self) -> None:
        """Touch the dirty marker once, immediately before the first change to the host"""
        if not self.touched:
            self.ctx.state.touch_dirty(self.run_dir.run_id, "rollback")
            self.touched = True

    def filtered_brewfile(self, prefix: str, brewfile: str, drop: Sequence[str]) -> str:
        """Write the snapshot's `Brewfile`, less the `cask` lines of `drop`, into the rollback run

        @param prefix    the instance's prefix, which names the copy's directory
        @param brewfile  the snapshot's `Brewfile`
        @param drop      the casks to leave out
        @returns         the path of the filtered copy
        """
        with open(brewfile, encoding="utf-8") as fh:
            text = snapshot.filter_brewfile(fh.read(), drop)
        path = os.path.join(self.run_dir.ensure("brewfiles", "brew-" + state.slug(prefix)), "Brewfile")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    # Preparation -------------------------------------------------------------

    def part(self, manager: Manager, prefix: str) -> _Brew | _Ports:
        """Return the part that restores one instance: prepared, or skipped with its reason

        @param manager  the manager the snapshot covers
        @param prefix   the prefix it covers
        @returns        the part
        """
        snapdir = (snapshot.brew_dir if manager is Manager.BREW else snapshot.ports_dir)(self.source.run_dir, prefix)
        unit = Unit(manager, prefix, snapdir, match(self.fresh, manager, prefix),
                    match(self.source.recorded, manager, prefix))
        unit.skip = skip_reason(unit)
        part: _Brew | _Ports = _Brew(self, unit) if manager is Manager.BREW else _Ports(self, unit)
        if unit.skip is None and isinstance(part, _Ports) and part.view is None:
            unit.skip = f"its registry cannot be read ({part.error})"
        if unit.skip is None:
            part.prepare()
        else:
            part.skipped(f"not restored: the instance is skipped: {unit.skip}")
        return part

    def prepare(self) -> None:
        """Find the instances again and prepare every part of the rollback"""
        self.fresh = locate(self.runner, self.ctx.environ, self.source.covered)
        self.homebrew = any(inst.manager is Manager.BREW for inst in self.fresh)
        self.parts = [self.part(manager, prefix) for manager, prefix in self.source.covered]
        self.hold_selections()
        starts = [(started, self.left_running(started)) for started in phase7_starts(self.source.entries)]
        self.started = [started for started, why in starts if why is None]
        self.left = [(started, why) for started, why in starts if why is not None]
        self.shell = shell_switch(self.source, self.ctx.state)
        self.build_index()
        self.replays = [self.judge(change) for change in file_changes(self.source)]

    def rolled(self) -> list[_Part]:
        """Return the parts that are not skipped

        @returns  the parts, in the order the snapshot covers them
        """
        return [part for part in self.parts if part.unit.skip is None]

    def hold_selections(self) -> None:
        """Leave each changed `port select` group of the target as it is while the source it stands in for is skipped

        Phase 7 selects a mapping's port in place of the commands of the mapping's source, so the recorded option
        comes back only when a part of that source runs.
        """
        plan = self.source.plan
        if plan is None or plan.target is not Manager.PORTS:
            return
        target = next((part for part in self.rolled() if isinstance(part, _Ports)
                       and part.prefix == plan.target_prefix), None)
        if target is None:
            return
        for group, option in list(target.selections):
            sources = {m.source.instance_prefix for m in plan.mappings if any(g == group for g, _ in m.selections)}
            owners = [part for part in self.parts if part.prefix in sources]
            if not sources or any(part.unit.skip is None for part in owners):
                continue
            names = [part.unit.title for part in owners] or sorted(sources)
            target.selections.remove((group, option))
            target.kept.append((group, f"{', '.join(names)} is skipped, so the {group} commands phase 7 replaced "
                                       "do not come back"))

    def left_running(self, started: Started) -> str | None:
        """Return why a target service phase 7 started is left running; None when the rollback stops it

        It is stopped only when a part that runs records a source service the start replaced, which that part
        starts again.

        @param started  a start of phase 7
        @returns        the reason the preview prints, or None
        """
        replaced = self.replaced(started)
        if any(part.unit.skip is None for part, _ in replaced):
            return None
        if replaced:
            titles = dict.fromkeys(part.unit.title for part, _ in replaced)
            return (f"{', '.join(titles)} is skipped, so nothing starts {', '.join(s.label for _, s in replaced)} "
                    "again")
        return "no part of this rollback starts a service it replaced"

    def replaced(self, started: Started) -> list[tuple[_Part, Service]]:
        """Return the recorded source services a phase 7 start replaced, each with the part that records it

        @param started  a start of phase 7
        @returns        the services, part by part
        """
        kind = "formula" if started.manager is Manager.BREW else "port"
        mappings = self.source.plan.mappings if self.source.plan is not None else []
        sources = [m.source for m in mappings if m.target_kind == kind and m.target_name == started.name]
        return [(part, svc) for part in self.parts for svc in part.services
                if any(_replaced(svc, src) for src in sources)]

    # Which instance a line names ---------------------------------------------

    def build_index(self) -> None:
        """Index every instance the run knew by status, and each part's instance: the target's among them

        The status is `restored`, `gone`, or `kept` when not rolled back; `settle` marks an instance whose
        part left a package absent `short`.
        """
        known: list[Instance] = []
        status: dict[int, str] = {}
        plan = self.source.plan
        self.units, self.target_inst = [], None
        for part in self.parts:
            unit = part.unit
            base = unit.fresh or unit.recorded or placeholder(unit.manager, unit.prefix)
            spellings = list(base.spellings) + [unit.prefix] + list(unit.recorded.spellings if unit.recorded else ())
            inst = dataclasses.replace(base, spellings=tuple(dict.fromkeys(spellings)))
            known.append(inst)
            self.units.append((part, inst))
            if plan is not None and unit.manager is plan.target and unit.prefix == plan.target_prefix:
                self.target_inst = inst
            status[id(inst)] = "restored" if unit.skip is None else ("gone" if unit.fresh is None else "kept")
        for inst in list(self.source.recorded) + list(self.fresh):
            if any(other.manager is inst.manager and (inst.prefix == other.prefix or inst.prefix in other.spellings)
                   for other in known):
                continue
            known.append(inst)
            status[id(inst)] = "gone" if match(self.fresh, inst.manager, inst.prefix) is None else "kept"
        self.known, self.status, self.index = known, status, env.PrefixIndex(known)

    def named(self, lines: Sequence[str]) -> list[Instance]:
        """Return the instances whose prefixes or `brew` paths the lines name

        @param lines  lines of a file the run changed
        @returns      the instances, each once, in the order the lines name them
        """
        out: list[Instance] = []
        for line in lines:
            for token in _PATH_TOKEN.findall(line):
                inst = self.index.by_text(token.rstrip("/") or "/") or self.brew_named(token)
                if inst is not None and all(inst is not other for other in out):
                    out.append(inst)
        return out

    def brew_named(self, token: str) -> Instance | None:
        """Return the known Homebrew instance whose `brew` a path names

        @param token  an absolute path of a line
        @returns      the instance; None when no known instance has that `brew`
        """
        for inst in self.known:
            if inst.manager is Manager.BREW and (token == inst.binary or any(
                    token == spelling.rstrip("/") + "/bin/brew" for spelling in inst.spellings)):
                return inst
        return None

    def judge(self, change: FileChange) -> Replay:
        """Return whether to replay a file change, and why

        The file must still hold what the run left and its old copy be readable text; the lines it brings back
        must name no instance that is still gone. Every source its edits name must be restored, and when they
        name the target, whose lines the replay takes out, every source of the snapshot; the target alone
        never counts.

        @param change  a file the run changed
        @returns       the verdict, with the diff of a file edited since the run
        """
        current = _read_bytes(change.path)
        left = (current is None if change.sha256 is None
                else (current is not None and sha256_bytes(current) == change.sha256))
        before = _text(_read_bytes(change.original)) if change.original else None
        if not left:
            diff = diff_lines(change.path, _text(current), before) if change.known else []
            return Replay(change, False, "edited since the run: left alone", diff)
        if not change.known:
            return Replay(change, False, "its copy from before the run is only in the root backup store: "
                          f"sudo cp -p {change.store} {change.path}")
        if change.original and before is None:
            return Replay(change, False, f"its copy from before the run is not UTF-8 text: {change.original}")
        old, new = _lines(before), _lines(_text(current))
        back = [line for line in old if line not in new]
        dropped = [line for line in new if line not in old]
        gone = [inst.prefix for inst in self.named(back) if self.status.get(id(inst)) == "gone"]
        if gone:
            return Replay(change, False, f"it would bring back the lines of {', '.join(gone)}, which is still gone")
        named = self.named(back + dropped)
        sources = [inst for _, inst in self.units if inst is not self.target_inst]
        concerned = [inst for inst in sources if any(inst is other for other in named)]
        behind = [inst.prefix for inst in concerned if self.status.get(id(inst)) != "restored"]
        if behind:
            return Replay(change, False, f"its edits concern {', '.join(behind)}, which is not restored")
        target = self.target_inst
        if target is not None and any(target is other for other in named):
            behind = [inst.prefix for inst in sources if self.status.get(id(inst)) != "restored"]
            if behind:
                return Replay(change, False, f"it would take out the lines of the target {target.prefix}, and "
                              f"{', '.join(behind)} is not restored")
            concerned.append(target)
        if not concerned:
            return Replay(change, False, "its edits concern no instance this rollback restores")
        return Replay(change, True, f"its edits concern {', '.join(inst.prefix for inst in concerned)}")

    # Preview -----------------------------------------------------------------

    def preview(self) -> None:
        """Print what the rollback restores and runs, part by part"""
        source = self.source
        self.say(f"rollback of {source.run_dir.run_id}, {source.describe()}")
        # A doctor --fix manager repair writes its records without the `complete` marker.
        if source.plan is not None and not snapshot.is_complete(source.run_dir):
            self.say("note: phase 1 of the run did not finish; its snapshot holds what was written before it stopped")
        for part in self.parts:
            self.show_part(part)
        self.show_phase7()
        self.show_shell()
        self.show_upgrades()
        self.show_lines("archives of the run, never extracted by brew-ports:", archive_lines(source.run_dir))
        self.show_replays()
        notes = snapshot.snapshot_dir(source.run_dir)
        self.show_lines("notes of the snapshot:", _lines(_text(_read_bytes(os.path.join(notes, snapshot.NOTES)))))

    def show_lines(self, title: str, lines: Sequence[str]) -> None:
        """Print a titled list, or nothing when it is empty

        @param title  the heading line
        @param lines  the lines, indented under it
        """
        if lines:
            self.say(title)
            for line in lines:
                self.say(f"  {line}")

    def show_part(self, part: _Part) -> None:
        """Print one part of the rollback, or why it is skipped and how to restore it by hand

        @param part  the part
        """
        unit = part.unit
        if unit.skip is None:
            self.say(f"{unit.title}:")
            for line in part.describe():
                self.say(f"  {line}")
            return
        self.say(f"{unit.title}: skipped: {unit.skip}")
        if unit.fresh is not None:
            self.say("  `brew-ports doctor` names the repair that makes it drivable again, or:")
        for line in reinstall_lines(unit.manager, unit.prefix, self.runner.host_arch, self.source):
            self.say(f"  {line}")
        self.say(f"  then run `brew-ports rollback {self.source.run_dir.run_id}` again")
        for gap in self.gaps:
            if gap.prefix == unit.prefix:
                self.say(f"  not restored: {gap.kind} {gap.name}")
        for line in part.offers():
            self.say(f"  {line}")

    def target(self) -> Instance | None:
        """Return the plan's target as found on the host

        @returns  the instance; None for a `doctor --fix` run or a target that is gone
        """
        plan = self.source.plan
        return match(self.fresh, plan.target, plan.target_prefix) if plan is not None else None

    @property
    def target_prefix(self) -> str:
        """Return the plan's target prefix

        @returns  the prefix; empty for a `doctor --fix` run
        """
        return self.source.plan.target_prefix if self.source.plan is not None else ""

    def jobs(self, started: Started) -> list[Service]:
        """Return the launchd jobs a phase 7 `brew services start` may have written, one user plist per label

        @param started  a Homebrew start of phase 7
        @returns        one service per label of `brew_labels`
        """
        prefix = self.target_prefix
        out = []
        for label in brew_labels(started):
            plist = os.path.join(self.home, LAUNCH_AGENTS, label + ".plist")
            info = env_services.read_plist(plist, "user")
            out.append(Service(label=label, plist=plist, scope="user", domain=None, loaded=False, running=False,
                               pid=None, exit_timeout_s=info.exit_timeout_s, owned=True, data_dirs=[],
                               package=started.name, package_kind="formula", instance_prefix=prefix,
                               program=info.program))
        return out

    def unload_action(self, started: Started, target: Instance | None) -> Action | None:
        """Build the probe that unloads a startup item phase 7 loaded, with the target's `port`

        @param started  a MacPorts start of phase 7
        @param target   the target on the host, or None
        @returns        the action; None when the target cannot run `port` or refuses the port's name
        """
        if target is None or not target.drivable or not target.binary:
            return None
        try:
            return probe(mp_actions.unload(target, self.runner.host_arch, f"{PHASE}.target.unload.{started.name}",
                                           started.name))
        except ValueError:
            return None

    def unload_line(self, started: Started, target: Instance | None) -> str:
        """Return the `port unload` line for the terminal, for a target that cannot run `port`

        @param started  a MacPorts start of phase 7
        @param target   the target on the host, or None
        @returns        the line
        """
        port = (target.binary if target is not None and target.binary
                else os.path.join(self.target_prefix, "bin", "port"))
        return f"by hand: sudo {port} -N unload {started.name}"

    def show_phase7(self) -> None:
        """Print the target services phase 7 of the run started: those the rollback stops first, and those it leaves"""
        lines = []
        target = self.target()
        for started in self.started:
            if started.manager is Manager.BREW:
                plists = [svc.plist for svc in self.jobs(started) if os.path.lexists(svc.plist)]
                lines.append(f"{started.label}: boot out the job of {started.name} and delete "
                             f"{', '.join(plists) or 'its plist (none is there)'}")
                continue
            action = self.unload_action(started, target)
            command = shown(action) if action is not None else self.unload_line(started, target)
            lines.append(f"{started.label}: {command}")
        self.show_lines("target services that phase 7 of the run started, stopped before the source services start:",
                        lines)
        self.show_lines("target services that phase 7 of the run started, left running:",
                        [f"{started.label}: {why}" for started, why in self.left])

    def show_shell(self) -> None:
        """Print the login shell switch of phase 5 and whether the rollback switches it back"""
        sw = self.shell
        if sw is None:
            return
        if sw.old:
            self.say(f"login shell: phase 5 switched {sw.user} from {sw.old} to {sw.new}; it is switched back once "
                     f"{sw.old} exists again")
        else:
            self.say(f"login shell: phase 5 switched {sw.user} to {sw.new}; the shell before the run is not recorded")

    def show_upgrades(self) -> None:
        """Report the target's upgrades in place with their old versions; they are never reverted"""
        plan = self.source.plan
        if plan is None or not plan.target_upgrades:
            return
        part = next((p for p in self.parts if p.unit.manager is plan.target
                     and p.unit.prefix == plan.target_prefix), None)
        if part is None:
            return
        if isinstance(part, _Brew):
            lines = _brew_upgrades(part, plan.target_upgrades)
        else:
            lines = _ports_upgrades(part, plan.target_upgrades)
        self.show_lines("upgraded in place by the run and not reverted:", lines)

    def show_replays(self) -> None:
        """Print each file change of the run and whether it is replayed, with the diff of an edited file"""
        if not self.replays:
            return
        self.say("backups of the run, replayed after a confirmation:")
        for item in self.replays:
            verb = "replay" if item.replay else "listed, not replayed"
            self.say(f"  {verb} {item.change.path}: {item.reason}")
            for line in item.diff:
                self.say(f"    {line}")

    # Running -----------------------------------------------------------------

    def switching(self) -> bool:
        """Return whether the rollback switches the login shell back

        @returns  True when phase 5 switched it and the shell before the run is known
        """
        return self.shell is not None and bool(self.shell.old)

    def stage_one(self) -> bool:
        """Return whether anything but the backups is to run: phase 7 undone, an instance, the login shell

        @returns  True when one of them has work
        """
        return bool(self.started or self.switching() or any(part.busy() for part in self.rolled()))

    def escalates(self, replays: Sequence[Replay]) -> bool:
        """Return whether anything to run needs sudo: a `port` command, `chsh` or a root file copied back

        @param replays  the backups chosen for replay
        @returns        True when the sudo preflight is due
        """
        ports = any(isinstance(part, _Ports) and part.busy() for part in self.rolled())
        return bool(ports or self.switching() or any(s.manager is Manager.PORTS for s in self.started)
                    or any(item.change.root for item in replays))

    def undo_phase7(self, undone: list[Undone]) -> None:
        """Stop the target services phase 7 started whose source services a part starts again, before those start

        A Homebrew job is booted out and waited for, its plist kept for `redo_phase7`; a MacPorts item is unloaded.
        Each stop joins `undone` as soon as it is made, so an interrupt that ends the stops loses none.

        @param undone  receives each start the rollback stopped
        """
        target = self.target()
        for started in self.started:
            if started.manager is Manager.PORTS:
                action = self.unload_action(started, target)
                if action is None:
                    self.say(f"  {started.label}: not unloaded: {self.unload_line(started, target)}")
                    continue
                self.execute(action)
                undone.append(Undone(started))
                continue
            services = self.jobs(started)
            stopped = servicectl.stop(self.runner, services, self.uid, id_prefix=PHASE + ".target")
            running = {svc.label for svc, _ in stopped.still_running}
            for service, reason in stopped.still_running:
                self.say(f"  {service.label}: {reason}; its plist is left in place")
            undone.append(Undone(started, stopped.booted, [svc for svc in services if svc.label not in running]))
            if stopped.error is not None:
                raise stopped.error

    def redo_phase7(self, undone: Sequence[Undone]) -> None:
        """Delete the plists of the stopped target services whose replaced service is up, and start the others again

        It runs in the runner's cleanup mode, so neither an interrupt nor a source service that did not start leaves
        both down.

        @param undone  the starts `undo_phase7` stopped
        """
        target = self.target()
        with self.runner.cleanup():
            for item in undone:
                started = item.started
                if any(svc.label in part.up for part, svc in self.replaced(started)):
                    for service, gone in servicectl.delete_plists(self.runner, item.stale,
                                                                  id_prefix=PHASE + ".target"):
                        if not gone:
                            self.say(f"  {service.label}: could not delete {service.plist}")
                    continue
                if started.manager is Manager.BREW and not item.booted:
                    continue
                self.say(f"  {started.label}: started again, as no service it replaced came back")
                if started.manager is Manager.BREW:
                    for service, ok in servicectl.restart(self.runner, item.booted, self.fresh,
                                                          id_prefix=PHASE + ".target"):
                        if not ok:
                            self.say(f"  {service.label}: could not be started again from {service.plist}")
                    continue
                if target is None or target.binary is None:
                    continue
                action = probe(mp_actions.load(target, self.runner.host_arch, f"{PHASE}.target.load.{started.name}",
                                               started.name))
                try:
                    loaded = self.execute(action).exit == 0
                except EscalationFailed:
                    loaded = False
                if not loaded:
                    self.say(f"  {started.label}: could not be loaded again: sudo {target.binary} -N load "
                             f"{started.name}")

    def switch_shell(self) -> None:
        """Switch the login shell back with `sudo chsh` once the old one exists, unless the user changed it since"""
        sw = self.shell
        if sw is None:
            return
        current = env_shell.login_shell(self.runner, sw.user)
        if current != sw.new:
            self.say(f"login shell: {sw.user} has {current}, not the {sw.new} phase 5 set: left alone")
        elif not sw.old:
            self.say("login shell: the shell before the run is not recorded: switch back by hand with "
                     f"`sudo chsh -s <shell> {sw.user}`")
        elif not env_shell.is_command(sw.old):
            self.say(f"login shell: {sw.old} is not back, so {sw.user} keeps {sw.new}")
        else:
            action = Action(action_id=f"{PHASE}.shell", kind="command", argv=[CHSH, "-s", sw.old, sw.user],
                            sudo=True, description=f"switch the login shell of {sw.user} back to {sw.old}",
                            on_failure=OnFailure.PROBE)
            ok = self.execute(action).exit == 0
            self.say(f"login shell: {'switched back to' if ok else 'could not switch back to'} {sw.old}")

    def run(self) -> None:
        """Touch the dirty marker, run the parts' installs, swap the phase 7 services back, switch the login shell

        A target service phase 7 started is stopped only after the installs, just before the source services
        start, so it keeps serving while they run; `redo_phase7` then finishes or reverses each stop, whatever
        ends the starts.
        """
        self.touch()
        for part in self.rolled():
            part.run()
        undone: list[Undone] = []
        try:
            self.undo_phase7(undone)
            for part in self.rolled():
                part.start_services()
        finally:
            self.redo_phase7(undone)
        self.switch_shell()

    # Replaying ---------------------------------------------------------------

    def keeps_login_shell(self, change: FileChange) -> bool:
        """Return whether a replay keeps the login shell valid: an `/etc/shells` copy must list it

        @param change  a file change chosen for replay
        @returns       False only for an `/etc/shells` copy that lacks the user's login shell
        """
        if etc_rel(change.path) != "shells":
            return True
        user = self.shell.user if self.shell is not None else system.login_name()
        login = env_shell.login_shell(self.runner, user)
        return not login or login in _lines(_text(_read_bytes(change.original)))

    def journal_write(self, path: str, digest: str, backup: str | None) -> None:
        """Journal a replayed write with the SHA-256 of the content it wrote

        @param path    the file
        @param digest  the SHA-256 of its content
        @param backup  the rollback run's copy of what the file held before the replay, or None
        """
        action = Action(action_id=f"{PHASE}.write.{state.slug(path)}", kind="write", argv=[], sudo=False,
                        description=f"replay the backup of {path}", dst=path)
        self.run_dir.journal.append({"ts": state.now_iso(), "phase": PHASE, "action_id": action.action_id,
                                     "kind": "write", "path": path, "sha256": digest, "backup": backup,
                                     "root": False})
        self.runner.record_result(action, True)

    def replay_user(self, change: FileChange) -> bool:
        """Replay a user file: back up its content, then write back its old copy, or remove a file the run created

        @param change  a user file change
        @returns       True when the file holds its old copy again, or is gone
        """
        real = change.path
        try:
            owner = os.lstat(real).st_uid
        except FileNotFoundError:
            owner = os.getuid()
        if owner != os.getuid():
            self.say(f"  {real} belongs to uid {owner}: not replayed")
            return False
        backup = self.run_dir.backup_first_copy(real)
        if change.original is None:
            self.execute(Action(action_id=f"{PHASE}.remove.{state.slug(real)}", kind="command",
                                argv=[RM, "-f", real], sudo=False,
                                description=f"remove {real}, which the run created", on_failure=OnFailure.PROBE))
            return not os.path.lexists(real)
        text = _text(_read_bytes(change.original)) or ""
        try:
            state.write_user_file(real, text)
        except OSError as exc:
            self.say(f"  {real}: not written: {exc.strerror or exc}")
            return False
        self.journal_write(real, sha256_bytes(text.encode("utf-8")), backup)
        return True

    def replay_root(self, change: FileChange) -> bool:
        """Replay a root file with `sudo cp -p` from the root backup store, after copying its content for the report

        @param change  a root file change, which `file_changes` gives its store copy
        @returns       True when the file then matches its copy from before the run
        """
        real = change.path
        if change.store is None:
            raise ValueError(f"{real} is a root file change without its root backup store copy")
        if os.path.lexists(real):
            copy = self.run_dir.sub("backup", "etc", etc_rel(real))
            if not os.path.lexists(copy):
                os.makedirs(os.path.dirname(copy), exist_ok=True)
                shutil.copy2(real, copy)
        action = Action(action_id=f"{PHASE}.restore.{state.slug(real)}", kind="command",
                        argv=[CP, "-p", change.store, real], sudo=True,
                        description=f"restore {real} from the root backup store", on_failure=OnFailure.PROBE)
        if self.execute(action).exit != 0:
            return False
        return _read_bytes(real) == _read_bytes(change.original)

    def settle(self) -> None:
        """Mark the instance of each part that ran yet left a package absent `short`, for the replay's judgement"""
        for part, inst in self.units:
            if self.status.get(id(inst)) == "restored" and not part.back():
                self.status[id(inst)] = "short"

    def replay(self, chosen: Sequence[Replay]) -> None:
        """Replay the chosen backups after a confirmation of their own, each judged again on what came back

        @param chosen  the backups `judge` marked for replay
        """
        if not chosen:
            return
        if not self.ctx.confirm(f"Replay these {len(chosen)} backups of the run?", default=False):
            self.say("backups: not replayed")
            return
        self.touch()
        self.settle()
        for item in chosen:
            again = self.judge(item.change)
            if not again.replay:
                self.say(f"listed, not replayed: {item.change.path}: {again.reason}")
                continue
            if not self.keeps_login_shell(item.change):
                self.say(f"listed, not replayed: {item.change.path}: it does not list the login shell")
                continue
            ok = self.replay_root(item.change) if item.change.root else self.replay_user(item.change)
            self.say(f"{'replayed' if ok else 'could not replay'} {item.change.path}")

    # The run -----------------------------------------------------------------

    def done(self) -> int:
        """Report the packages, services and selections that did not come back

        @returns  5 when one did not, else 0
        """
        for part in self.rolled():
            part.finish()
        if self.gaps:
            self.say(f"rollback: {len(self.gaps)} did not come back:")
            for gap in self.gaps:
                self.say(f"  {gap.line()}")
            return EXIT_VERIFY
        self.say("rollback: every package, service and selection of the snapshot is back")
        return EXIT_OK

    def main(self) -> int:
        """Preview the rollback, then after one confirmation and the sudo preflight run it and replay the backups

        `--dry-run` stops after the preview.

        @returns  3 when no instance can be driven or the sudo preflight fails, 5 when something did not come
                  back, else 0
        """
        self.prepare()
        self.preview()
        if not self.rolled():
            self.say("rollback: no instance of the snapshot can be driven")
            return EXIT_PREFLIGHT
        if self.dry_run:
            self.say("rollback --dry-run: nothing was run")
            return EXIT_OK
        chosen = [item for item in self.replays if item.replay]
        first = self.stage_one()
        if not first and not chosen:
            self.say("rollback: nothing to run")
            return self.done()
        if first and not self.ctx.confirm("Roll back as shown above?", default=False):
            self.say("rollback: nothing changed")
            return EXIT_OK
        if self.escalates(chosen):
            try:
                self.runner.sudo_preflight()
            except PreflightError as exc:
                self.say(f"brew-ports: {exc}")
                return EXIT_PREFLIGHT
        if first:
            self.run()
        self.replay(chosen)
        return self.done()


def _brew_upgrades(part: _Brew, names: Sequence[str]) -> list[str]:
    """Return each upgraded formula's old version and keg; `HOMEBREW_NO_INSTALL_CLEANUP` keeps the keg

    @param part   the target's Homebrew part
    @param names  the formulae the run upgraded in place
    @returns      one line per formula that has a keg the snapshot does not record
    """
    racks, _ = brew_inventory.walk_cellar(part.prefix)
    recorded = {line.name: line for line in part.formulae}
    out = []
    for name in names:
        line, rack = recorded.get(name), racks.get(name)
        if line is None or rack is None or not line.versions:
            continue
        new = [keg.version for keg in rack.kegs if keg.version not in line.versions]
        if not new:
            continue
        keg = os.path.join(part.prefix, "Cellar", name, line.versions[-1])
        where = f"the old keg stays at {keg}" if os.path.isdir(keg) else (f"the old keg {keg} is gone")
        out.append(f"{name}: {new[-1]}, upgraded from {line.versions[-1]}; {where}")
    return out


def _ports_upgrades(part: _Ports, names: Sequence[str]) -> list[str]:
    """Return each upgraded port's old version and its `port activate` line, while the old image is inactive

    @param part   the target's MacPorts part
    @param names  the ports the run upgraded in place
    @returns      one line per port whose active version differs from the recorded one
    """
    out = []
    view = part.view
    for name in names:
        old = next((line for line in part.installed if line.active and line.name.lower() == name.lower()), None)
        row = view.active_row(name) if view is not None else None
        if old is None or row is None or row.spec_args[1] == old.version:
            continue
        if view is not None and view.holds(old.name, old.version):
            back = f"sudo {part.binary('port')} -N activate {old.name} {old.version} brings it back"
        else:
            back = "the pre-upgrade image is gone"
        out.append(f"{name}: {row.spec_args[1]}, upgraded from {old.version}; {back}")
    return out


def cmd_rollback(ctx: Context, make_runner: Callable[[Context, state.RunDir], BaseRunner] | None = None) -> int:
    """Run `brew-ports rollback RUN-ID [--yes] [--dry-run]`

    @param ctx          the command's context, whose `run_id` argument names the run
    @param make_runner  builds the runner from the context and the rollback's run directory; None for the real one
    @returns            2 for an unknown run; 3 without a snapshot, a readable plan, a drivable instance or sudo
                        credentials; 5 when something did not come back; else 0, a declined confirmation included
    """
    run_id = ctx.args.run_id
    try:
        source = load_source(ctx.state, run_id)
    except (ValueError, FileNotFoundError):
        ctx.console.warn(f"brew-ports rollback: no run {run_id} in {ctx.state.runs}")
        return EXIT_USAGE
    except SourceError as exc:
        ctx.console.warn(f"brew-ports rollback: {exc}")
        return EXIT_PREFLIGHT
    if not source.covered:
        ctx.console.warn(f"brew-ports rollback: run {run_id} holds no snapshot, so there is nothing to roll back")
        return EXIT_PREFLIGHT
    run_dir, runner = start_run(ctx, PHASE, make_runner)
    rollback = Rollback(ctx, runner, run_dir, source)
    with runner.signals():
        try:
            return rollback.main()
        finally:
            rollback.write_report()

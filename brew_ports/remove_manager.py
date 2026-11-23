"""Phase 6 of `apply`: removing a source manager itself, every path tested against the safety rules first

A resumed phase starts over: checks and boot-outs run again, archives until the instance's first deletion.
"""

from __future__ import annotations

import dataclasses
import glob
import os
import sqlite3
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import apply_report, env, plan_phases, servicectl, snapshot, state, system
from .context import Context
from .homebrew import catalogue as brew_catalogue, inventory as brew_inventory, locate as brew_locate
from .macports import locate as mp_locate, registry
from .model import Action, Instance, Manager, OnFailure, Plan, Service, Usability
from .report import Redactor, at, counted, some
from .runner import RM, ActionFailed, Result, RootFiles

TAR = system.TAR
DU = system.DU
LSOF = "/usr/sbin/lsof"
DSCL = system.DSCL
PKGUTIL = system.PKGUTIL
GIT = system.GIT
PKG_ID = mp_locate.PKG_ID
PHASE = 6
MARGIN = 1 << 30                 # room for the archives plus 1 GiB
ARCHIVES = "data-archive"
IDENTITY = "6.identity."
KEEP = "6.keep."
DELETIONS = ("6.delete.", "6.links.")
MACPORTS_USER = "macports"
MACPORTS_CONF = mp_locate.CONF_REL
LINK_DIRS = ("bin", "sbin", "lib", "include", "share", "etc", "opt", "Frameworks")
LINK_TARGETS = ("Cellar", "Caskroom", "opt")
APP_KINDS = ("app", "suite")
ARGV_BUDGET = 200000             # bytes of link names per `rm -f`, far below ARG_MAX
SAVED_SHOWN = 4                  # archived paths one line names before "and N more"


@dataclass
class Host:
    """The system locations and clocks phase 6 uses; the tests point them into a temporary tree"""

    usr_local: str = brew_locate.USR_LOCAL
    applications: str = "/Applications"
    library: str = "/Library"
    etc_paths_d: str = "/etc/paths.d"
    free_bytes: Callable[[str], int | None] = system.free_bytes
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    alive: Callable[[int | None], bool] = servicectl.pid_alive


class Stopped(ActionFailed):
    """A check, an archive or a deletion stopped phase 6 (exit 4); `lines` is the report so far"""

    def __init__(self, result: Result, reason: str, lines: Sequence[str] = ()) -> None:
        """Carry the result that stopped the phase, the reason and the report so far

        @param result  the failed command's result, or the one `_result` builds for a check
        @param reason  why the phase stopped, which is also the exception's message
        @param lines   the report lines so far
        """
        super().__init__(result)
        self.args = (reason,)
        self.reason = reason
        self.lines = list(lines)


def _result(action_id: str, exit_code: int = 1) -> Result:
    """Build the result a stop carries when no command failed: a check that found something

    @param action_id  the check's action id
    @param exit_code  the exit status the result records
    @returns          a failed result without output files
    """
    return Result(action_id=action_id, exit=exit_code, stdout_path=None, stderr_path=None, ok=False)


# Parsers -------------------------------------------------------------------------------------

@dataclass
class Process:
    """One process of `lsof -F pn`: its PID, the `c` field when present, and its files"""

    pid: int
    command: str | None = None
    files: list[tuple[str, str]] = field(default_factory=list)   # (descriptor, name)

    @property
    def program(self) -> str | None:
        """Return the command name when lsof gave one, else the first `txt` file: the executable

        @returns  the name; None when lsof gave neither
        """
        if self.command:
            return self.command
        return next((name for fd, name in self.files if fd == "txt"), None)


def parse_lsof(text: str) -> list[Process]:
    """Parse the output of `lsof -F pn` into its processes

    A `p<pid>` line starts a process, an `f<descriptor>` line starts one of its files (lsof adds that
    field to every file) and an `n<name>` line names it.

    @param text  the output
    @returns     the processes in output order; a PID that is not a number reads as -1
    """
    out: list[Process] = []
    current: Process | None = None
    descriptor = ""
    for line in text.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            current = Process(int(value) if value.isdigit() else -1)
            out.append(current)
            descriptor = ""
        elif current is None:
            continue
        elif tag == "c":
            current.command = value
        elif tag == "f":
            descriptor = value
        elif tag == "n":
            current.files.append((descriptor, value))
    return out


def processes_under(processes: Sequence[Process], index: env.PrefixIndex) -> list[tuple[Process, list[str]]]:
    """Return the processes that use the instance, each with the names that lie under it

    A name counts when the executable, a mapped library, the working directory or an open file lies under
    the instance's `owned_roots` (identity, else the recorded spellings).

    @param processes  the processes `parse_lsof` found
    @param index      the index of the instance alone
    @returns          each such process with its names, each once
    """
    out = []
    for proc in processes:
        names: list[str] = []
        for _, name in proc.files:
            if name.startswith("/") and name not in names and index.owner(name) is not None:
                names.append(name)
        if names:
            out.append((proc, names))
    return out


def parse_du(text: str) -> dict[str, int]:
    """Parse `du -sk` output: `<KiB>\\t<path>` per operand, the path as given

    @param text  the output; a line without a size, such as an error, is skipped
    @returns     the size in KiB by path
    """
    out: dict[str, int] = {}
    for line in text.splitlines():
        size, sep, path = line.partition("\t")
        if sep and size.strip().isdigit():
            out[path] = int(size.strip())
    return out


_GIT_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _unquote(text: str) -> str:
    """Undo git's C-style quoting of a path with special characters (`"a\\tb"`, octal bytes)

    @param text  a path as `git status --porcelain` prints it
    @returns     the path; unchanged when it is not quoted
    """
    if len(text) < 2 or not (text.startswith('"') and text.endswith('"')):
        return text
    body = text[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 >= len(body):
            out += ch.encode("utf-8", "surrogateescape")
            i += 1
            continue
        digits = body[i + 1:i + 4]
        if len(digits) == 3 and all(c in "01234567" for c in digits):
            out.append(int(digits, 8) & 0xFF)
            i += 4
        elif body[i + 1] in _GIT_ESCAPES:
            out.append(_GIT_ESCAPES[body[i + 1]])
            i += 2
        else:
            out += body[i + 1].encode("utf-8", "surrogateescape")
            i += 2
    return out.decode("utf-8", "surrogateescape")


def parse_porcelain(text: str) -> list[str]:
    """Parse the paths `git status --porcelain` lists, relative to the repository root

    Both sides of a rename or copy count; an untracked directory loses its trailing slash.

    @param text  the output
    @returns     the paths, unquoted, each once in output order
    """
    out: list[str] = []
    for line in text.splitlines():
        if len(line) < 4:
            continue
        status, rest = line[:2], line[3:]
        names = rest.split(" -> ", 1) if ("R" in status or "C" in status) and " -> " in rest else [rest]
        for name in names:
            path = _unquote(name).rstrip("/")
            if path and path not in out:
                out.append(path)
    return out


def receipt_under(receipt: Iterable[str], inst: Instance) -> bool:
    """Return whether the receipt's files lie under this prefix, as `pkgutil --forget` requires

    The directories a receipt lists that lead to the prefix (`/opt`) do not count.

    @param receipt  the receipt's absolute paths
    @param inst     the MacPorts instance
    @returns        True when every path lies under the prefix or leads to it, and one lies under it
    """
    fold = env.fold_case_for(inst)
    spellings = [inst.prefix] + list(inst.spellings or ())
    leading = [system.normalise_text_path(s, fold) for s in spellings]
    inside = 0
    for path in receipt:
        if system.text_names_prefix(path, spellings, fold):
            inside += 1
            continue
        norm = system.normalise_text_path(path, fold)
        if norm == "/" or any(s.startswith(norm.rstrip("/") + "/") for s in leading):
            continue
        return False
    return inside > 0


def deletion_begun(entries: Sequence[dict[str, Any]], prefix: str) -> bool:
    """Return whether a deletion of the instance has run

    One has run when a `6.delete.*` or `6.links.*` command line follows the instance's identity record
    before another prefix's record.

    @param entries  the run's journal entries
    @param prefix   the instance's prefix
    @returns        True after such a command line
    """
    mine = IDENTITY + state.slug(prefix)
    inside = False
    for entry in entries:
        if entry.get("phase") != PHASE:
            continue
        action_id = str(entry.get("action_id") or "")
        if action_id.startswith(IDENTITY):
            inside = action_id == mine
        elif inside and "argv" in entry and action_id.startswith(DELETIONS):
            return True
    return False


def _last_result(entries: Sequence[dict[str, Any]], action_id: str) -> str | None:
    """Return the result the journal last records for a phase 6 action

    @param entries    the run's journal entries
    @param action_id  the action's id
    @returns          the result, such as `ok` or `failed`; None when no entry records one
    """
    found = None
    for entry in entries:
        if entry.get("phase") == PHASE and entry.get("action_id") == action_id and "result" in entry:
            found = entry["result"]
    return found


@dataclass
class Unregistered:
    """The unregistered entries of a MacPorts prefix and the number of files they hold

    A unit is the largest directory that holds nothing else, or a single entry; `count` counts the files
    inside, an unreadable directory once.
    """

    units: list[str] = field(default_factory=list)
    count: int = 0


def unregistered_units(root: str, skip: Iterable[str], unregistered: Callable[[str], bool]) -> Unregistered:
    """Find the unregistered entries under `root`, a directory whose every entry is unregistered as one unit

    An unreadable directory is one entry, since only `sudo tar` can see into it.

    @param root          the prefix
    @param skip          the directories not walked: base's own and the registry's, `var/macports`
    @param unregistered  returns whether a file is unregistered
    @returns             the units in walk order and their file count; empty when `root` holds nothing
    """
    skipped = {os.path.normpath(p) for p in skip}

    def visit(directory: str) -> tuple[bool, bool, list[str], int]:
        """Return (holds an entry, every entry unregistered, units, count) of one directory."""
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except FileNotFoundError:
            return False, True, [], 0
        except OSError:
            return True, True, [directory], 1
        holds, whole, units, count = False, True, [], 0
        for entry in entries:
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            if is_dir and os.path.normpath(entry.path) in skipped:
                holds, whole = True, False
            elif is_dir:
                held, all_of, inner, number = visit(entry.path)
                if held:
                    holds, count = True, count + number
                    whole = whole and all_of
                    units.extend([entry.path] if all_of else inner)
            else:
                holds = True
                if unregistered(entry.path):
                    units.append(entry.path)
                    count += 1
                else:
                    whole = False
        if holds and whole:
            return True, True, [directory], count
        return holds, False, units, count

    holds, _, units, count = visit(root)
    return Unregistered(units if holds else [], count)


# Small helpers ---------------------------------------------------------------------------------

def _entries(path: str) -> list[str] | None:
    """List the names in a directory, sorted

    @param path  the directory
    @returns     the names; empty when it is absent, None when it cannot be listed
    """
    try:
        return sorted(os.listdir(path))
    except FileNotFoundError:
        return []
    except OSError:
        return None


def _files_below(top: str) -> list[str]:
    """List every non-directory below `top`, symlinks not followed

    @param top  the directory
    @returns    the paths, by name at each level; an unreadable directory is listed itself
    """
    try:
        with os.scandir(top) as it:
            entries = sorted(it, key=lambda e: e.name)
    except FileNotFoundError:
        return []
    except OSError:
        return [top]
    out: list[str] = []
    for entry in entries:
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            is_dir = False
        out.extend(_files_below(entry.path) if is_dir else [entry.path])
    return out


def _outermost(paths: Sequence[str]) -> list[str]:
    """Return the paths that lie under no other path of the list, each once, as `du` counts nested paths twice

    @param paths  the paths
    @returns      the outermost paths, normalised, in their first order
    """
    norm = list(dict.fromkeys(os.path.normpath(p) for p in paths))
    return [p for p in norm if not any(o != p and system.text_names_prefix(p, [o], False) for o in norm)]


def _chunks(names: Sequence[str], budget: int) -> list[list[str]]:
    """Split names into groups whose argv bytes, a terminator per name, stay within the budget

    @param names   the names, in order
    @param budget  the most bytes a group holds; a longer name forms a group alone
    @returns       the groups, in order
    """
    out: list[list[str]] = []
    current: list[str] = []
    used = 0
    for name in names:
        size = len(name.encode("utf-8", "surrogateescape")) + 1
        if current and used + size > budget:
            out.append(current)
            current, used = [], 0
        current.append(name)
        used += size
    if current:
        out.append(current)
    return out


def _size(nbytes: int) -> str:
    """Format a byte count for the report: GiB, MiB or KiB to one decimal, else bytes

    @param nbytes  the count
    @returns       the text, such as `1.5 GiB`
    """
    for unit, scale in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if nbytes >= scale:
            return f"{nbytes / scale:.1f} {unit}"
    return f"{nbytes} bytes"


def _brief(paths: Sequence[str], limit: int = 3) -> str:
    """Join the first paths of a list for the report, with the number of the others

    @param paths  the paths
    @param limit  how many are named
    @returns      the text, such as `a, b, c and 2 more`
    """
    shown = ", ".join(paths[:limit])
    return shown + (f" and {len(paths) - limit} more" if len(paths) > limit else "")


def _same(a: Instance, b: Instance) -> bool:
    """Return whether two records are one instance: the same manager and a shared spelling of the prefix

    @param a  an instance record
    @param b  another instance record
    @returns  True when both hold
    """
    if a.manager is not b.manager:
        return False
    names = {os.path.normpath(s) for s in (a.prefix,) + tuple(a.spellings or ())}
    return any(os.path.normpath(s) in names for s in (b.prefix,) + tuple(b.spellings or ()))


def _instances(plan: Plan, bundle) -> list[Instance]:
    """Return the plan's instances, then any the fresh scan found that the plan does not record

    A deleted prefix is known only to the plan.

    @param plan    the plan phase 6 runs
    @param bundle  the fresh scan bundle, or None
    @returns       the instances, each once
    """
    out = list(plan.instances)
    fresh = bundle.result.instances if bundle is not None and bundle.result is not None else []
    for inst in fresh:
        if not any(_same(inst, other) for other in out):
            out.append(inst)
    return out


@dataclass
class _Archive:
    """One `tar` stream: `name` gives its file and action id, `paths` what it holds"""

    name: str
    paths: list[str]

    @property
    def subject(self) -> str:
        """Return the slug of `name`, the subject of the archive's file and action id

        @returns  the slug, as in `<run>/data-archive/<subject>.tar.gz` and `6.archive.<subject>`
        """
        return state.slug(self.name)


# The phase ------------------------------------------------------------------------------------

class _Phase:
    """One start of phase 6 over the instances the plan names"""

    def __init__(self, runner, run_dir: state.RunDir, plan: Plan, bundle, ask: Context, *, resumed: bool,
                 host: Host) -> None:
        """Gather what one start of phase 6 needs: the instances, the prefixes the plan names and the target

        @param runner   the runner of the phase's commands, with its console and environment
        @param run_dir  the run directory: journal, archives and backups
        @param plan     the plan; its `remove_manager` option names the prefixes
        @param bundle   the fresh scan of the host as phase 5 left it
        @param ask      the `Context` that asks the user
        @param resumed  read this run's earlier phase 6 records
        @param host     the system locations and clocks
        """
        self.runner = runner
        self.run_dir = run_dir
        self.plan = plan
        self.bundle = bundle
        self.ask: Context = ask
        self.host = host
        self.home = runner.environ.get("HOME") or os.path.expanduser("~")
        recorded = (bundle.result.system or {}).get("uid")
        self.uid = recorded if isinstance(recorded, int) and not isinstance(recorded, bool) else os.getuid()
        self.entries = run_dir.journal.entries() if resumed else []
        self.instances = _instances(plan, bundle)
        named = str((plan.options or {}).get("remove_manager") or "").split(",")
        self.named = [p for p in dict.fromkeys(named) if p]
        self.target = self._target()
        self.tilde = Redactor(home=self.home, user="")    # writes the home folder as `~` in the report lines
        self.kept: set[str] = set()       # named prefixes a "no" kept in this start
        self.skipped: set[str] = set()    # named prefixes left in place by a precondition
        self.emptied: set[str] = set()    # Homebrew prefixes whose enumerated list ran
        self.lines: list[str] = []
        self._receipt: tuple[frozenset[str] | None] | None = None
        self._root_files: RootFiles | None = None

    def _target(self) -> Instance:
        """Return the target with its current identity, for the identity test of `unsafe`

        @returns  the instance record of the target prefix, else one made from the plan
        """
        prefix = self.plan.target_prefix
        target = next((i for i in self.instances if i.prefix == prefix), None)
        if target is None:
            target = Instance(manager=self.plan.target, prefix=prefix, identity=(0, 0), spellings=(prefix,),
                              binary=None, version=None, arch=None, usability=Usability.USABLE,
                              usability_detail=None, drivable=True, inventory_error=None, repository=None,
                              cache_dir=None, portdbpath=None, applications_dir=None)
        current = system.identity(target.prefix)
        return dataclasses.replace(target, identity=current) if current is not None else target

    def run(self) -> list[str]:
        """Remove every named instance in order, then the shared Homebrew caches

        @returns  the report lines
        """
        for prefix in self.named:
            inst = next((i for i in self.instances if i.prefix == prefix), None)
            if inst is None:
                self.say(f"  {prefix} stays, untouched: the plan knows no Homebrew or MacPorts there.")
                continue
            removal = _MacPorts(self, inst) if inst.manager is Manager.PORTS else _Homebrew(self, inst)
            removal.run()
        self.caches()
        return list(self.lines)

    # Report, journal and questions ---------------------------------------------------------

    def say(self, text: str) -> None:
        """Add a report line and print it at once, so a listing comes before its question

        `--quiet` does not hide it: the questions refer to these lines, and each says what was deleted. A path in
        the home folder is written with `~`, as the other phases write it.

        @param text  the line
        """
        text = self.tilde(text)
        self.lines.append(text)
        self.runner.console.out(text)

    def record(self, action_id: str, **fields: Any) -> None:
        """Journal a phase 6 record of the tool's own; the command lines are the runner's

        @param action_id  the record's action id
        @param fields     the record's other fields
        """
        entry: dict[str, Any] = {"ts": state.now_iso(), "phase": PHASE, "action_id": action_id}
        entry.update(fields)
        self.run_dir.journal.append(entry)

    def confirm(self, question: str) -> bool:
        """Ask one of the phase's second confirmations; `--yes` answers every confirmation of this phase

        @param question  the question
        @returns         the answer; no answer counts as False
        """
        if self.ask.yes:
            return True
        return bool(self.ask.confirm(question, False))

    def accepted(self, inst: Instance) -> dict[str, Any] | None:
        """Return an earlier start's identity record of the instance, which stands in for its marker files

        That start's deletion may have removed the markers; the record counts while the prefix is gone or is
        still the same directory.

        @param inst  the instance
        @returns     the last such record; None without one, or when the prefix is another directory
        """
        action_id = IDENTITY + state.slug(inst.prefix)
        found = None
        for entry in self.entries:
            if entry.get("phase") == PHASE and entry.get("action_id") == action_id:
                found = entry
        if found is None:
            return None
        current = system.identity(inst.prefix)
        if current is not None and tuple(found.get("identity") or ()) != tuple(current):
            return None
        return found

    # The host --------------------------------------------------------------------------------

    def receipt(self) -> frozenset[str] | None:
        """Return the files of the MacPorts installer receipt, probed once with `pkgutil --files`

        @returns  the paths, `/` prepended; None without a receipt, as for a base built from source
        """
        if self._receipt is None:
            result = self.runner.run(system.probe(f"6.check.pkgutil.{PKG_ID}", [PKGUTIL, "--files", PKG_ID],
                                                  "files of the MacPorts installer receipt"))
            files = None
            if result.exit == 0:
                files = frozenset("/" + line.strip().lstrip("/") for line in result.stdout().splitlines()
                                  if line.strip())
            self._receipt = (files,)
        return self._receipt[0]

    def root_files(self) -> RootFiles:
        """Return this run's root backup store, made on first use

        @returns  the store
        """
        if self._root_files is None:
            self._root_files = RootFiles(self.runner, self.run_dir.run_id)
        return self._root_files

    def is_usr_local(self, inst: Instance) -> bool:
        """Return whether the instance is at `/usr/local`, which other installers share: never a dedicated prefix

        @param inst  a Homebrew instance
        @returns     True for the host's `/usr/local`, by identity while both exist, else by spelling
        """
        usr = self.host.usr_local
        if os.path.exists(inst.prefix) and os.path.exists(usr):
            return system.same_path(inst.prefix, usr)
        fold = env.fold_case_for(inst)
        want = system.normalise_text_path(usr, fold)
        return any(system.normalise_text_path(s, fold) == want for s in (inst.prefix,) + tuple(inst.spellings or ()))

    def origin_ok(self, inst: Instance) -> bool:
        """Return whether phase 6 may delete this Homebrew prefix, judged by its origin

        The prefix must be `/opt/homebrew`, `/usr/local`, `HOMEBREW_PREFIX` or one found through its own
        `brew` binary.

        @param inst  a Homebrew instance
        @returns     True for one of those origins
        """
        allowed = [brew_locate.ARM64_PREFIX, self.host.usr_local, self.runner.environ.get("HOMEBREW_PREFIX") or ""]
        if inst.binary:
            allowed.append(os.path.dirname(os.path.dirname(inst.binary)))
        fold = env.fold_case_for(inst)
        names = {system.normalise_text_path(s, fold) for s in (inst.prefix,) + tuple(inst.spellings or ())}
        return any(a and system.normalise_text_path(a, fold) in names for a in allowed)

    def legacy_paths(self) -> list[str]:
        """Return the legacy MacPorts paths that exist under the host's `/Applications` and `/Library`

        The patterns are `plan_phases.MACPORTS_LEGACY`: `/Applications/DarwinPorts`,
        `/Library/Receipts/MacPorts*.pkg` and the like.

        @returns  the paths, sorted within each pattern
        """
        out: list[str] = []
        for pattern in plan_phases.MACPORTS_LEGACY:
            for real, root in (("/Applications", self.host.applications), ("/Library", self.host.library)):
                if pattern.startswith(real + "/"):
                    out += sorted(glob.glob(glob.escape(root) + pattern[len(real):]))
        return out

    def survivors(self, inst: Instance, manager: Manager | None = None) -> list[Instance]:
        """Return the instances other than `inst` that stay on the host

        They are the target, every instance the plan does not name, and every named one this start kept or
        left in place; a named instance still to come counts as removed.

        @param inst     the instance phase 6 removes
        @param manager  only the instances of this manager; None for all
        @returns        the survivors, in the order of the instances
        """
        out = []
        for other in self.instances:
            if _same(other, inst) or (manager is not None and other.manager is not manager):
                continue
            if other.prefix in self.named and other.prefix not in self.kept and other.prefix not in self.skipped:
                continue
            out.append(other)
        return out

    # Deleting ------------------------------------------------------------------------------

    def unsafe(self, path: str, inst: Instance) -> str | None:
        """Return why `path` must never be deleted, or None

        The rules of `plan_phases.unsafe` (the target prefix or below, a system directory, the home directory
        or a parent of it), and the same for every survivor: its owned roots, below them, or holding one.

        @param path  a path phase 6 is about to delete
        @param inst  the instance it deletes for
        @returns     the reason, as the report prints it; None when the path may go
        """
        why = plan_phases.unsafe(path, self.target, self.home)
        if why:
            return why
        ident = system.identity(path)
        for other in [self.target] + self.survivors(inst):
            for root in env.roots_of(other):
                root_ident = system.identity(root)
                if root_ident is not None and system.lies_under(path, root_ident):
                    return f"it lies under {root}, which stays"
                if ident is not None and system.lies_under(root, ident):
                    return f"it holds {root}, which stays"
        return None

    def rm(self, action_id: str, argv: list[str], sudo: bool, description: str) -> bool:
        """Run one `rm` as a probe, so a path an earlier start removed fails nothing

        @param action_id    the action id the journal records
        @param argv         the `rm` command line
        @param sudo         whether it runs as root
        @param description  what the journal says it does
        @returns            True when it exited 0
        """
        action = Action(action_id=action_id, kind="command", argv=argv, sudo=sudo, description=description,
                        on_failure=OnFailure.PROBE)
        return self.runner.run(action).exit == 0

    def remove(self, path: str, inst: Instance, *, sudo: bool | None = None, flags: str = "-rf",
               checked: bool = False, quiet: bool = False) -> bool | None:
        """Run `rm <flags> <path>` after the safety rules, and report the outcome

        With `sudo` None it runs as the user when the parent is writable, and again under `sudo` when that
        leaves the path in place, so `sudo` serves only paths the user cannot remove.

        @param path     the path
        @param inst     the instance it deletes for, whose survivors the safety rules keep
        @param sudo     True runs it as root at once, False as the user first; None decides as above
        @param flags    the `rm` flags: `-rf`, `-f` for a file or link, `-d` for an empty directory
        @param checked  whether the caller applied the safety rules already
        @param quiet    report a failure only
        @returns        None when the path is absent or refused, else whether it is gone
        """
        if not os.path.lexists(path):
            return None
        if not checked:
            why = self.unsafe(path, inst)
            if why:
                self.say(f"  {path} stays: {why}.")
                return None
        action_id = f"6.delete.{state.slug(path)}"
        escalate = sudo if sudo is not None else not os.access(os.path.dirname(path) or "/", os.W_OK)
        what = f"delete {path}"
        ok = self.rm(action_id, [RM, flags, path], escalate, what)
        if not ok and not escalate and os.path.lexists(path):
            ok = self.rm(action_id + ".sudo", [RM, flags, path], True, what + " as root")
        gone = ok and not os.path.lexists(path)
        if not gone or not quiet:
            self.say(("  Deleted %s." if gone else "  Could not delete %s.") % path)
        return gone

    def caches(self) -> None:
        """Delete the caches every Homebrew instance of the user shares, once no Homebrew instance survives

        A `cache_dir` the user set elsewhere (`HOMEBREW_CACHE`) is reported, never deleted.
        """
        brews = [i for i in self.instances if i.manager is Manager.BREW and i.prefix in self.named]
        if not brews:
            return
        shared = plan_phases.homebrew_shared_caches(self.home, self.host.library)
        defaults = {os.path.normpath(p) for p in shared}
        for inst in brews:
            if inst.cache_dir and os.path.normpath(inst.cache_dir) not in defaults:
                self.say(f"  {inst.cache_dir} stays: it is the download folder you set with HOMEBREW_CACHE.")
        stays = [i for i in self.instances if i.manager is Manager.BREW
                 and (i.prefix not in self.named or i.prefix not in self.emptied)]
        present = [p for p in shared if os.path.lexists(p)]
        if not present:
            return
        if stays:
            self.say(f"  Homebrew's download folders stay: {at(stays[0])} uses them.")
            return
        self.say("  No Homebrew is left, so its download folders go too.")
        for path in present:
            self.remove(path, brews[0])


# One instance ---------------------------------------------------------------------------------

class _Removal:
    """Phase 6 of one instance; the manager classes below supply the lists and the checks"""

    def __init__(self, phase: _Phase, inst: Instance) -> None:
        """Gather the instance's services, index and earlier records for its removal

        @param phase  the start of phase 6 the removal belongs to
        @param inst   the instance to remove
        """
        self.p = phase
        self.runner = phase.runner
        self.inst = inst
        self.prefix = inst.prefix
        self.subject = state.slug(inst.prefix)
        self.services = [s for s in phase.bundle.result.services if s.instance_prefix == inst.prefix]
        self.owned = [s for s in self.services if s.owned]
        self.index = env.PrefixIndex([inst])
        self.identity_record = phase.accepted(inst)
        self.begun = deletion_begun(phase.entries, inst.prefix)
        self.booted: list[Service] = []
        self.deleting = False
        self.archived: list[str] = []
        self.failures: list[str] = []

    # The steps the managers supply -----------------------------------------------------------

    def precondition(self) -> str | None:
        """Return why the prefix is left in place, untouched, or None when the removal goes ahead

        @returns  the reason the report prints, or None
        """
        raise NotImplementedError

    def markers(self) -> list[str]:
        """Return the marker files, relative to the prefix, that show it is the manager's

        @returns  the markers that exist, for the identity record
        """
        raise NotImplementedError

    def prepare(self) -> None:
        """Gather what the checks need besides the archive list"""

    def check_packages(self) -> None:
        """Stop the phase when a drivable instance still holds a package phase 5 should have removed

        @throws Stopped  when a package is left, or the check cannot tell
        """
        raise NotImplementedError

    def archives(self) -> list[_Archive]:
        """Return the archives the phase takes before the first deletion

        @returns  one archive per path of the manager's archive list, and any the manager adds
        """
        raise NotImplementedError

    def extra_archives(self) -> list[str]:
        """Return the paths archived later in the phase, counted by the space check

        @returns  the paths; none unless the manager has some
        """
        return []

    def confirm_data(self) -> None:
        """Ask the second confirmation that comes before the first deletion"""

    def delete(self) -> None:
        """Delete the instance's delete list; a path that stays joins `failures`"""
        raise NotImplementedError

    # The order of the phase ----------------------------------------------------------------

    def run(self) -> None:
        """Run phase 6 for one instance: the precondition, the checks, archives, identity record, deletions

        An undrivable instance's services stop before the checks, a drivable one's after the archives; until
        the first deletion a failure starts the booted-out services again before it stops the phase. Only a
        drivable instance gets the package check.
        """
        if len(self.p.named) > 1:
            self.p.say(f"  {at(self.inst)}:")
        target = self.p.target
        if _same(self.inst, target) or (system.identity(self.prefix) or ()) == tuple(target.identity or ()):
            why: str | None = "it is where this plan moves the packages"
        else:
            why = self.precondition()
        if why:
            self.p.skipped.add(self.prefix)
            self.p.say(f"  {at(self.inst)} stays, untouched: {why}.")
            return
        try:
            if not self.inst.drivable:
                self.stop_services()
            self.prepare()
            if self.inst.drivable:
                self.check_packages()
            self.check_processes()
            self.check_space()
            self.take(self.archives())
            if self.inst.drivable:
                self.stop_services()
            self.confirm_data()
        except Stopped as exc:
            self.restart()
            exc.lines = list(self.p.lines)
            raise
        except ActionFailed as exc:
            self.restart()
            raise self.failed_command(exc) from exc
        except BaseException:           # interrupts too; only on failure, so not `finally`
            self.restart()
            raise
        self.start_deletions()
        try:
            self.delete()
        except Stopped as exc:
            exc.lines = list(self.p.lines)
            raise
        except ActionFailed as exc:
            raise self.failed_command(exc) from exc
        self.finish()
        if self.failures:
            raise Stopped(_result(f"6.delete.{self.subject}"),
                          f"{_brief(self.failures)} could not be deleted, so {at(self.inst)} is only partly "
                          "uninstalled", self.p.lines)

    def failed_command(self, exc: ActionFailed) -> Stopped:
        """Build the `Stopped` that ends the phase with a failed command

        @param exc  the failure of a `STOP` action
        @returns    the stop, with the command's result and the report so far; `apply` prints its reason
        """
        return Stopped(exc.result, apply_report.failed(exc.result), self.p.lines)

    def fail(self, result: Any, reason: str, details: Sequence[str] = ()) -> Stopped:
        """Build a `Stopped` for a check, its details put into the report first

        @param result   the check's result, or the action id of a check that ran no command
        @param reason   why the phase stops, which `apply` prints as its error
        @param details  the report lines the reason refers to
        @returns        the stop, for the caller to raise
        """
        for line in details:
            self.p.say("    " + line)
        return Stopped(result if isinstance(result, Result) else _result(str(result)), reason, self.p.lines)

    def stop_services(self) -> None:
        """Boot out each owned service of the instance from the domain the probes find it in, and wait

        An undrivable instance's services go first, because nothing else stopped them.

        @throws Stopped  when a job outlives the wait
        """
        if not self.owned:
            return
        host = self.p.host
        res = servicectl.stop(self.runner, self.owned, self.p.uid, id_prefix=str(PHASE), clock=host.clock,
                              sleep=host.sleep, alive=host.alive)
        for svc in res.booted:
            self.booted.append(svc)
            self.p.say(f"  Stopped the service {svc.label}.")
        if res.error is not None:
            raise res.error
        if res.still_running:
            text = "; ".join(why for _, why in res.still_running)
            raise self.fail(f"6.stop.{res.still_running[0][0].label}", f"{text}; nothing of {self.prefix} is deleted "
                            "while it runs: stop it yourself, or quit what keeps it running")

    def restart(self) -> None:
        """Start the services this phase booted out again, while nothing is deleted"""
        if self.deleting or not self.booted:
            return
        for svc, ok in servicectl.restart(self.runner, self.booted, (), id_prefix=str(PHASE)):
            self.p.say(("  Started the service %s again." if ok else
                        "  Could not start the service %s again; start it yourself.") % svc.label)
        self.booted = []

    def check_processes(self) -> None:
        """Stop the phase when `sudo lsof -nP -F pn` shows a process that uses the instance

        The probe exits 1 when it lists nothing. A process uses the instance when its executable, a mapped
        library, its working directory or an open file lies under the `owned_roots`.

        @throws Stopped  when a process uses the instance, or lsof fails
        """
        action = Action(action_id=f"6.check.lsof.{self.subject}", kind="command", argv=[LSOF, "-nP", "-F", "pn"],
                        sudo=True, description=f"processes that use {self.prefix}", on_failure=OnFailure.PROBE,
                        read_only=True)
        result = self.runner.run(action)
        if result.exit not in (0, 1):
            raise self.fail(result, f"`sudo lsof` failed (exit {result.exit}), so it is unknown whether a program "
                            f"still uses {self.prefix}")
        hits = processes_under(parse_lsof(result.stdout()), self.index)
        if hits:
            details = [f"{proc.program or 'a program'} (pid {proc.pid}): {_brief(names)}" for proc, names in hits]
            one = len(hits) == 1
            raise self.fail(result, f"{counted(len(hits), 'program')} still {'uses' if one else 'use'} {self.prefix}, "
                            f"listed above; quit {'it' if one else 'them'} first", details)

    def check_space(self) -> None:
        """Stop the phase unless the run directory's volume has room for all it still archives plus 1 GiB

        `sudo du -sk` measures, so root-only directories count.

        @throws Stopped  when the room is short or unknown, or du gives no size for a path
        """
        paths = _outermost([p for p in self.to_archive() if os.path.lexists(p)])
        total, result = 0, None
        if paths:
            action = Action(action_id=f"6.check.du.{self.subject}", kind="command", argv=[DU, "-sk"] + paths,
                            sudo=True, description=f"size of what phase 6 archives from {self.prefix}",
                            on_failure=OnFailure.PROBE, read_only=True)
            result = self.runner.run(action)
            sizes = parse_du(result.stdout())
            unknown = [p for p in paths if p not in sizes]
            if unknown:
                raise self.fail(result, f"`sudo du` gave no size for {_brief(unknown)}, so the room its copy needs "
                                "is unknown")
            total = sum(sizes[p] for p in paths) * 1024
        free = self.p.host.free_bytes(self.p.run_dir.path)
        if free is None or free < total + MARGIN:
            raise self.fail(result or f"6.check.du.{self.subject}",
                            f"the disk of the run folder has {'an unknown amount' if free is None else _size(free)} "
                            f"free; the settings and data of {self.prefix} to save need {_size(total)} plus 1 GiB. "
                            "Free up space there first")
        self.p.say(f"  Checked: no program uses {self.prefix}, and {_size(free)} is free for the {_size(total)} to "
                   "save.")

    def to_archive(self) -> list[str]:
        """Return every path this phase still archives from the instance

        @returns  the paths of every archive but those an earlier start keeps, then the entries the manager
                  archives later in the phase
        """
        out = [p for arc in self.archives() if not self.kept_archive(arc) for p in arc.paths]
        return out + self.extra_archives()

    def kept_archive(self, arc: _Archive) -> bool:
        """Return whether an earlier start's archive stays as it is, since its paths may be gone

        It stays once a deletion of the instance has run and the journal records the archive as `ok`.

        @param arc  the archive
        @returns    True to keep it rather than take it again
        """
        return self.begun and _last_result(self.p.entries, f"6.archive.{arc.subject}") == "ok"

    def take(self, archives: Sequence[_Archive]) -> None:
        """Take each archive with `sudo tar -czf - -C /`, its output stored through `Action.dst`

        The file is `<run>/data-archive/<slug>.tar.gz`; an archive an earlier start keeps is not taken again.

        @param archives       the archives, in order; their paths that are gone are left out
        @throws ActionFailed  when `tar` fails, a `STOP` action, which stops the phase
        """
        kept: list[str] = []
        saved: list[str] = []
        try:
            for arc in archives:
                dst = os.path.join(self.p.run_dir.path, ARCHIVES, arc.subject + ".tar.gz")
                if self.kept_archive(arc):
                    self.archived.extend(arc.paths)
                    kept.extend(arc.paths)
                    continue
                paths = [p for p in arc.paths if os.path.lexists(p)]
                if not paths:
                    continue
                action = Action(action_id=f"6.archive.{arc.subject}", kind="command",
                                argv=[TAR, "-czf", "-", "-C", "/"] + [p.lstrip("/") for p in paths], sudo=True,
                                description=f"archive {', '.join(paths)} into {dst}", dst=dst)
                self.runner.run(action)
                self.archived.extend(paths)
                saved.extend(paths)
        finally:
            if kept:
                self.p.say(f"  Saved by an earlier attempt: {some(kept, SAVED_SHOWN)}")
            if saved:
                self.p.say(f"  Saved in the folder {ARCHIVES} of the run folder: {some(saved, SAVED_SHOWN)}")

    def covered(self, path: str) -> bool:
        """Return whether `path` lies inside an archive this phase took, or kept, of the instance

        @param path  an entry about to be archived
        @returns     True when it is an archived path or lies under one
        """
        return bool(self.archived) and system.text_names_prefix(path, self.archived, False)

    def start_deletions(self) -> None:
        """Journal the instance's identity before its first deletion; from here on nothing starts again

        The record (its prefix and the marker files the safety rules test) stands in for the markers on a
        resumed phase; once a deletion follows it, an archive journaled `ok` is not taken again.
        """
        rec = self.identity_record or {}
        ident = system.identity(self.prefix) or tuple(rec.get("identity") or ()) or tuple(self.inst.identity)
        self.p.record(IDENTITY + self.subject, prefix=self.prefix, manager=self.inst.manager.value,
                      identity=list(ident), spellings=list(self.inst.spellings or (self.prefix,)),
                      markers=self.markers() or list(rec.get("markers") or []))
        self.deleting = True

    def remove(self, path: str, **kw: Any) -> bool | None:
        """Delete one path of the instance with `_Phase.remove`, a path that stays joining `failures`

        @param path  the path
        @param kw    the options of `_Phase.remove`: `sudo`, `flags`, `checked` and `quiet`
        @returns     None when the path is absent or refused, else whether it is gone
        """
        gone = self.p.remove(path, self.inst, **kw)
        if gone is False:
            self.failures.append(path)
        return gone

    def finish(self) -> None:
        """List each user's own launchd job that runs a binary of the instance as "will stop working"

        The job itself is left alone.
        """
        for svc in self.services:
            if not svc.owned and not os.path.lexists(svc.program or self.prefix):
                self.p.say(f"  Your own service file {svc.plist} runs {svc.program or self.prefix}, which is gone: "
                           "edit or delete it.")


class _MacPorts(_Removal):
    """Phase 6 for a MacPorts instance: archive first, then delete"""

    def __init__(self, phase: _Phase, inst: Instance) -> None:
        """Start the removal of a MacPorts instance; `prepare` reads its configuration and files

        @param phase  the start of phase 6 the removal belongs to
        @param inst   the MacPorts instance
        """
        super().__init__(phase, inst)
        self.root = inst.prefix
        self.user = MACPORTS_USER
        self.keep = False
        self.receipt: frozenset[str] | None = None
        self.registered: set[str] = set()
        self.unregistered = Unregistered()

    def precondition(self) -> str | None:
        """Return why the prefix is left in place, or None: it must hold `etc/macports/macports.conf`

        An earlier start's identity record stands in for the file.

        @returns  the reason the report prints, or None
        """
        if self.identity_record is not None or os.path.isfile(os.path.join(self.prefix, MACPORTS_CONF)):
            return None
        return f"it holds no {MACPORTS_CONF}, so nothing shows that it is MacPorts"

    def markers(self) -> list[str]:
        """Return the MacPorts marker file when the prefix holds it

        @returns  `etc/macports/macports.conf`, or none
        """
        return [MACPORTS_CONF] if os.path.isfile(os.path.join(self.prefix, MACPORTS_CONF)) else []

    def prepare(self) -> None:
        """Read the instance's configuration and receipt, and find the files under it that neither base nor a port owns

        @throws Stopped  when the registry cannot be read
        """
        config = mp_locate.read_config(self.prefix, self.runner.environ)
        root = config.get("prefix") or self.prefix
        self.root = root if system.same_path(root, self.prefix) else self.prefix
        self.user = config.get("macportsuser") or MACPORTS_USER
        self.receipt = self.p.receipt()
        self.registered = self.registered_files()
        base = mp_locate.BaseFiles(self.root, self.receipt or frozenset())
        skip = [os.path.join(self.root, tree) for tree in mp_locate.BASE_TREES]
        self.unregistered = unregistered_units(
            self.root, skip,
            lambda path: not base.owns(path) and system.normalise_text_path(path, False) not in self.registered)

    def registered_files(self) -> set[str]:
        """Read the files the registry records below the prefix and `applications_dir`

        Both `files.path` and `files.actual_path` count, read from the phase 1 registry backup, else from a
        fresh backup.

        @returns  the paths, normalised; none without a registry
        """
        backup = os.path.join(snapshot.ports_dir(self.p.run_dir, self.prefix), snapshot.REGISTRY)
        action_id = f"6.check.registry.{self.subject}"
        try:
            if os.path.isfile(backup):
                reg = registry.Registry.open_backup(backup)
            elif self.inst.portdbpath:
                reg = registry.Registry.open_copy(self.inst.portdbpath)
            else:
                return set()
        except registry.RegistryMissing:
            return set()
        except (registry.RegistryBusy, sqlite3.DatabaseError, OSError) as exc:
            raise self.fail(action_id, f"MacPorts' record of what is installed in {self.prefix} cannot be read "
                                       f"({exc}), so the files that no port installed are unknown")
        out: set[str] = set()
        try:
            rows = reg.files_below(self.root)
            if self.inst.applications_dir:
                rows += reg.files_below(self.inst.applications_dir)
        except sqlite3.DatabaseError as exc:
            raise self.fail(action_id, f"the saved copy of MacPorts' record of {self.prefix} cannot be read ({exc})")
        finally:
            reg.close()
        for _, row in rows:
            for path in (row.path, row.actual_path):
                if path:
                    out.add(system.normalise_text_path(path, False))
        return out

    def check_packages(self) -> None:
        """Stop the phase when a fresh registry backup of a drivable instance still holds a port

        Phase 5 uninstalls every row, so a row left is a failure.

        @throws Stopped  when a port is left, or the registry cannot be read
        """
        if not self.inst.portdbpath:
            return
        action_id = f"6.check.registry.{self.subject}"
        try:
            with registry.Registry.open_copy(self.inst.portdbpath) as reg:
                rows = reg.ports()
        except registry.RegistryMissing:
            return
        except (registry.RegistryBusy, sqlite3.DatabaseError, OSError) as exc:
            raise self.fail(action_id, f"MacPorts' record of what is installed in {self.prefix} cannot be read "
                                       f"({exc}), so whether a port is left is unknown")
        if rows:
            raise self.fail(action_id, f"{self.prefix} still holds {counted(len(rows), 'port')}, listed above, which "
                            "phase 5 should have uninstalled", [" ".join(r.spec_args) for r in rows[:20]])

    def archives(self) -> list[_Archive]:
        """Return one archive per path of the MacPorts archive list

        @returns  the archives, in the list's order
        """
        return [_Archive(p, [p]) for p in plan_phases.macports_archive_list(self.inst, self.p.home)]

    def extra_archives(self) -> list[str]:
        """Return the unregistered entries outside the archive list, which the second confirmation archives

        @returns  the entries
        """
        initial = [p for arc in self.archives() for p in arc.paths]
        return [u for u in self.unregistered.units if not system.text_names_prefix(u, initial, False)]

    def confirm_data(self) -> None:
        """List the unregistered entries and ask before they are archived and deleted with the prefix

        A "no" keeps the prefix with them, while the rest of the delete list still goes, and makes the
        instance a survivor (`6.keep.<prefix>`).

        @throws ActionFailed  when an archive of the entries fails
        """
        found = self.unregistered
        if not found.units:
            return
        one = len(found.units) == 1
        self.p.say(f"  {counted(len(found.units), 'item')} in {self.prefix} ({counted(found.count, 'file')}) "
                   f"{'was' if one else 'were'} not installed by a port:")
        for unit in found.units:
            self.p.say(f"    {unit}{'/' if os.path.isdir(unit) and (not os.path.islink(unit)) else ''}")
        them = "it" if one else "them"
        if self.p.ask.yes:
            self.p.say(f"  --yes answers for you: {'it is' if one else 'they are'} saved in the run folder, then "
                       f"deleted with {self.prefix}.")
        else:
            self.p.say(f"  y saves {them} in the run folder, then deletes {them} with {self.prefix}.")
            self.p.say(f"  n keeps {self.prefix} with everything in it; what MacPorts put outside it is still "
                       "deleted.")
        if self.p.confirm(f"Delete {self.prefix} with {'this item' if one else 'these items'}?"):
            self.take([_Archive(u, [u]) for u in found.units if not self.covered(u)])
            return
        self.keep = True
        self.p.kept.add(self.prefix)
        self.p.say(f"  {self.prefix} stays with everything in it, as you answered.")

    def delete(self) -> None:
        """Delete the `macports` user and group, the delete list, then the installer receipt once the prefix is gone

        The delete list holds `<prefix>`, `<portdbpath>` outside it, `applications_dir` unless it is
        `/Applications` or `~/Applications`, the owned plists, and the legacy MacPorts paths with `~/.macports`
        when no other MacPorts instance survives.
        """
        others = bool(self.p.survivors(self.inst, Manager.PORTS))
        home = self.macports_user(others)
        paths = plan_phases.macports_delete_list(self.inst, self.p.home, self.services, True)
        if not others:
            paths += self.p.legacy_paths()
            dot = os.path.join(self.p.home, ".macports")
            if os.path.isdir(dot):
                paths.append(dot)
        for path in dict.fromkeys(paths):
            self.delete_one(path, home)
        self.unowned_plists()
        if not self.keep and not os.path.lexists(self.prefix):
            self.forget()

    def delete_one(self, path: str, home: str | None) -> None:
        """Delete one path with sudo, unless it is kept or unsafe; a `home` inside it survives

        `applications_dir` also stays while a file below it is not registered to this instance.

        @param path  a path of the delete list
        @param home  the home of a MacPorts user that stays, or None
        """
        if not os.path.lexists(path):
            return
        if self.keep and system.text_names_prefix(path, [self.prefix], False):
            if os.path.normpath(path) != os.path.normpath(self.prefix):
                self.p.say(f"  {path} stays with {self.prefix}.")
            return
        why = self.p.unsafe(path, self.inst)
        apps = self.inst.applications_dir
        if why is None and apps and os.path.normpath(path) == os.path.normpath(apps):
            why = self.apps_refusal(path)
        if why:
            self.p.say(f"  {path} stays: {why}.")
            return
        if home and os.path.normpath(home) != os.path.normpath(path) and system.text_names_prefix(home, [path], False):
            self.remove_around(path, home)
            return
        self.remove(path, sudo=True, checked=True)

    def apps_refusal(self, apps: str) -> str | None:
        """Return why `applications_dir` stays, or None when every file below it is registered to this instance

        Only a port of this instance counts, so another instance's apps keep the directory.

        @param apps  the instance's `applications_dir`
        @returns     the reason the report prints; None when it may go
        """
        strays = [p for p in _files_below(apps) if system.normalise_text_path(p, False) not in self.registered]
        if strays:
            return f"it holds files that no port of {self.prefix} installed: {_brief(strays)}"
        return None

    def remove_around(self, path: str, keep: str) -> None:
        """Remove everything under `path` except `keep` and the directories leading to it

        `keep` is the home of a MacPorts user that stays, which SIP keeps from being removed.

        @param path  a path of the delete list that holds `keep`
        @param keep  the home to leave in place
        """
        current = path
        while os.path.normpath(current) != os.path.normpath(keep):
            names = _entries(current)
            if names is None:
                self.failures.append(current)
                self.p.say(f"  Could not list {current}.")
                return
            following = None
            for name in names:
                child = os.path.join(current, name)
                if system.text_names_prefix(keep, [child], False):
                    following = child
                else:
                    self.remove(child, sudo=True, checked=True)
            if following is None:
                break
            current = following
        self.p.say(f"  {keep} stays: it is the home of the user {self.user}, who stays.")

    def deleted_roots(self) -> list[str]:
        """Return the paths of the delete list a user's home may lie under, where the safety rules let them go

        They are `<prefix>` unless a "no" keeps it, and `<portdbpath>` when it lies outside the prefix.

        @returns  the paths that exist
        """
        out = [] if self.keep else [self.prefix]
        db = self.inst.portdbpath
        if db and not system.text_names_prefix(db, [self.prefix], False):
            out.append(db)
        return [p for p in out if os.path.lexists(p) and self.p.unsafe(p, self.inst) is None]

    def macports_user(self, others: bool) -> str | None:
        """Delete the `macports` user and group whose home this run deletes, unless another MacPorts instance survives

        With SIP on, the home of a user that exists cannot be removed, so the deletion leaves a staying user's
        home in place.

        @param others  whether another MacPorts instance survives
        @returns       the home of a user that stays, for the deletion to leave in place; None when there is none
        """
        record = f"/Users/{self.user}"
        result = self.runner.run(system.probe(f"6.check.dscl.{state.slug(record)}",
                                              [DSCL, ".", "-read", record, "NFSHomeDirectory"],
                                              f"the home of the {self.user} user"))
        fields = system.parse_dscl(result.stdout()) if result.exit == 0 else {}
        home = fields.get("NFSHomeDirectory")
        if not home or not any(system.text_names_prefix(home, [p], False) for p in self.deleted_roots()):
            return None
        if self.user != MACPORTS_USER:
            self.p.say(f"  The user {self.user} stays: macports.conf names it as MacPorts' user (macportsuser), and "
                       "brew-ports deletes only the user macports.")
            return home
        if others:
            self.p.say("  The user macports stays: another MacPorts uses it.")
            return home
        user_gone = self.dscl_delete("/Users/macports")
        group_gone = self.dscl_delete("/Groups/macports")
        if not user_gone:
            self.p.say("  Could not delete the user macports.")
            return home
        self.p.say(f"  Deleted the user macports{' and its group' if group_gone else '; its group stays'}.")
        return None

    def dscl_delete(self, record: str) -> bool:
        """Delete a record of the local directory as root, a probe

        @param record  `/Users/macports` or `/Groups/macports`
        @returns       True when `dscl` exited 0
        """
        action = Action(action_id=f"6.dscl.{state.slug(record)}", kind="command",
                        argv=[DSCL, ".", "-delete", record], sudo=True,
                        description=f"delete the directory record {record}", on_failure=OnFailure.PROBE)
        return self.runner.run(action).exit == 0

    def unowned_plists(self) -> None:
        """List, and never delete, each MacPorts-named plist that MacPorts does not own or the tool could not read

        The plists are the `org.macports.*` ones in `/Library/LaunchDaemons` and `/Library/LaunchAgents`; one
        MacPorts does not own is a user's own launchd job.
        """
        services = self.p.bundle.result.services
        owned = {s.plist for s in services if s.owned}
        elsewhere = {s.plist for s in services if s.instance_prefix != self.prefix}
        for sub in ("LaunchDaemons", "LaunchAgents"):
            pattern = os.path.join(glob.escape(os.path.join(self.p.host.library, sub)), "org.macports.*.plist")
            for path in sorted(glob.glob(pattern)):
                if path not in owned and path not in elsewhere:
                    self.p.say(f"  {path} stays: it is not a service file of MacPorts, or it could not be read.")

    def forget(self) -> None:
        """Forget the MacPorts installer receipt with `sudo pkgutil --forget` when its files lie under this prefix

        A base built from source has no receipt; the command is a probe.
        """
        receipt = self.receipt
        if not receipt:
            return
        if not receipt_under(receipt, self.inst):
            self.p.say("  The record macOS keeps of the MacPorts installer stays: it names files outside "
                       f"{self.prefix}.")
            return
        action = Action(action_id=f"6.pkgutil.{PKG_ID}", kind="command", argv=[PKGUTIL, "--forget", PKG_ID],
                        sudo=True, description="forget the MacPorts installer receipt", on_failure=OnFailure.PROBE)
        ok = self.runner.run(action).exit == 0
        self.p.say(("  Deleted the record macOS keeps of the MacPorts installer (%s)." if ok else
                    "  Could not delete the record macOS keeps of the MacPorts installer (%s).") % PKG_ID)

    def finish(self) -> None:
        """List the users' own jobs, then journal the prefix a "no" keeps with its unregistered entries

        The `6.keep.<prefix>` record makes the instance a survivor for the environment cleanup.
        """
        super().finish()
        if self.keep:
            self.p.record(KEEP + self.subject, result="keep", prefix=self.prefix, entries=list(self.unregistered.units))


class _Homebrew(_Removal):
    """Phase 6 for a source Homebrew instance; the target prefix is never touched"""

    def __init__(self, phase: _Phase, inst: Instance) -> None:
        """Start the removal of a Homebrew instance; `prepare` reads its repository's state

        @param phase  the start of phase 6 the removal belongs to
        @param inst   the Homebrew instance
        """
        super().__init__(phase, inst)
        self.repository = inst.repository or inst.prefix
        self.usr_local = phase.is_usr_local(inst)
        self.repo_paths: list[str] | None = None

    def precondition(self) -> str | None:
        """Return why the prefix is left in place, or None when the removal goes ahead

        It needs its phase 1 disk snapshot, an origin phase 6 may delete, and `bin/brew` or `Cellar`, for
        which an earlier start's identity record may stand in.

        @returns  the reason the report prints, or None
        """
        snap = snapshot.brew_dir(self.p.run_dir, self.prefix)
        missing = [n for n in (snapshot.FORMULAE, snapshot.CASKS) if not os.path.isfile(os.path.join(snap, n))]
        if missing:
            return f"the record saved for undo lacks {apply_report.series(missing)}"
        if not self.p.origin_ok(self.inst):
            return ("it is not /opt/homebrew, /usr/local, HOMEBREW_PREFIX or a folder found through its own `brew`, "
                    "so nothing shows that Homebrew made it")
        if self.identity_record is None and not self.markers():
            return "it holds neither bin/brew nor Cellar, so nothing shows that it is Homebrew"
        return None

    def markers(self) -> list[str]:
        """Return the Homebrew marker files the prefix holds

        @returns  `bin/brew` and `Cellar`, each when present
        """
        out = []
        if os.path.lexists(os.path.join(self.prefix, "bin", "brew")):
            out.append("bin/brew")
        if os.path.isdir(os.path.join(self.prefix, "Cellar")):
            out.append("Cellar")
        return out

    def prepare(self) -> None:
        """Find the repository's local state, which the archives then include"""
        self.repo_paths = self.repository_state()

    def check_packages(self) -> None:
        """Stop the phase when a drivable instance still holds a formula or cask

        A walk of `Cellar` and `Caskroom` finds them, a rename link not counted; phase 5 uninstalls them all,
        so one left is a failure.

        @throws Stopped  when a package is left, or `Cellar` or `Caskroom` cannot be listed
        """
        left: list[str] = []
        for sub, walk in (("Cellar", brew_inventory.walk_cellar), ("Caskroom", brew_inventory.walk_caskroom)):
            directory = os.path.join(self.prefix, sub)
            if _entries(directory) is None:
                raise self.fail(f"6.check.packages.{self.subject}",
                                f"{directory} cannot be listed, so whether it is empty is unknown")
            found, _ = walk(self.prefix)
            left += [f"{sub}/{name}" for name in sorted(found)]
        if left:
            raise self.fail(f"6.check.packages.{self.subject}", f"{self.prefix} still holds "
                            f"{counted(len(left), 'package')}, listed above, which phase 5 should have uninstalled",
                            left[:20])

    def repository_state(self) -> list[str] | None:
        """Return the `.git` and every existing path `status` lists when the repository holds local state

        Local state is a non-empty `status --porcelain`, a local commit or `refs/stash` (lock-free probes);
        a repository git cannot read gets its `.git` archived.

        @returns  the paths to archive, `.git` first; None without local state or without a `.git`
        """
        repo = self.repository
        git_dir = os.path.join(repo, ".git")
        if not os.path.isdir(git_dir):
            return None
        tag = state.slug(repo)
        head = [GIT, "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", repo]
        status = self.runner.run(brew_inventory.git_status_probe(repo, f"6.check.git-status.{tag}"))
        commits = self.runner.run(system.probe(f"6.check.git-commits.{tag}",
                                               head + ["rev-list", "--count", "--branches", "--not", "--remotes"],
                                               f"local commits in {repo}"))
        stash = self.runner.run(system.probe(f"6.check.git-stash.{tag}",
                                             head + ["rev-parse", "-q", "--verify", "refs/stash"],
                                             f"a stash in {repo}"))
        reasons: list[str] = []
        changed = parse_porcelain(status.stdout()) if status.exit == 0 else []
        if status.exit != 0:
            reasons.append(f"git status exited {status.exit}")
        elif changed:
            reasons.append(counted(len(changed), "changed path"))
        count = commits.stdout().strip()
        if commits.exit != 0:
            reasons.append(f"git rev-list exited {commits.exit}")
        elif count.isdigit() and int(count) > 0:
            reasons.append(counted(int(count), "local commit"))
        if stash.exit == 0:
            reasons.append("a stash")
        elif stash.exit != 1:
            reasons.append(f"git rev-parse exited {stash.exit}")
        if not reasons:
            return None
        self.p.say(f"  Homebrew's own files in {repo} hold changes of yours ({', '.join(reasons)}); they are saved "
                   "too.")
        paths = [git_dir]
        for rel in changed:
            path = os.path.normpath(os.path.join(repo, rel))
            if (os.path.lexists(path) and system.text_names_prefix(path, [repo], False)
                    and not system.text_names_prefix(path, paths, False)):
                paths.append(path)
        return paths

    def archives(self) -> list[_Archive]:
        """Return one archive per path of the Homebrew archive list, then one of the repository's local state

        @returns  the archives; the local state's is `<repository>.repository`
        """
        out = [_Archive(p, [p]) for p in plan_phases.homebrew_archive_list(self.inst)]
        if self.repo_paths:
            out.append(_Archive(self.repository + ".repository", list(self.repo_paths)))
        return out

    def extra_archives(self) -> list[str]:
        """Return the entries a dedicated prefix keeps after its enumerated list

        They are every top-level entry the list does not delete, which the phase lists, archives and removes
        behind a second confirmation.

        @returns  the entries; none at `/usr/local`
        """
        if self.usr_local:
            return []
        initial = [p for arc in self.archives() for p in arc.paths]
        listed = {os.path.normpath(p) for p in plan_phases.homebrew_delete_list(self.inst, [])}
        out = []
        for name in _entries(self.prefix) or []:
            path = os.path.join(self.prefix, name)
            if (os.path.normpath(path) in listed or system.text_names_prefix(path, initial, False)
                    or self.kept_archive(_Archive(path, [path]))):
                continue
            out.append(path)
        return out

    def delete(self) -> None:
        """Delete the owned plists, then the enumerated list of the official uninstall script, without running it

        Then the links into the Cellar and the directories they leave empty, `/etc/paths.d/homebrew`, the
        Applications links into the Cellar, and a dedicated prefix's remaining entries.

        @throws ActionFailed  when an archive of the remaining entries fails
        """
        links = self.cellar_links()
        app_links = self.application_links()
        trash = [] if self.inst.drivable else self.trash()
        for svc in self.owned:
            # A keg's own plist (`brew services run`) goes with the Cellar.
            if os.path.lexists(svc.plist) and self.index.by_identity(svc.plist) is None:
                self.remove(svc.plist, flags="-f", sudo=True if svc.scope == "system" else None)
        listed = plan_phases.homebrew_delete_list(self.inst, [])
        for path in listed:
            self.remove(path)
        self.remove_links(links)
        self.remove_emptied(list(links) + [os.path.dirname(path) for path in listed])
        self.paths_d()
        for link in app_links:
            self.remove(link, flags="-f")
        self.p.emptied.add(self.prefix)
        self.remaining()
        for token, path in trash:
            self.p.say(f"  {path} stays: move the app of the cask {token} to the Trash yourself.")

    def cellar_links(self) -> dict[str, list[str]]:
        """Find the links into the prefix's `Cellar`, `Caskroom` or `opt`, before the Cellar goes

        The walk covers `<prefix>/{bin,sbin,lib,include,share,etc,opt,Frameworks}`; a symlink counts when its
        target resolves into one of the three.

        @returns  the links, by the directory that holds them
        """
        roots: list[str] = []
        for sub in LINK_TARGETS:
            for base in (self.prefix,) + tuple(self.inst.spellings or ()):
                for form in (os.path.join(base, sub), os.path.realpath(os.path.join(base, sub))):
                    if form not in roots:
                        roots.append(form)
        out: dict[str, list[str]] = {}
        for top in LINK_DIRS:
            start = os.path.join(self.prefix, top)
            if os.path.islink(start) or not os.path.isdir(start):
                continue
            for dirpath, dirnames, filenames in os.walk(start):
                dirnames.sort()
                for name in sorted(dirnames + filenames):
                    path = os.path.join(dirpath, name)
                    if os.path.islink(path) and system.text_names_prefix(os.path.realpath(path), roots, False):
                        out.setdefault(dirpath, []).append(path)
        return out

    def remove_links(self, links: dict[str, list[str]]) -> None:
        """Run one `rm -f` per directory for its links into the Cellar, in chunks that fit an argv

        It runs as the user where the directory is writable, and again under `sudo` for the links that stay.

        @param links  the links by directory, as `cellar_links` finds them
        """
        count = 0
        for directory in sorted(links):
            names = [link for link in links[directory] if os.path.lexists(link)]
            if not names:
                continue
            why = self.p.unsafe(directory, self.inst)
            if why:
                self.p.say(f"  The links in {directory} to Homebrew's packages stay: {why}.")
                continue
            escalate = not os.access(directory, os.W_OK)
            for number, chunk in enumerate(_chunks(names, ARGV_BUDGET)):
                action_id = f"6.links.{state.slug(directory)}{'' if number == 0 else f'.{number + 1}'}"
                what = f"delete {counted(len(chunk), 'link')} into the Cellar in {directory}"
                self.p.rm(action_id, [RM, "-f"] + chunk, escalate, what)
                rest = [link for link in chunk if os.path.lexists(link)]
                if rest and not escalate:
                    self.p.rm(action_id + ".sudo", [RM, "-f"] + rest, True, what + " as root")
                    rest = [link for link in rest if os.path.lexists(link)]
                for link in rest:
                    self.failures.append(link)
                    self.p.say(f"  Could not delete {link}.")
                count += len(chunk) - len(rest)
        if count:
            self.p.say(f"  Deleted {counted(count, 'link')} to Homebrew's packages.")

    def remove_emptied(self, directories: Iterable[str]) -> None:
        """Remove the directories the link removal and the enumerated list left empty, deepest first

        `rm -d` removes an empty directory and nothing else; at `/usr/local` the top directories other
        installers share stay, while Homebrew's own `opt` goes.

        @param directories  the directories that held the links or the listed paths; each is tried with its
                            parents up to the prefix
        """
        prefix = os.path.normpath(self.prefix)
        candidates: set[str] = set()
        for directory in directories:
            current = os.path.normpath(directory)
            while current != prefix and current.startswith(prefix.rstrip("/") + "/"):
                candidates.add(current)
                current = os.path.dirname(current)
        removed = 0
        for directory in sorted(candidates, key=lambda d: (-d.count("/"), d)):
            if os.path.dirname(directory) == prefix and self.usr_local and os.path.basename(directory) != "opt":
                continue
            if os.path.islink(directory) or _entries(directory) != [] or not os.path.isdir(directory):
                continue
            if self.remove(directory, flags="-d", quiet=True):
                removed += 1
        if removed:
            self.p.say(f"  Deleted {counted(removed, 'folder')} the links left empty.")

    def paths_d(self) -> None:
        """Delete `/etc/paths.d/homebrew` when its only line is `<prefix>/bin`

        It is copied into the root backup store first, then removed with `sudo rm -f`, a probe.
        """
        path = os.path.join(self.p.host.etc_paths_d, "homebrew")
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except FileNotFoundError:
            return
        except OSError as exc:
            self.p.say(f"  {path} stays: it cannot be read ({exc.strerror or exc}).")
            return
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        fold = env.fold_case_for(self.inst)
        bins = {system.normalise_text_path(os.path.join(s, "bin"), fold)
                for s in (self.prefix,) + tuple(self.inst.spellings or ())}
        if len(lines) != 1 or system.normalise_text_path(lines[0], fold) not in bins:
            if any(system.normalise_text_path(line, fold) in bins for line in lines):
                self.p.say(f"  {path} stays: it names more than {self.prefix}/bin.")
            return
        why = self.p.unsafe(path, self.inst)
        if why:
            self.p.say(f"  {path} stays: {why}.")
            return
        # The readable original that `rollback` replays; root's own copy goes to the store.
        self.p.run_dir.etc_copy(path, "paths.d/homebrew")
        try:
            self.p.root_files().backup(path)
        except ActionFailed as exc:
            self.failures.append(path)
            self.p.say(f"  Could not delete {path}: the copy that undo needs could not be made (exit "
                       f"{exc.result.exit}).")
            return
        self.remove(path, flags="-f", sudo=True, checked=True)

    def application_links(self) -> list[str]:
        """Find the symlinks in `/Applications` and `~/Applications` that resolve into the Cellar

        @returns  the links, the host's `/Applications` first
        """
        spellings = (self.prefix,) + tuple(self.inst.spellings or ())
        roots = list(dict.fromkeys([os.path.join(s, "Cellar") for s in spellings]
                                   + [os.path.realpath(os.path.join(self.prefix, "Cellar"))]))
        out = []
        for directory in (self.p.host.applications, os.path.join(self.p.home, "Applications")):
            for name in _entries(directory) or []:
                path = os.path.join(directory, name)
                if os.path.islink(path) and system.text_names_prefix(os.path.realpath(path), roots, False):
                    out.append(path)
        return out

    def trash(self) -> list[tuple[str, str]]:
        """Find the `app` and `suite` bundles of an undrivable instance's casks, for the user to move to the Trash

        Phase 6 cannot uninstall them; the casks a `brew` target adopted are the target's.

        @returns  the token and path of each bundle that exists
        """
        plan = self.p.plan
        adopted = {m.source.name for m in plan.mappings if m.adopt and m.source.instance_prefix == self.prefix}
        adopted |= {pair[1] for pair in plan.path_removed.get(self.prefix, []) if pair[0] == "cask-adopted"}
        rooms, _ = brew_inventory.walk_caskroom(self.prefix)
        catalogue = self.p.bundle.catalogue(self.prefix)
        base = brew_catalogue.cask_dirs(self.prefix, self.runner.environ, (), self.p.home)
        if base.get("appdir") == brew_catalogue.DEFAULT_CASK_DIRS["appdir"]:
            base["appdir"] = self.p.host.applications
        out: list[tuple[str, str]] = []
        for token in sorted(rooms):
            if token in adopted:
                continue
            room = rooms[token]
            items = (room.receipt or {}).get("uninstall_artifacts")
            if items:
                artifacts = brew_catalogue.normalise_artifacts(items)
            else:
                info = catalogue.cask(token) if catalogue is not None else None
                artifacts = info.artifacts if info is not None else []
            dirs = brew_catalogue.dirs_from_config(room.config, base)
            for art in artifacts:
                if art.kind not in APP_KINDS:
                    continue
                for target in brew_catalogue.artifact_targets(art, dirs, self.prefix, self.p.home):
                    if os.path.lexists(target) and (token, target) not in out:
                        out.append((token, target))
        return out

    def remaining(self) -> None:
        """List, archive and remove what the enumerated list left, behind a second confirmation; then the prefix

        `/usr/local` is never a dedicated prefix and never removed: what remains is listed.
        """
        names = _entries(self.prefix)
        if names is None:
            self.p.say(f"  {self.prefix} stays: it cannot be listed.")
            return
        if self.usr_local:
            if names:
                self.p.say(f"  {self.prefix} stays, because other installers use it too. It still holds: "
                           f"{', '.join(names)}")
            return
        if names:
            one = len(names) == 1
            self.p.say(f"  {self.prefix} still holds {counted(len(names), 'item')} that Homebrew's own uninstall "
                       f"leaves: {', '.join(names)}")
            them = "it" if one else "them"
            if self.p.ask.yes:
                self.p.say(f"  --yes answers for you: {'it is' if one else 'they are'} saved in the run folder, then "
                           f"deleted with {self.prefix}.")
            else:
                self.p.say(f"  y saves {them} in the run folder, then deletes {them} and {self.prefix} itself.")
                self.p.say(f"  n keeps {self.prefix} with {them}."
                           + ("" if self.failures else " Homebrew itself is already gone from it."))
            if not self.p.confirm(f"Delete {self.prefix} with {'this item' if one else 'these items'}?"):
                self.p.say(f"  {self.prefix} stays with {', '.join(names)}, as you answered.")
                return
            entries = [os.path.join(self.prefix, n) for n in names]
            self.take([_Archive(e, [e]) for e in entries if not self.covered(e)])
            for entry in entries:
                self.remove(entry)
        if os.path.isdir(self.prefix) and not os.path.islink(self.prefix) and _entries(self.prefix) == []:
            self.remove(self.prefix, flags="-d")


def run(runner, run_dir: state.RunDir, plan: Plan, bundle, ask: Context, *, resumed: bool,
        host: Host | None = None) -> list[str]:
    """Run phase 6 for every instance `plan.options["remove_manager"]` names, in order

    @param runner    the runner of the phase's commands; its phase becomes 6
    @param run_dir   the run directory: journal, archives and backups
    @param plan      the plan being applied
    @param bundle    the fresh scan of the host as phase 5 left it
    @param ask       the `Context` that asks the second confirmations
    @param resumed   read this run's earlier phase 6 records
    @param host      the system locations and clocks; None for the real ones
    @returns         the report lines
    @throws Stopped  when a check, an archive or a deletion stops the phase (exit 4); `lines` holds the report
    """
    runner.phase = PHASE
    return _Phase(runner, run_dir, plan, bundle, ask, resumed=resumed, host=host or Host()).run()

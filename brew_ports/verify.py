"""The checks of `brew-ports verify` and phase 8, and the phase 4 gate

`verify` and phase 8 exit 5 on a failure; the gate's caller maps one to exit 4.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import envclean, model, report, scan, snapshot, state, system
from .context import Context
from .env import PrefixIndex, interpreters as env_interpreters, linkage as env_linkage, root_spellings, roots_of, \
    shell as env_shell
from .equiv import rules
from .exec_run import phase6_prefixes
from .homebrew import actions as brew_actions, catalogue as brew_catalogue, inventory as brew_inventory, \
    locate as brew_locate
from .macports import locate as mp_locate, registry
from .model import Action, Instance, Manager, OnFailure, Plan
from .remove_manager import ARCHIVES
from .runner import BaseRunner, arch_argv, start_run

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_VERIFY = 5
LOGIN_TIMEOUT_S = 120
ENV = "/usr/bin/env"
CASK_ARTIFACTS = ("app", "suite", "binary")
INSTALLED_KINDS = ("formula", "port")
REBUILDS = ("reinstall", "upgrade")
SERVICE_KEYS = ("service", "service_args", "service_run_args")
LIBRARY = re.compile(r"\.(?:dylib|so|a)$")
REGISTRY_ERRORS = (registry.RegistryMissing, registry.RegistryBusy, sqlite3.DatabaseError, OSError)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07")
_NOT_FOUND = re.compile(r"(?i)(?:not found|unknown command)\W+(?:brew|port)\b|\b(?:brew|port)\W+(?:command )?not found")

# The `step` of a finding, and the label the text output prints for it.
CHECKS = {
    "installed": "replacements installed",
    "commands": "commands provided",
    "libraries": "variant libraries",
    "linkage": "clean linkage",
    "services": "services replaced",
    "login-path": "login shell PATH",
    "language-packages": "language packages",
    "removed": "sources removed",
    "gate": "gate",
}


@dataclass
class Finding:
    """One failure or report line of a check"""

    step: str                        # a key of CHECKS
    subject: str
    text: str

    def line(self) -> str:
        """Return the finding as the text output prints it

        @returns  `<subject> (<check label>): <text>`
        """
        return f"{self.subject} ({CHECKS[self.step]}): {self.text}"


@dataclass
class VerifyResult:
    """The failures (exit 5, or 4 for the gate) and the report-only lines"""

    gate: bool = False
    failures: list[Finding] = field(default_factory=list)
    reports: list[Finding] = field(default_factory=list)
    # What the user has to repair after an upgrade of `--upgrade-all`: the task of each package, by its name.
    tasks: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """Return whether every check passed

        @returns  True without failures
        """
        return not self.failures

    @property
    def exit_code(self) -> int:
        """Return the exit code of `verify` and phase 8

        @returns  0 when every check passed, else 5
        """
        return EXIT_OK if self.ok else EXIT_VERIFY

    def fail(self, step: str, subject: str, text: str) -> None:
        """Record a failure

        @param step     the check, a key of `CHECKS`
        @param subject  what failed, such as a mapping or a package
        @param text     why it failed
        """
        self.failures.append(Finding(step, subject, text))

    def report(self, step: str, subject: str, text: str) -> None:
        """Record a report line, which never fails the run

        @param step     the check, a key of `CHECKS`
        @param subject  what the line is about
        @param text     the line
        """
        self.reports.append(Finding(step, subject, text))

    def task(self, step: str, subject: str, text: str, todo: str) -> None:
        """Record a broken package that only `--upgrade-all` brought into the checks: a report line and a task

        The move needs no such package, so it never fails the run. A package gets one task.

        @param step     the check, a key of `CHECKS`
        @param subject  the package
        @param text     what is wrong with it, for the report
        @param todo     the task: what the user does, why, and the command
        """
        self.report(step, subject, f"{text} (for you to repair; the move does not need it)")
        self.tasks.setdefault(subject, todo)

    def lines(self) -> list[str]:
        """Return the text output: a head line, a line per failure and per report line, then the tasks

        @returns  `verify: passed` or the failure count, the `FAIL` and `note` lines, and `For you to do:` with
                  the tasks when there are any
        """
        what = "gate" if self.gate else "verify"
        count = len(self.failures)
        head = f"{what}: passed" if self.ok else f"{what}: {count} failure{'' if count == 1 else 's'}"
        todo = ["For you to do:"] + [f"  {task}" for task in self.tasks.values()] if self.tasks else []
        return ([head] + ["FAIL " + f.line() for f in self.failures] + ["note " + f.line() for f in self.reports]
                + todo)


def _files_in(directory: str) -> list[str]:
    """Return the names of a directory's entries that are not directories

    @param directory  the directory
    @returns          the names, sorted; empty when the directory cannot be read
    """
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []
    return [n for n in names if not os.path.isdir(os.path.join(directory, n))]


def _and_parents(path: str) -> list[str]:
    """Return a path and every directory that holds it, up to the root

    @param path  an absolute path
    @returns     the normalised paths, the path itself first
    """
    out = [os.path.normpath(path)]
    while os.path.dirname(out[-1]) != out[-1]:
        out.append(os.path.dirname(out[-1]))
    return out


def _read_json(path: str) -> Any:
    """Return the JSON value of a file

    @param path  the file
    @returns     the value, or None when the file cannot be read or holds no JSON
    """
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _libraries(files: Iterable[registry.FileRow], lib_dir: str) -> set[str]:
    """Return the basenames of the libraries among a port's files below a `lib` directory

    @param files    the port's file rows
    @param lib_dir  the `lib` directory
    @returns        the basenames of the `.dylib`, `.so` and `.a` files
    """
    base = lib_dir.rstrip("/") + "/"
    return {os.path.basename(f.location) for f in files if f.location.startswith(base) and LIBRARY.search(f.location)}


def rebuilt_names(plan: Plan, prefix: str) -> list[str]:
    """Return the packages phases 2 and 3 reinstall or upgrade in the target, read from their argv

    @param plan    the plan
    @param prefix  the target's prefix
    @returns       the names, each once, in plan order
    """
    out: list[str] = []
    for phase in plan.phases:
        if phase.number not in (2, 3):
            continue
        for action in phase.actions:
            if action.kind != "command" or action.manual or action.instance_prefix != prefix:
                continue
            words = [a for a in action.argv if a in REBUILDS]
            if not words or "--cask" in action.argv:
                continue
            tail = action.argv[action.argv.index(words[0]) + 1:]
            names = list(action.split_order) or [a for a in tail if not a.startswith(("-", "+", "@"))]
            out.extend(n for n in names if n not in out)
    return out


# The target, read afresh --------------------------------------------------------------------

class _BrewTarget:
    """A Homebrew target as a fresh `brew info --json=v2 --installed` and its Cellar and Caskroom show it"""

    manager = Manager.BREW

    def __init__(self, runner, instance: Instance, action_id: str) -> None:
        """Read the target: `brew info` once, then its Cellar and Caskroom

        @param runner     the runner of the probes
        @param instance   the Homebrew target
        @param action_id  the id of the `brew info` probe
        """
        self.instance = instance
        self.prefix = instance.prefix
        self.error: str | None = None
        self.formulae: dict[str, dict[str, Any]] = {}
        self.casks: dict[str, dict[str, Any]] = {}
        data = self._read(runner, action_id)
        self.json_read = isinstance(data, dict)
        if self.json_read:
            entries = [e for e in data.get("formulae") or [] if isinstance(e, dict) and e.get("name")]
            for entry in entries:
                self.formulae[str(entry["name"])] = entry
            for entry in entries:
                for other in list(entry.get("aliases") or []) + list(entry.get("oldnames") or []):
                    self.formulae.setdefault(str(other), entry)
            for entry in data.get("casks") or []:
                if isinstance(entry, dict) and entry.get("token"):
                    self.casks[str(entry["token"])] = entry
        self.racks, _ = brew_inventory.walk_cellar(self.prefix)
        self.rooms, _ = brew_inventory.walk_caskroom(self.prefix)

    def _read(self, runner, action_id: str) -> Any:
        """Run `brew info --json=v2 --installed` and parse its output; a failure goes into `error`

        @param runner     the runner of the probes
        @param action_id  the id of the probe
        @returns          the parsed JSON, or None when the probe or the parse failed
        """
        what = "brew info --json=v2 --installed"
        try:
            result = runner.run(brew_actions.info_installed(self.instance, runner.host_arch, action_id))
        except ValueError as exc:
            self.error = str(exc)
            return None
        if result.exit != 0 or result.timed_out:
            self.error = brew_locate.failure_text(result, what)
            return None
        try:
            return json.loads(result.stdout())
        except ValueError as exc:
            self.error = f"{what} printed no JSON: {exc}"
            return None

    def names(self) -> list[str]:
        """Return the installed formulae: from the JSON, else the Cellar's racks

        @returns  the names, sorted
        """
        if self.json_read:
            return sorted({str(e["name"]) for e in self.formulae.values()})
        return sorted(self.racks)

    def versions(self, name: str) -> list[str]:
        """Return the installed versions of a formula: from the JSON, else its rack's kegs

        @param name  a formula's name, alias or old name
        @returns     the versions; empty when the formula is not installed
        """
        entry = self.formulae.get(name)
        if entry is not None:
            return [str(k["version"]) for k in entry.get("installed") or [] if isinstance(k, dict) and k.get("version")]
        if self.json_read:
            return []
        rack = self.racks.get(name)
        return [keg.version for keg in rack.kegs] if rack else []

    def installed(self, name: str) -> bool:
        """Return whether a formula is installed

        @param name  a formula's name, alias or old name
        @returns     True when it has an installed version
        """
        return bool(self.versions(name))

    def active(self, name: str) -> bool:
        """Return `Package.active` of a formula: linked or keg-only

        @param name  a formula's name, alias or old name
        @returns     True for a linked or keg-only formula; without the JSON, for any rack
        """
        entry = self.formulae.get(name)
        if entry is not None:
            return entry.get("linked_keg") is not None or bool(entry.get("keg_only"))
        return not self.json_read and name in self.racks

    def keg_only(self, name: str) -> bool:
        """Return whether `brew info` marks a formula keg-only

        @param name  a formula's name, alias or old name
        @returns     False also when the JSON does not list the formula
        """
        return bool((self.formulae.get(name) or {}).get("keg_only"))

    def keg(self, name: str) -> str | None:
        """Return the keg `opt/<name>` points at, else the linked or the newest one

        @param name  a formula's name, alias or old name
        @returns     the keg's path, or None when no keg exists
        """
        opt = os.path.join(self.prefix, "opt", name)
        if os.path.isdir(opt):
            return os.path.realpath(opt)
        entry = self.formulae.get(name) or {}
        rack = str(entry.get("name") or name)
        linked = entry.get("linked_keg")
        newest = sorted(self.versions(name), key=brew_catalogue.version_key, reverse=True)
        for version in ([str(linked)] if linked else []) + newest:
            path = os.path.join(self.prefix, "Cellar", rack, version)
            if os.path.isdir(path):
                return path
        return None

    def deps(self, name: str) -> list[str]:
        """Return the declared dependencies and the receipts' `runtime_dependencies`

        @param name  a formula's name, alias or old name
        @returns     the short names, each once
        """
        entry = self.formulae.get(name) or {}
        out = [brew_inventory.short_name(d) for d in entry.get("dependencies") or [] if isinstance(d, str)]
        for keg in entry.get("installed") or []:
            for dep in (keg.get("runtime_dependencies") or []) if isinstance(keg, dict) else []:
                if isinstance(dep, dict) and dep.get("full_name"):
                    out.append(brew_inventory.short_name(dep["full_name"]))
        return list(dict.fromkeys(out))

    def has_cask(self, token: str) -> bool:
        """Return whether the Caskroom holds a version of a cask

        @param token  the cask token
        @returns      True when its Caskroom entry lists a version
        """
        room = self.rooms.get(token)
        return room is not None and bool(room.versions)

    def close(self) -> None:
        """Close nothing: unlike a MacPorts target, a Homebrew target keeps nothing open"""


class _PortsTarget:
    """A MacPorts target as a fresh registry backup shows it"""

    manager = Manager.PORTS

    def __init__(self, instance: Instance, environ) -> None:
        """Read the target: the prefix its `macports.conf` names, then a fresh backup of its registry

        A registry that cannot be read leaves no rows, and the reason in `error`.

        @param instance  the MacPorts target
        @param environ   the environment the tool runs with
        """
        self.instance = instance
        self.prefix = mp_locate.read_config(instance.prefix, environ).get("prefix") or instance.prefix
        self.error: str | None = None
        self.reg: registry.Registry | None = None
        self.rows: list[registry.PortRow] = []
        self.depends: dict[int, list[str]] = {}
        if not instance.portdbpath:
            self.error = f"{instance.prefix} has no portdbpath"
            return
        try:
            self.reg = registry.Registry.open_copy(instance.portdbpath)
            self.rows = self.reg.ports()
            self.depends = self.reg.dependencies()
        except REGISTRY_ERRORS as exc:
            self.error = f"the registry backup failed: {type(exc).__name__}: {exc}"

    def row(self, name: str) -> registry.PortRow | None:
        """Return the active row of a port

        @param name  the port's name, in any case
        @returns     the row, or None when no version of the port is active
        """
        return next((r for r in self.rows if r.active and r.name.lower() == name.lower()), None)

    def names(self) -> list[str]:
        """Return the active ports

        @returns  the names, sorted
        """
        return sorted({r.name for r in self.rows if r.active})

    def versions(self, name: str) -> list[str]:
        """Return the versions of a port's active rows

        @param name  the port's name, in any case
        @returns     the versions; empty when the port is not active
        """
        return [r.version for r in self.rows if r.active and r.name.lower() == name.lower()]

    def installed(self, name: str) -> bool:
        """Return whether a version of a port is active

        @param name  the port's name, in any case
        @returns     True when the port has an active row
        """
        return self.row(name) is not None

    active = installed

    def stored(self, name: str) -> bool:
        """Return whether the registry holds a version of a port, active or not

        @param name  the port's name, in any case
        @returns     True when the port has a row
        """
        return any(r.name.lower() == name.lower() for r in self.rows)

    def files(self, row: registry.PortRow) -> list[registry.FileRow]:
        """Return the registry's file rows of a port

        @param row  the port's row
        @returns    the file rows; empty when the registry cannot be read
        """
        return self.reg.files(row.id) if self.reg is not None else []

    def executables(self, row: registry.PortRow) -> set[str]:
        """Return the names of a port's files directly in the prefix's `bin` and `sbin`

        @param row  the port's row
        @returns    the names
        """
        dirs = (os.path.join(self.prefix, "bin"), os.path.join(self.prefix, "sbin"))
        return {os.path.basename(f.location) for f in self.files(row) if os.path.dirname(f.location) in dirs}

    def binaries(self, row: registry.PortRow) -> list[str]:
        """Return the active files of a port that the registry marks binary, for the linkage scan

        @param row  the port's row
        @returns    the paths
        """
        return [f.location for f in self.files(row) if f.binary and f.active]

    def deps(self, name: str) -> list[str]:
        """Return the dependencies the registry records for a port's active row

        @param name  the port's name, in any case
        @returns     the names; empty when the port is not active
        """
        row = self.row(name)
        return list(self.depends.get(row.id, [])) if row is not None else []

    def close(self) -> None:
        """Close the registry backup, which removes the copy"""
        if self.reg is not None:
            self.reg.close()
            self.reg = None


class _Removal:
    """Where a target binary's reference must not point for the linkage check: into what phase 5 or 6 removes

    Racks and Caskroom entries match by identity and port files by owner, in a prefix that survives `--only` too.
    A formula's rack and a cask's entry are the ones `ScanBundle.formula_racks` and `cask_rooms` name, as phase 5
    uninstalls them.
    """

    def __init__(self, plan: Plan, bundle, instances: Sequence[Instance]) -> None:
        """Gather what the run removes: the prefixes phase 6 deletes, and the packages phase 5 uninstalls

        @param plan       the plan
        @param bundle     the scan, whose Homebrew inventories hold the racks and MacPorts ones the owners of files
        @param instances  the instances the checks know
        """
        gone = set(phase6_prefixes(plan))
        self.prefixes = PrefixIndex([inst for inst in instances if inst.prefix in gone])
        self.kegs: dict[tuple[int, int], str] = {}
        self.ports: dict[str, set[str]] = {}
        for prefix, pairs in list(plan.removal_set.items()) + list(plan.path_removed.items()):
            held = bundle.formula_racks(prefix) if bundle is not None else {}
            rooms = bundle.cask_rooms(prefix) if bundle is not None else {}
            for kind, name in pairs:
                sub = {"formula": "Cellar", "cask": "Caskroom"}.get(kind)
                entry = held.get(name, name) if kind == "formula" else rooms.get(name, name)
                ident = system.identity(os.path.join(prefix, sub, entry)) if sub else None
                if ident is not None:
                    self.kegs[ident] = f"{kind} {name} of {prefix}"
                if kind == "port":
                    self.ports.setdefault(prefix, set()).add(name.lower())
        self.inventories = [(inst.prefix, inv) for inst, _, inv in bundle.ports]

    def reason(self, path: str) -> str | None:
        """Return why the run deletes `path`, or None when it keeps it

        @param path  a reference of a target binary
        @returns     the reason, as the failure line words it
        """
        inst = self.prefixes.owner(path)
        if inst is not None:
            return f"inside {inst.prefix}, which phase 6 deletes"
        current = os.path.realpath(path)
        while True:
            label = self.kegs.get(system.identity(current) or (-1, -1))
            if label:
                return f"a file of the {label}, which phase 5 removes"
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        for prefix, inv in self.inventories:
            names = self.ports.get(prefix)
            if not names:
                continue
            owner = inv.owner_of(path)
            if owner and owner.lower() in names:
                return f"a file of the port {owner} of {prefix}, which phase 5 removes"
        return None


# The checks -----------------------------------------------------------------------------------

def _subject(mapping: model.Mapping) -> str:
    """Return the subject of a mapping's findings

    @param mapping  the mapping
    @returns        `<source> -> <target>`
    """
    return f"{mapping.source.name} -> {mapping.target_name}"


def _target_name(mapping: model.Mapping) -> str:
    """Return the target name of a mapping the checks hold, which keep only mappings that have one

    @param mapping  a mapping of `_Verifier.mappings`
    @returns        the target package's name
    """
    if mapping.target_name is None:
        raise ValueError(f"the mapping of {mapping.source.name} has no target name")
    return mapping.target_name


def _pipx_venv(venvs: dict[str, Any], name: str) -> dict[str, Any] | None:
    """Return a package's pipx venv, matched by venv name or main package, in any case and with `_` as `-`

    @param venvs  the venvs of `pipx list --json`
    @param name   the package's name
    @returns      the venv, or None when pipx has none for the package
    """
    def norm(text: Any) -> str:
        return str(text).lower().replace("_", "-")
    want = norm(name)
    for key, venv in venvs.items():
        main = ((venv or {}).get("metadata") or {}).get("main_package") or {}
        if norm(key) == want or norm(main.get("package", "")) == want:
            return venv
    return None


def _position(entries: Sequence[str], directory: str) -> int | None:
    """Return where a directory stands in a PATH, matched as a normalised path or as the same directory

    @param entries    the PATH's entries
    @param directory  the directory
    @returns          the index of its first entry, or None when the PATH lacks it
    """
    want = os.path.normpath(directory)
    for number, entry in enumerate(entries):
        if os.path.normpath(entry) == want or system.same_path(entry, directory):
            return number
    return None


def _names_removed(text: str, surv: envclean.Survivors) -> bool:
    """Return whether a text names a root of a removed instance, in any of the instance's spellings

    @param text  a line the login shell printed on its error stream
    @param surv  the survivor set
    @returns     True when a spelling appears, and not as the start of a longer name
    """
    for inst in surv.removed_instances():
        for root in roots_of(inst):
            for spelling in root_spellings(inst, root):
                if re.search(re.escape(spelling.rstrip("/")) + r"(?![\w.-])", text):
                    return True
    return False


class _Verifier:
    """The checks over one plan: the target read once, each step adding its failures and report lines to `result`"""

    def __init__(self, bundle, plan: Plan, runner, run_dir: state.RunDir | None, gate: bool) -> None:
        """Prepare the checks; `run` reads the target

        @param bundle   the scan taken after the installs
        @param plan     the plan
        @param runner   the runner of the probes
        @param run_dir  the run directory with the snapshot and the journal, or None
        @param gate     whether the checks are the phase 4 gate's
        """
        self.bundle = bundle
        self.plan = plan
        self.runner = runner
        self.run_dir = run_dir
        self.gate = gate
        self.result = VerifyResult(gate=gate)
        self.phase = runner.phase if runner.phase is not None else 8
        self.environ = runner.environ
        self.home = self.environ.get("HOME") or os.path.expanduser("~")
        self.instances = envclean.tested_instances(bundle.result.instances, plan.instances)
        self.target = next((i for i in self.instances if envclean.spells(i, plan.target_prefix)), None)
        self.catalogue = bundle.catalogue(self.target.prefix) if self.target is not None else None
        self.mappings = [m for m in plan.mappings if m.target_name]
        # What only `--upgrade-all` upgrades, and the packages whose libraries are judged only because of it: a
        # break there is a task for the user, never a failure of the move.
        self.optional = {name.lower() for name in plan.optional_upgrades}
        self.optional_casks = set(plan.optional_casks)
        self.only_optional: set[str] = set()
        self.state: Any = None
        self._venvs: dict[str, Any] | None = None
        self._venv_error: str | None = None

    def aid(self, subject: str, step: str) -> str:
        """Return the action id of a probe

        The id is `<phase>.verify.<subject>.<step>`, with the subject slugged.

        @param subject  what the probe reads, such as a prefix
        @param step     the probe
        @returns        the id
        """
        return f"{self.phase}.verify.{state.slug(subject)}.{step}"

    def companions(self) -> list[str]:
        """Return the companions of every mapping

        @returns  the names, each once, in plan order
        """
        return list(dict.fromkeys(c for m in self.mappings for c in m.companions))

    def _found_target(self) -> Instance:
        """Return the target instance, which `open` has found before any check of the target runs

        @returns  the target
        """
        if self.target is None:
            raise ValueError(f"a check of the target ran without the target instance {self.plan.target_prefix}")
        return self.target

    def run(self) -> VerifyResult:
        """Run every check in order; the phase 4 gate runs `installed`, `commands`, `linkage` and its own two

        @returns  the result
        """
        try:
            if self.open():
                self.check_installed()
                self.check_commands()
                if not self.gate:
                    self.check_libraries()
                self.check_linkage()
                if self.gate:
                    self.pre_existing()
                    self.upgrades()
                else:
                    self.check_services()
            if not self.gate:
                self.check_login_path()
                self.check_language_packages()
                self.check_removed()
        finally:
            if self.state is not None:
                self.state.close()
        return self.result

    def open(self) -> bool:
        """Read the target afresh: `brew info --json=v2 --installed`, or a new registry backup

        @returns  whether the checks of the target run: False when the target instance is not found
        """
        if self.target is None:
            self.result.fail("installed", self.plan.target_prefix, "the target instance is not found")
            return False
        if self.target.manager is Manager.BREW:
            self.state = _BrewTarget(self.runner, self.target, self.aid(self.target.prefix, "info"))
        else:
            self.state = _PortsTarget(self.target, self.environ)
        if self.state.error:
            self.result.fail("installed", self.target.prefix,
                             f"its installed packages cannot be read: {self.state.error}")
        return True

    # Replacements installed ------------------------------------------------------------

    def check_installed(self) -> None:
        """Check every mapping is installed in the target at its major version, and every companion at any"""
        prefix = self._found_target().prefix
        for m in self.mappings:
            if m.target_kind in INSTALLED_KINDS:
                self.installed_package(m)
            elif m.target_kind == "cask":
                self.installed_cask(m)
            elif m.target_kind == "pip":
                self.installed_pipx(m)
            else:
                self.result.report("installed", _subject(m),
                                   f"a {m.target_kind} mapping is never installed by the tool")
        for name in self.companions():
            if not self.state.installed(name):
                self.result.fail("installed", name, f"the companion is not installed in {prefix}")

    def installed_package(self, m: model.Mapping) -> None:
        """Check a formula or port mapping is installed in the target, at the major version of its target version

        A Homebrew formula must also be linked or keg-only: a pour whose link step failed puts no command on PATH.

        @param m  the mapping
        """
        prefix = self._found_target().prefix
        versions = self.state.versions(m.target_name)
        if not versions:
            self.result.fail("installed", _subject(m), f"{m.target_name} is not installed in {prefix}")
            return
        want = rules.major(m.target_version)
        if want is not None and not any(rules.major(v) == want for v in versions):
            self.result.fail("installed", _subject(m),
                             f"installed at {', '.join(versions)}, not at major {want} of {m.target_version}")
        name = _target_name(m)
        if m.target_kind == "formula" and self.state.manager is Manager.BREW and not self.state.active(name) \
                and not self.keg_only(name):
            self.result.fail("installed", _subject(m), f"{name} is installed in {prefix} but neither linked nor "
                             f"keg-only: `brew link {name}` links it")

    def keg_only(self, name: str) -> bool:
        """Return whether a Homebrew target formula is keg-only, as `brew info` or the catalogue marks it

        @param name  the formula's name
        @returns     True when either marks it keg-only
        """
        return self.state.keg_only(name) or (self.catalogue is not None and self.catalogue.keg_only(name))

    def installed_cask(self, m: model.Mapping) -> None:
        """Check that the target cask of a mapping is installed in the target

        @param m  a cask mapping
        """
        target = self._found_target()
        token = _target_name(m)
        if target.manager is not Manager.BREW:
            self.result.fail("installed", _subject(m), "a cask mapping into MacPorts")
            return
        if not self.state.has_cask(token):
            room = os.path.join(target.prefix, "Caskroom", token)
            self.result.fail("installed", _subject(m), f"no Caskroom directory {room}")
        elif self.state.json_read and token not in self.state.casks:
            self.result.fail("installed", _subject(m), f"{token} is not listed by brew info --json=v2 --installed")
        if m.adopt and not self.gate:
            self.adopted_cask_gone(m)

    def adopted_cask_gone(self, m: model.Mapping) -> None:
        """Check a drivable source's record of an adopted cask is gone after phase 5

        The record is the cask's entry of `ScanBundle.cask_rooms`, else the one of its token.
        An undrivable source's record stays until phase 6 deletes the prefix, or for good under `--only` or when
        phase 6 leaves the prefix.

        @param m  the adopted cask's mapping
        """
        source = m.source.instance_prefix
        rooms = self.bundle.cask_rooms(source) if self.bundle is not None else {}
        record = os.path.join(source, "Caskroom", rooms.get(m.source.name, m.source.name))
        inst = next((i for i in self.plan.instances if i.prefix == source), None)
        drivable = inst.drivable if inst is not None else source in self.plan.removal_set
        if drivable:
            if os.path.lexists(record):
                self.result.fail("installed", _subject(m), f"the adopted cask is still recorded in {record}")
        elif envclean.only_run(self.plan) or source not in phase6_prefixes(self.plan):
            self.result.report("installed", _subject(m),
                               f"the record {record} of the undrivable source stays in place")
        else:
            self.result.report("installed", _subject(m),
                               f"the record {record} stays until phase 6 deletes {source}")

    def venvs(self) -> dict[str, Any] | None:
        """Return the venvs of `<target>/bin/pipx list --json`, probed once

        @returns  the venvs by name, or None when the probe failed; `_venv_error` then says why
        """
        if self._venvs is None and self._venv_error is None:
            target = self._found_target()
            pipx = os.path.join(target.prefix, "bin", "pipx")
            argv = arch_argv(target.arch, self.runner.host_arch, [pipx, "list", "--json"])
            action = Action(action_id=self.aid(target.prefix, "pipx"), kind="command",
                            argv=argv, sudo=False, description="pipx venvs",
                            env_profile=target.manager.value, on_failure=OnFailure.PROBE, read_only=True,
                            instance_prefix=target.prefix)
            result = self.runner.run(action)
            data = None
            if result.exit == 0:
                try:
                    data = json.loads(result.stdout())
                except ValueError:
                    data = None
            if isinstance(data, dict) and isinstance(data.get("venvs"), dict):
                self._venvs = data["venvs"]
            else:
                self._venv_error = f"pipx list --json exited {result.exit} without its JSON"
        return self._venvs

    def installed_pipx(self, m: model.Mapping) -> None:
        """Check pipx holds the target package of a `pip` mapping

        @param m  the mapping
        """
        venvs = self.venvs()
        if venvs is None:
            self.result.fail("installed", _subject(m), self._venv_error or "pipx list failed")
        elif _pipx_venv(venvs, _target_name(m)) is None:
            self.result.fail("installed", _subject(m), f"{m.target_name} is not installed by pipx")

    # Commands provided -----------------------------------------------------------------

    def target_executables(self, m: model.Mapping) -> set[str] | None:
        """Return the executables the target installs, never looking in `/usr/bin`; None when it is not installed

        @param m  the mapping
        @returns  the names, or None when the target package is not installed or its kind installs none to compare
        """
        name = _target_name(m)
        if m.target_kind == "formula" and self.state.manager is Manager.BREW:
            keg = self.state.keg(name)
            if keg is None:
                return None
            found = set(self.catalogue.executables(name)) if self.catalogue is not None else set()
            return found | set(_files_in(os.path.join(keg, "bin"))) | set(_files_in(os.path.join(keg, "sbin")))
        if m.target_kind == "port" and self.state.manager is Manager.PORTS:
            row = self.state.row(name)
            return self.state.executables(row) if row is not None else None
        if m.target_kind == "pip":
            venv = _pipx_venv(self.venvs() or {}, name)
            if venv is None:
                return None
            apps = ((venv.get("metadata") or {}).get("main_package") or {}).get("apps") or []
            bindir = os.path.join(self.home, ".local", "bin")
            return {a for a in apps if os.path.lexists(os.path.join(bindir, a))}
        return None

    def companion_executables(self, m: model.Mapping) -> set[str]:
        """Return the executables a mapping's companions install, which count towards its commands

        @param m  the mapping
        @returns  the names; empty without companions, or for one that is not installed
        """
        out: set[str] = set()
        for name in m.companions:
            if self.state.manager is Manager.PORTS:
                row = self.state.row(name)
                if row is not None:
                    out |= set(self.state.executables(row))
            elif self.state.manager is Manager.BREW:
                keg = self.state.keg(name)
                if keg is not None:
                    out |= set(self.catalogue.executables(name)) if self.catalogue is not None else set()
                    out |= set(_files_in(os.path.join(keg, "bin"))) | set(_files_in(os.path.join(keg, "sbin")))
        return out

    def check_commands(self) -> None:
        """Check each root with executables gets at least one from its target, and a cask target's artifacts exist"""
        for m in self.mappings:
            if m.target_kind == "cask":
                self.cask_provided(m)
                continue
            if not m.source.executables:
                continue
            found = self.target_executables(m)
            if found is None:
                continue
            found |= self.companion_executables(m)
            if not found:
                had = ", ".join(sorted(m.source.executables)[:10])
                self.result.fail("commands", _subject(m),
                                 f"{m.target_name} installs no executable; the source had {had}")
                continue
            lost = [s for s in sorted(set(m.source.executables)) if not any(rules.exe_match(s, t) for t in found)]
            if lost:
                self.result.report("commands", _subject(m), f"renamed or lost: {', '.join(lost)}")
            if m.target_kind == "formula" and self.keg_only(_target_name(m)):
                bin_dir = os.path.join(self._found_target().prefix, "opt", _target_name(m), "bin")
                self.result.report("commands", _subject(m), f"keg-only: its executables are in {bin_dir}, which is "
                                   "not on PATH (the phase 7 note)")

    def cask_artifacts(self, token: str) -> list[brew_catalogue.Artifact] | None:
        """Return the app, suite and binary artifacts of a cask: from `brew info`, else from the catalogue

        @param token  the cask token
        @returns      the artifacts, or None when neither knows the cask
        """
        entry = self.state.casks.get(token) if self.state.manager is Manager.BREW else None
        if entry is not None and entry.get("artifacts") is not None:
            arts = brew_catalogue.normalise_artifacts(entry.get("artifacts"))
        else:
            info = self.catalogue.cask(token) if self.catalogue is not None else None
            if info is None:
                return None
            arts = info.artifacts
        return [a for a in arts if a.kind in CASK_ARTIFACTS]

    def cask_provided(self, m: model.Mapping) -> None:
        """Check that the app, suite and binary artifacts of a mapped target cask exist

        @param m  a cask mapping
        """
        token = _target_name(m)
        if self.state.manager is not Manager.BREW or not self.state.has_cask(token):
            return
        arts = self.cask_artifacts(token)
        if arts is None:
            return
        prefix = self._found_target().prefix
        dirs = brew_catalogue.cask_dirs(prefix, self.environ, brew_locate.brew_env_lines(prefix, self.environ),
                                        self.home)
        room = self.state.rooms.get(token)
        dirs = brew_catalogue.dirs_from_config(room.config if room else None, dirs)
        paths = [p for art in arts for p in brew_catalogue.artifact_targets(art, dirs, prefix, self.home)]
        if not paths:
            self.result.report("commands", _subject(m), "no app, suite or binary artifact to check")
            return
        present = [p for p in paths if os.path.exists(p)]
        if not present:
            self.result.fail("commands", _subject(m),
                             f"none of its app, suite and binary artifacts exists: {', '.join(paths)}")
        elif len(present) < len(paths):
            missing = ", ".join(p for p in paths if p not in present)
            self.result.report("commands", _subject(m), f"missing artifacts: {missing}")

    # Variant libraries -----------------------------------------------------------------

    def source_libraries(self, pkg: model.Package) -> set[str] | None:
        """Return a source port's library basenames, from its live registry, else from the run's phase 1 backup

        @param pkg  the mapping's source package
        @returns    the basenames, or None for a package that is not a port or whose file list is gone
        """
        if pkg.kind != "port":
            return None
        lib = os.path.join(mp_locate.read_config(pkg.instance_prefix, self.environ).get("prefix")
                           or pkg.instance_prefix, "lib")
        for inst, _, inv in self.bundle.ports:
            if inst.prefix == pkg.instance_prefix:
                files = inv.files(pkg)
                if files:
                    return _libraries(files, lib)
        if self.run_dir is None:
            return None
        backup = os.path.join(snapshot.ports_dir(self.run_dir, pkg.instance_prefix), snapshot.REGISTRY)
        if not os.path.isfile(backup):
            return None
        try:
            with registry.Registry.open_backup(backup) as reg:
                rows = reg.ports()
                row = next((r for r in rows if r.spec_args == list(pkg.spec_args)), None) or \
                    next((r for r in rows if r.name.lower() == pkg.name.lower()), None)
                return _libraries(reg.files(row.id), lib) if row is not None else None
        except REGISTRY_ERRORS:
            return None

    def target_libraries(self, m: model.Mapping) -> set[str] | None:
        """Return the library basenames the target package of a mapping installs

        @param m  a formula or port mapping
        @returns  the basenames, or None when the target package is not installed
        """
        if self.state.manager is Manager.BREW:
            keg = self.state.keg(m.target_name)
            if keg is None:
                return None
            out: set[str] = set()
            for _, _, names in os.walk(os.path.join(keg, "lib")):
                out.update(n for n in names if LIBRARY.search(n))
            return out
        row = self.state.row(m.target_name)
        return _libraries(self.state.files(row), os.path.join(self.state.prefix, "lib")) if row is not None else None

    def check_libraries(self) -> None:
        """Report the libraries of a root built with variants that its target does not install"""
        for m in self.mappings:
            if not m.source.requested_variants or m.target_kind not in INSTALLED_KINDS:
                continue
            source = self.source_libraries(m.source)
            if source is None:
                self.result.report("libraries", _subject(m), "the source's file list is gone, so its libraries are "
                                   "not compared")
                continue
            target = self.target_libraries(m)
            missing = sorted(source - target) if target is not None else []
            if missing:
                variants = " ".join(m.source.requested_variants)
                self.result.report("libraries", _subject(m), f"libraries of {m.source.name} {variants} that "
                                   f"{m.target_name} does not install: {', '.join(missing)}")

    # Clean linkage ---------------------------------------------------------------------

    def upgrade_dependents(self, needed: bool = False) -> list[str]:
        """Return the target packages that depend on a `target_upgrades` package

        @param needed  count only the upgrades the replacements need, not those `--upgrade-all` adds
        @returns       the names; empty without such an upgrade
        """
        upgraded = {n.lower() for n in self.plan.target_upgrades} - (self.optional if needed else set())
        if not upgraded:
            return []
        return [n for n in self.state.names() if upgraded & {d.lower() for d in self.state.deps(n)}]

    def scan_set(self) -> dict[str, list[str]]:
        """Return the binaries of the mapped targets, companions, rebuilt packages and `target_upgrades` dependents

        The names among them that the move itself does not touch are kept in `only_optional`.

        @returns  the binaries by linkage key `<prefix>|<kind>|<name>`
        """
        prefix = self._found_target().prefix
        names = [_target_name(m) for m in self.mappings if m.target_kind in INSTALLED_KINDS] + self.companions()
        rebuilt = rebuilt_names(self.plan, prefix)
        moved = names + [n for n in rebuilt if n.lower() not in self.optional] + self.upgrade_dependents(needed=True)
        names += rebuilt + self.upgrade_dependents()
        self.only_optional = {n.lower() for n in names} - {n.lower() for n in moved}
        out: dict[str, list[str]] = {}
        for name in dict.fromkeys(names):
            if self.state.manager is Manager.BREW:
                keg = self.state.keg(name)
                if keg is not None:
                    out[f"{prefix}|formula|{name}"] = env_linkage.keg_binaries(keg)
            else:
                row = self.state.row(name)
                if row is not None:
                    out[f"{prefix}|port|{row.name}"] = self.state.binaries(row)
        return out

    def judge(self, key: str, path: str, ref: dict[str, Any], removal: _Removal) -> None:
        """Record one reference of the linkage check as a failure or a report line

        `missing` fails; `other` and `usrlocal` fail when they point into what the plan removes.

        @param key      the binary's linkage key `<prefix>|<kind>|<name>`
        @param path     the binary
        @param ref      the reference, with its class
        @param removal  what the run removes
        """
        name = key.rsplit("|", 1)[-1]
        cls = ref.get("class")
        shown = ref.get("resolved") or ref.get("name") or ""
        aside = name.lower() in self.only_optional
        if cls == "missing" and aside:
            cause = ("its upgrade, which --upgrade-all asked for," if name.lower() in self.optional
                     else "--upgrade-all upgraded a package it uses, which")
            self.result.task("linkage", name, f"{path} references {ref.get('name')}, which does not exist",
                             f"Install {name} again, because {cause} left it without a library it needs: "
                             f"{self.again(name, 'reinstall')}")
        elif cls == "missing":
            self.result.fail("linkage", name, f"{path} references {ref.get('name')}, which does not exist")
        elif cls in ("other", "usrlocal"):
            why = removal.reason(shown)
            if why and not aside:
                self.result.fail("linkage", name, f"{path} references {shown}, {why}")
            elif why:
                self.result.report("linkage", name, f"{path} references {shown}, {why}")
            else:
                self.result.report("linkage", name, f"{path} keeps a cross-prefix reference to {shown}")
        else:
            self.result.report("linkage", name, f"{path}: {cls} reference {ref.get('name')} (listed, never a failure)")

    def check_linkage(self) -> None:
        """Scan the linkage of `scan_set`, then report `brew missing` and the breakage of other target packages

        A binary `otool -l` cannot read is reported; a package none of whose binaries it reads fails.
        """
        binaries = self.scan_set()
        if binaries:
            found = env_linkage.scan(self.runner, binaries, self.instances)
            removal = _Removal(self.plan, self.bundle, self.instances)
            for key, path, ref in env_linkage.references(found, ("missing", "other", "usrlocal", "unresolved", "weak")):
                self.judge(key, path, ref, removal)
            for path, item in sorted(found["binaries"].items()):
                if item.get("error"):
                    self.result.report("linkage", item["package"].rsplit("|", 1)[-1],
                                       f"{path}: {item['error']}")
            for key, paths in binaries.items():
                # The scan reports a binary that two keys list under the first key only.
                items = [found["binaries"][p] for p in paths if found["binaries"].get(p, {}).get("package") == key]
                if items and all(item.get("error") for item in items):
                    what = "its binary" if len(items) == 1 else f"any of its {len(items)} binaries"
                    name = key.rsplit("|", 1)[-1]
                    note = self.result.report if name.lower() in self.only_optional else self.result.fail
                    note("linkage", name, f"otool -l could not read {what} ({items[0]['error']}), so its linkage "
                         "is unknown")
            for error in found.get("errors") or []:
                self.result.report("linkage", self._found_target().prefix, error)
        self.brew_missing()
        self.other_breakage(set(binaries))

    def brew_missing(self) -> None:
        """Probe `brew missing` and quote its output in the report"""
        target = self._found_target()
        if target.manager is not Manager.BREW or not target.drivable:
            return
        result = self.runner.run(brew_actions.missing(target, self.runner.host_arch,
                                                      self.aid(target.prefix, "missing")))
        if result.exit in (0, 1) and not result.timed_out and "Error:" not in result.stderr():
            for line in result.stdout().splitlines():
                if line.strip():
                    self.result.report("linkage", "brew missing", line.strip())
        else:
            self.result.report("linkage", "brew missing", brew_locate.failure_text(result, "brew missing"))

    def other_breakage(self, scanned: set[str]) -> None:
        """Report the breakage the scan found in any other target package, under its doctor finding

        @param scanned  the linkage keys `check_linkage` scanned itself
        """
        target = self._found_target()
        for key, item in sorted((self.bundle.result.linkage.get("packages") or {}).items()):
            prefix, _, rest = key.partition("|")
            kind, _, name = rest.partition("|")
            if key in scanned or not item.get("broken") or not envclean.spells(target, prefix):
                continue
            code = "brew-broken-linkage" if kind == "formula" else "ports-broken-binaries"
            count = len(item["broken"])
            self.result.report("linkage", name,
                               f"{code}: {count} binaries with broken references (never a failure here)")

    # Services replaced -----------------------------------------------------------------

    def plan_packages(self) -> list[model.Package]:
        """Return the packages the plan records: roots, mapped and unmigratable sources, kept and left packages

        @returns  the packages, a package once per list that holds it
        """
        sources = [m.source for m in list(self.plan.mappings) + list(self.plan.unmigratable)]
        return list(self.plan.roots) + sources + list(self.plan.kept) + list(self.plan.left_in_place)

    def archive_of(self, path: str) -> str | None:
        """Return the archive phase 6 took in the run directory of a path, or of a directory that holds it

        @param path  a path phase 6 may have archived
        @returns     the archive's file, or None without a run directory or such an archive
        """
        if self.run_dir is None:
            return None
        archives = (os.path.join(self.run_dir.path, ARCHIVES, state.slug(p) + ".tar.gz") for p in _and_parents(path))
        return next((a for a in archives if os.path.isfile(a)), None)

    def deleted_in_phase6(self, path: str) -> bool:
        """Return whether phase 6 deleted a path, or a directory that held it, as the run's journal records

        @param path  a path phase 6 may have deleted
        @returns     True when a `6.delete.` action of it or of a parent, or its retry as root, recorded `ok`
        """
        if self.run_dir is None:
            return False
        journal = self.run_dir.journal
        return any(journal.result(6, f"6.delete.{state.slug(p)}{retry}") == "ok"
                   for p in _and_parents(path) for retry in ("", ".sudo"))

    def data_text(self, svc: model.Service) -> str:
        """Return where an owned service's data is: its directories, or what phase 6 did with one it deleted

        A directory that is gone and that no archive or phase 6 deletion accounts for is named as it was.

        @param svc  the service
        @returns    ` (data in ...)`, ` (data of ... archived in ...)`, then ` (data of ... deleted by phase 6
                    without an archive)`; empty without data directories
        """
        here: list[str] = []
        archived: list[str] = []
        deleted: list[str] = []
        for path in svc.data_dirs:
            if os.path.lexists(path):
                here.append(path)
            elif (archive := self.archive_of(path)) is not None:
                archived.append(f"{path} archived in {archive}")
            elif self.deleted_in_phase6(path):
                deleted.append(path)
            else:
                here.append(path)
        return ((f" (data in {', '.join(here)})" if here else "")
                + (f" (data of {'; '.join(archived)})" if archived else "")
                + (f" (data of {', '.join(deleted)} deleted by phase 6 without an archive)" if deleted else ""))

    def service_note(self, svc: model.Service, m: model.Mapping | None) -> str:
        """Return the target's service with its start command, or the note to start it by hand

        @param svc  an owned source service
        @param m    the mapping of the service's package, or None
        @returns    the report line
        """
        data = self.data_text(svc)
        if m is None or not m.target_name:
            return f"{svc.package} has no replacement in the target: start what it ran by hand{data}"
        if self._found_target().manager is Manager.BREW:
            entry = self.catalogue.formula(m.target_name) if self.catalogue is not None else None
            if entry and any(key in entry for key in SERVICE_KEYS):
                return f"the target {m.target_name} has a service: `brew services start {m.target_name}`{data}"
        elif self.state is not None:
            row = self.state.row(m.target_name)
            files = self.state.files(row) if row is not None else []
            if any("/LaunchDaemons/" in f.location or "/LaunchAgents/" in f.location for f in files):
                return f"the target {m.target_name} has a startup item: `sudo port -N load {m.target_name}`{data}"
        return f"no service is known for the target {m.target_name}: start it by hand{data}"

    def check_services(self) -> None:
        """Report each owned source service of a removed package with its target service or a manual note"""
        removed = {(prefix, kind, name) for prefix, pairs in
                   list(self.plan.removal_set.items()) + list(self.plan.path_removed.items())
                   for kind, name in pairs if kind != "cask-adopted"}
        mapping_of = {(m.source.instance_prefix, m.source.kind, m.source.name): m for m in self.plan.mappings}
        seen: set[tuple[str, str, str]] = set()
        for pkg in self.plan_packages():
            key = (pkg.instance_prefix, pkg.kind, pkg.name)
            if key not in removed or key in seen:
                continue
            seen.add(key)
            for svc in pkg.services:
                if svc.owned:
                    self.result.report("services", svc.label, self.service_note(svc, mapping_of.get(key)))

    # Login shell PATH ------------------------------------------------------------------

    def zdotdir(self) -> list[str]:
        """Return `ZDOTDIR=<dir>` when the analysis took it from the environment, which the neutral profile drops

        @returns  the assignment for `env`, or an empty list
        """
        analysis = self.bundle.analysis
        environment = self.bundle.result.environment
        zdotdir = analysis.zdotdir if analysis is not None else environment.get("zdotdir")
        source = analysis.zdotdir_source if analysis is not None else environment.get("zdotdir_source")
        return ["ZDOTDIR=" + zdotdir] if zdotdir and source == "environment" else []

    def login_path(self, entries: Sequence[str], surv: envclean.Survivors) -> None:
        """Check the parsed login PATH has no removed prefix and the primary survivor's `bin` before the others'

        @param entries  the PATH entries of a new login shell
        @param surv     the survivor set
        """
        index = PrefixIndex(surv.instances)
        for entry in entries:
            if not entry.startswith("/") or os.path.normpath(entry) in envclean.STOCK:
                continue
            owner = index.owner(os.path.normpath(entry))
            if owner is not None and owner.prefix in surv.removed:
                self.result.report("login-path", entry,
                                   f"the login PATH holds this entry of the removed {owner.prefix}")
        if not surv.primary:
            return
        primary_bin = os.path.join(surv.primary, "bin")
        first = _position(entries, primary_bin)
        if first is None:
            self.result.report("login-path", surv.primary, f"the login PATH lacks {primary_bin}")
            return
        for inst in surv.survivor_instances():
            other = _position(entries, os.path.join(inst.prefix, "bin")) if inst.prefix != surv.primary else None
            if other is not None and other < first:
                self.result.report("login-path", surv.primary,
                                   f"the login PATH lists {os.path.join(inst.prefix, 'bin')} before {primary_bin}")

    def check_login_path(self) -> None:
        """Report a new login shell's PATH, and its stderr lines that name a removed prefix or a missing tool"""
        shell = envclean.login_shell_of(self.bundle)
        if not shell or not os.path.exists(shell):
            self.result.report("login-path", shell or "login shell", "not found, so the login PATH is not checked")
            return
        surv = envclean.survivors(self.bundle, self.plan, self.run_dir.journal if self.run_dir else None)
        argv = [ENV, "TERM=dumb"] + self.zdotdir() + env_shell.login_path_argv(shell)
        action = Action(action_id=self.aid("login-shell", "path"), kind="command", argv=argv, sudo=False,
                        description="the PATH of a new login shell", on_failure=OnFailure.PROBE, read_only=True,
                        timeout_s=LOGIN_TIMEOUT_S, new_session=True)
        result = self.runner.run(action)
        if result.timed_out:
            self.result.report("login-path", shell,
                               f"did not finish within {LOGIN_TIMEOUT_S} s; its process group was killed")
        entries = env_shell.parse_login_path(result.stdout(), shell)
        if entries is None:
            self.result.report("login-path", shell, f"printed no PATH (exit {result.exit})")
        else:
            self.login_path(entries, surv)
        for line in result.stderr().splitlines():
            text = _ANSI.sub("", line).strip()
            if text and (_names_removed(text, surv) or _NOT_FOUND.search(text)):
                self.result.report("login-path", shell, f"stderr: {text}")

    # Language packages -----------------------------------------------------------------

    def requirement_dirs(self) -> list[str]:
        """Return the run directory, then the run that made the plan

        @returns  the directories, the plan's run only when it exists; empty without a run directory
        """
        if self.run_dir is None:
            return []
        out = [self.run_dir.path]
        made = os.path.join(os.path.dirname(self.run_dir.path), self.plan.run_id) if self.plan.run_id else None
        if made and os.path.isdir(made) and made not in out:
            out.append(made)
        return out

    def check_language_packages(self) -> None:
        """Report the requirements file of each interpreter with extras, and the failed `pipx install`s"""
        dirs = self.requirement_dirs()
        extras = next((data.get("interpreter_extras") or {} for data in
                       (_read_json(os.path.join(d, "scan.json")) for d in dirs) if isinstance(data, dict)),
                      self.bundle.result.interpreter_extras)
        for name in sorted(env_interpreters.requirements(extras)):
            found = next((os.path.join(d, name) for d in dirs if os.path.isfile(os.path.join(d, name))), None)
            self.result.report("language-packages", name, f"kept in {found}" if found else
                               "missing: no requirements file for an interpreter with extras")
        journal = self.run_dir.journal if self.run_dir is not None else None
        for phase in self.plan.phases:
            for action in phase.actions if phase.number == 3 else []:
                if action.kind == "command" and "install" in action.argv and \
                        any(os.path.basename(a) == "pipx" for a in action.argv):
                    got = journal.result(3, action.action_id) if journal is not None else None
                    if got != "ok":
                        self.result.report("language-packages", action.argv[-1],
                                           f"pipx install did not succeed ({got or 'not run'})")

    # Sources removed -------------------------------------------------------------------

    def check_removed(self) -> None:
        """Check nothing of the removal set is left in its source: no Cellar or Caskroom entry, no registry row"""
        for prefix, pairs in sorted(self.plan.removal_set.items()):
            if not os.path.isdir(prefix):
                continue
            inst = next((i for i in self.instances if envclean.spells(i, prefix)), None)
            if inst is not None and inst.manager is Manager.PORTS:
                self.ports_removed(inst, pairs)
            else:
                self.brew_removed(prefix, pairs)

    def brew_removed(self, prefix: str, pairs: Sequence[tuple[str, str]]) -> None:
        """Check that no formula or cask of the removal set is left in a Homebrew source

        A formula is looked for in its rack of `ScanBundle.formula_racks` and a cask in its entry of `cask_rooms`, as
        phase 5 uninstalls them.

        @param prefix  the source prefix
        @param pairs   its `(kind, name)` pairs of the removal set
        """
        racks, _ = brew_inventory.walk_cellar(prefix)
        rooms, _ = brew_inventory.walk_caskroom(prefix)
        held = self.bundle.formula_racks(prefix) if self.bundle is not None else {}
        entries = self.bundle.cask_rooms(prefix) if self.bundle is not None else {}
        for kind, name in pairs:
            if kind == "formula":
                left = held.get(name, name) in racks
            else:
                left = kind in ("cask", "cask-adopted") and entries.get(name, name) in rooms
            if left:
                self.result.fail("removed", name, f"the {kind} is still installed in {prefix}")

    def ports_removed(self, inst: Instance, pairs: Sequence[tuple[str, str]]) -> None:
        """Check that no port of the removal set is still installed in `inst`

        @param inst   the MacPorts source
        @param pairs  its `(kind, name)` pairs of the removal set
        """
        if not inst.portdbpath or not os.path.exists(registry.registry_path(inst.portdbpath)):
            return
        try:
            with registry.Registry.open_copy(inst.portdbpath) as reg:
                rows = reg.ports()
        except REGISTRY_ERRORS as exc:
            self.result.fail("removed", inst.prefix, f"the registry backup failed: {type(exc).__name__}: {exc}")
            return
        for kind, name in pairs:
            left = [r for r in rows if kind == "port" and r.name.lower() == name.lower()]
            if left:
                specs = ", ".join(" ".join(r.spec_args) for r in left)
                self.result.fail("removed", name, f"still installed in {inst.prefix}: {specs}")

    # The gate's own checks -------------------------------------------------------------

    def snapshot_active(self, target: Instance, run_dir: state.RunDir) -> list[tuple[str, str, bool]] | None:
        """Return `(kind, name, must be active)` of each package the target's phase 1 snapshot records, or None

        An inactive port, or with `installed.json` a formula neither linked nor keg-only, is left out; without that
        file, each formula of `all-formulae.txt` need only be installed.

        @param target   the target instance
        @param run_dir  the run directory that holds the snapshot
        @returns        the packages, or None when the snapshot is missing
        """
        prefix = target.prefix
        if target.manager is Manager.PORTS:
            path = os.path.join(snapshot.ports_dir(run_dir, prefix), snapshot.INSTALLED)
            if not os.path.isfile(path):
                return None
            return [("port", line.name, True) for line in snapshot.read_installed(path) if line.active]
        sub = snapshot.brew_dir(run_dir, prefix)
        data = _read_json(os.path.join(sub, snapshot.INSTALLED_JSON))
        if isinstance(data, dict):
            out = [("formula", str(e["name"]), True) for e in data.get("formulae") or []
                   if isinstance(e, dict) and e.get("name") and (e.get("linked_keg") is not None or e.get("keg_only"))]
            return out + [("cask", str(e["token"]), True) for e in data.get("casks") or []
                          if isinstance(e, dict) and e.get("token")]
        formulae = os.path.join(sub, snapshot.FORMULAE)
        if not os.path.isfile(formulae):
            return None
        out = [("formula", line.name, False) for line in snapshot.read_formulae(formulae)]
        casks = os.path.join(sub, snapshot.CASKS)
        if os.path.isfile(casks):
            out += [("cask", line.token, True) for line in snapshot.read_casks(casks)[0] if line.versions]
        return out

    def pre_existing(self) -> None:
        """Check each package the snapshot records as active still is, so a repair that dropped one stops the run"""
        target = self._found_target()
        if self.run_dir is None:
            self.result.fail("gate", target.prefix, "no run directory, so the packages active before the run "
                             "cannot be checked")
            return
        recorded = self.snapshot_active(target, self.run_dir)
        if recorded is None:
            self.result.fail("gate", target.prefix,
                             f"the phase 1 snapshot of the target is missing from {self.run_dir.path}")
            return
        for kind, name, active in recorded:
            if kind == "cask":
                ok = self.state.has_cask(name)
            else:
                ok = self.state.active(name) if active else self.state.installed(name)
            if ok:
                continue
            optional = name in self.optional_casks if kind == "cask" else name.lower() in self.optional
            if optional:
                self.lost(name, cask=kind == "cask")
            else:
                self.result.fail("gate", name, f"was active in {target.prefix} before the run and is not now: "
                                 f"`brew-ports rollback {self.run_dir.run_id}` reinstalls it")

    def upgrades(self) -> None:
        """Check every package of `target_upgrades` is installed; one that only `--upgrade-all` names is a task"""
        prefix = self._found_target().prefix
        for name in self.plan.target_upgrades:
            if self.state.installed(name):
                continue
            if name.lower() in self.optional:
                self.lost(name)
            else:
                self.result.fail("gate", name, f"phase 3 was to upgrade or check it, and it is not installed in "
                                 f"{prefix}")

    def again(self, name: str, verb: str, *, cask: bool = False) -> str:
        """Return the command that puts a package of the target back in use, as the user types it

        @param name  the formula, the port or the cask's token
        @param verb  `install` for a package that is gone, `link` for a formula that is not linked, `activate`
                     for a port that is stored but switched off, `reinstall` for a package with a broken binary,
                     which a port mends by a forced upgrade
        @param cask  whether the package is a cask
        @returns     the command; MacPorts builds in trace mode while a Homebrew is installed
        """
        target = self._found_target()
        if target.manager is Manager.BREW:
            kind = [] if verb == "link" else ["--cask" if cask else "--formula"]
            return brew_actions.typed_line(target, [verb, *kind, name], self.runner.host_arch)
        trace = ["-t"] if any(i.manager is Manager.BREW for i in self.bundle.result.instances) else []
        args = {"reinstall": ["-n", *trace, "upgrade", "--force", name], "activate": ["activate", name]}.get(
            verb, [*trace, "install", name])
        return report.typed([target.binary or os.path.join(target.prefix, "bin", "port"), *args], True)

    def lost(self, name: str, *, cask: bool = False) -> None:
        """Record a package that only `--upgrade-all` upgrades and that is not in use after its upgrade, as a task

        @param name  the formula, the port or the cask's token
        @param cask  whether the package is a cask
        """
        target = self._found_target()
        where = report.at(target)
        subject = f"the app {name}" if cask else name
        if target.manager is Manager.PORTS and self.state.stored(name):
            verb, do, left = "activate", "Switch", f"stored in {where}, but switched off"
        elif cask or not self.state.installed(name):
            verb, do, left = "install", "Install", f"uninstalled in {where}"
        else:
            verb, do, left = "link", "Link", f"installed, but not linked into {where}"
        self.result.task("gate", subject, f"is {left} after its upgrade",
                         f"{do} {subject}{' on' if verb == 'activate' else ''} again, because its upgrade, which "
                         f"--upgrade-all asked for, left it {left}: {self.again(name, verb, cask=cask)}")


def check(bundle, plan: Plan, runner, *, gate: bool = False, run_dir: state.RunDir | None = None) -> VerifyResult:
    """Run every check of `plan` over a `bundle` taken after the installs, or with `gate` the phase 4 gate's

    `run_dir`, by default the runner's, holds the run's snapshot and journal.

    @param bundle   the scan taken after the installs
    @param plan     the plan
    @param runner   the runner of the probes
    @param gate     whether to run the phase 4 gate's checks
    @param run_dir  the run directory; None for the runner's
    @returns        the result
    """
    return _Verifier(bundle, plan, runner, run_dir if run_dir is not None else runner.run_dir, gate).run()


# The command ----------------------------------------------------------------------------------

def plan_path(state_dir: state.StateDir, given: str | None) -> str | None:
    """Return `PLAN` as given (a file, or a run id holding `plan.json`), else the newest run's `plan.json`

    @param state_dir  the state directory
    @param given      the PLAN argument, or None
    @returns          the path; None only without PLAN, when no run holds a `plan.json`
    """
    if given:
        if os.path.isfile(given):
            return given
        candidate = os.path.join(state_dir.runs, given, "plan.json")
        return candidate if "/" not in given and os.path.isfile(candidate) else given
    for run_id in reversed(state_dir.run_ids()):
        path = os.path.join(state_dir.runs, run_id, "plan.json")
        if os.path.isfile(path):
            return path
    return None


def _run_of(path: str) -> state.RunDir | None:
    """Return the run directory that holds a plan file, when it has a journal or a snapshot

    @param path  the plan file
    @returns     the run directory, or None for a plan outside a run
    """
    directory = os.path.dirname(os.path.abspath(path))
    if os.path.isfile(os.path.join(directory, "journal.jsonl")) or os.path.isdir(os.path.join(directory,
                                                                                                snapshot.SNAPSHOT)):
        return state.RunDir(directory)
    return None


def cmd_verify(ctx: Context, make_runner: Callable[[Context, state.RunDir], BaseRunner] | None = None) -> int:
    """Run `brew-ports verify [PLAN]` on the plan and the host, read afresh; exit 5 on a failure

    The dirty marker is never consulted.

    @param ctx          the command's context
    @param make_runner  the runner factory, given the context and the run directory; None for `command_runner`
    @returns            0 when every check passes, 2 without a readable plan, 5 on a failure
    """
    path = plan_path(ctx.state, ctx.args.plan)
    if path is None:
        ctx.console.warn("brew-ports verify: no run holds a plan.json; name the PLAN")
        return EXIT_USAGE
    try:
        plan = envclean.read_plan(path)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        ctx.console.warn(f"brew-ports verify: {path} is not a plan: {exc}")
        return EXIT_USAGE
    source = _run_of(path)
    run_dir, runner = start_run(ctx, 8, make_runner)
    with runner.signals():
        bundle = scan.build(runner, ctx.environ)
        try:
            scan.write(bundle, run_dir)
            result = check(bundle, plan, runner, run_dir=source or run_dir)
        finally:
            bundle.close()
    lines = [f"verify {path}"] + result.lines()
    for line in lines:
        ctx.console.out(line)
    report.write_markdown(run_dir.sub("report.md"), lines)
    return result.exit_code

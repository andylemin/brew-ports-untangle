"""Builders for the rollback tests: the made-up Mac a FakeRunner plays, and the runs rolled back

The source runs are written with the snapshot module's own writers; plans, journal lines and command contexts
complete them.
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import shutil
import sqlite3
import stat
from collections.abc import Callable, Sequence
from typing import Any

from brew_ports import model, runner as runner_mod, snapshot, state, system
from brew_ports.context import Context
from brew_ports.env import services as env_services
from brew_ports.macports import registry
from brew_ports.model import Confidence, Manager
from tests.unit.fixtures.doctor import builders as doctor_builders
from tests.unit.fixtures.macports.builders import port
from tests.unit.helpers import make_instance, make_package

UID = os.getuid()
USER = "alice"
GUI = f"gui/{UID}"
LAUNCHCTL = env_services.LAUNCHCTL
DSCL = "/usr/bin/dscl"
CHSH = "/usr/bin/chsh"
QuietConsole = doctor_builders.QuietConsole
bundle = doctor_builders.bundle
write_plist = doctor_builders.write_plist
OK = runner_mod.FakeResponse()
FAILED = runner_mod.FakeResponse(exit=1, stderr="Error: it failed\n")


def split_target(target: str) -> tuple[str, str]:
    """Split a launchctl service target, `gui/501/<label>` or `system/<label>`, into its domain and label

    @param target  the target
    @returns       the domain and the label
    """
    parts = target.split("/")
    if parts[0] == "system":
        return "system", "/".join(parts[1:])
    return "/".join(parts[:2]), "/".join(parts[2:])


class Host:
    """The made-up Mac behind the FakeRunner: what the snapshot writers' and `rollback`'s commands find

    Installs create kegs, Caskroom entries and registry rows, service starts load the jobs of `items`,
    a name in `fail` makes its install fail, and one in `interrupt` interrupts the run during its `port install`
    or the `launchctl bootout` of that label.
    """

    def __init__(self, home: str) -> None:
        """Start with a Mac where no job is loaded, nothing fails and no command has run

        @param home  the user's home directory
        """
        self.home = home
        self.run_path = ""
        self.run_id = ""
        self.jobs: dict[tuple[str, str], tuple[str, str]] = {}      # (domain, label) -> (plist, program)
        self.items: dict[str, tuple[str, str, str, str]] = {}       # package -> (domain, label, plist, program)
        self.shell: str | None = None
        self.fail: set[str] = set()
        self.interrupt: set[str] = set()
        self.sigint: Callable[[], None] = lambda: None              # the runner's SIGINT, which `fake` sets
        self.bundles: list[str] = []
        self.dump = ""
        self.selected: dict[str, dict[str, str]] = {}               # port binary -> group -> option
        self.portdbs: dict[str, str] = {}                           # port binary -> portdbpath
        self.commands: list[list[str]] = []

    def real(self, word: str) -> str:
        """Put the run directory and run id back into a word the FakeRunner keyed with placeholders

        @param word  a word of a command line
        @returns     the word with `<run>` and `<id>` replaced
        """
        return word.replace("<run>", self.run_path).replace("<id>", self.run_id)

    def ran(self, *words: str) -> list[list[str]]:
        """Return the commands run so far that contain `words` in order

        @param words  consecutive words of a command line
        @returns      the command lines, in the order they ran
        """
        size = len(words)
        return [argv for argv in self.commands
                if any(tuple(argv[i:i + size]) == words for i in range(len(argv) - size + 1))]

    def __call__(self, key: Sequence[str]) -> runner_mod.FakeResponse:
        """Record one command and answer it as the made-up Mac, its sudo and arch prefixes taken off

        @param key  the command line, with placeholders
        @returns    the response; an unknown command raises `KeyError`, as the FakeRunner does
        """
        argv = [self.real(word) for word in key]
        self.commands.append(argv)
        if argv[:3] == [runner_mod.SUDO, "-n", "--"]:
            argv = argv[3:]
        if argv[:1] == [runner_mod.ARCH]:
            argv = argv[2:]
        program = argv[0]
        if program == LAUNCHCTL:
            return self.launchctl(argv[1], argv[2], argv[3:])
        if program.endswith("/bin/brew"):
            return self.brew(os.path.dirname(os.path.dirname(program)), argv[1:])
        if program.endswith("/bin/port"):
            return self.port(program, argv[2:])
        if program == snapshot.TMUTIL:
            return OK
        if program == DSCL:
            return runner_mod.FakeResponse(stdout=f"UserShell: {self.shell}\n") if self.shell else FAILED
        if program == CHSH:
            self.shell = argv[2]
            return OK
        if program == runner_mod.CP:
            if not os.path.isfile(argv[-2]):
                return FAILED
            shutil.copyfile(argv[-2], argv[-1])
            return OK
        if program == runner_mod.RM:
            for path in argv[1:]:
                if not path.startswith("-") and os.path.lexists(path):
                    os.remove(path)
            return OK
        raise KeyError(key)

    # launchd ---------------------------------------------------------------

    def launchctl(self, verb: str, target: str, rest: Sequence[str]) -> runner_mod.FakeResponse:
        """Answer `launchctl print` from `jobs`, unload a job for `bootout`, and load a plist for `bootstrap`

        @param verb    `print`, `bootout` or `bootstrap`
        @param target  the service target, `<domain>/<label>`; for `bootstrap`, the domain
        @param rest    the words after the target: the plist of a `bootstrap`
        @returns       the job's description, or not found; success for `bootout`, and for a readable plist
        """
        if verb == "bootstrap":
            try:
                with open(rest[0], "rb") as fh:
                    data = plistlib.load(fh)
            except (OSError, IndexError):
                return FAILED
            self.jobs[(target, data["Label"])] = (rest[0], data["ProgramArguments"][0])
            return OK
        domain, label = split_target(target)
        if verb == "print":
            job = self.jobs.get((domain, label))
            return doctor_builders.printed(domain, label, job[0], job[1]) if job else doctor_builders.NOT_FOUND
        if verb == "bootout":
            self.jobs.pop((domain, label), None)
            if label in self.interrupt:
                self.sigint()
            return OK
        raise KeyError((verb, target))

    def load(self, package_name: str) -> runner_mod.FakeResponse:
        """Load the job `items` names for a package, as a service start does

        @param package_name  the formula or port
        @returns             success; a failure when the package is in `fail` or has no item
        """
        if package_name in self.fail or package_name not in self.items:
            return FAILED
        domain, label, plist, program = self.items[package_name]
        self.jobs[(domain, label)] = (plist, program)
        return OK

    # Homebrew --------------------------------------------------------------

    def brew(self, prefix: str, args: list[str]) -> runner_mod.FakeResponse:
        """Answer a `brew` command of the instance at `prefix`

        @param prefix  the instance's prefix, from the path of its `brew`
        @param args    the command's arguments
        @returns       the response; an unknown command raises `KeyError`
        """
        if args[:2] == ["bundle", "dump"]:
            path = next(a for a in args if a.startswith("--file="))[len("--file="):]
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.dump)
            return OK
        if args[:1] == ["info"]:
            return runner_mod.FakeResponse(stdout='{"formulae": [], "casks": []}')
        if args[:2] == ["bundle", "install"]:
            return self.bundle(prefix, next(a for a in args if a.startswith("--file="))[len("--file="):])
        if args[:2] == ["install", "--formula"]:
            return self.install(prefix, "formula", args[-1])
        if args[:2] == ["install", "--cask"]:
            return self.install(prefix, "cask", args[-1])
        if args[:1] == ["tap"]:
            return OK
        if args[:2] == ["services", "start"]:
            return self.load(args[2])
        raise KeyError(args)

    def install(self, prefix: str, kind: str, name: str) -> runner_mod.FakeResponse:
        """Install a formula as a version 9.9 keg, or a cask as a Caskroom entry

        @param prefix  the instance's prefix
        @param kind    `formula` or `cask`
        @param name    the package, a formula possibly tap-qualified
        @returns       success; a failure for a name in `fail`
        """
        if name in self.fail:
            return FAILED
        if kind == "formula":
            keg(prefix, name.rsplit("/", 1)[-1], "9.9")
        else:
            room(prefix, name)
        return OK

    def bundle(self, prefix: str, path: str) -> runner_mod.FakeResponse:
        """Install every `brew` and `cask` line of a Brewfile, keeping its text in `bundles`

        @param prefix  the instance's prefix
        @param path    the Brewfile
        @returns       success; a failure when one install fails
        """
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.bundles.append(text)
        failed = False
        for line in text.splitlines():
            words = line.split('"')
            if len(words) >= 2 and words[0].strip() in ("brew", "cask"):
                failed = self.install(prefix, "formula" if words[0].strip() == "brew" else "cask",
                                      words[1]).exit != 0 or failed
        return FAILED if failed else OK

    # MacPorts --------------------------------------------------------------

    def port(self, binary: str, args: list[str]) -> runner_mod.FakeResponse:
        """Answer a `port` command of the instance whose binary it is, the registry in `portdbs` updated

        @param binary  the instance's `port`
        @param args    the command's arguments after `-N`
        @returns       the response; an unknown command raises `KeyError`
        """
        groups = self.selected.setdefault(binary, {})
        if args[:2] == ["select", "--summary"]:
            if not groups:
                return runner_mod.FakeResponse(exit=1, stdout="No ports with the select option were found.\n")
            lines = ["Name     Selected   Options", "====     ========   ======="]
            lines += [f"{g}  {o}  {o} none" for g, o in sorted(groups.items())]
            return runner_mod.FakeResponse(stdout="\n".join(lines) + "\n")
        if args[:2] == ["select", "--set"]:
            groups[args[2]] = args[3]
            return OK
        if "install" in args:
            rest = args[args.index("install") + 1:]
            words = [w for w in rest if not w.startswith("--")]
            if words[0] in self.interrupt:
                self.sigint()
                return FAILED
            if words[0] in self.fail:
                return FAILED
            add_row(self.portdbs[binary], words[0], words[1:], requested="--unrequested" not in rest)
            executable(os.path.join(os.path.dirname(binary), words[0]))
            return OK
        if args[:1] == ["load"]:
            return self.load(args[1])
        if args[:1] == ["unload"]:
            domain, label, _, _ = self.items.get(args[1], ("system", "org.macports." + args[1], "", ""))
            self.jobs.pop((domain, label), None)
            return OK
        if args[:2] == ["snapshot", "--create"]:
            conn = _connect(self.portdbs[binary])
            try:
                conn.execute("INSERT INTO snapshots (note) VALUES (?)", (args[-1],))
                conn.commit()
            finally:
                conn.close()
            return OK
        if args[:2] == ["snapshot", "--export"]:
            return runner_mod.FakeResponse(exit=1, stdout="not json")
        raise KeyError(args)


# Prefixes ---------------------------------------------------------------------------

def executable(path: str) -> str:
    """Write a shell script the owner may run, making its directory first

    @param path  the file
    @returns     the path
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


def keg(prefix: str, name: str, version: str = "1.0", requested: bool | None = True,
        tap: str | None = "homebrew/core") -> str:
    """Make a keg with its receipt

    @param prefix     the Homebrew prefix
    @param name       the formula
    @param version    the keg's version
    @param requested  the receipt's `installed_on_request`; None leaves it out
    @param tap        the receipt's `source.tap`; None leaves the source empty
    @returns          the keg's path
    """
    path = os.path.join(prefix, "Cellar", name, version)
    os.makedirs(path, exist_ok=True)
    receipt: dict[str, Any] = {"source": {"tap": tap} if tap else {}}
    if requested is not None:
        receipt["installed_on_request"] = requested
    with open(os.path.join(path, "INSTALL_RECEIPT.json"), "w", encoding="utf-8") as fh:
        json.dump(receipt, fh)
    return path


def room(prefix: str, token: str, version: str = "1.0") -> str:
    """Make a Caskroom entry with its version and metadata directories

    @param prefix   the Homebrew prefix
    @param token    the cask
    @param version  the installed version
    @returns        the entry's path
    """
    path = os.path.join(prefix, "Caskroom", token)
    os.makedirs(os.path.join(path, version), exist_ok=True)
    os.makedirs(os.path.join(path, ".metadata", version, "20261101000000.000"), exist_ok=True)
    return path


def drop(prefix: str, sub: str, name: str) -> None:
    """Remove a rack or Caskroom entry, as a run's phase 5 does

    @param prefix  the Homebrew prefix
    @param sub     `Cellar` or `Caskroom`
    @param name    the formula or cask
    """
    shutil.rmtree(os.path.join(prefix, sub, name))


def _connect(portdbpath: str) -> sqlite3.Connection:
    """Open a live registry with the `VERSION` collation its indexes use

    @param portdbpath  the instance's `portdbpath`
    @returns           the connection
    """
    conn = sqlite3.connect(os.path.join(portdbpath, "registry", "registry.db"))
    conn.create_collation("VERSION", registry.vercmp)
    return conn


def add_row(portdbpath: str, name: str, variants: Sequence[str], requested: bool = True, version: str = "9.9") -> None:
    """Add a version of a port as `port install` does: active, every other row of the port inactive

    @param portdbpath  the instance's `portdbpath`
    @param name        the port
    @param variants    its variants, such as `+ssl`
    @param requested   whether it is requested
    @param version     its version
    """
    conn = _connect(portdbpath)
    try:
        columns = [r[1] for r in conn.execute("PRAGMA table_info(ports)")]
        new_id = (conn.execute("SELECT MAX(id) FROM ports").fetchone()[0] or 0) + 1
        conn.execute("UPDATE ports SET state = 'imaged' WHERE name = ?", (name,))
        row = port(new_id, name, version, variants="".join(variants), requested_variants="".join(variants),
                   requested=1 if requested else 0)
        keys = [k for k in row if k in columns]
        conn.execute(f"INSERT INTO ports ({', '.join(keys)}) VALUES ({', '.join('?' * len(keys))})",
                     [row[k] for k in keys])
        conn.commit()
    finally:
        conn.close()


def deactivate(portdbpath: str, *names: str) -> None:
    """Deactivate ports, as `port migrate --all` leaves those whose rebuild fails

    @param portdbpath  the instance's `portdbpath`
    @param names       the ports
    """
    conn = _connect(portdbpath)
    try:
        for name in names:
            conn.execute("UPDATE ports SET state = 'imaged' WHERE name = ?", (name,))
        conn.commit()
    finally:
        conn.close()


def drop_rows(portdbpath: str, *names: str) -> None:
    """Delete every registry row of the ports, as a run's phase 5 does

    @param portdbpath  the instance's `portdbpath`
    @param names       the ports
    """
    conn = _connect(portdbpath)
    try:
        for name in names:
            conn.execute("DELETE FROM ports WHERE name = ?", (name,))
        conn.commit()
    finally:
        conn.close()


def instance(tmp: str, manager: Manager, rel: str, **kw: Any) -> model.Instance:
    """Make an instance whose prefix exists under the test's directory, with its real identity

    @param tmp      the test's temporary directory
    @param manager  Homebrew or MacPorts
    @param rel      the prefix below the directory, with `/` separators
    @param kw       further fields of the instance, which override the defaults
    @returns        the instance, as `make_instance` builds it
    """
    prefix = os.path.join(tmp, *rel.split("/"))
    os.makedirs(os.path.join(prefix, "bin"), exist_ok=True)
    kw.setdefault("identity", system.identity(prefix))
    kw.setdefault("spellings", (prefix,))
    kw.setdefault("owned_roots", (prefix,))
    if manager is Manager.PORTS:
        kw.setdefault("portdbpath", os.path.join(prefix, "var", "macports"))
    return make_instance(manager, prefix, **kw)


def package(inst: model.Instance, name: str, **kw: Any) -> model.Package:
    """Make a package of an instance, a port or a formula unless `kind` says otherwise

    @param inst  the instance
    @param name  the package
    @param kw    further fields of the package, `kind` among them
    @returns     the package, as `make_package` builds it
    """
    kind = kw.pop("kind", "port" if inst.manager is Manager.PORTS else "formula")
    return make_package(name, kind=kind, prefix=inst.prefix, **kw)


def service(inst: model.Instance, label: str, plist: str, package_name: str, *, scope: str = "user",
            domain: str | None = None) -> model.Service:
    """Make an owned service of an instance's package, loaded when it has a domain

    @param inst          the instance
    @param label         the job's label
    @param plist         the job's plist
    @param package_name  the formula or port the job runs
    @param scope         `user` or `system`
    @param domain        the launchd domain it is loaded in; None for a job that is not loaded
    @returns             the service
    """
    kind = "port" if inst.manager is Manager.PORTS else "formula"
    return doctor_builders.service(label, plist, inst.prefix, package_name, kind=kind, scope=scope,
                                   domain=domain, loaded=domain is not None)


# Runs and plans ---------------------------------------------------------------------------

def plan(target: model.Instance, instances: Sequence[model.Instance], **kw: Any) -> model.Plan:
    """Make a plan with nothing to migrate, the target's prefix and the others as sources

    @param target     the plan's target
    @param instances  every instance of the plan
    @param kw         further fields of the plan, which override the defaults
    @returns          the plan; `source_run` sets its `run_id`
    """
    values: dict[str, Any] = {
        "created": "2026-11-13T10:00:00+1100", "run_id": "", "target": target.manager, "instances": list(instances),
        "source_prefixes": [i.prefix for i in instances if i.prefix != target.prefix],
        "target_prefix": target.prefix, "roots": [], "kept": [], "left_in_place": [], "mappings": [],
        "unmigratable": [], "removal_set": {}, "path_removed": {}, "manual_casks": [], "target_upgrades": [],
        "phases": [], "options": {}}
    values.update(kw)
    return model.Plan(**values)


def adoption(source: model.Package) -> model.Mapping:
    """Make the mapping by which the target adopts a source cask

    @param source  the source cask
    @returns       an exact mapping to the cask of the same name, with `adopt` set
    """
    return model.Mapping(source=source, target_kind="cask", target_name=source.name,
                         target_version=None, confidence=Confidence.EXACT, evidence=[], companions=[], selections=[],
                         variants_note=None, adopt=True)


def mapping(source: model.Package, target_kind: str, target_name: str,
            selections: Sequence[tuple[str, str]] = ()) -> model.Mapping:
    """Make the exact mapping of a source package to a target package

    @param source       the source package
    @param target_kind  `formula` or `port`
    @param target_name  the target package
    @param selections   the `port select` groups and options phase 7 sets for it
    @returns            the mapping
    """
    return model.Mapping(source=source, target_kind=target_kind, target_name=target_name, target_version=None,
                         confidence=Confidence.EXACT, evidence=[], companions=[], selections=list(selections),
                         variants_note=None)


def fake(host: Host, run_dir: state.RunDir, console=None) -> runner_mod.FakeRunner:
    """Make a FakeRunner for a run that the made-up Mac answers

    @param host     the made-up Mac, which learns the run's directory and id, and the runner's SIGINT
    @param run_dir  the run directory
    @param console  the console; None for a quiet one
    @returns        the runner
    """
    host.run_path, host.run_id = run_dir.path, run_dir.run_id
    runner = runner_mod.FakeRunner(default=host, console=console or QuietConsole(),
                                   environ={"HOME": host.home, "USER": USER}, run_dir=run_dir)
    host.sigint = runner.note_sigint
    return runner


def source_run(state_dir: state.StateDir, host: Host, scan, instances: Sequence[model.Instance], *,
               the_plan: model.Plan | None = None, id_prefix: str = "1") -> state.RunDir:
    """Make a run whose snapshot `snapshot.write` takes of `instances`, with the plan copied in as `apply` does

    @param state_dir  the state directory that holds the run
    @param host       the made-up Mac the snapshot's commands run on
    @param scan       the scan bundle the snapshot records
    @param instances  the instances the snapshot covers
    @param the_plan   the plan; None for a `doctor --fix` run
    @param id_prefix  the prefix of the snapshot's action ids
    @returns          the run directory
    """
    run_dir = state_dir.new_run()
    snapshot.write(fake(host, run_dir), run_dir, scan, instances, id_prefix=id_prefix, uid=UID)
    if the_plan is not None:
        the_plan.run_id = run_dir.run_id
        run_dir.write_json("plan.json", model.to_json(the_plan))
    return run_dir


def command(phase: int, action_id: str, argv: Sequence[str], exit_code: int = 0, sudo: bool = False) -> dict[str, Any]:
    """Return a journal command line, as the runner writes it

    @param phase      the phase that ran it
    @param action_id  the action's id
    @param argv       the command, without the sudo prefix
    @param exit_code  its exit status
    @param sudo       whether it ran as root, which puts the sudo prefix in front
    @returns          the entry
    """
    full = ([runner_mod.SUDO, "-n", "--"] if sudo else []) + list(argv)
    return {"ts": "2026-11-13T10:00:00+1100", "phase": phase, "action_id": action_id, "argv": full, "sudo": sudo,
            "exit": exit_code}


def write_record(phase: int, path: str, content: str, backup: str | None, root: bool = False) -> dict[str, Any]:
    """Return the journal record of a `write`, as `envclean.apply` makes it

    @param phase    the phase that wrote the file
    @param path     the file
    @param content  what the write left in it, whose SHA-256 the record holds
    @param backup   the copy from before the write; None for a file the write created
    @param root     whether the file is root-owned
    @returns        the record
    """
    return {"ts": "2026-11-13T10:00:00+1100", "phase": phase, "action_id": f"{phase}.write.{state.slug(path)}",
            "kind": "write", "path": path, "sha256": runner_mod.sha256_bytes(content.encode("utf-8")),
            "backup": backup, "root": root}


def journal(run_dir: state.RunDir, *entries: dict[str, Any]) -> None:
    """Append entries to a run's journal, each copied

    @param run_dir  the run directory
    @param entries  the entries, in order
    """
    for entry in entries:
        run_dir.journal.append(dict(entry))


def context(state_dir: state.StateDir, home: str, run_id: str, *, yes: bool = True, dry_run: bool = False,
            tty: bool = False) -> Context:
    """Make the context of a `rollback RUN-ID` command, with a quiet console

    @param state_dir  the state directory
    @param home       the user's home directory
    @param run_id     the run to roll back
    @param yes        the `--yes` flag
    @param dry_run    the `--dry-run` flag
    @param tty        whether a terminal is attached
    @returns          the context
    """
    args = argparse.Namespace(command="rollback", run_id=run_id, yes=yes, dry_run=dry_run)
    return Context(args, QuietConsole(), state_dir, tty=tty,
                   environ={"HOME": home, "USER": USER, "PATH": "/usr/bin:/bin"})

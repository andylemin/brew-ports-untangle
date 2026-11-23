"""Builders for the executor tests: a synthetic host, plans, a responder and stand-ins for phase modules

The responder changes the host in a temporary tree as `brew`, `port` and `launchctl` would.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import re
import shutil
import sqlite3
import types
from collections.abc import Callable, Sequence
from typing import Any
from unittest import mock

from brew_ports import envclean as real_envclean, model, plan_phases, planner, \
    remove_manager as real_remove_manager, runner as runner_mod, scan, servicectl, system, verify as real_verify
from brew_ports.context import Context
from brew_ports.homebrew import actions as brew_actions, inventory as brew_inventory
from brew_ports.macports import registry
from brew_ports.model import Confidence, Manager
from tests.unit.fixtures.doctor import builders as db
from tests.unit.fixtures.macports import builders as mb
from tests.unit.fixtures.verify import builders as vb
from tests.unit.helpers import make_instance

UID = 501
USER = "alice"
HOME = "/Users/alice"
ARCH = runner_mod.ARCH
SUDO = runner_mod.SUDO


# The host -------------------------------------------------------------------------------------

def brew_prefix(root: str, rel: str) -> str:
    """Make a Homebrew prefix: `bin/brew`, an empty Cellar and an empty Caskroom

    @param root  the test's temporary directory
    @param rel   the prefix below it, such as `opt/homebrew`
    @returns     the prefix
    """
    prefix = os.path.join(root, rel)
    for sub in ("bin", "Cellar", "Caskroom"):
        os.makedirs(os.path.join(prefix, sub), exist_ok=True)
    with open(os.path.join(prefix, "bin", "brew"), "w") as fh:
        fh.write("#!/bin/sh\n")
    return prefix


def ports_prefix(root: str, rel: str, rows: Sequence[dict[str, Any]] = (),
                 deps: Sequence[tuple[int, str]] = ()) -> str:
    """Make a MacPorts prefix: `macports.conf` naming it, and a registry holding the rows

    @param root  the test's temporary directory
    @param rel   the prefix below it, such as `opt/local`
    @param rows  the registry's port rows, as `mb.port` makes them
    @param deps  the registry's `(port id, dependency name)` rows
    @returns     the prefix
    """
    prefix = os.path.join(root, rel)
    os.makedirs(os.path.join(prefix, "bin"), exist_ok=True)
    os.makedirs(os.path.join(prefix, "etc", "macports"), exist_ok=True)
    with open(os.path.join(prefix, "etc", "macports", "macports.conf"), "w") as fh:
        fh.write(f"prefix {prefix}\n")
    mb.make_registry(os.path.join(prefix, "var", "macports"), ports=rows, deps=deps, journal="delete")
    return prefix


def brew(prefix: str) -> model.Instance:
    """Return the Homebrew instance of a prefix that `brew_prefix` made

    @param prefix  the prefix
    @returns       a drivable instance that owns the whole prefix
    """
    return make_instance(Manager.BREW, prefix, identity=system.identity(prefix), spellings=(prefix,),
                         owned_roots=(prefix,))


def ports(prefix: str) -> model.Instance:
    """Return the MacPorts instance of a prefix that `ports_prefix` made

    @param prefix  the prefix
    @returns       a drivable instance whose `portdbpath` is `<prefix>/var/macports`
    """
    return make_instance(Manager.PORTS, prefix, identity=system.identity(prefix), spellings=(prefix,),
                         owned_roots=(prefix,), portdbpath=os.path.join(prefix, "var", "macports"))


def keg(prefix: str, name: str, version: str, *, deps: Sequence[str] = (), exes: Sequence[str] = (),
        requested: bool | None = True) -> str:
    """Make a keg with a receipt naming its run-time dependencies, Mach-O `bin` files and an `opt` link

    @param prefix     the Homebrew prefix
    @param name       the formula
    @param version    the keg's version
    @param deps       the receipt's runtime dependencies
    @param exes       the executables in its `bin`
    @param requested  the receipt's `installed_on_request`; None leaves the key out
    @returns          the keg's path
    """
    path = vb.keg(prefix, name, version, exes=exes)
    receipt: dict[str, Any] = {"runtime_dependencies": [{"full_name": d, "version": "1"} for d in deps],
                               "poured_from_bottle": True, "source": {"tap": "homebrew/core"}}
    if requested is not None:
        receipt["installed_on_request"] = requested
    with open(os.path.join(path, "INSTALL_RECEIPT.json"), "w") as fh:
        json.dump(receipt, fh)
    return path


def caskroom(prefix: str, token: str, version: str = "1.0") -> str:
    """Make a cask's Caskroom entry, as `vb.caskroom` does

    @param prefix   the Homebrew prefix
    @param token    the cask token
    @param version  the installed version
    @returns        the Caskroom entry's path
    """
    return vb.caskroom(prefix, token, version)


def registry_db(prefix: str) -> str:
    """Return the registry file of a prefix that `ports_prefix` made

    @param prefix  the MacPorts prefix
    @returns       the path of its `registry.db`
    """
    return registry.registry_path(os.path.join(prefix, "var", "macports"))


def _connect(path: str) -> sqlite3.Connection:
    """Open a registry with the `VERSION` collation its indexes need

    @param path  the registry file
    @returns     the connection
    """
    conn = sqlite3.connect(path)
    conn.create_collation("VERSION", registry.vercmp)
    return conn


def port_names(prefix: str) -> list[str]:
    """Return the names of the ports a prefix's registry holds, in every state

    @param prefix  the MacPorts prefix
    @returns       the names, sorted, a name once per row
    """
    conn = _connect(registry_db(prefix))
    try:
        return sorted(r[0] for r in conn.execute("SELECT name FROM ports"))
    finally:
        conn.close()


def add_port(prefix: str, name: str, version: str) -> None:
    """Add a port's row to a prefix's registry, as `port install` would

    @param prefix   the MacPorts prefix
    @param name     the port
    @param version  its version
    """
    conn = _connect(registry_db(prefix))
    try:
        columns = [r[1] for r in conn.execute("PRAGMA table_info(ports)")]
        next_id = (conn.execute("SELECT MAX(id) FROM ports").fetchone()[0] or 0) + 1
        row = {k: v for k, v in mb.port(next_id, name, version).items() if k in columns}
        conn.execute(f"INSERT INTO ports ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                     list(row.values()))
        conn.commit()
    finally:
        conn.close()


def drop_port(prefix: str, name: str, spec: str) -> None:
    """Delete the row `spec` (`@<version>_<revision><variants>`) of a port

    @param prefix  the MacPorts prefix
    @param name    the port
    @param spec    the row's version spec
    """
    version, _, rest = spec[1:].rpartition("_")
    digits = re.match(r"\d+", rest)
    revision = int(digits.group(0)) if digits else 0
    conn = _connect(registry_db(prefix))
    try:
        conn.execute("DELETE FROM ports WHERE name = ? AND version = ? AND revision = ?", (name, version, revision))
        conn.commit()
    finally:
        conn.close()


def plist(root: str, label: str, program: str) -> str:
    """Write a launchd plist under `<root>/Library/LaunchDaemons`

    @param root     the test's temporary directory
    @param label    the job's label, which names the file
    @param program  the program the job runs
    @returns        the plist's path
    """
    return db.write_plist(os.path.join(root, "Library", "LaunchDaemons", label + ".plist"), label, program)


def service(label: str, path: str, prefix: str, package: str, kind: str, *, scope: str = "system",
            loaded: bool = True) -> model.Service:
    """Return an owned service of a package, loaded in its scope's domain with a pid when `loaded`

    @param label    the job's label
    @param path     its plist
    @param prefix   the prefix of the package's instance
    @param package  the package
    @param kind     the package's kind
    @param scope    `system`, or `user` for a job of the GUI domain
    @param loaded   whether launchd holds the job
    @returns        the service
    """
    domain = "system" if scope == "system" else f"gui/{UID}"
    return db.service(label, path, prefix, package, kind=kind, scope=scope, domain=domain if loaded else None,
                      loaded=loaded, pid=4321 if loaded else None)


# Catalogue and inventories ---------------------------------------------------------------------

class FakeCatalogue:
    """The parts of `homebrew.catalogue.Catalogue` the executor asks"""

    def __init__(self, versions: dict[str, str]) -> None:
        """Know the formulae and casks of `versions`, with no refusal, alias or executable

        @param versions  the catalogue version of each name
        """
        self.versions = dict(versions)
        self.refusals: dict[str, dict[str, Any]] = {}
        self.aliases: dict[str, str] = {}
        self.exes: dict[str, list[str]] = {}

    def canonical(self, name: str, _kind: str = "formula") -> str | None:
        """Return the name a name or alias stands for, whatever its kind

        @param name   a formula or cask name, or an alias
        @param _kind  the kind the caller asks for
        @returns      the name, or None when the catalogue lacks it
        """
        name = self.aliases.get(name, name)
        return name if name in self.versions else None

    def version(self, name: str, kind: str = "formula") -> str | None:
        """Return the catalogue version of a name or alias

        @param name  a formula or cask name, or an alias
        @param kind  the kind the caller asks for
        @returns     the version, or None when the catalogue lacks the name
        """
        return self.versions.get(self.canonical(name, kind) or name)

    def refused(self, name: str, _kind: str = "formula") -> dict[str, Any] | None:
        """Return why Homebrew refuses to install a name, from `refusals`

        @param name   a formula or cask name
        @param _kind  the kind the caller asks for
        @returns      the refusal, or None
        """
        return self.refusals.get(name)

    def executables(self, name: str) -> list[str]:
        """Return the executables `exes` lists for a formula

        @param name  the formula
        @returns     the names; empty when `exes` lists none
        """
        return list(self.exes.get(name, []))

    def has_bottle(self, _name: str) -> bool:
        """Return that every formula has a bottle

        @param _name  the formula
        @returns      True
        """
        return True


class FakePortsInventory:
    """The part of a MacPorts inventory the linkage check asks: the port that owns a file"""

    def __init__(self, owners: dict[str, str] | None = None) -> None:
        """Know the owners of some files

        @param owners  the port of each file; None for no file
        """
        self.owners = dict(owners or {})

    def owner_of(self, path: str) -> str | None:
        """Return the port that owns a file

        @param path  the file
        @returns     the port, or None when no port owns the file
        """
        return self.owners.get(path)

    def close(self) -> None:
        """Close nothing: the inventory holds no registry copy"""


class Host:
    """A stand-in for `scan.build`: a new bundle of the synthetic host on every call"""

    def __init__(self) -> None:
        """Hold an empty host, which the test fills"""
        self.instances: list[model.Instance] = []
        self.packages: list[model.Package] = []
        self.services: list[model.Service] = []
        self.environment: dict[str, Any] = {}
        self.catalogues: dict[str, FakeCatalogue] = {}
        self.owners: dict[str, dict[str, str]] = {}
        self.kegs: dict[str, dict[str, list[str]]] = {}      # prefix -> formula -> its kegs, as the inventory holds
        self.rooms: dict[str, dict[str, str]] = {}           # prefix -> cask -> its Caskroom entry, the same
        self.scans = 0

    def __call__(self, runner, environ, deep: bool = False) -> scan.ScanBundle:
        """Return a new bundle of the host as it stands, and count the scan

        @param runner   the scan's runner, which the host does not need
        @param environ  the scan's environment, which the host does not need
        @param deep     the scan's depth, which the host does not need
        @returns        the bundle, with the test's catalogues, the kegs of `kegs`, the Caskroom entries of `rooms`
                        and the owners of MacPorts files
        """
        self.scans += 1
        bundle = db.bundle(instances=self.instances, packages=self.packages, services=self.services,
                           environment=json.loads(json.dumps(self.environment)))
        # Duck-typed stand-ins: a FakeCatalogue for a Catalogue, a Homebrew inventory that holds only the kegs of
        # `kegs` and the Caskroom entries of `rooms` (or none), a FakePortsInventory.
        brew_entries: list[Any] = [
            (inst, self.catalogues.get(inst.prefix),
             brew_inventory.HomebrewInventory(instance_prefix=inst.prefix, kegs=dict(self.kegs.get(inst.prefix, {})),
                                              caskrooms=dict(self.rooms.get(inst.prefix, {})))
             if inst.prefix in self.kegs or inst.prefix in self.rooms else None)
            for inst in self.instances if inst.manager is Manager.BREW]
        ports_entries: list[Any] = [(inst, None, FakePortsInventory(self.owners.get(inst.prefix)))
                                    for inst in self.instances if inst.manager is Manager.PORTS]
        bundle.brew = brew_entries
        bundle.ports = ports_entries
        return bundle


# Plans --------------------------------------------------------------------------------------------

def mapping(source: model.Package, kind: str, name: str, *, version: str = "1.0", companions: Sequence[str] = (),
            selections: Sequence[tuple[str, str]] = (), adopt: bool = False) -> model.Mapping:
    """Return an exact mapping of a source package

    @param source      the source package
    @param kind        the target kind, such as `formula` or `port`
    @param name        the target package
    @param version     the target version
    @param companions  the extra target packages the mapping needs
    @param selections  the `(group, option)` pairs phase 7 selects
    @param adopt       whether the target adopts the source cask
    @returns           the mapping
    """
    return model.Mapping(source=source, target_kind=kind, target_name=name, target_version=version,
                         confidence=Confidence.EXACT, evidence=["test"], companions=list(companions),
                         selections=list(selections), variants_note=None, adopt=adopt)


def plan(target: model.Instance, sources: Sequence[model.Instance], *, mappings: Sequence[model.Mapping] = (),
         removal: dict[str, list[tuple[str, str]]] | None = None, phase2: Sequence[model.Action] = (),
         phase3: Sequence[model.Action] = (), phase6: Sequence[model.Action] = (), upgrades: Sequence[str] = (),
         remove: Sequence[str] = (), unmigratable: Sequence[model.Mapping] = (), optional: Sequence[str] = (),
         optional_casks: Sequence[str] = (), **options: Any) -> model.Plan:
    """Return a plan of the mappings, its phases assembled as the planner does

    @param target          the target instance
    @param sources         the source instances
    @param mappings        the mappings, whose sources are the roots
    @param removal         the removal set: the `(kind, name)` pairs of each source prefix
    @param phase2          the repairs of phase 2
    @param phase3          the actions of phase 3
    @param phase6          the actions of phase 6
    @param upgrades        the plan's `target_upgrades`
    @param remove          the prefixes of the old installations the plan uninstalls
    @param unmigratable    the mappings of packages that are not migrated
    @param optional        the plan's `optional_upgrades`, which join `target_upgrades`
    @param optional_casks  the plan's `optional_casks`
    @param options         `PlanOptions` fields, such as `start_services=True`
    @returns               the plan
    """
    opts = planner.PlanOptions(target=target.manager, **options)
    return model.Plan(
        created="2026-11-13T10:00:00+1100", run_id="20261113-100000-aaaaaa", target=target.manager,
        instances=[target] + list(sources), source_prefixes=[s.prefix for s in sources], target_prefix=target.prefix,
        roots=[m.source for m in mappings], kept=[], left_in_place=[], mappings=list(mappings),
        unmigratable=list(unmigratable), removal_set={k: list(v) for k, v in (removal or {}).items()},
        path_removed={}, manual_casks=[],
        target_upgrades=list(upgrades) + [name for name in optional if name not in upgrades],
        phases=plan_phases.assemble(list(phase2), list(phase3), list(phase6), bool(remove)),
        options=opts.as_strings(target.prefix, list(remove)),
        optional_upgrades=list(optional), optional_casks=list(optional_casks))


def write_plan(path: str, value: model.Plan) -> str:
    """Write a plan as `plan.json` text

    @param path   the file
    @param value  the plan
    @returns      the path
    """
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(model.to_json(value))
    return path


# The responder ------------------------------------------------------------------------------------

def strip(key: Sequence[str]) -> tuple[bool, list[str]]:
    """Return whether sudo runs the argv, and the argv without `sudo -n [--preserve-env=...] --` or `arch`

    @param key  the command's argv, as the runner keys it
    @returns    whether it runs as root, and the command itself
    """
    tail = list(key)
    sudo = bool(tail) and tail[0] == SUDO
    if sudo:
        tail = tail[tail.index("--") + 1:] if "--" in tail else tail[1:]
    if tail[:1] == [ARCH]:
        tail = tail[2:]
    return sudo, tail


def otool_text(files: Sequence[str], refs: dict[str, list[str]]) -> str:
    """Return `otool -l` text for a batch: each file with an `LC_LOAD_DYLIB` per reference

    @param files  the files of the batch, in order
    @param refs   the references of each file
    @returns      the text, one section per file
    """
    out = []
    for path in files:
        out.append(f"{path}:")
        for number, name in enumerate(refs.get(path, [])):
            out += [f"Load command {number}", "          cmd LC_LOAD_DYLIB", "      cmdsize 56",
                    f"         name {name} (offset 24)"]
    return "\n".join(out) + "\n"


class Responder:
    """Answer commands as the synthetic host would: `brew`, `port`, `launchctl`, `rm` and `otool -l`"""

    def __init__(self, state_dir) -> None:
        """Answer for a host with nothing loaded, failing or hooked

        @param state_dir  the state directory, whose dirty marker each command's record notes
        """
        self.state_dir = state_dir
        self.versions: dict[str, str] = {}
        self.pours: dict[str, list[tuple[str, str]]] = {}     # name -> the dependency kegs its install pours
        self.keep: set = set()                    # packages an uninstall fails on
        self.fail: dict[str, int] = {}
        self.loaded: dict[str, str] = {}          # label -> domain
        self.programs: dict[str, str] = {}        # label -> the program its plist runs
        self.stuck: set = set()                   # labels a bootout never removes
        self.refs: dict[str, list[str]] = {}      # binary -> the references `otool -l` prints
        self.refs_after: dict[str, list[str]] = {}
        self.hooks: dict[str, Callable[[list[str]], runner_mod.FakeResponse | None]] = {}   # verb -> run first
        self.log: list[tuple[bool, list[str]]] = []
        self.marker: list[tuple[str, bool]] = []  # whether the dirty marker existed as each command ran

    def __call__(self, key) -> runner_mod.FakeResponse:
        """Log a command and answer it: its hook first, then the handler of its program, else exit 0

        @param key  the command's argv, as the runner keys it
        @returns    the response
        """
        sudo, tail = strip(key)
        self.log.append((sudo, tail))
        word = os.path.basename(tail[0]) if tail else ""
        verb = self.verb(word, tail)
        self.marker.append((f"{word} {verb}", os.path.exists(self.state_dir.dirty_path)))
        hook = self.hooks.get(verb) or self.hooks.get(word)
        if hook is not None:
            answer = hook(tail)
            if answer is not None:
                return answer
        handler = getattr(self, "answer_" + word.replace("-", "_"), None)
        return handler(tail, verb) if handler is not None else runner_mod.FakeResponse()

    @staticmethod
    def verb(word: str, tail: list[str]) -> str:
        """Return a command's verb: the first word past the options for `brew` and `port`, else the second word

        @param word  the program's basename
        @param tail  the command without sudo and arch
        @returns     the verb; empty when there is none
        """
        if word in ("brew", "port"):
            return next((a for a in tail[1:] if not a.startswith("-")), "")
        return tail[1] if len(tail) > 1 else ""

    # brew -------------------------------------------------------------------------------------

    def answer_brew(self, tail: list[str], verb: str) -> runner_mod.FakeResponse:
        """Answer `brew`: installs pour kegs or Caskroom entries, uninstalls remove them

        @param tail  the command without sudo and arch
        @param verb  its verb
        @returns     exit 1 when a formula install names a package of `fail` or an uninstall one of `keep`
        """
        prefix = os.path.dirname(os.path.dirname(tail[0]))
        rest = tail[1:]
        names = [a for a in rest[1:] if not a.startswith("-")]
        if verb in ("install", "reinstall", "upgrade") and "--cask" in rest:
            for token in names:
                caskroom(prefix, token)
            return runner_mod.FakeResponse()
        if verb in ("install", "reinstall", "upgrade"):
            failing = [n for n in names if n in self.fail]
            for name in names:
                if name in self.fail:
                    continue
                version = self.versions.get(name, "1.0")
                if not os.path.isdir(os.path.join(prefix, "Cellar", name, version)):
                    keg(prefix, name, version)
                for dep, dep_version in self.pours.get(name, []):
                    if not os.path.isdir(os.path.join(prefix, "Cellar", dep, dep_version)):
                        keg(prefix, dep, dep_version, requested=False)
                if name in self.refs_after:
                    for path in list(self.refs):
                        if f"/Cellar/{name}/" in path:
                            self.refs[path] = self.refs_after[name]
            return runner_mod.FakeResponse(exit=1 if failing else 0)
        if verb == "uninstall":
            sub = "Caskroom" if "--cask" in rest else "Cellar"
            failed = False
            for name in names:
                if name in self.keep:
                    failed = True
                    continue
                shutil.rmtree(os.path.join(prefix, sub, name), ignore_errors=True)
            return runner_mod.FakeResponse(exit=1 if failed else 0)
        return runner_mod.FakeResponse()

    # port ---------------------------------------------------------------------------------------

    def answer_port(self, tail: list[str], verb: str) -> runner_mod.FakeResponse:
        """Answer `port`: uninstalls drop registry rows, installs add them, `load` loads the startup item

        @param tail  the command without sudo and arch
        @param verb  its verb
        @returns     exit 1 when an uninstall names a port of `keep` or an archive install one of `fail`
        """
        prefix = os.path.dirname(os.path.dirname(tail[0]))
        rest = tail[1:]
        if verb == "uninstall":
            words = rest[rest.index("uninstall") + 1:]
            failed = False
            for name, spec in zip(words[::2], words[1::2]):
                if name in self.keep:
                    failed = True
                    continue
                drop_port(prefix, name, spec)
            return runner_mod.FakeResponse(exit=1 if failed else 0)
        if verb == "install":
            name = next(a for a in rest[rest.index("install") + 1:] if not a.startswith("-"))
            if "-b" in rest and name in self.fail:
                return runner_mod.FakeResponse(exit=1, stderr="no archive\n")
            add_port(prefix, name, self.versions.get(name, "1.0"))
            return runner_mod.FakeResponse()
        if verb == "load":
            self.loaded[f"org.macports.{rest[-1]}"] = "system"
            return runner_mod.FakeResponse()
        return runner_mod.FakeResponse()

    # launchctl, rm, otool -------------------------------------------------------------------------

    def answer_launchctl(self, tail: list[str], verb: str) -> runner_mod.FakeResponse:
        """Answer `launchctl` from `loaded`: `print` finds a loaded job, `bootout` and `bootstrap` change it

        @param tail  the command without sudo and arch
        @param verb  its verb
        @returns     the job's `print` output, the not-found answer, or exit 0
        """
        if verb == "print":
            domain, _, label = tail[2].rpartition("/")
            if self.loaded.get(label) == domain:
                return db.printed(domain, label, f"/x/{label}.plist", self.programs.get(label, "/x/bin/" + label),
                                  pid=4321)
            return db.NOT_FOUND
        if verb == "bootout":
            label = tail[2].rpartition("/")[2]
            if label not in self.stuck:
                self.loaded.pop(label, None)
            return runner_mod.FakeResponse()
        if verb == "bootstrap":
            self.loaded[os.path.basename(tail[3])[:-len(".plist")]] = tail[2]
            return runner_mod.FakeResponse()
        return runner_mod.FakeResponse()

    def answer_rm(self, tail: list[str], _verb: str) -> runner_mod.FakeResponse:
        """Answer `rm`: delete each path named, a directory with its contents

        @param tail   the command without sudo and arch
        @param _verb  its verb
        @returns      exit 0
        """
        for path in tail[1:]:
            if path.startswith("-"):
                continue
            if os.path.islink(path) or os.path.isfile(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        return runner_mod.FakeResponse()

    def answer_otool(self, tail: list[str], _verb: str) -> runner_mod.FakeResponse:
        """Answer `otool -l` with the references `refs` holds for each file

        @param tail   the command without sudo and arch
        @param _verb  its verb
        @returns      the load commands of the files
        """
        return runner_mod.FakeResponse(stdout=otool_text(tail[2:], self.refs))

    def ran(self, word: str, verb: str | None = None) -> list[list[str]]:
        """Return every command run with that program (and verb), its argv without sudo and arch

        @param word  the program's basename
        @param verb  the verb, or None for any
        @returns     the commands, in the order they ran
        """
        return [tail for _, tail in self.log if tail and os.path.basename(tail[0]) == word
                and (verb is None or self.verb(word, tail) == verb)]


# Stand-ins for verify, envclean and remove_manager ------------------------------------------------

def verify_module(failures: dict[bool, list[tuple[str, str, str]]] | None = None,
                  tasks: dict[bool, list[tuple[str, str, str, str]]] | None = None) -> types.SimpleNamespace:
    """Return a stand-in for `brew_ports.verify` whose `check` returns a real `VerifyResult`

    `failures[gate]` lists the `(step, subject, text)` of each failure, `tasks[gate]` the `(step, subject, text,
    task)` of each package left for the user to repair; `calls` records `gate` per call.

    @param failures  the failures of the gate (True) and of phase 8 (False); None for none
    @param tasks     the tasks of the gate (True) and of phase 8 (False); None for none
    @returns         the stand-in, for `sys.modules`
    """
    mod = types.SimpleNamespace(calls=[])

    def check(_bundle, _plan, _runner, *, gate=False, run_dir=None):
        del run_dir
        mod.calls.append(gate)
        result = real_verify.VerifyResult(gate=gate)
        for step, subject, text in (failures or {}).get(gate, []):
            result.fail(step, subject, text)
        for step, subject, text, task in (tasks or {}).get(gate, []):
            result.task(step, subject, text, task)
        return result
    mod.check = check
    return mod


def envclean_module(edits: Sequence[real_envclean.Edit] = (), failed: Sequence[str] = ()) -> types.SimpleNamespace:
    """Return a stand-in for `brew_ports.envclean` with fakes of `survivors`, `compute` and `apply`

    `applied`, `journals` and `bundles` record what they were given.

    @param edits   the edits `compute` returns
    @param failed  the files `apply` reports as not written
    @returns       the stand-in, for `sys.modules`
    """
    mod = types.SimpleNamespace(applied=[], journals=[], bundles=[])

    def survivors(bundle, run_plan, journal=None, **_kw):
        mod.journals.append(journal)
        mod.bundles.append(bundle)
        return real_envclean.Survivors(instances=list(bundle.result.instances), surviving=[run_plan.target_prefix],
                                       removed=list(run_plan.source_prefixes), primary=run_plan.target_prefix)

    def compute(_bundle, _surv, _home, _environ, **_kw):
        return list(edits)

    def apply(_runner, _run_dir, given, _root_files, *, show=True):
        del show
        mod.applied.append(list(given))
        return real_envclean.ApplyResult(written=[e.path for e in given if e.changed and not e.manual],
                                         failed=list(failed))
    mod.survivors = survivors
    mod.survivor_lines = real_envclean.survivor_lines
    mod.compute = compute
    mod.render = real_envclean.render
    mod.apply = apply
    return mod


def remove_manager_module(error: Exception | None = None) -> types.SimpleNamespace:
    """Return a stand-in for `brew_ports.remove_manager` whose `run` records its calls, with the real `deletion_begun`

    @param error  the exception `run` raises; None for a run that returns its line
    @returns      the stand-in, for `sys.modules`
    """
    mod = types.SimpleNamespace(calls=[], deletion_begun=real_remove_manager.deletion_begun,
                                Stopped=real_remove_manager.Stopped)

    def run(runner, run_dir, _plan, bundle, ask, *, resumed):
        mod.calls.append({"resumed": resumed, "phase": runner.phase, "run_id": run_dir.run_id, "bundle": bundle,
                          "yes": ask.yes})
        if error is not None:
            raise error
        return ["phase 6 done"]
    mod.run = run
    return mod


class FakeRootFiles:
    """`runner.RootFiles` writing straight to the file, so `/etc/shells` can be a temporary one"""

    writes: list[tuple[str, str]] = []

    def __init__(self, _runner, _run_id) -> None:
        """Stage nothing: every write goes straight to its file

        @param _runner  the run's runner
        @param _run_id  the run's id
        """
        self.staging = None

    def write(self, path: str, content: str, _tmp_dir: str) -> str:
        """Write the file as the user, and keep the write in `writes`

        @param path      the file
        @param content   its new text
        @param _tmp_dir  the directory the root form stages its copy in
        @returns         the SHA-256 of the content
        """
        FakeRootFiles.writes.append((path, content))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def remove_staging(self) -> None:
        """Remove nothing: no write is staged"""


# The command --------------------------------------------------------------------------------------

def args(**kw: Any) -> argparse.Namespace:
    """Return the parsed command line of `apply`: `--yes`, without a plan, a resume, a dry run or a last phase

    @param kw  the values that override those
    @returns   the namespace
    """
    values = {"command": "apply", "plan": None, "resume": None, "yes": True, "dry_run": False, "stop_after": None}
    values.update(kw)
    return argparse.Namespace(**values)


class FakeContext(Context):
    """A `Context` that prints into memory and answers its terminal prompts from a queue"""

    console: db.QuietConsole

    def __init__(self, namespace: argparse.Namespace, state_dir, answers: Sequence[bool], tty: bool) -> None:
        """Build the context of one command

        @param namespace  the parsed command line
        @param state_dir  the state directory
        @param answers    the terminal's answers, in order; once they run out, each prompt takes its default
        @param tty        whether the prompts can be answered
        """
        super().__init__(namespace, db.QuietConsole(), state_dir, tty=tty, environ={"HOME": HOME, "USER": USER})
        self.answers = list(answers)
        self.asked: list[str] = []

    def ask_terminal(self, question: str, default: bool) -> bool:
        """Take the next queued answer, else the default, and keep the question in `asked`

        @param question  the question
        @param default   the answer once the queue is empty
        @returns         the answer
        """
        self.asked.append(question)
        return self.answers.pop(0) if self.answers else default


def context(state_dir, answers: Sequence[bool] = (), tty: bool = False, **kw: Any) -> FakeContext:
    """Return the context of one `apply`, with `--yes` and no terminal unless the arguments say otherwise

    @param state_dir  the state directory
    @param answers    the terminal's answers, in order
    @param tty        whether the prompts can be answered
    @param kw         the command line's values that override those of `args`
    @returns          the context
    """
    return FakeContext(args(**kw), state_dir, answers, tty)


def fixed_stop(clock) -> Callable[..., servicectl.StopResult]:
    """Return `servicectl.stop` on a fake clock, with every stopped process already gone

    @param clock  the fake clock, whose `sleep` advances it
    @returns      the stop function
    """
    return functools.partial(servicectl.stop, clock=clock, sleep=clock.sleep, alive=lambda pid: False)


def patches(test, host: Host) -> None:
    """Patch the scan, the detectors, the service wait and the root form for one test

    @param test  the test case, which removes the patches when it ends
    @param host  the synthetic host the scans read
    """
    clock = db.FakeClock()
    for patcher in (mock.patch("brew_ports.scan.build", side_effect=host),
                    mock.patch("brew_ports.doctor.detect_all", return_value=[]),
                    mock.patch("brew_ports.servicectl.stop", fixed_stop(clock)),
                    mock.patch("brew_ports.exec_run.RootFiles", FakeRootFiles)):
        patcher.start()
        test.addCleanup(patcher.stop)


def install_action(target: model.Instance, action_id: str, names: Sequence[str]) -> model.Action:
    """Return a Homebrew formula install on an arm64 host

    @param target     the Homebrew target
    @param action_id  the install's id
    @param names      the formulae
    @returns          the install
    """
    return brew_actions.install_formulae(target, "arm64", action_id, names)

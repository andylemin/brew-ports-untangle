"""Builders for the planner tests: temporary prefixes, synthetic scan bundles and a fake terminal

The prefixes are real directories, so identity checks hold on Linux and macOS alike.
"""

from __future__ import annotations

import datetime
import io
import os
from collections.abc import Iterable, Mapping, Sequence
from typing import Any
from unittest import mock

from brew_ports import doctor, model, planner, report, runner as runner_mod, scan, state, system
from brew_ports.homebrew import inventory as brew_inventory
from brew_ports.homebrew.catalogue import Catalogue
from brew_ports.macports import registry
from brew_ports.model import Blocks, Manager, Severity
from tests.unit.fixtures.equiv import builders as eq
from tests.unit.helpers import TempDirTest, make_instance, make_package

BREW, PORTS = Manager.BREW, Manager.PORTS
TODAY = datetime.date(2026, 11, 13)
SYSTEM = {"macos": "15.7", "host_arch": "arm64", "uid": 501, "user": "alice", "home": "/Users/alice"}


class QuietConsole(report.Console):
    """A console that writes into memory, so a test prints nothing"""

    def __init__(self) -> None:
        """Write both streams into memory"""
        super().__init__(stream=io.StringIO(), err=io.StringIO())


def instance(manager: Manager, prefix: str, **kw: Any) -> model.Instance:
    """Return an instance on an existing directory, with that directory's identity

    @param manager  the instance's package manager
    @param prefix   the prefix, made when it is missing
    @param kw       `Instance` fields that override the defaults; `drivable=False` alone makes it `cannot-run`
    @returns        the instance
    """
    os.makedirs(prefix, exist_ok=True)
    fields: dict[str, Any] = {"identity": system.identity(prefix), "spellings": (prefix,), "owned_roots": (prefix,)}
    fields.update(kw)
    if not fields.get("drivable", True) and "usability" not in kw:
        fields["usability"] = model.Usability.CANNOT_RUN
    return make_instance(manager, prefix, **fields)


def formula(name: str, prefix: str, **kw: Any) -> model.Package:
    """Return a formula of an instance

    @param name    the formula name
    @param prefix  the instance's prefix
    @param kw      `Package` fields that override the defaults
    @returns       a requested, active formula
    """
    return make_package(name, "formula", prefix, **kw)


def cask(token: str, prefix: str, **kw: Any) -> model.Package:
    """Return a cask of an instance, at version 1.0 unless `kw` names another

    @param token   the cask token
    @param prefix  the instance's prefix
    @param kw      `Package` fields that override the defaults
    @returns       a requested cask
    """
    kw.setdefault("version", "1.0")
    return make_package(token, "cask", prefix, **kw)


def port(name: str, prefix: str, version: str = "1.0", revision: int = 0, **kw: Any) -> model.Package:
    """Return a port of an instance, as the registry lists an installed version

    @param name      the port name
    @param prefix    the instance's prefix
    @param version   the port's version
    @param revision  the port's revision
    @param kw        `Package` fields that override the defaults
    @returns         a requested, active port at `<version>_<revision>`
    """
    return eq.port(name, version, prefix=prefix, revision=revision, **kw)


def catalogue(home: str, payload: dict[str, Any] | None = None) -> Catalogue:
    """Return the equiv fixture catalogue, or a catalogue of the given payload

    @param home     the home directory the fixture catalogue's casks install under
    @param payload  a catalogue payload, or None for the fixture catalogue
    @returns        the catalogue, as of `TODAY`
    """
    if payload is None:
        return eq.catalogue(home, TODAY)
    return Catalogue.from_payload(payload, prefix=eq.BREW_TARGET, home=home, today=TODAY)


def portindex(directory: str, drop: Iterable[str] = (), add: Iterable[Mapping[str, Any]] = ()) -> Any:
    """Return the equiv fixture PortIndex, written below a directory

    @param directory  the directory the PortIndex is written below
    @param drop       the names of fixture entries to leave out
    @param add        entries to add, each a mapping of PortIndex fields
    @returns          the PortIndex
    """
    return eq.portindex(directory, drop, add)


class PortsInventory:
    """A stand-in `MacPortsInventory` with each row's registered files and their owners"""

    def __init__(self, files: Mapping[tuple[str, str], Sequence[tuple[str, bool]]] | None = None) -> None:
        """Index the files of each row, and the first port that registers each file

        @param files  each row's `(path, active)` files, by `(name, "@<version>_<revision>")`; None for none
        """
        self._files: dict[tuple[str, str], list[registry.FileRow]] = {}
        self._owners: dict[str, str] = {}
        for (name, version), rows in (files or {}).items():
            self._files[(name.lower(), version)] = [registry.FileRow(path, None, active, False)
                                                    for path, active in rows]
            for path, _ in rows:
                self._owners.setdefault(path, name)

    def files(self, pkg: model.Package) -> list[registry.FileRow]:
        """Return the registered files of a registry row

        @param pkg  a port's row
        @returns    its files; none for a row the stand-in lacks
        """
        return list(self._files.get((pkg.name.lower(), pkg.spec_args[1] if len(pkg.spec_args) == 2 else ""), []))

    def owner_of(self, path: str) -> str | None:
        """Return the port that registered a file

        @param path  a file's path
        @returns     the port name, or None
        """
        return self._owners.get(path)

    def close(self) -> None:
        """Close nothing: the stand-in holds no database"""


class World:
    """The instances, packages and services of one test host, turned into a `ScanBundle`"""

    def __init__(self) -> None:
        """Start a host without instances"""
        self.instances: list[model.Instance] = []
        self.packages: list[model.Package] = []
        self.services: list[model.Service] = []
        self.catalogues: dict[str, Catalogue | None] = {}
        self.indexes: dict[str, Any] = {}
        self.brew_facts: dict[str, dict[str, Any]] = {}
        self.files: dict[str, dict[tuple[str, str], Sequence[tuple[str, bool]]]] = {}
        self.environment: dict[str, Any] = {}
        self.linkage: dict[str, Any] = {}
        self.extras: dict[str, Any] = {}

    def add(self, inst: model.Instance, *packages: model.Package, cat: Any = None, index: Any = None,
            **facts: Any) -> model.Instance:
        """Add an instance with its packages, and its catalogue or PortIndex

        @param inst      the instance
        @param packages  its packages
        @param cat       a Homebrew instance's catalogue, or None
        @param index     a MacPorts instance's PortIndex, or None
        @param facts     `HomebrewInventory` fields of a Homebrew instance, such as `root_owned`
        @returns         the instance
        """
        self.instances.append(inst)
        self.packages.extend(packages)
        self.catalogues[inst.prefix] = cat
        self.indexes[inst.prefix] = index
        self.brew_facts[inst.prefix] = facts
        return inst

    def bundle(self) -> scan.ScanBundle:
        """Return the host as a scan bundle, each instance with its inventory and catalogue or PortIndex

        @returns  a fresh bundle on each call
        """
        result = model.ScanResult(created="2026-11-13T10:00:00+1100", system=dict(SYSTEM),
                                  instances=list(self.instances), packages=list(self.packages),
                                  services=list(self.services), environment=dict(self.environment),
                                  linkage=dict(self.linkage), interpreter_extras=dict(self.extras))
        brew, ports = [], []
        for inst in self.instances:
            mine = [p for p in self.packages if p.instance_prefix == inst.prefix]
            if inst.manager is BREW:
                inv = brew_inventory.HomebrewInventory(instance_prefix=inst.prefix, packages=mine,
                                                       **self.brew_facts.get(inst.prefix, {}))
                brew.append((inst, self.catalogues.get(inst.prefix), inv))
            else:
                ports.append((inst, self.indexes.get(inst.prefix), PortsInventory(self.files.get(inst.prefix))))
        return scan.ScanBundle(result=result, brew=brew, ports=ports)


class FakeAsk:
    """The terminal of `Context` for `plan`: `answers` maps a question fragment to its answer

    `--yes` or no terminal takes the defaults, as `Context.choose` and `Context.confirm` do.
    """

    def __init__(self, answers: Mapping[str, str] | None = None, tty: bool = True, yes: bool = False,
                 confirm_answer: bool = False) -> None:
        """Keep the answers and the terminal's state

        @param answers         the answer to each question that holds a fragment, by fragment
        @param tty             whether a terminal is attached
        @param yes             whether `--yes` is given
        @param confirm_answer  the terminal's answer to every yes-or-no question
        """
        self.answers = dict(answers or {})
        self.tty = tty
        self.yes = yes
        self.confirm_answer = confirm_answer
        self.asked: list[str] = []

    def choose(self, question: str, choices: Sequence[str], default: str) -> str:
        """Answer a question with choices: the first fragment it holds gives the answer, else the default

        @param question  the question, recorded in `asked`
        @param choices   the answers it offers; a fragment's answer must be one of them
        @param default   the answer under `--yes`, without a terminal or without a matching fragment
        @returns         the answer
        """
        self.asked.append(question)
        if self.yes or not self.tty:
            return default
        for fragment, answer in self.answers.items():
            if fragment in question:
                assert answer in choices, (answer, choices)
                return answer
        return default

    def confirm(self, _question: str, default: bool = False) -> bool:
        """Answer a yes-or-no question: yes under `--yes`, else `confirm_answer` on a terminal

        @param _question  the question, never shown
        @param default    the answer without a terminal
        @returns          the answer
        """
        if self.yes:
            return True
        return self.confirm_answer if self.tty else default

    def confirm_terminal(self, _question: str) -> bool:
        """Decline a question only a terminal answers

        @param _question  the question, never shown
        @returns          False
        """
        return False


def options(target: Manager, target_prefix: str | None = None, **kw: Any) -> planner.PlanOptions:
    """Return the options of `brew-ports plan`

    @param target         the target manager
    @param target_prefix  `--target-prefix`, or None
    @param kw             other `PlanOptions` fields
    @returns              the options
    """
    return planner.PlanOptions(target=target, target_prefix=target_prefix, **kw)


def fake_runner(run_dir: state.RunDir, responses: Mapping[Any, Any] | None = None,
                environ: dict[str, str] | None = None) -> runner_mod.FakeRunner:
    """Return a quiet arm64 FakeRunner whose unknown commands exit 1

    @param run_dir    the run directory
    @param responses  the answers to known commands, by argv
    @param environ    variables added to alice's `HOME` and `USER`
    @returns          the runner
    """
    env = {"HOME": "/Users/alice", "USER": "alice"}
    env.update(environ or {})
    return runner_mod.FakeRunner(responses=responses or {}, default=runner_mod.FakeResponse(exit=1),
                                 console=QuietConsole(), environ=env, host_arch="arm64", run_dir=run_dir)


def blocker(code: str, prefix: str | None, *blocks: Blocks, severity: Severity = Severity.HIGH,
            subject: str | None = None) -> model.Issue:
    """Return a finding that blocks a plan in the given ways

    @param code      the finding's code
    @param prefix    the instance it concerns, or None
    @param blocks    what it blocks: `ANY`, `TARGET`, `UNINSTALL`, `CASKS` or `REMOVE`
    @param severity  the finding's severity
    @param subject   the package it concerns, or None
    @returns         the finding
    """
    return doctor._issue(code, severity, f"finding {code}", subject, prefix, evidence=["evidence"], blocks=blocks)


def run(state_dir: state.StateDir, bundle: scan.ScanBundle, opts: planner.PlanOptions, *, ask: Any = None,
        issues: Sequence[model.Issue] = (), environ: dict[str, str] | None = None) -> planner.PlanOutcome:
    """Run `planner.build` in a fresh run directory, with `doctor.detect_all` answering `issues`

    @param state_dir  the state directory the run directory goes into
    @param bundle     the scan
    @param opts       the plan's options
    @param ask        answers the terminal questions; None for a FakeAsk without a terminal
    @param issues     the findings
    @param environ    variables added to the runner's environment
    @returns          the outcome
    """
    run_dir = state_dir.new_run()
    runner = fake_runner(run_dir, environ=environ)
    with mock.patch("brew_ports.doctor.detect_all", return_value=list(issues)):
        return planner.build(bundle, opts, runner, ask=ask or FakeAsk(tty=False), state_dir=state_dir, run_dir=run_dir)


def actions(plan: model.Plan, number: int) -> list[model.Action]:
    """Return the actions of one phase of a plan

    @param plan    the plan
    @param number  the phase number, 0 to 8
    @returns       the actions; none when the plan lacks the phase
    """
    return next((p.actions for p in plan.phases if p.number == number), [])


class PlannerCase(TempDirTest):
    """A test host under the test's temporary directory

    `/opt/homebrew`, `/usr/local` and `/opt/local` live below it, so their identities are real.
    """

    def setUp(self) -> None:
        super().setUp()
        self.world = World()
        self.sd = self.state_dir()
        self.target: model.Instance | None = None

    @property
    def local(self) -> str:
        """Return the host's `/opt/local`

        @returns  the path below the temporary directory
        """
        return self.path("opt", "local")

    @property
    def usr_local(self) -> str:
        """Return the host's `/usr/local`

        @returns  the path below the temporary directory
        """
        return self.path("usr", "local")

    def brew_target(self, *packages: model.Package, payload: dict[str, Any] | None = None,
                    prefix: str | None = None, **facts: Any) -> model.Instance:
        """Add the Homebrew target with its packages and catalogue

        @param packages  the target's packages
        @param payload   a catalogue payload, or None for the fixture catalogue
        @param prefix    the target's prefix; None for the host's `/opt/homebrew`
        @param facts     `drivable` and `usability` for the instance, the rest for its inventory
        @returns         the target
        """
        own = {k: facts.pop(k) for k in list(facts) if k in ("drivable", "usability")}
        inst = instance(BREW, prefix or self.path("opt", "homebrew"), **own)
        self.target = self.world.add(inst, *packages, cat=catalogue(self.tmp, payload), **facts)
        return self.target

    def ports_target(self, *packages: model.Package, prefix: str | None = None, drop: Iterable[str] = (),
                     add: Iterable[Mapping[str, Any]] = (), **kw: Any) -> model.Instance:
        """Add the MacPorts target with its packages and the fixture PortIndex

        @param packages  the target's packages
        @param prefix    the target's prefix; None for the host's `/opt/local`
        @param drop      the names of PortIndex entries to leave out
        @param add       PortIndex entries to add
        @param kw        `Instance` fields
        @returns         the target
        """
        inst = instance(PORTS, prefix or self.local, **kw)
        self.target = self.world.add(inst, *packages, index=portindex(self.tmp, drop, add))
        return self.target

    def ports_source(self, *packages: model.Package, prefix: str | None = None, **kw: Any) -> model.Instance:
        """Add a MacPorts source with its packages

        @param packages  the source's packages
        @param prefix    the source's prefix; None for the host's `/opt/local`
        @param kw        `Instance` fields
        @returns         the source
        """
        return self.world.add(instance(PORTS, prefix or self.local, **kw), *packages)

    def brew_source(self, *packages: model.Package, prefix: str | None = None, **kw: Any) -> model.Instance:
        """Add a Homebrew source with its packages and the fixture catalogue

        @param packages  the source's packages
        @param prefix    the source's prefix; None for the host's `/usr/local`
        @param kw        `Instance` fields, and the inventory's `root_owned`, `outdated_formulae`, `kegs` and
                         `inventory_error`
        @returns         the source
        """
        facts = {k: kw.pop(k) for k in list(kw) if k in ("root_owned", "outdated_formulae", "kegs")}
        if "inventory_error" in kw:
            facts["inventory_error"] = kw["inventory_error"]
        inst = instance(BREW, prefix or self.usr_local, **kw)
        return self.world.add(inst, *packages, cat=catalogue(self.tmp), **facts)

    def plan(self, ask: Any = None, issues: Sequence[model.Issue] = (), environ: dict[str, str] | None = None,
             target_prefix: Any = "default", target: Manager | None = None, **kw: Any) -> planner.PlanOutcome:
        """Plan the host against its target

        @param ask            answers the terminal questions; None for a FakeAsk without a terminal
        @param issues         the findings
        @param environ        variables added to the runner's environment
        @param target_prefix  `--target-prefix`; `default` gives the target's prefix
        @param target         the target manager; None for the target's
        @param kw             other `PlanOptions` fields
        @returns              the outcome
        """
        prefix = self.target.prefix if target_prefix == "default" else target_prefix
        manager = target or self.target.manager
        return run(self.sd, self.world.bundle(), options(manager, prefix, **kw), ask=ask, issues=issues,
                   environ=environ)

    def assert_exit(self, outcome: planner.PlanOutcome, code: int) -> None:
        """Assert a plan's exit code, with its report as the failure message

        @param outcome  the plan's outcome
        @param code     the exit code expected
        """
        self.assertEqual(outcome.exit_code, code, "\n".join(outcome.report))

    @staticmethod
    def text(outcome: planner.PlanOutcome) -> str:
        """Return the report of an outcome as one text

        @param outcome  the plan's outcome
        @returns        the report lines, joined by newlines
        """
        return "\n".join(outcome.report)

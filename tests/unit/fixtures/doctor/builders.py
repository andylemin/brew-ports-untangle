"""Builders for the doctor, snapshot and servicectl tests

Scan bundles, services, launchctl output, fake health modules and command contexts.
"""

from __future__ import annotations

import argparse
import io
import os
import plistlib
import types
from collections.abc import Callable, Sequence
from typing import Any

from brew_ports import model, report, runner as runner_mod, scan, state
from brew_ports.context import Context
from brew_ports.env import services as env_services

HERE = os.path.dirname(os.path.abspath(__file__))
UID = 501
NOT_FOUND = runner_mod.FakeResponse(exit=113, stderr='Could not find service "x" in domain for user gui: 501\n')

SYSTEM = {"macos": "15.7", "host_arch": "arm64", "translated": False, "uid": UID, "user": "alice",
          "home": "/Users/alice", "developer_dir": "/Library/Developer/CommandLineTools", "clt_dir_exists": True,
          "clt_receipt": True}


def fixture(name: str) -> str:
    """Return the text of a fixture file beside this module

    @param name  the file's name
    @returns     its text
    """
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return fh.read()


class QuietConsole(report.Console):
    """A console that writes into memory, so a test reads what a command printed"""

    stream: io.StringIO
    err: io.StringIO

    def __init__(self) -> None:
        """Write both streams into memory"""
        super().__init__(stream=io.StringIO(), err=io.StringIO())

    @property
    def text(self) -> str:
        """Return everything written so far

        @returns  the output, then the warnings
        """
        return self.stream.getvalue() + self.err.getvalue()


def bundle(instances: Sequence[model.Instance] = (), *, packages: Sequence[model.Package] = (),
           services: Sequence[model.Service] = (), environment: dict[str, Any] | None = None,
           linkage: dict[str, Any] | None = None, extras: dict[str, Any] | None = None,
           system: dict[str, Any] | None = None) -> scan.ScanBundle:
    """Return a scan bundle of the given parts, its system facts `SYSTEM` with `system` on top

    @param instances    the instances the scan found
    @param packages     the scanned packages
    @param services     the scanned services
    @param environment  the environment analysis; None for an empty one
    @param linkage      the linkage scan; None for an empty one
    @param extras       the interpreter extras; None for none
    @param system       the facts that replace or add to `SYSTEM`
    @returns            the bundle
    """
    facts = dict(SYSTEM)
    facts.update(system or {})
    result = model.ScanResult(created="2026-11-13T10:00:00+1100", system=facts, instances=list(instances),
                              packages=list(packages), services=list(services), environment=environment or {},
                              linkage=linkage or {}, interpreter_extras=extras or {})
    return scan.ScanBundle(result=result)


def service(label: str, plist: str, prefix: str, package: str | None = None, *, kind: str | None = "formula",
            scope: str = "user", owned: bool = True, data_dirs: Sequence[str] = (), domain: str | None = None,
            loaded: bool = False, pid: int | None = None, exit_timeout_s: int = 20,
            program: str | None = None) -> model.Service:
    """Return a scanned service; a `pid` makes it a running one

    @param label           the launchd label
    @param plist           the plist's path
    @param prefix          the prefix of the instance it belongs to
    @param package         the package that owns it, or None
    @param kind            that package's kind, dropped without a package
    @param scope           `user` or `system`
    @param owned           whether a manager owns the job; False for the user's own
    @param data_dirs       the service's data directories
    @param domain          the launchd domain it is loaded in, or None
    @param loaded          whether launchd has it loaded
    @param pid             the pid of the running job, or None
    @param exit_timeout_s  the seconds it gets to exit after a stop
    @param program         the program it runs, or None
    @returns               the service
    """
    return model.Service(label=label, plist=plist, scope=scope, domain=domain, loaded=loaded, running=pid is not None,
                         pid=pid, exit_timeout_s=exit_timeout_s, owned=owned, data_dirs=list(data_dirs),
                         package=package, package_kind=kind if package else None, instance_prefix=prefix,
                         program=program)


def write_plist(path: str, label: str, program: str, **extra: Any) -> str:
    """Write a launchd plist that runs one program, making its directory

    @param path     the plist's path
    @param label    the job's label
    @param program  the program, the job's only argument
    @param extra    more top-level keys
    @returns        the path
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = {"Label": label, "ProgramArguments": [program]}
    data.update(extra)
    with open(path, "wb") as fh:
        plistlib.dump(data, fh)
    return path


def printed(domain: str, label: str, plist: str, program: str, pid: int | None = None) -> runner_mod.FakeResponse:
    """Return `launchctl print <domain>/<label>` output for a loaded job

    @param domain   the launchd domain
    @param label    the job's label
    @param plist    the plist path the output names
    @param program  the program the output names
    @param pid      the pid of the running job; None for a job that is not running
    @returns        the response
    """
    lines = ["%s/%s = {" % (domain, label), "\tactive count = 1", f"\tpath = {plist}",
             f"\tstate = {'running' if pid else 'not running'}", "", f"\tprogram = {program}",
             "\targuments = {", f"\t\t{program}", "\t}", ""]
    if pid:
        lines.append(f"\tpid = {pid}")
    lines.append("}")
    return runner_mod.FakeResponse(stdout="\n".join(lines) + "\n")


def print_key(domain: str, label: str):
    """Return the FakeRunner key of `launchctl print` for a job

    @param domain  the launchd domain
    @param label   the job's label
    @returns       the argv
    """
    return (env_services.LAUNCHCTL, "print", f"{domain}/{label}")


def bootout_key(domain: str, label: str, sudo: bool = False):
    """Return the FakeRunner key of `launchctl bootout` for a job

    @param domain  the launchd domain
    @param label   the job's label
    @param sudo    whether the bootout runs under `sudo -n`
    @returns       the argv
    """
    argv = (env_services.LAUNCHCTL, "bootout", f"{domain}/{label}")
    return ((runner_mod.SUDO, "-n", "--") + argv) if sudo else argv


class FakeClock:
    """A monotonic clock that `sleep` advances, so the waits for a service to stop take no time"""

    def __init__(self) -> None:
        """Start at 1000 s, with no sleep recorded"""
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        """Return the clock's time

        @returns  the seconds
        """
        return self.now

    def sleep(self, seconds: float) -> None:
        """Record a sleep and move the clock on by it

        @param seconds  the length of the sleep
        """
        self.sleeps.append(seconds)
        self.now += seconds


# Health modules ----------------------------------------------------------------------

def health_module(name: str, issues: Sequence[model.Issue] = (), *, terminal: Sequence[str] = (),
                  removes: dict[str, Any] | None = None, verified: dict[str, bool | None] | None = None,
                  repairs: Sequence[str] = (), repair: Callable[..., tuple[list[str], bool]] | None = None,
                  leaves: Callable[[str], list[model.Issue]] | None = None,
                  notes: Sequence[str] = ()) -> types.SimpleNamespace:
    """Return a stand-in for `homebrew.health` or `macports.health` with the agreed functions

    A name that ends in `macports.health` also gets `MANAGER_REPAIRS`, `manager_repair` and `recompute_leaves`;
    `calls` records the manager repairs and `recomputed` the prefixes whose leaves were recomputed.

    @param name      the name of the module it stands in for
    @param issues    the findings `detect` returns
    @param terminal  the names of the findings whose remedy needs an answer on a terminal
    @param removes   what each finding's remedy removes, by finding name; a kind alone means `(kind, subject)`
    @param verified  the post-check's answer, by finding name
    @param repairs   the `MANAGER_REPAIRS` of a MacPorts module
    @param repair    answers `manager_repair` in place of its one report line; None for that line
    @param leaves    answers `recompute_leaves` for a prefix; None for no leaves
    @param notes     the notes `detect` adds to the bundle
    @returns         the stand-in, for `sys.modules`
    """
    mod = types.SimpleNamespace(__name__=name, calls=[], recomputed=[])

    def detect(scan_bundle, _runner):
        scan_bundle.notes.extend(notes)
        return list(issues)

    def removes_package(issue):
        value = (removes or {}).get(issue.code)
        return (value, issue.subject) if isinstance(value, str) else value

    mod.detect = detect
    mod.needs_terminal_answer = lambda issue: issue.code in terminal
    mod.removes_package = removes_package
    mod.verify = lambda issue, runner, bundle: (verified or {}).get(issue.code)
    if name.endswith("macports.health"):
        mod.MANAGER_REPAIRS = tuple(repairs)

        def manager_repair(issue, runner, run_dir, environ, show, *, confirm):
            """Record the repair in `calls`, then answer with `repair`, else with one report line that it shows

            @param issue    the finding
            @param runner   the runner
            @param run_dir  the run directory, whose id is recorded
            @param environ  the environment
            @param show     prints a report line as it comes
            @param confirm  asks the user a question and returns the answer
            @returns        the report lines, and that the finding is gone
            """
            mod.calls.append((issue.code, run_dir.run_id))
            if repair:
                return repair(issue, runner, run_dir, environ, show, confirm=confirm)
            show(f"  repaired {issue.code}")
            return [f"repaired {issue.code}"], True

        def recompute_leaves(prefix, _runner, _bundle):
            mod.recomputed.append(prefix)
            return list(leaves(prefix)) if leaves else []
        mod.manager_repair = manager_repair
        mod.recompute_leaves = recompute_leaves
    return mod


def health_modules(brew: Sequence[model.Issue] = (), ports: Sequence[model.Issue] = (), **kw: Any) -> dict[str, Any]:
    """Return `sys.modules` entries for both health modules; `brew_<key>` and `ports_<key>` go to one of them

    @param brew   the findings of the Homebrew module
    @param ports  the findings of the MacPorts module
    @param kw     `health_module` arguments, each name prefixed with `brew_` or `ports_` for its module
    @returns      the two modules by module name
    """
    brew_kw = {k[5:]: v for k, v in kw.items() if k.startswith("brew_")}
    ports_kw = {k[6:]: v for k, v in kw.items() if k.startswith("ports_")}
    return {"brew_ports.homebrew.health": health_module("brew_ports.homebrew.health", brew, **brew_kw),
            "brew_ports.macports.health": health_module("brew_ports.macports.health", ports, **ports_kw)}


# The command context -------------------------------------------------------------------

def args(**kw: Any) -> argparse.Namespace:
    """Return the parsed command line of `brew-ports doctor`, its defaults overridden by `kw`

    @param kw  the argument values that differ from the defaults
    @returns   the namespace
    """
    values: dict[str, Any] = {"command": "doctor", "json": False, "deep": False, "rescan": False, "fix": False,
                              "yes": False, "dry_run": False}
    values.update(kw)
    return argparse.Namespace(**values)


class ScriptedContext(Context):
    """A `Context` whose terminal answers come from a list; the questions are kept in `asked`"""

    console: QuietConsole

    def __init__(self, state_dir: state.StateDir, answers: Sequence[bool], tty: bool, environ: dict[str, str],
                 **kw: Any) -> None:
        """Start a context that has asked nothing yet

        @param state_dir  the state directory
        @param answers    the terminal answers, in order; once they run out a question takes its default
        @param tty        whether the prompts can be answered
        @param environ    the environment
        @param kw         the argument values that differ from the defaults of `args`
        """
        super().__init__(args(**kw), QuietConsole(), state_dir, tty=tty, environ=environ)
        self.answers = list(answers)
        self.asked: list[str] = []

    def ask_terminal(self, question: str, default: bool) -> bool:
        """Record the question and give the next answer

        @param question  the question
        @param default   the answer once the list has run out
        @returns         the answer
        """
        self.asked.append(question)
        return self.answers.pop(0) if self.answers else default


def context(state_dir: state.StateDir, answers: Sequence[bool] = (), tty: bool = False, environ=None,
            **kw: Any) -> ScriptedContext:
    """Return a doctor context whose terminal answers come from `answers`; the questions are kept in `asked`

    @param state_dir  the state directory
    @param answers    the terminal answers, in order
    @param tty        whether the prompts can be answered
    @param environ    the environment; None for one whose `HOME` is `/Users/alice`
    @param kw         the argument values that differ from the defaults of `args`
    @returns          the context
    """
    return ScriptedContext(state_dir, answers, tty, environ or {"HOME": "/Users/alice"}, **kw)

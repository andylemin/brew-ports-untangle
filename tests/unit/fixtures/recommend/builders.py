"""Synthetic hosts for the recommend tests, below the test's directory, and the command context

The instances carry their real identities and the `fixtures/equiv` catalogue and PortIndex.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from brew_ports import model, runner as runner_mod, scan, state, system
from brew_ports.context import Context
from brew_ports.homebrew.catalogue import Catalogue
from brew_ports.model import Manager, Severity
from tests.unit.fixtures.doctor.builders import QuietConsole
from tests.unit.fixtures.equiv import builders as eq
from tests.unit.helpers import make_instance, make_package

SYSTEM = {"macos": "26.1", "host_arch": "arm64", "translated": False, "uid": 501, "user": "alice",
          "home": "/Users/alice"}


class Inventory:
    """A stand-in MacPortsInventory, which the bundle only closes"""

    def __init__(self) -> None:
        """Start open"""
        self.closed = False

    def close(self) -> None:
        """Record the close, which a test checks"""
        self.closed = True


def instance(manager: Manager, prefix: str, **kw: Any) -> model.Instance:
    """Return an instance whose prefix exists, with the directory's identity, which target choice compares

    @param manager  the instance's package manager
    @param prefix   the prefix, made when it is missing
    @param kw       `Instance` fields that override the defaults
    @returns        the instance
    """
    os.makedirs(prefix, exist_ok=True)
    kw.setdefault("identity", system.identity(prefix))
    return make_instance(manager, prefix, **kw)


def issue(code: str, prefix: str | None, severity: Severity = Severity.HIGH,
          evidence: Iterable[str] = ()) -> model.Issue:
    """Return a finding of an instance, without remedies and blocking nothing

    @param code      the finding's code
    @param prefix    the instance's prefix, which is also the subject; or None
    @param severity  the finding's severity
    @param evidence  the finding's evidence lines
    @returns         the finding
    """
    return model.Issue(code=code, severity=severity, title=f"{code} title", subject=prefix, instance_prefix=prefix,
                       evidence=list(evidence), remedies=[], auto_fix=False, confirm_each=False,
                       repairs_install=False, blocks=())


def brew_sh(prefix: str, oldest: str) -> str:
    """Write `<repository>/Library/Homebrew/brew.sh` with Homebrew's oldest supported macOS

    @param prefix  the repository
    @param oldest  the major version `HOMEBREW_MACOS_OLDEST_SUPPORTED` names
    @returns       the file's path
    """
    path = os.path.join(prefix, "Library", "Homebrew", "brew.sh")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('# - HOMEBREW_MACOS_OLDEST_SUPPORTED in .github/workflows/release.yml\n'
                 f'HOMEBREW_MACOS_OLDEST_SUPPORTED="{oldest}"\nHOMEBREW_MACOS_OLDEST_ALLOWED="11"\n')
    return path


class Host:
    """A Mac below `tmp`: Homebrew at `<tmp>/opt/homebrew`, MacPorts at `<tmp>/opt/local`, maybe `<tmp>/usr/local`

    `HOMEBREW_PREFIX` names `<tmp>/opt/homebrew` as the brew target, so the test host's own Homebrew never decides.
    """

    def __init__(self, tmp: str) -> None:
        """Lay out the host's prefixes and environment below a directory, without instances

        @param tmp  the test's temporary directory
        """
        self.tmp = tmp
        self.home = os.path.join(tmp, "home")
        self.brew_prefix = os.path.join(tmp, "opt", "homebrew")
        self.ports_prefix = os.path.join(tmp, "opt", "local")
        self.usr_local = os.path.join(tmp, "usr", "local")
        self.environ = {"HOME": self.home, "HOMEBREW_PREFIX": self.brew_prefix}
        self.system: dict[str, Any] = dict(SYSTEM)
        self.extras: dict[str, Any] = {}
        self.packages: list[model.Package] = []
        self.brew: list[Any] = []
        self.ports: list[Any] = []

    def add_brew(self, prefix: str | None = None, catalogue: Catalogue | None = None,
                 **kw: Any) -> model.Instance:
        """Add a Homebrew instance with a catalogue

        @param prefix     the prefix; None for `<tmp>/opt/homebrew`
        @param catalogue  the instance's catalogue; None for the fixture catalogue
        @param kw         `Instance` fields
        @returns          the instance
        """
        inst = instance(Manager.BREW, prefix or self.brew_prefix, **kw)
        self.brew.append((inst, catalogue if catalogue is not None else eq.catalogue(self.home), None))
        return inst

    def add_ports(self, index: bool = True, drop: Iterable[str] = (), add: Iterable[Mapping[str, Any]] = (),
                  **kw: Any) -> model.Instance:
        """Add the MacPorts instance at `<tmp>/opt/local`, with the fixture PortIndex or none

        @param index  whether the instance has a PortIndex
        @param drop   the names of PortIndex entries to leave out
        @param add    PortIndex entries to add
        @param kw     `Instance` fields
        @returns      the instance
        """
        inst = instance(Manager.PORTS, self.ports_prefix, **kw)
        self.ports.append((inst, eq.portindex(self.tmp, drop, add) if index else None, Inventory()))
        return inst

    def formula(self, name: str, prefix: str | None = None, **kw: Any) -> model.Package:
        """Add a formula with the fixture catalogue's version, homepage and executables when it has one

        @param name    the formula name
        @param prefix  the instance's prefix; None for `<tmp>/opt/homebrew`
        @param kw      `Package` fields that override the defaults
        @returns       the formula
        """
        prefix = prefix or self.brew_prefix
        try:
            pkg = eq.formula(name, prefix, **kw)
        except KeyError:
            pkg = make_package(name, "formula", prefix, **kw)
        self.packages.append(pkg)
        return pkg

    def cask(self, token: str, prefix: str | None = None, **kw: Any) -> model.Package:
        """Add a cask of a Homebrew instance

        @param token   the cask token
        @param prefix  the instance's prefix; None for `<tmp>/opt/homebrew`
        @param kw      `Package` fields that override the defaults
        @returns       the cask
        """
        pkg = eq.cask(token, prefix=prefix or self.brew_prefix, **kw)
        self.packages.append(pkg)
        return pkg

    def port(self, name: str, version: str = "1.0", **kw: Any) -> model.Package:
        """Add a port of the MacPorts instance

        @param name     the port name
        @param version  the port's version
        @param kw       `Package` fields that override the defaults, and the port's `revision`
        @returns        the port
        """
        pkg = eq.port(name, version, prefix=self.ports_prefix, **kw)
        self.packages.append(pkg)
        return pkg

    def bundle(self) -> scan.ScanBundle:
        """Return the host as a scan bundle, its services those of its packages

        @returns  a fresh bundle on each call
        """
        instances = [inst for inst, _, _ in self.brew] + [inst for inst, _, _ in self.ports]
        services = [svc for pkg in self.packages for svc in pkg.services]
        result = model.ScanResult(created="2026-11-13T10:00:00+1100", system=dict(self.system),
                                  instances=instances, packages=list(self.packages), services=services,
                                  environment={}, linkage={}, interpreter_extras=dict(self.extras))
        return scan.ScanBundle(result=result, brew=list(self.brew), ports=list(self.ports))


def context(state_dir: state.StateDir, host: Host, verbose: bool = False, **args: Any) -> Context:
    """Return the `Context` of `brew-ports recommend`, without a terminal

    @param state_dir  the state directory
    @param host       the host whose environment the context gets
    @param verbose    whether the console is verbose
    @param args       argument values over the defaults `json=False` and `rescan=False`
    @returns          the context
    """
    values: dict[str, Any] = {"command": "recommend", "json": False, "rescan": False}
    values.update(args)
    ctx = Context(argparse.Namespace(**values), QuietConsole(), state_dir, tty=False, environ=dict(host.environ))
    ctx.console.verbose = verbose
    return ctx


def runner_factory(made: list[runner_mod.FakeRunner]) -> Callable[[Context, state.RunDir], runner_mod.FakeRunner]:
    """Return a `make_runner` whose FakeRunner answers every probe with exit 0 and no output

    @param made  receives each runner the factory makes
    @returns     the factory
    """
    def make(ctx: Context, run_dir: state.RunDir) -> runner_mod.FakeRunner:
        fake = runner_mod.FakeRunner(default=runner_mod.FakeResponse(), console=ctx.console,
                                     environ=dict(ctx.environ), run_dir=run_dir)
        made.append(fake)
        return fake
    return make

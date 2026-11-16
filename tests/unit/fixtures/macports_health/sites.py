"""One synthetic MacPorts instance and the scan bundle around it, for the health tests

A prefix and registry from the MacPorts builders, its inventory, and the scan facts each test gives.
"""

from __future__ import annotations

import os
import sqlite3
import struct
import tempfile
from collections.abc import Mapping, Sequence
from typing import Any

from brew_ports import model, scan
from brew_ports.macports import inventory, locate, registry
from brew_ports.model import Manager, Service, Usability
from brew_ports.runner import ARCH, SUDO
from tests.unit.fixtures.macports.builders import FakePortIndex, fake_runner, make_prefix, make_registry, write
from tests.unit.helpers import make_instance

PLATFORM = ("darwin", 25)
ARM64, X86_64 = 0x0100000C, 0x01000007


def macho(path: str, *cpus: int, fat: bool = False) -> str:
    """Write a file with a Mach-O header: thin 64-bit little-endian, or a fat table

    @param path  the file
    @param cpus  the cputype of each architecture; a thin header takes the first
    @param fat   write a fat header with one entry per cputype
    @returns     the path
    """
    if fat:
        data = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(cpus))
        data += b"".join(struct.pack(">iiIII", cpu, 0, 4096 * (i + 1), 16, 12) for i, cpu in enumerate(cpus))
    else:
        data = b"\xcf\xfa\xed\xfe" + struct.pack("<i", cpus[0]) + b"\0" * 24
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def mode_executable(path: str) -> bool:
    """Return whether a path is a regular file with an execute bit, the mode bits deciding

    Not access(2): the test container's /tmp is noexec and refuses X_OK.

    @param path  the path
    @returns     True for a file with any execute bit set
    """
    return os.path.isfile(path) and bool(os.stat(path).st_mode & 0o111)


def sql(portdbpath: str, statement: str, *params: Any) -> None:
    """Change the live registry the way a `port` command would have

    @param portdbpath  the instance's `portdbpath`
    @param statement   the SQL statement
    @param params      the statement's parameters
    """
    conn = sqlite3.connect(registry.registry_path(portdbpath))
    try:
        conn.create_collation("VERSION", registry.vercmp)
        conn.execute(statement, params)
        conn.commit()
    finally:
        conn.close()


def service(label: str, plist: str, prefix: str, package: str | None, *, scope: str = "system",
            loaded: bool = False, program: str | None = None, owned: bool = True,
            domain: str | None = None) -> Service:
    """Return a launchd job of a MacPorts prefix, owned by one of its ports unless `owned` is false

    @param label    the job's label
    @param plist    the plist's path
    @param prefix   the instance's prefix
    @param package  the port that owns the plist, or None
    @param scope    `system` for a LaunchDaemon, `user` for a LaunchAgent
    @param loaded   whether launchctl found the job loaded
    @param program  the program the plist runs, or None
    @param owned    whether a port of the prefix owns the plist
    @param domain   the launchctl domain; None for `system` when the job is loaded, else for none
    @returns        the service
    """
    return Service(label=label, plist=plist, scope=scope, domain=domain or ("system" if loaded else None),
                   loaded=loaded, running=False, pid=None, exit_timeout_s=20, owned=owned, data_dirs=[],
                   package=package, package_kind="port" if owned else None, instance_prefix=prefix, program=program)


def port_argv(prefix: str, *args: str) -> list[str]:
    """Return the argv of `port -N <args>` under `arch -arm64`, as the builders of `actions` make it

    @param prefix  the MacPorts prefix
    @param args    the arguments after `port -N`
    @returns       the argv
    """
    return [ARCH, "-arm64", os.path.join(prefix, "bin", "port"), "-N"] + list(args)


def sudo_port(prefix: str, *args: str) -> tuple:
    """Return the argv the runner starts for an escalated `port` command

    @param prefix  the MacPorts prefix
    @param args    the arguments after `port -N`
    @returns       the argv after `sudo -n --`, as a tuple
    """
    return tuple([SUDO, "-n", "--"] + port_argv(prefix, *args))


class Site:
    """A MacPorts prefix at `<tmp>/site-<random>/opt/local` with its registry, so one test can build several"""

    def __init__(self, tmp: str, ports: Sequence[Mapping[str, Any]] = (), files: Sequence[Sequence[Any]] = (),
                 deps: Sequence[Any] = (), entries: Sequence[Any] | None = None, *, version: str = "2.12.7",
                 os_major: str = "25", binary: bool = True, conf: Mapping[str, str] | None = None,
                 registry_db: bool = True) -> None:
        """Make the prefix and, unless `registry_db` is false, its registry

        @param tmp          the test's temporary directory
        @param ports        the `ports` rows, as `port` builds them
        @param files        the `files` rows, `(id, path, actual_path, active, binary)` tuples
        @param deps         the `dependencies` rows, `(id, name)` pairs
        @param entries      the PortIndex entries; None for no PortIndex
        @param version      base's version
        @param os_major     the Darwin major base is built for
        @param binary       write `bin/port`
        @param conf         the macports.conf settings; None for the builders' defaults
        @param registry_db  create the registry; False leaves it to `fill`
        """
        self.tmp = tmp
        root = tempfile.mkdtemp(prefix="site-", dir=tmp)
        self.prefix = make_prefix(os.path.join(root, "opt", "local"), version=version, os_major=os_major,
                                  binary=binary, conf=conf)
        self.portdb = os.path.join(self.prefix, "var", "macports")
        self.version = version
        self.binary = binary
        self.entries = entries
        if registry_db:
            make_registry(self.portdb, schema="1.215", ports=ports, files=files, deps=deps)

    def fill(self, ports: Sequence[Mapping[str, Any]] = (), files: Sequence[Sequence[Any]] = (),
             deps: Sequence[Any] = ()) -> None:
        """Fill the registry of a site made with `registry_db=False`, once its images exist

        @param ports  the `ports` rows, as `port` builds them
        @param files  the `files` rows, `(id, path, actual_path, active, binary)` tuples
        @param deps   the `dependencies` rows, `(id, name)` pairs
        """
        make_registry(self.portdb, schema="1.215", ports=ports, files=files, deps=deps)

    def path(self, *parts: str) -> str:
        """Return a path inside the prefix

        @param parts  the path's components below the prefix
        @returns      the path
        """
        return os.path.join(self.prefix, *parts)

    def image(self, name: str, spec: str) -> str:
        """Write an image archive under `software/<name>/`

        @param name  the port's name
        @param spec  the version, as `<version>_<revision><variants>`
        @returns     the archive's path, the row's location
        """
        return write(os.path.join(self.portdb, "software", name, f"{name}-{spec}.darwin_25.arm64.tbz2"))

    def gone(self, name: str, spec: str) -> str:
        """Return the location of an image that does not exist

        @param name  the port's name
        @param spec  the version, as `<version>_<revision><variants>`
        @returns     the path the archive would have
        """
        return os.path.join(self.portdb, "software", name, f"{name}-{spec}.darwin_25.arm64.tbz2")

    def instance(self, **kw: Any) -> model.Instance:
        """Return the site's MacPorts instance, usable unless `kw` says otherwise

        @param kw  `Instance` fields that override the site's; a `usability` sets `drivable` too
        @returns   the instance
        """
        st = os.stat(self.prefix)
        usability = kw.pop("usability", Usability.USABLE)
        base: dict[str, Any] = {
            "prefix": self.prefix, "identity": (st.st_dev, st.st_ino), "spellings": (self.prefix,),
            "portdbpath": self.portdb, "arch": "arm64",
            "binary": os.path.join(self.prefix, "bin", "port") if self.binary else None,
            "version": self.version, "features": locate.features_for(self.version), "usability": usability,
            "drivable": usability is Usability.USABLE}
        base.update(kw)
        return make_instance(Manager.PORTS, **base)

    def bundle(self, inst: model.Instance | None = None, *, services: Sequence[Service] = (),
               linkage: dict[str, Any] | None = None, extras: dict[str, Any] | None = None,
               environment: dict[str, Any] | None = None, brew: bool = False, index: Any = "default",
               uid: int = 501) -> scan.ScanBundle:
        """Return the scan bundle of the site's instance: its inventory and the scan facts given

        @param inst         the instance; None for the site's usable one
        @param services     the launchd jobs of the scan
        @param linkage      the linkage scan
        @param extras       the interpreter-extras scan
        @param environment  the environment analysis
        @param brew         add a Homebrew instance at `<tmp>/opt/homebrew`
        @param index        the PortIndex; `default` for one of the site's entries, None for none
        @param uid          the user's uid in the scan
        @returns            the bundle
        """
        inst = inst or self.instance()
        if index == "default":
            index = FakePortIndex(self.entries) if self.entries is not None else None
        inv = inventory.inventory(fake_runner(self.tmp), inst, index, platform=PLATFORM)
        result = model.ScanResult(
            created="2026-11-13T00:00:00+0000", system={"uid": uid, "user": "alice"}, instances=[inst],
            packages=list(inv.packages), services=list(services), environment=environment or {},
            linkage=linkage or {}, interpreter_extras=extras or {})
        brew_entries: list[Any] = []
        if brew:
            brew_entries.append((make_instance(prefix=os.path.join(self.tmp, "opt", "homebrew")), None, None))
        return scan.ScanBundle(result=result, brew=brew_entries, ports=[(inst, index, inv)])

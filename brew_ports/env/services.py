"""The launchd services of both managers: each plist attributed by its program and matched to its loaded job"""

from __future__ import annotations

import dataclasses
import glob
import os
import plistlib
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any
from xml.parsers.expat import ExpatError

from .. import system
from ..model import Instance, Manager, Package, Service
from ..state import slug
from . import PrefixIndex

LAUNCHCTL = system.LAUNCHCTL
DEFAULT_EXIT_TIMEOUT = 20
BREW_LABEL_PREFIXES = ("sh.brew.", "homebrew.mxcl.")
MACPORTS_LABEL_PREFIX = "org.macports."
MACPORTS_ETC_DIRS = ("etc/LaunchDaemons", "etc/LaunchAgents")
SYSTEM_LAUNCH_AGENTS = "/Library/LaunchAgents"
SYSTEM_LAUNCH_DAEMONS = "/Library/LaunchDaemons"

OwnerOf = Callable[[str], str | None]


@dataclass
class LaunchDir:
    """A launchd directory the scan reads, and the managers whose ownership rules apply there"""

    path: str
    scope: str                      # "user" (agents) or "system" (daemons)
    rules: tuple[str, ...]          # whose ownership rules apply here: "brew", "ports"


@dataclass
class PlistInfo:
    """What a launchd plist says, or why it cannot be used"""

    path: str
    scope: str | None            # None for a plist inside a keg
    readable: bool
    error: str | None            # why the plist could not be used
    label: str | None
    program: str | None          # by `program_of`
    arguments: list[str]            # Program and ProgramArguments, strings only
    exit_timeout_s: int
    link_target: str | None      # os.path.realpath of a symlinked plist


@dataclass
class Job:
    """What `launchctl print <domain>/<label>` reports for a loaded job"""

    domain: str
    label: str
    path: str | None
    program: str | None
    arguments: list[str]
    state: str | None
    pid: int | None
    running: bool


@dataclass
class ServiceScan:
    """The result of a service scan: the services, every plist read, and what could not be attributed"""

    services: list[Service] = field(default_factory=list)
    plists: list[PlistInfo] = field(default_factory=list)       # every plist read
    unreadable: list[PlistInfo] = field(default_factory=list)   # listed; only a MacPorts startup item is attributed
    unattributed: list[str] = field(default_factory=list)       # no program, or a program under no prefix
    notes: list[str] = field(default_factory=list)

    def program(self, plist: str) -> str | None:
        """Return the program of a plist the scan read

        @param plist  the plist's path, as the scan found it
        @returns      the program; None for a plist the scan did not read or one that names no program
        """
        for info in self.plists:
            if info.path == plist:
                return info.program
        return None


def launch_dirs(home: str) -> list[LaunchDir]:
    """Return the launchd directories the scan reads, each with the managers whose rules apply there

    Homebrew's per-user agents and root daemons, MacPorts' startup items in `/Library/LaunchDaemons` and
    `/Library/LaunchAgents`.

    @param home  the user's home, which holds the per-user agents
    @returns     `~/Library/LaunchAgents`, `/Library/LaunchAgents` and `/Library/LaunchDaemons`
    """
    return [
        LaunchDir(os.path.join(home, "Library", "LaunchAgents"), "user", ("brew",)),
        LaunchDir(SYSTEM_LAUNCH_AGENTS, "user", ("ports",)),
        LaunchDir(SYSTEM_LAUNCH_DAEMONS, "system", ("brew", "ports")),
    ]


# Reading plists ------------------------------------------------------------------

def program_of(data: dict[str, Any]) -> str | None:
    """Return `Program` when it is a string, else the first element of `ProgramArguments` when that is one

    @param data  a parsed plist
    @returns     the program; None when neither key holds a string there
    """
    program = data.get("Program")
    if isinstance(program, str):
        return program
    args = data.get("ProgramArguments")
    if isinstance(args, list) and args and isinstance(args[0], str):
        return args[0]
    return None


def arguments_of(data: dict[str, Any]) -> list[str]:
    """Return the `Program` and `ProgramArguments` of a plist, the strings only

    @param data  a parsed plist
    @returns     `Program` when it is a string, then each string of `ProgramArguments`
    """
    out: list[str] = []
    program = data.get("Program")
    if isinstance(program, str):
        out.append(program)
    args = data.get("ProgramArguments")
    if isinstance(args, list):
        out.extend(a for a in args if isinstance(a, str))
    return out


def exit_timeout_of(data: dict[str, Any]) -> int:
    """Return the plist's `ExitTimeOut`, 20 when absent (or not a whole number of seconds)

    @param data  a parsed plist
    @returns     the seconds launchd waits after SIGTERM before it kills the job
    """
    value = data.get("ExitTimeOut")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return DEFAULT_EXIT_TIMEOUT


def _stem(path: str) -> str:
    """Return the file name of a plist without its `.plist` suffix, the label launchd usually knows it by

    @param path  a plist
    @returns     the file name, less the suffix when it has one
    """
    name = os.path.basename(path)
    return name[:-len(".plist")] if name.endswith(".plist") else name


def read_plist(path: str, scope: str | None = None) -> PlistInfo:
    """Read and parse a plist

    An unreadable or malformed one, or one whose root is not a dict, comes back with `readable=False` and its error.

    @param path   the plist
    @param scope  user or system, from its launchd directory; None for a keg's plist
    @returns      what the plist says
    """
    link: str | None = None
    try:
        if os.path.islink(path):
            link = os.path.realpath(path)
    except (OSError, ValueError):
        link = None

    def failed(error: str) -> PlistInfo:
        return PlistInfo(path, scope, False, error, None, None, [], DEFAULT_EXIT_TIMEOUT, link)

    # Malformed input escapes plistlib as more than InvalidFileException and ExpatError: a bad <date> as
    # AttributeError or TypeError, a top-level <key> as IndexError, a binary plist nested too deep as
    # RecursionError.
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except (plistlib.InvalidFileException, ExpatError, AttributeError, IndexError, OSError, RecursionError, TypeError,
            ValueError) as exc:
        return failed(f"{type(exc).__name__}: {exc}")
    if not isinstance(data, dict):
        return failed(f"the root object is a {type(data).__name__}, not a dict")
    label = data.get("Label") if isinstance(data.get("Label"), str) else None
    return PlistInfo(path, scope, True, None, label, program_of(data), arguments_of(data), exit_timeout_of(data),
                     link)


# launchctl print -----------------------------------------------------------------

def parse_print(text: str, domain: str, label: str) -> Job:
    """Parse the top-level `key = value` fields of `launchctl print` output and its `arguments` block

    A job is running when it has a `pid` or its `state` is `running`.

    @param text    the output of `launchctl print <domain>/<label>`
    @param domain  that domain
    @param label   that label
    @returns       the job's plist path, program, arguments, state and pid, and whether it runs
    """
    fields: dict[str, str] = {}
    arguments: list[str] = []
    depth = 0
    block: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.endswith("{"):
            depth += 1
            if depth == 2:
                block = line[:-1].rstrip(" =").strip()
            continue
        if line == "}":
            depth -= 1
            if depth < 2:
                block = None
            continue
        if depth == 1 and " = " in line:
            key, _, value = line.partition(" = ")
            fields.setdefault(key.strip(), value.strip())
        elif depth == 2 and block == "arguments":
            arguments.append(line)
    pid_text = fields.get("pid", "")
    pid = int(pid_text) if pid_text.isdigit() else None
    state = fields.get("state")
    program = fields.get("program") or (arguments[0] if arguments else None)
    return Job(domain, label, fields.get("path"), program, arguments, state, pid,
               pid is not None or state == "running")


def print_job(runner, domain: str, label: str) -> Job | None:
    """Probe `/bin/launchctl print <domain>/<label>`

    @param runner  the runner of the probe
    @param domain  a launchd domain: `system`, `gui/<uid>` or `user/<uid>`
    @param label   the job's label
    @returns       the job; None when launchd has no such job there (exit 113) or the probe fails
    """
    target = f"{domain}/{label}"
    action = system.probe(f"0.launchd.{slug(target)}.print", [LAUNCHCTL, "print", target],
                          f"launchd job {target}")
    try:
        result = runner.run(action)
    except OSError:
        return None
    if result.exit != 0:
        return None
    return parse_print(result.stdout(), domain, label)


def user_domains(uid: int) -> list[str]:
    """Return `gui/<uid>` (a console session), then `user/<uid>` (SSH, sudo)

    @param uid  the user's uid
    @returns    the user's two launchd domains, in that order
    """
    return [f"gui/{uid}", f"user/{uid}"]


def domains_for(scope: str | None, uid: int) -> list[str]:
    """Return the launchd domains a plist of a scope loads in

    @param scope  `system` for a daemon; any other scope is a user's agent
    @param uid    the user's uid
    @returns      `system` alone, or the user's domains
    """
    return ["system"] if scope == "system" else user_domains(uid)


class _Prober:
    """One `launchctl print` per (domain, label) for the whole scan"""

    def __init__(self, runner, uid: int) -> None:
        """Start with no job probed

        @param runner  the runner of the probes
        @param uid     the user's uid
        """
        self.runner = runner
        self.uid = uid
        self.cache: dict[tuple[str, str], Job | None] = {}

    def job(self, domain: str, label: str) -> Job | None:
        """Return the job `launchctl print` reports, probing each domain and label once

        @param domain  a launchd domain
        @param label   the job's label
        @returns       the job; None when it is not loaded there or the probe fails
        """
        key = (domain, label)
        if key not in self.cache:
            self.cache[key] = print_job(self.runner, domain, label)
        return self.cache[key]


def same_file(a: str | None, b: str | None) -> bool:
    """Return whether two program paths resolve to the same file (identity, else `realpath`)

    @param a  a program path, or None
    @param b  another, or None
    @returns  True for the same file; False when either is None or empty
    """
    if not a or not b:
        return False
    return system.same_path(a, b) or os.path.realpath(a) == os.path.realpath(b)


def _job_for(prober: _Prober, domains: Sequence[str], label: str, program: str | None,
             plist: str | None = None) -> Job | None:
    """Return the loaded job of a plist: the one whose reported program is the same file as the plist's own

    A plist whose program cannot be read (a dangling symlink) claims only the job loaded from that file.

    @param prober   the probes of the scan
    @param domains  the launchd domains to look in, in order
    @param label    the plist's label
    @param program  the plist's program; None when it cannot be read
    @param plist    the plist's path, which a job must be loaded from when the program is None
    @returns        the first job that matches; None when no domain holds one
    """
    for domain in domains:
        job = prober.job(domain, label)
        if job is None:
            continue
        if program is not None and same_file(job.program, program):
            return job
        if program is None and plist is not None and job.path and job.path == plist:
            return job
    return None


# Ownership and data directories --------------------------------------------------

def homebrew_formula(label: str, service_labels: dict[str, str]) -> str | None:
    """Return the formula of a Homebrew launchd label

    @param label           a catalogue `service_name_args` label, `sh.brew.<f>` or the legacy `homebrew.mxcl.<f>`
    @param service_labels  launchd labels to formulae, the catalogue's `service_name_args`
    @returns               the formula; None for a label of none of these forms
    """
    if label in service_labels:
        return service_labels[label]
    for prefix in BREW_LABEL_PREFIXES:
        if label.startswith(prefix) and len(label) > len(prefix):
            return label[len(prefix):]
    return None


def keg_rack(prefix: str, path: str) -> str | None:
    """Return the rack of the keg a path's realpath lies in, `<prefix>/Cellar/<rack>/<version>/...`

    The Cellar is compared by identity, so a case variant or the `/System/Volumes/Data` spelling matches.

    @param prefix  a Homebrew prefix
    @param path    a program's path
    @returns       the rack's name; None for a path in no keg of the prefix
    """
    cellar = system.identity(os.path.join(prefix, "Cellar"))
    current = os.path.realpath(path)
    while cellar is not None:
        rack = os.path.dirname(current)
        if rack == current:
            return None
        if system.identity(os.path.dirname(rack)) == cellar:
            return os.path.basename(rack)
        current = rack
    return None


def _under_etc(target: str, inst: Instance) -> bool:
    """Return whether a symlink target lies in `<prefix>/etc/LaunchDaemons/` or `<prefix>/etc/LaunchAgents/`

    Each directory is compared by identity, else as text in every spelling of the prefix.

    @param target  the realpath of a symlinked plist, which may be dangling
    @param inst    a MacPorts instance
    @returns       True when the target lies below one of the two directories
    """
    fold = None
    for sub in MACPORTS_ETC_DIRS:
        ident = system.identity(os.path.join(inst.prefix, sub))
        if ident is not None and system.lies_under(target, ident, include_self=False):
            return True
        bases = [os.path.join(s, sub) for s in (inst.spellings or (inst.prefix,))]
        if fold is None:
            fold = system.case_insensitive(inst.prefix) if os.path.exists(inst.prefix) else False
        if any(system.text_names_prefix(target, (b,), fold) and
               system.normalise_text_path(target, fold) != system.normalise_text_path(b, fold) for b in bases):
            return True
    return False


def _macports_owner(info: PlistInfo, inst: Instance, owner_of: OwnerOf) -> tuple[bool, str | None]:
    """Return whether MacPorts owns the plist, and its port

    Owned when it links into `<prefix>/etc/LaunchDaemons/` or `etc/LaunchAgents/`, or it or its target is
    a registered file; the port is that file's, else the `org.macports.<name>` label's name.

    @param info      the plist
    @param inst      the MacPorts instance whose program it runs
    @param owner_of  returns the port that registered a path
    @returns         whether MacPorts owns the plist, and the port; None for a port neither names
    """
    target = info.link_target
    linked = target is not None and _under_etc(target, inst)
    port = owner_of(info.path) or (owner_of(target) if target else None)
    if not linked and not port:
        return False, None
    if not port:
        label = info.label or _stem(info.path)
        if label.startswith(MACPORTS_LABEL_PREFIX) and len(label) > len(MACPORTS_LABEL_PREFIX):
            port = label[len(MACPORTS_LABEL_PREFIX):]
    return True, port


def _argument_paths(arg: str) -> list[str]:
    """Return the absolute paths a program argument names, as itself or after its `=`

    @param arg  a program argument, such as `/opt/local/var/db/x` or `--datadir=/opt/local/var/db/x`
    @returns    the normalised paths
    """
    out = []
    if arg.startswith("/"):
        out.append(arg)
    if "=" in arg:
        value = arg.partition("=")[2]
        if value.startswith("/"):
            out.append(value)
    return [os.path.normpath(p) for p in out]


def data_dirs(prefix: str, name: str | None, arguments: Sequence[str]) -> list[str]:
    """Return the existing data directories of a service

    They are `<prefix>/var/<name>`, `var/<name>@*`, `var/lib/<name>`, `var/db/<name>*`, and each directory
    below `<prefix>/var` that an argument names.

    @param prefix     the prefix of the service's instance
    @param name       the owning package; None leaves only the directories the arguments name
    @param arguments  the plist's program arguments
    @returns          the directories, each once, in the order found
    """
    out: list[str] = []
    if name:
        base, n = glob.escape(prefix), glob.escape(name)
        patterns = (os.path.join(base, "var", n), os.path.join(base, "var", n + "@*"),
                    os.path.join(base, "var", "lib", n), os.path.join(base, "var", "db", n),
                    os.path.join(base, "var", "db", n + "*"))
        for pattern in patterns:
            for path in sorted(glob.glob(pattern)):
                if os.path.isdir(path) and path not in out:
                    out.append(path)
    var = system.identity(os.path.join(prefix, "var"))
    if var is not None:
        for arg in arguments:
            for path in _argument_paths(arg):
                if path not in out and os.path.isdir(path) and system.lies_under(path, var, include_self=False):
                    out.append(path)
    return out


# The scan ------------------------------------------------------------------------

def _service(info: PlistInfo, label: str, scope: str, job: Job | None, *, owned: bool, package: str | None,
             kind: str | None, inst: Instance) -> Service:
    """Return the service of one plist, with its data directories

    @param info     the plist
    @param label    the launchd label
    @param scope    user or system
    @param job      the loaded launchd job, or None when it is not loaded
    @param owned    whether a package of the instance owns the plist
    @param package  the owning package, or None
    @param kind     formula or port; None when no package owns the plist
    @param inst     the instance the plist belongs to
    @returns        the service
    """
    return Service(label=label, plist=info.path, scope=scope, domain=job.domain if job else None,
                   loaded=job is not None, running=bool(job and job.running), pid=job.pid if job else None,
                   exit_timeout_s=info.exit_timeout_s, owned=owned,
                   data_dirs=data_dirs(inst.prefix, package, info.arguments), package=package,
                   package_kind=kind, instance_prefix=inst.prefix, program=info.program)


class _Scan:
    """One service scan: the plists of the launchd directories, then the jobs loaded from keg plists"""

    def __init__(self, runner, instances: Sequence[Instance], service_labels: dict[str, str] | None,
                 owner_of: OwnerOf | None, uid: int, *, racks: dict[str, dict[str, str]] | None = None) -> None:
        """Start a scan with an empty result

        @param runner          the runner of the `launchctl print` probes
        @param instances       the instances whose programs the plists may run
        @param service_labels  launchd labels to formulae, the catalogue's `service_name_args`; None for none
        @param owner_of        returns the port that registered a path; None attributes no file
        @param uid             the user's uid, for the launchd domains
        @param racks           each Homebrew prefix's racks, each to its installed formula; None for none
        """
        self.index = PrefixIndex(instances)
        self.labels = dict(service_labels or {})
        self.racks = dict(racks or {})
        self.owner_of: OwnerOf = owner_of or (lambda path: None)
        self.uid = uid
        self.prober = _Prober(runner, uid)
        self.claimed: set[tuple[str, str]] = set()
        self.result = ServiceScan()

    def directory(self, d: LaunchDir) -> None:
        """Read every plist of a launchd directory into the result

        A plist whose path or registry lookup fails is recorded as unreadable; any other error, an interrupt
        among them, ends the scan.

        @param d  the launchd directory
        """
        pattern = os.path.join(glob.escape(os.path.expanduser(d.path)), "*.plist")
        for path in sorted(glob.glob(pattern)):
            info = read_plist(path, d.scope)
            self.result.plists.append(info)
            try:
                svc = self.directory_plist(info, d)
            except (OSError, ValueError, sqlite3.Error) as exc:
                # A program path the file system rejects, or a registry copy that fails, skips the plist.
                info.readable, info.error = False, f"{type(exc).__name__}: {exc}"
                if info not in self.result.unreadable:
                    self.result.unreadable.append(info)
                svc = None
            if svc is not None:
                self.result.services.append(svc)

    def directory_plist(self, info: PlistInfo, d: LaunchDir) -> Service | None:
        """Return the service a plist of a launchd directory describes

        @param info  the plist
        @param d     its launchd directory
        @returns     the service; None when no instance runs its program, or for an unreadable plist that is
                     no MacPorts startup item
        """
        if not info.readable:
            self.result.unreadable.append(info)
            return self.dangling_startup_item(info, d) if "ports" in d.rules else None
        inst = self.index.owner(info.program) if info.program else None
        if inst is None:
            self.result.unattributed.append(info.path)   # no program, or one under no known prefix
            return None
        label = info.label or _stem(info.path)
        owned, package, kind = False, None, None
        if "brew" in d.rules and inst.manager is Manager.BREW:
            package = self.brew_formula(info, inst)
            owned, kind = package is not None, ("formula" if package else None)
        if not owned and "ports" in d.rules and inst.manager is Manager.PORTS:
            owned, package = _macports_owner(info, inst, self.owner_of)
            kind = "port" if owned else None
        job = _job_for(self.prober, domains_for(d.scope, self.uid), label, info.program)
        if job is not None:
            self.claimed.add((job.domain, label))
        return _service(info, label, d.scope, job, owned=owned, package=package, kind=kind, inst=inst)

    def brew_formula(self, info: PlistInfo, inst: Instance) -> str | None:
        """Return the formula of a Homebrew plist: its label's, else the one whose keg holds the program's realpath

        The keg decides only when the label names no formula installed in the instance, as for a job started
        under a renamed formula's old name.

        @param info  a readable plist whose program the instance owns
        @param inst  the Homebrew instance
        @returns     the formula; None for a label that is not Homebrew's
        """
        package = homebrew_formula(_stem(info.path), self.labels)
        racks = self.racks.get(inst.prefix, {})
        if package is None or package in racks.values() or not info.program:
            return package
        rack = keg_rack(inst.prefix, info.program)
        return racks.get(rack, package) if rack else package

    def dangling_startup_item(self, info: PlistInfo, d: LaunchDir) -> Service | None:
        """Attribute a dangling symlink into a MacPorts `etc/LaunchDaemons/` or `etc/LaunchAgents/` to its instance

        It cannot be read, yet its link alone makes it an owned startup item.

        @param info  the unreadable plist
        @param d     its launchd directory
        @returns     the service; None when the plist links into no MacPorts prefix
        """
        if info.link_target is None:
            return None
        for inst in self.index.instances:
            if inst.manager is Manager.PORTS and _under_etc(info.link_target, inst):
                owned, port = _macports_owner(info, inst, self.owner_of)
                label = _stem(info.path)
                job = _job_for(self.prober, domains_for(d.scope, self.uid), label, None, plist=info.path)
                if job is not None:
                    self.claimed.add((job.domain, label))
                return _service(info, label, d.scope, job, owned=owned, package=port, kind="port", inst=inst)
        return None

    def keg_plists(self, packages: Iterable[Package]) -> dict[str, list[tuple[Instance, Package, PlistInfo]]]:
        """Read the plist at the top of every installed formula's keg (`opt/<f>`, else `Cellar/<f>/<version>`)

        @param packages  the installed packages; only Homebrew formulae are read
        @returns         the instance, formula and plist of each readable keg plist, by label
        """
        out: dict[str, list[tuple[Instance, Package, PlistInfo]]] = {}
        for pkg in packages:
            if pkg.kind != "formula":
                continue
            inst = self.index.by_prefix(pkg.instance_prefix)
            if inst is None or inst.manager is not Manager.BREW:
                continue
            opt = os.path.join(inst.prefix, "opt", pkg.name)
            keg = opt if os.path.isdir(opt) else os.path.join(inst.prefix, "Cellar", pkg.name, pkg.version)
            for path in sorted(glob.glob(os.path.join(glob.escape(keg), "*.plist"))):
                info = read_plist(path)
                self.result.plists.append(info)
                if not info.readable:
                    self.result.unreadable.append(info)
                    continue
                out.setdefault(info.label or _stem(path), []).append((inst, pkg, info))
        return out

    def keg_jobs(self, packages: Iterable[Package]) -> None:
        """Probe every keg label, since `brew services run <f>` loads the keg's own plist

        A job no directory plist claimed is attributed by the program `launchctl print` reports, so a
        target's running job is never taken for the source's.

        @param packages  the installed packages
        """
        kegs = self.keg_plists(packages)
        for label in sorted(kegs):
            for domain in user_domains(self.uid) + ["system"]:
                if (domain, label) in self.claimed:
                    continue
                job = self.prober.job(domain, label)
                if job is None:
                    continue
                owner = self.index.owner(job.program) if job.program else None
                match = [entry for entry in kegs[label] if entry[0] is owner]
                if not match:
                    self.result.notes.append(f"launchd job {domain}/{label} runs {job.program}, "
                                             "which no plist of that label accounts for")
                    continue
                inst, pkg, info = match[0]
                self.claimed.add((domain, label))
                scope = "system" if domain == "system" else "user"
                self.result.services.append(_service(info, label, scope, job, owned=True, package=pkg.name,
                                                     kind="formula", inst=inst))


def inspect(runner, instances: Sequence[Instance], packages: Iterable[Package], *,
            service_labels: dict[str, str] | None, owner_of: OwnerOf | None, home: str, uid: int,
            directories: Sequence[LaunchDir] | None = None,
            brew_services: dict[str, list[dict[str, Any]]] | None = None,
            racks: dict[str, dict[str, str]] | None = None) -> ServiceScan:
    """Classify every plist of both managers: an owned service, a user's own job, or unattributed

    @param runner          the runner that probes `launchctl print`
    @param instances       the instances whose programs the plists may run
    @param packages        the installed packages, whose keg plists are read
    @param service_labels  launchd labels to formulae, the catalogue's `service_name_args`
    @param owner_of        maps a registered file to its port; None attributes no file
    @param home            the user's home, for the user's launchd directories
    @param uid             the user's uid, for the launchd domains
    @param directories     the launchd directories to read; None reads the standard ones
    @param brew_services   prefix to `brew services list --json`, which only adds notes
    @param racks           each Homebrew prefix's racks, each to the formula the inventory matched it to; None for
                           none, so no plist is attributed by its keg
    @returns               the scan
    """
    packages = list(packages)
    scan = _Scan(runner, instances, service_labels, owner_of, uid, racks=racks)
    for d in directories if directories is not None else launch_dirs(home):
        scan.directory(d)
    scan.keg_jobs(packages)
    for prefix, entries in sorted((brew_services or {}).items()):
        scan.result.notes.extend(corroborate(scan.result.services, prefix, entries))
    return scan.result


def collect(runner, instances: Sequence[Instance], packages: Iterable[Package], *,
            service_labels: dict[str, str] | None, owner_of: OwnerOf | None, home: str, uid: int,
            **kwargs: Any) -> list[Service]:
    """Return the services of `inspect`: owned ones and users' own jobs

    @param runner          the runner that probes `launchctl print`
    @param instances       the instances whose programs the plists may run
    @param packages        the installed packages, whose keg plists are read
    @param service_labels  launchd labels to formulae, the catalogue's `service_name_args`
    @param owner_of        maps a registered file to its port; None attributes no file
    @param home            the user's home, for the user's launchd directories
    @param uid             the user's uid, for the launchd domains
    @param kwargs          the other options of `inspect`
    @returns               the services
    """
    return inspect(runner, instances, packages, service_labels=service_labels, owner_of=owner_of, home=home, uid=uid,
                   **kwargs).services


def refresh(runner, service: Service, uid: int) -> Service:
    """Return the service with `domain`, `loaded`, `running` and `pid` probed afresh, matched as in the scan

    @param runner   the runner of the `launchctl print` probes
    @param service  a service of a scan; its recorded domain is probed as well as those of its scope
    @param uid      the user's uid, for the launchd domains
    @returns        a copy with those four fields current
    """
    info = read_plist(service.plist, service.scope)
    domains = domains_for(service.scope, uid)
    if service.domain and service.domain not in domains:
        domains.insert(0, service.domain)
    program = info.program if info.readable else None
    job = _job_for(_Prober(runner, uid), domains, service.label, program,
                   plist=service.plist if program is None else None)
    return dataclasses.replace(service, loaded=job is not None, running=bool(job and job.running),
                               pid=job.pid if job else None, domain=job.domain if job else None)


def corroborate(services: Sequence[Service], prefix: str, entries: Iterable[Any]) -> list[str]:
    """Note each started service file of one instance that the plist scan did not attribute to that instance

    @param services  the services of the plist scan
    @param prefix    the Homebrew instance's prefix
    @param entries   the instance's `brew services list --json` output
    @returns         one note per such file
    """
    ours = {os.path.realpath(s.plist) for s in services
            if s.owned and s.instance_prefix == prefix and s.package_kind == "formula"}
    notes = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        path, status = entry.get("file"), entry.get("status")
        if isinstance(path, str) and path and status not in (None, "none") and os.path.realpath(path) not in ours:
            notes.append(f"brew services ({prefix}) lists {path} for {entry.get('name')} ({status}); "
                         "the plist scan did not attribute it there")
    return notes


def attach(services: Iterable[Service], packages: Iterable[Package]) -> None:
    """Append each owned service to its package's `services`

    A port installed in several versions gets it on its active row.

    @param services  the services of the scan
    @param packages  the inventoried packages, which receive their services
    """
    by_key: dict[tuple[str, str, str], Package] = {}
    for pkg in packages:
        key = (pkg.instance_prefix, pkg.kind, pkg.name)
        if key not in by_key or (pkg.active and not by_key[key].active):
            by_key[key] = pkg
    for svc in services:
        if svc.owned and svc.package and svc.package_kind:
            owner = by_key.get((svc.instance_prefix, svc.package_kind, svc.package))
            if owner is not None and svc not in owner.services:
                owner.services.append(svc)

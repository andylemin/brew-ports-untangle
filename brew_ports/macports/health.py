"""MacPorts health checks: the `ports-` findings of `doctor`, their post-checks and the manager repairs

`detect` probes only through the runner; its `port` actions come from `actions`, and a note may name one as text.
"""

from __future__ import annotations

import dataclasses
import functools
import hashlib
import os
import re
import sqlite3
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .. import progress, snapshot, system
from ..env import linkage as env_linkage, services as env_services
from ..homebrew import locate as brew_locate
from ..model import Action, Blocks, Instance, Issue, OnFailure, Package, Service, Severity, Usability
from ..report import MOVE_OUT, NAMES_SHOWN, at, counted, limited, offered, some, tilde, typed
from ..runner import RM, ActionFailed
from ..state import RunDir, slug
from . import (actions, bootstrap, inventory as mp_inventory, locate, macho, portindex as mp_portindex, registry,
               strays)

TAR = system.TAR
DU = system.DU
USR_LOCAL_CELLAR = "/usr/local/Cellar"
PORTINDEX_MAX_AGE_S = 30 * 86400
EVIDENCE_LIMIT = 50

MANAGER_REPAIRS = ("ports-platform-mismatch", "ports-built-for-other-os", "ports-registry-schema-update",
                   "ports-cannot-run")

SEVERITY = {
    "ports-diagnose-warning": Severity.MEDIUM, "ports-platform-mismatch": Severity.HIGH,
    "ports-damaged-registry": Severity.HIGH, "ports-missing-file": Severity.HIGH,
    "ports-missing-image": Severity.HIGH, "ports-inactive-versions": Severity.LOW,
    "ports-unrequested-leaf": Severity.INFO, "ports-obsolete-port": Severity.INFO,
    "ports-built-for-other-os": Severity.HIGH, "ports-broken-binaries": Severity.HIGH,
    "ports-unregistered-file": Severity.MEDIUM, "ports-stale-portindex": Severity.LOW,
    "ports-macports-user": Severity.MEDIUM, "ports-registry-busy": Severity.CRITICAL,
    "ports-disk-usage": Severity.INFO, "ports-dangling-plist": Severity.LOW,
    "ports-missing-selection": Severity.LOW, "ports-no-binary-archives": Severity.INFO,
    "ports-not-on-path": Severity.LOW, "ports-usr-local-cellar": Severity.INFO,
    "ports-registry-schema-update": Severity.HIGH, "ports-replaced-port": Severity.INFO,
    "ports-cannot-run": Severity.HIGH, "ports-no-registry": Severity.HIGH,
}

MIGRATE_TAKES_LONG = ("`port migrate` builds MacPorts itself again for this Mac, switches every port off, builds again "
                      "the ports made for another macOS or processor, and switches the others back on. That can "
                      "take a long time.")

# Unregistered files: the directories walked, and the ones whose regular files may be removed.
STRAY_TOPS = ("bin", "sbin", "lib", "include", "libexec", "Library/Frameworks",
              "share/man", "share/info", "share/doc", "share/aclocal", "share/pkgconfig")
REMOVABLE_TOPS = ("bin", "sbin", "lib", "include")
LEFT_ALONE = {      # why an unregistered file is not offered for removal -> what one such file is, what several are
    "link": ("is a link", "are links"),
    "special": ("is no ordinary file", "are no ordinary files"),
    "outside": ("lies outside bin, sbin, lib and include", "lie outside bin, sbin, lib and include"),
    "select": ("is where `port select` puts a link", "are where `port select` puts links"),
    "extras": ("belongs to a package that pip, gem, cpan or npm installed",
               "belong to packages that pip, gem, cpan or npm installed"),
}

# The settings packages.macports.org builds its archives with.
ARCHIVE_DEFAULTS = (("prefix", "/opt/local"), ("applications_dir", "/Applications/MacPorts"),
                    ("frameworks_dir", "/opt/local/Library/Frameworks"))
_TRUE_WORDS = ("yes", "true", "on", "1")


@dataclass
class _Site:
    """One MacPorts instance of the bundle, with what every detector needs"""

    instance: Instance
    index: Any                       # PortIndex, a stand-in with `get`, or None
    inv: mp_inventory.MacPortsInventory
    host_arch: str
    homebrew_present: bool
    running: locate.Platform
    default_prefix: str
    run_path: str | None

    @property
    def prefix(self) -> str:
        """Return the prefix of the site's instance

        @returns  the prefix as located
        """
        return self.instance.prefix

    @property
    def at(self) -> str:
        """Return the installation as the report names it

        @returns  such as `MacPorts at /opt/local`
        """
        return at(self.instance)

    @property
    def drivable(self) -> bool:
        """Return whether the tool drives `port` on the site's instance

        @returns  True only for a usable instance
        """
        return self.instance.drivable


# Building issues and remedies --------------------------------------------------------

def action_id(code: str, subject: str, step: str) -> str:
    """Return a remedy's id, built from the finding's code, the subject's slug and the step

    The id is `doctor.<finding code>.<subject slug>.<step>`; an uninstall step carries the version of its
    registry row, so two rows of one port never share an id.

    @param code     the finding's code
    @param subject  the port, path, label or group the remedy acts on
    @param step     the remedy's step
    @returns        the id
    """
    return f"doctor.{code}.{slug(subject)}.{step}"


def _qualified(code: str, prefix: str | None, remedies: Sequence[Action]) -> list[Action]:
    """Return the remedies with the instance in their ids, beside the port, label or group they act on

    The same port in two MacPorts prefixes then never shares an id.

    @param code      the finding's code
    @param prefix    the instance's prefix; None leaves the ids as they are
    @param remedies  the remedies
    @returns         the remedies, each id under the finding's `doctor.` head carrying the prefix's slug once
    """
    if not prefix:
        return list(remedies)
    head, tag = f"doctor.{code}.", slug(prefix)
    return [dataclasses.replace(a, action_id=head + tag + "." + a.action_id[len(head):])
            if a.action_id.startswith(head) and tag not in a.action_id else a
            for a in remedies]


def _issue(code: str, subject: str | None, prefix: str | None, evidence: Sequence[str],
           remedies: Sequence[Action] = (), *, title: str, confirm_each: bool = False,
           repairs_install: bool = False, blocks: Sequence[Blocks] = ()) -> Issue:
    """Build a `ports-` finding at its `SEVERITY`

    A flag holds only when the issue has a remedy the tool runs: a manual one is printed, never applied.

    @param code             the finding's code, which gives its severity
    @param subject          the port, path, label or group the finding is about, or None
    @param prefix           the instance's prefix, or None
    @param evidence         the evidence lines
    @param remedies         the remedies, in the order they are applied
    @param title            a sentence that names what the finding is about
    @param confirm_each     `doctor --fix` applies the remedies after a per-item prompt
    @param repairs_install  apply phase 2 applies them when the subject is a plan target or its dependency
    @param blocks           the plan contexts the finding blocks
    @returns                the finding
    """
    runs = any(not a.manual for a in remedies)
    return Issue(code=code, severity=SEVERITY[code], title=title, subject=subject,
                 instance_prefix=prefix, evidence=list(evidence), remedies=_qualified(code, prefix, remedies),
                 auto_fix=False,
                 confirm_each=confirm_each and runs, repairs_install=repairs_install and runs,
                 blocks=tuple(blocks))


def _note(code: str, subject: str, step: str, text: str) -> Action:
    """Build a remedy the user carries out: a `note` action, printed with its finding, never run

    @param code     the finding's code
    @param subject  the port, path, label or group the remedy acts on
    @param step     the remedy's step
    @param text     what the user does
    @returns        the note
    """
    return Action(action_id=action_id(code, subject, step), kind="note", argv=[], sudo=False, description=text,
                  manual=True)


def _built(code: str, subject: str, build: Callable[[], list[Action]]) -> list[Action]:
    """Return the remedies of `build`, or a note of why there are none when it refuses a name or variant

    @param code     the finding's code
    @param subject  the port, path, label or group the remedies act on
    @param build    builds the remedies; ValueError for a registry name or variant `actions.py` refuses
    @returns        the remedies, or the note
    """
    try:
        return build()
    except ValueError as exc:
        return [_note(code, subject, "refused", "brew-ports offers no fix: MacPorts' record holds a name or variant "
                      f"that brew-ports does not pass to `port` ({exc}).")]


def _port_remedies(site: _Site, code: str, subject: str, build: Callable[[], list[Action]]) -> list[Action]:
    """Return the remedies of `build` for a drivable instance only

    On an undrivable one, `port` runs only for the manager repairs and the creation of a missing registry.

    @param site     the instance's site
    @param code     the finding's code
    @param subject  the port, path, label or group the remedies act on
    @param build    builds the remedies
    @returns        the remedies, or a note of why there are none
    """
    if not site.drivable:
        return [_note(code, subject, "no-port", f"No fix until the `port` command of {site.at} runs.")]
    return _built(code, subject, build)


def _digest(text: str) -> str:
    """Return a short digest of a text, for the id of a remedy that only its text tells apart

    @param text  the text
    @returns     the first eight hex digits of its SHA-1
    """
    return hashlib.sha1(text.encode("utf-8", "surrogateescape")).hexdigest()[:8]


def _display_instance(inst: Instance, host_arch: str) -> Instance:
    """Return the instance with `<prefix>/bin/port` as its binary and an architecture

    A remedy that runs after the base package procedure has installed that binary builds its command on it.

    @param inst       the MacPorts instance
    @param host_arch  the architecture for an instance that has none
    @returns          a copy of the instance
    """
    return dataclasses.replace(inst, binary=inst.binary or os.path.join(inst.prefix, "bin", "port"),
                               arch=inst.arch or host_arch)


def _at_default(inst: Instance, default_prefix: str) -> bool:
    """Return whether the instance is the one at `/opt/local`, the only prefix the base package installs to

    The prefixes compare by identity, or by text when the default prefix cannot be stat'ed.

    @param inst            the MacPorts instance
    @param default_prefix  the default MacPorts prefix
    @returns               True for the instance there
    """
    ident = system.identity(default_prefix)
    if ident is not None and tuple(inst.identity) == ident:
        return True
    return os.path.normpath(inst.prefix) == os.path.normpath(default_prefix)


def _by_name(packages: Sequence[Package]) -> list[tuple[str, list[Package]]]:
    """Group the registry rows by lower-cased port name, in registry order

    @param packages  the packages of the registry rows
    @returns         each lower-cased name and its rows
    """
    groups: dict[str, list[Package]] = {}
    for pkg in packages:
        groups.setdefault(pkg.name.lower(), []).append(pkg)
    return list(groups.items())


def _loaded_items(services: Sequence[Service], prefix: str) -> set[str]:
    """Return the lower-cased names of this instance's ports whose owned startup item is loaded

    @param services  the host's launchd jobs
    @param prefix    the instance's prefix
    @returns         the port names
    """
    return {svc.package.lower() for svc in services
            if svc.owned and svc.package and svc.package_kind == "port" and svc.instance_prefix == prefix
            and svc.loaded}


def _port(inst: Instance, *args: str) -> str:
    """Return a `port` command of an installation as the user would type it, under sudo

    @param inst  the MacPorts instance
    @param args  the arguments after `port`
    @returns     the command, by the bare name `port` only where typing that name runs this installation's
    """
    return typed([inst.binary or os.path.join(inst.prefix, "bin", "port"), *args], True)


def _procedure_notes(code: str, inst: Instance, then: str = "") -> list[Action]:
    """Build the notes that offer the signed MacPorts installer over the instance

    @param code  the finding's code
    @param inst  the MacPorts instance at `/opt/local`
    @param then  what `doctor --fix` does after the installer, such as `, then runs ...`; with it, the ports are
                 built again
    @returns     what `doctor --fix` does, and what that takes
    """
    ports = ("The installer keeps your ports; `port migrate` then builds them again." if then
             else "Your installed ports stay.")
    return [_note(code, inst.prefix, "base-package",
                  offered(f"installs MacPorts over {inst.prefix} again from its official signed installer{then}")),
            _note(code, inst.prefix, "base-package-needs",
                  "It downloads the installer from MacPorts' releases, checks its signature and runs it with your "
                  f"password (sudo). The installer adds MacPorts to the PATH in your shell's login files. {ports}")]


def _release_of(inst: Instance) -> str:
    """Return an instance's version as the words that follow `MacPorts` in a sentence

    @param inst  the MacPorts instance
    @returns     such as ` 2.9.3`; empty for an instance whose version is not known
    """
    return f" {inst.version}" if inst.version else ""


def _too_old(inst: Instance) -> str:
    """Return what to do about a MacPorts that has no `port migrate`

    @param inst  the MacPorts instance
    @returns     the fix line, with the two commands for the user
    """
    return (f"Fix: MacPorts{_release_of(inst)} is too old for `port migrate`. Run `{_port(inst, 'selfupdate')}`, "
            f"then `{_port(inst, '-N', 'migrate', '--all')}`.")


def _source_build_note(code: str, inst: Instance, migrate: bool = False) -> Action:
    """Build the note telling the user to build base from source, the only way for a prefix other than `/opt/local`

    @param code     the finding's code
    @param inst     the MacPorts instance
    @param migrate  whether `port migrate` is to follow, which only a current MacPorts has
    @returns        the note
    """
    then = f", then run `{_port(inst, '-N', 'migrate', '--all')}`" if migrate else ""
    return _note(code, inst.prefix, "source-build",
                 "Fix: MacPorts' installer installs to /opt/local only, so build the current MacPorts from source "
                 f"with `./configure --prefix={inst.prefix}`{then}.")


# Diagnose warnings -------------------------------------------------------------------

_DIAG_START = re.compile(r"^(?:Warning|Error): ")
_MISSING_FILE = re.compile(r"^Warning: couldn't find file '(?P<file>.*)' for port '(?P<port>[^']*)'")


def parse_diagnose(text: str) -> list[str]:
    """Return the warnings of `port diagnose --quiet` output

    A `Warning: ` or `Error: ` line starts one, indented lines continue it, and any other line ends it.

    @param text  the output
    @returns     each warning, its lines joined with spaces
    """
    entries: list[list[str]] = []
    current: list[str] | None = None
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if _DIAG_START.match(raw):
            current = [raw.strip()]
            entries.append(current)
        elif current is not None and raw[:1].isspace():
            current.append(raw.strip())
        else:
            current = None
    return [" ".join(parts) for parts in entries]


def _diagnose_issue(site: _Site, subject: str, text: str, evidence: Sequence[str], *, title: str, fix: str) -> Issue:
    """Build a `ports-diagnose-warning` finding

    @param site      the instance's site
    @param subject   the port the warning names, or the prefix
    @param text      the warning, which tells the ids of two findings about one subject apart
    @param evidence  the evidence lines
    @param title     the finding's title
    @param fix       what to do about it
    @returns         the finding
    """
    return _issue("ports-diagnose-warning", subject, site.prefix, evidence,
                  [_note("ports-diagnose-warning", subject, "warning-" + _digest(text), fix)], title=title)


def _diagnose_warnings(site: _Site, runner, notes: list[str]) -> list[Issue]:
    """Report each warning of `port -N diagnose --quiet` (drivable instances only)

    Base warns once per missing file; those warnings fold into one issue per port, which `detect` drops
    when the missing-file finding of that port has the detail and the fix.

    @param site    the instance's site
    @param runner  the runner that runs `port diagnose`
    @param notes   receives a line when the probe is skipped or times out
    @returns       one finding per warning, or per port for the missing-file warnings
    """
    if not site.drivable:
        notes.append(f"What `port diagnose` reports about {site.at}: its `port` command cannot run")
        return []
    result = runner.run(actions.diagnose(site.instance, site.host_arch, f"0.ports.{slug(site.prefix)}.diagnose"))
    if result.timed_out:
        notes.append(f"`port diagnose` of {site.at} ran out of time, so some of its warnings may be missing")
    warnings: list[str] = []
    for text in parse_diagnose(result.stderr()) + parse_diagnose(result.stdout()):
        if text not in warnings:
            warnings.append(text)
    order: list[tuple[str, str]] = []
    folded: dict[str, list[tuple[str, str]]] = {}
    for text in warnings:
        match = _MISSING_FILE.match(text)
        if match is None:
            order.append(("text", text))
            continue
        port = match.group("port")
        if port not in folded:
            folded[port] = []
            order.append(("port", port))
        folded[port].append((match.group("file"), text))
    out = []
    for kind, value in order:
        if kind == "text":
            out.append(_diagnose_issue(site, site.prefix, value, [value],
                                       title="MacPorts' own check, `port diagnose`, reports a problem",
                                       fix="brew-ports offers no fix: what to do about it, if anything, is in "
                                           "MacPorts' message."))
            continue
        items = folded[value]
        out.append(_diagnose_issue(site, value, items[0][1], limited([f for f, _ in items], EVIDENCE_LIMIT),
                                   title=f"`port diagnose` cannot find {counted(len(items), 'file')} of {value}",
                                   fix=f"Fix: `{_port(site.instance, '-f', 'deactivate', value)}`, then "
                                       f"`{_port(site.instance, '-f', 'activate', value)}`, as MacPorts advises."))
    return out


# The instance itself --------------------------------------------------------------------

def _migrate_remedies(site: _Site, code: str, inst: Instance) -> list[Action]:
    """Build `sudo port -N migrate --all`, then `sudo port -N sync`

    @param site  the instance's site
    @param code  the finding's code
    @param inst  the MacPorts instance
    @returns     the two remedies, and the note on how long the first one takes
    """
    return [actions.migrate_all(inst, site.host_arch, action_id(code, site.prefix, "migrate")),
            actions.sync(inst, site.host_arch, action_id(code, site.prefix, "sync")),
            _note(code, site.prefix, "long", MIGRATE_TAKES_LONG)]


def _platform_mismatch(site: _Site) -> list[Issue]:
    """Report base built for another platform: `PLATFORM_MISMATCH`, or another `os_major` in its autoconf

    Base 2.10.0 and newer migrates; an older base is replaced first, by the base package at `/opt/local`
    and elsewhere by a manual source build.

    @param site  the instance's site
    @returns     the finding, or none
    """
    code, inst = "ports-platform-mismatch", site.instance
    built = site.inv.autoconf.get("os_major") or ""
    other_os = built.isdigit() and int(built) != site.running[1]
    if inst.usability is not Usability.PLATFORM_MISMATCH and not other_os:
        return []
    mismatch = inst.usability is Usability.PLATFORM_MISMATCH
    evidence = [inst.usability_detail] if mismatch and inst.usability_detail else []
    if other_os:
        title = "MacPorts itself was built for another version of macOS"
        evidence = evidence or [f"MacPorts was built for {system.macos_name(int(built))}; this Mac runs "
                                f"{system.macos_name(site.running[1])}"]
    elif site.host_arch == "arm64" and inst.arch == "x86_64":
        title = "MacPorts itself is an Intel build, and this Mac is Apple Silicon"
        evidence = [line for line in evidence if line != locate.INTEL_ON_ARM]
    else:
        title = "MacPorts itself does not match this Mac"
    if "migrate" in inst.features and inst.binary:
        remedies = _built(code, site.prefix, lambda: _migrate_remedies(site, code, inst))
    elif _at_default(inst, site.default_prefix):
        shown = _display_instance(inst, site.host_arch)

        def reinstall() -> list[Action]:
            migrate = actions.migrate_all(shown, site.host_arch, action_id(code, site.prefix, "migrate"))
            return (_procedure_notes(code, inst, f", then runs `{typed(migrate.argv, migrate.sudo)}`")
                    + [actions.sync(shown, site.host_arch, action_id(code, site.prefix, "sync")), migrate,
                       _note(code, site.prefix, "long", MIGRATE_TAKES_LONG)])
        remedies = _built(code, site.prefix, reinstall)
    else:
        remedies = [_source_build_note(code, inst, migrate=True)]
    remedies.append(_note(code, site.prefix, "leaving", MOVE_OUT % site.prefix))
    return [_issue(code, site.prefix, site.prefix, evidence, remedies, confirm_each=True, blocks=(Blocks.TARGET,),
                   title=title)]


def _damaged_registry(site: _Site) -> list[Issue]:
    """Report a failed registry backup, whatever `usability` says, listing the image archives

    A busy registry is its own finding; there is no remedy.

    @param site  the instance's site
    @returns     the finding, or none
    """
    code, inst = "ports-damaged-registry", site.instance
    if inst.inventory_known or locate.registry_busy(inst):
        return []
    evidence = [_plain(inst.inventory_error)] if inst.inventory_error else []
    archives = site.inv.image_archives
    software = os.path.join(inst.portdbpath or "", "software")
    evidence.append(f"{counted(len(archives), 'port')} left files in {software}: {some(sorted(archives))}"
                    if archives else f"no port left files in {software}")
    record = registry.registry_path(inst.portdbpath or "")
    note = _note(code, site.prefix, "restore", "brew-ports offers no fix: without that record it can tell neither "
                 f"which ports are installed nor how to uninstall them. Restore {record} from a backup, or install "
                 "what you need with Homebrew yourself.")
    return [_issue(code, site.prefix, site.prefix, evidence, [note], blocks=(Blocks.TARGET, Blocks.REMOVE),
                   title="MacPorts' record of installed ports cannot be read")]


_WAITED = re.compile(r"^no progress for (\d+) s\b")
_PYTHON_ERROR = re.compile(r"^\w+Error: (?:\[Errno \d+\] )?")


def _plain(error: str | None) -> str:
    """Return an inventory error in the reader's words

    @param error  the instance's `inventory_error`, or None
    @returns      what happened to MacPorts' record, without the name of the check's outcome or of a Python error
    """
    head, sep, rest = (error or "").partition(": ")
    labels = registry.STATUS_LABELS
    if not sep or head not in labels.values():
        return error or ""
    if head == labels["missing"]:
        return f"{rest.partition('; ')[0]} is missing, but files of ports are still installed"
    if head == labels["busy"]:
        waited = _WAITED.match(rest)
        return (f"brew-ports waited {waited.group(1)} seconds for it to let go of the record" if waited
                else "the record kept changing while brew-ports read it")
    if head == labels["unreadable"]:
        return "the record cannot be read: " + _PYTHON_ERROR.sub("", rest)
    return f"the record's file is damaged: {rest}"


def _registry_busy(site: _Site) -> list[Issue]:
    """Report a `RegistryBusy` backup: no progress for 30 s, or a registry that keeps changing while it is copied

    @param site  the instance's site
    @returns     the finding, or none
    """
    if not locate.registry_busy(site.instance):
        return []
    code = "ports-registry-busy"
    return [_issue(code, site.prefix, site.prefix, [_plain(site.instance.inventory_error)],
                   [_note(code, site.prefix, "wait", "Fix: wait until that command ends, then run `brew-ports "
                                                     "doctor` again.")],
                   blocks=(Blocks.ANY,), title="Another `port` command is running, so MacPorts' record of installed "
                                               "ports cannot be read")]


def _registry_schema_update(site: _Site) -> list[Issue]:
    """Report `READONLY_REGISTRY`; one root run of `port version` updates the schema

    @param site  the instance's site
    @returns     the finding, or none
    """
    code, inst = "ports-registry-schema-update", site.instance
    if inst.usability is not Usability.READONLY_REGISTRY:
        return []
    remedies = _built(code, site.prefix, lambda: [
        actions.version(inst, site.host_arch, action_id(code, site.prefix, "version"), sudo=True)])
    return [_issue(code, site.prefix, site.prefix, [inst.usability_detail] if inst.usability_detail else [],
                   remedies, confirm_each=True, blocks=(Blocks.TARGET,),
                   title="MacPorts was updated and needs one run as root to bring its record of installed ports "
                         "up to date")]


def _cannot_run(site: _Site) -> list[Issue]:
    """Report `MISSING_BINARY` or `CANNOT_RUN` while the registry backup has rows

    At `/opt/local` the remedy is the base package procedure (the registry survives) and `sync`;
    elsewhere a manual source build.

    @param site  the instance's site
    @returns     the finding, or none
    """
    code, inst = "ports-cannot-run", site.instance
    if inst.usability not in (Usability.MISSING_BINARY, Usability.CANNOT_RUN) or not site.inv.rows:
        return []
    evidence = ([inst.usability_detail] if inst.usability_detail else []) + [
        f"MacPorts' record lists {counted(len({row.name.lower() for row in site.inv.rows}), 'installed port')}"]
    if _at_default(inst, site.default_prefix):
        shown = _display_instance(inst, site.host_arch)
        remedies = _built(code, site.prefix, lambda: _procedure_notes(code, inst) + [
            actions.sync(shown, site.host_arch, action_id(code, site.prefix, "sync"))])
    else:
        remedies = [_source_build_note(code, inst)]
    remedies.append(_note(code, site.prefix, "leaving", MOVE_OUT % site.prefix))
    return [_issue(code, site.prefix, site.prefix, evidence, remedies, confirm_each=True, blocks=(Blocks.TARGET,),
                   title=f"The `port` command of {site.at} is missing or does not start")]


def _no_registry(site: _Site) -> list[Issue]:
    """Report `NO_REGISTRY` with the inventory known to be empty (`locate.known_empty`)

    A lost registry with ports still installed is a damaged registry, and nothing recreates its file.

    @param site  the instance's site
    @returns     the finding, or none
    """
    code, inst = "ports-no-registry", site.instance
    if inst.usability is not Usability.NO_REGISTRY or not inst.inventory_known:
        return []
    remedies = _built(code, site.prefix, lambda: [
        actions.version(inst, site.host_arch, action_id(code, site.prefix, "version"), sudo=True)])
    return [_issue(code, site.prefix, site.prefix, [inst.usability_detail] if inst.usability_detail else [],
                   remedies, confirm_each=True, blocks=(Blocks.TARGET,),
                   title="MacPorts is installed but has never run as root, so it has no record of installed ports "
                         "yet")]


# Registry rows ---------------------------------------------------------------------------

def _version(pkg: Package) -> str:
    """Return the version of a registry row as the report writes it

    @param pkg  the row's package
    @returns    the version, revision and variants, such as `1.7.1_0+universal`
    """
    return pkg.spec_args[1].lstrip("@")


def _rebuild(site: _Site, code: str, pkg: Package) -> list[Action]:
    """Return the missing-image remedy of an active row

    A note for a `replaced_by` port, `upgrade -n` for an outdated one (its description naming the version
    change), else `upgrade_forced`.

    @param site  the instance's site
    @param code  the finding's code
    @param pkg   the active row's package
    @returns     the remedies, or a note of why there are none
    """
    name = pkg.name
    if pkg.renamed_to:
        return [_note(code, name, "replaced", f"The fix is with the finding that MacPorts replaced {name} with "
                      f"{pkg.renamed_to}.")]
    entry = site.index.get(name) if site.index is not None else None
    if pkg.outdated and entry is not None:
        new = f"{entry.version}_{entry.revision}"

        def upgrade() -> list[Action]:
            act = actions.upgrade(site.instance, site.host_arch, action_id(code, name, "upgrade"), name,
                                  homebrew_present=site.homebrew_present, no_deps=True)
            return [dataclasses.replace(act,
                                        description=f"upgrade {name} from {pkg.version} to {new} in {site.prefix}")]
        return _port_remedies(site, code, name, upgrade)
    return _port_remedies(site, code, name, lambda: [actions.upgrade_forced(
        site.instance, site.host_arch, action_id(code, name, "rebuild"), name, pkg.requested_variants,
        homebrew_present=site.homebrew_present)])


def _uninstall_row(site: _Site, code: str, pkg: Package) -> list[Action]:
    """Return the `sudo port -N uninstall <spec_args>` of one row

    @param site  the instance's site
    @param code  the finding's code
    @param pkg   the row's package
    @returns     the remedy, or a note of why there is none
    """
    return _port_remedies(site, code, pkg.name, lambda: [actions.uninstall(
        site.instance, site.host_arch, action_id(code, pkg.name, "uninstall" + pkg.spec_args[1]), [pkg.spec_args],
        on_failure=OnFailure.STOP)])


def _stat_active_files(files: Sequence[registry.FileRow]) -> tuple[list[str], int]:
    """Return the active files missing on disk, and how many files could not be checked

    A file is missing when `os.lstat` raises `FileNotFoundError` or `NotADirectoryError`; any other error,
    such as a `PermissionError` below a 0700 directory, leaves it unchecked.

    @param files  a row's registered files
    @returns      the missing paths, and the number of files left unchecked
    """
    missing: list[str] = []
    unchecked = 0
    progress.count(len(files))
    for row in files:
        if not row.active:
            continue
        try:
            os.lstat(row.location)
        except (FileNotFoundError, NotADirectoryError):
            missing.append(row.location)
        except OSError:
            unchecked += 1
    return missing, unchecked


def _missing_file(site: _Site, loaded: set[str]) -> list[Issue]:
    """Report, per active row, the registered active files missing on disk

    The remedy is `-f deactivate` and `-f activate`, then `load` when its startup item was loaded (the
    deactivation stops it); with the image missing too, the missing-image remedy.

    @param site    the instance's site
    @param loaded  the lower-cased names of the ports whose startup item is loaded
    @returns       one finding per active row with a missing file
    """
    code = "ports-missing-file"
    out = []
    progress.step(f"MacPorts {site.prefix}: checking registered files")
    progress.counting("files")
    for pkg in site.inv.packages:
        if not pkg.active:
            continue
        missing, unchecked = _stat_active_files(site.inv.files(pkg))
        if not missing:
            continue
        evidence = limited(missing, EVIDENCE_LIMIT)
        if unchecked:
            evidence.append(f"{counted(unchecked, 'more file')} could not be looked at")
        if not pkg.receipt_ok:
            evidence.append("MacPorts' stored copy of this version is missing too")
            remedies = _rebuild(site, code, pkg)
        else:
            remedies = _port_remedies(site, code, pkg.name, functools.partial(_reactivate, site, pkg, loaded))
        out.append(_issue(code, pkg.name, site.prefix, evidence, remedies, confirm_each=True, repairs_install=True,
                          title=f"{counted(len(missing), 'file')} of {pkg.name} {_version(pkg)} "
                                f"{'is' if len(missing) == 1 else 'are'} missing"))
    return out


def _reactivate(site: _Site, pkg: Package, loaded: set[str]) -> list[Action]:
    """Build the forced deactivate and activate of a row, then `load` when its startup item is loaded

    @param site    the instance's site
    @param pkg     the active row's package
    @param loaded  the lower-cased names of the ports whose startup item is loaded
    @returns       the remedies
    """
    code, inst, arch, name = "ports-missing-file", site.instance, site.host_arch, pkg.name
    out = [actions.deactivate(inst, arch, action_id(code, name, "deactivate"), pkg.spec_args),
           actions.activate(inst, arch, action_id(code, name, "activate"), pkg.spec_args)]
    if name.lower() in loaded:
        out.append(actions.load(inst, arch, action_id(code, name, "load"), name))
    return out


def _missing_image(site: _Site) -> list[Issue]:
    """Report each row without its image: an active one gets `_rebuild`, an inactive one its uninstall

    An image that is gone can never be activated again.

    @param site  the instance's site
    @returns     one finding per row without its image
    """
    code = "ports-missing-image"
    out = []
    for pkg in site.inv.packages:
        if pkg.receipt_ok:
            continue
        row = site.inv.row_for(pkg)
        evidence = [f"it should be {row.location}" if row is not None and row.location
                    else "MacPorts recorded no place for it"]
        if pkg.active:
            out.append(_issue(code, pkg.name, site.prefix, evidence, _rebuild(site, code, pkg), confirm_each=True,
                              repairs_install=True,
                              title=f"MacPorts' stored copy of {pkg.name} {_version(pkg)} is missing"))
        else:
            evidence.append("without it, MacPorts can never switch that version on again")
            out.append(_issue(code, pkg.name, site.prefix, evidence, _uninstall_row(site, code, pkg),
                              confirm_each=True, title=f"MacPorts' stored copy of the unused version "
                                                       f"{_version(pkg)} of {pkg.name} is missing"))
    return out


def _by_version(one: Package, other: Package) -> int:
    """Compare two rows of a port by version, as MacPorts orders versions

    @param one    a row's package
    @param other  another row's package
    @returns      a negative number when the first is the older, a positive one when it is the newer, else 0
    """
    return registry.vercmp(one.version or "", other.version or "")


def _inactive_versions(site: _Site) -> list[Issue]:
    """Report each inactive row of a port that also has an active one, with the uninstall of that row

    Imaged-only ports are listed as deactivated on purpose, never offered for removal; rows without
    their image belong to the missing-image finding.

    @param site  the instance's site
    @returns     one finding per inactive row, and one per imaged-only port
    """
    code = "ports-inactive-versions"
    out = []
    for _, pkgs in _by_name(site.inv.packages):
        inactive = [p for p in pkgs if not p.active and p.receipt_ok]
        if not inactive:
            continue
        active = next((p for p in pkgs if p.active), None)
        if active is None:
            name = inactive[0].name
            # With several stored versions, `port activate` takes the version too.
            newest = sorted(inactive, key=functools.cmp_to_key(_by_version))[-1]
            note = _note(code, name, "activate", "Nothing to do. To use it again: "
                         f"{_port(site.instance, 'activate', *newest.spec_args)}" if site.drivable
                         else "Nothing to do.")
            out.append(_issue(code, name, site.prefix, [f"stored: {', '.join(_version(p) for p in inactive)}"],
                              [note], title=f"{name} is installed but switched off"))
            continue
        for pkg in inactive:
            out.append(_issue(code, pkg.name, site.prefix, [f"in use: {_version(active)}"],
                              _uninstall_row(site, code, pkg), confirm_each=True,
                              title=f"Version {_version(pkg)} of {pkg.name} is stored but not in use"))
    return out


def _unrequested_leaf(site: _Site) -> list[Issue]:
    """Report the active rows with `requested = 0` and no dependents, each with its uninstall

    Inactive rows belong to the inactive-versions finding; imaged-only ports are never offered for removal.

    @param site  the instance's site
    @returns     one finding per leaf
    """
    code = "ports-unrequested-leaf"
    out = []
    for pkg in site.inv.leaves():
        if not pkg.active:
            continue
        out.append(_issue(code, pkg.name, site.prefix, [f"installed: {_version(pkg)}"],
                          _uninstall_row(site, code, pkg), confirm_each=True,
                          title=f"{pkg.name} came in as a dependency, and no installed port needs it"))
    return out


def _obsolete_port(site: _Site) -> list[Issue]:
    """Report the installed names absent from the PortIndex; nothing without one

    @param site  the instance's site
    @returns     one finding per name
    """
    if site.index is None:
        return []
    out = []
    for _, pkgs in _by_name(site.inv.packages):
        if pkgs[0].catalogue_present:
            continue
        name = pkgs[0].name
        note = _note("ports-obsolete-port", name, "note", "Nothing to do. A move out of this MacPorts still looks "
                     "for a replacement.")
        out.append(_issue("ports-obsolete-port", name, site.prefix, [], [note],
                          title=f"{name} is installed, but MacPorts' package list does not have it"))
    return out


def _replaced_port(site: _Site) -> list[Issue]:
    """Report each active port whose PortIndex entry has `replaced_by`

    `sudo port -N [-t] upgrade --no-rev-upgrade <name>` installs the replacement.

    @param site  the instance's site
    @returns     one finding per replaced port
    """
    code = "ports-replaced-port"
    out = []
    for pkg in site.inv.packages:
        if not pkg.active or not pkg.renamed_to:
            continue

        def build(pkg: Package = pkg) -> list[Action]:
            act = actions.upgrade(site.instance, site.host_arch, action_id(code, pkg.name, "upgrade"), pkg.name,
                                  homebrew_present=site.homebrew_present)
            return [dataclasses.replace(act, description=f"replace {pkg.name} with {pkg.renamed_to} in {site.prefix}")]
        out.append(_issue(code, pkg.name, site.prefix, [], _port_remedies(site, code, pkg.name, build),
                          confirm_each=True, title=f"MacPorts replaced {pkg.name} with {pkg.renamed_to}"))
    return out


# Ports built for another Darwin major -----------------------------------------------------

def _other_major(os_major: str | None, running_major: int) -> bool:
    """Return whether a recorded `os_major` is a number other than the running major

    `any`, which base records for `platforms any` and `{darwin any}` ports, never counts.

    @param os_major       the row's `os_major`, or None
    @param running_major  the running Darwin major
    @returns              True for another number
    """
    return os_major is not None and os_major.isdigit() and int(os_major) != running_major


def _built_for_other_os(site: _Site) -> list[Issue]:
    """Report the active rows built for another Darwin major while `usability == USABLE`

    The remedy is `sudo port -N migrate --all`, with the records and report of a platform-mismatch
    repair, then `sync`.

    @param site  the instance's site
    @returns     the finding, or none
    """
    code, inst = "ports-built-for-other-os", site.instance
    if inst.usability is not Usability.USABLE:
        return []
    odd: dict[str, list[str]] = {}
    for pkg, row in zip(site.inv.packages, site.inv.rows):
        if pkg.active and _other_major(row.os_major, site.running[1]):
            odd.setdefault(locate.release(row.os_platform or "", row.os_major or ""), []).append(pkg.name)
    if not odd:
        return []
    count = sum(len(names) for names in odd.values())
    evidence = [f"this Mac runs {system.macos_name(site.running[1])}"]
    evidence += [f"built for {release}: {some(names)}" for release, names in odd.items()]
    if "migrate" in inst.features:
        remedies = _built(code, site.prefix, lambda: _migrate_remedies(site, code, inst))
    else:
        remedies = [_note(code, site.prefix, "manual", _too_old(inst))]
    remedies.append(_note(code, site.prefix, "leaving", "A move out of this MacPorts does not need this repair."))
    return [_issue(code, site.prefix, site.prefix, evidence, remedies, confirm_each=True, blocks=(Blocks.TARGET,),
                   title=f"{counted(count, 'port')} {'was' if count == 1 else 'were'} built for another version of "
                         "macOS")]


# Broken binaries -----------------------------------------------------------------------

def _wanted_archs(host_arch: str, inst: Instance) -> set[str]:
    """Return the architectures a binary of the instance must have: the host's and the instance's

    @param host_arch  the host's architecture
    @param inst       the MacPorts instance
    @returns          the architectures that are known
    """
    return {a for a in (host_arch, inst.arch) if a}


def _package_key(prefix: str, name: str) -> str:
    """Return the key of a port in the linkage scan, `<prefix>|port|<name>`

    @param prefix  the instance's prefix
    @param name    the port's name
    @returns       the key
    """
    return f"{prefix}|port|{name}"


def _broken_binaries(site: _Site, linkage: Mapping[str, Any]) -> list[Issue]:
    """Report, per owning port, the binaries of the linkage scan with a `missing` reference or an architecture gap

    `unresolved` and `weak` references never count; the remedy rebuilds the active row.

    @param site     the instance's site
    @param linkage  the linkage scan, its `binaries` keyed by path
    @returns        one finding per port
    """
    found: dict[str, list[str]] = {}
    names: dict[str, str] = {}
    wanted = _wanted_archs(site.host_arch, site.instance)
    cache: dict[str, frozenset[str] | None] = {}
    for path, item in sorted((linkage.get("binaries") or {}).items()):
        prefix, kind, name = (str(item.get("package") or "").split("|", 2) + ["", "", ""])[:3]
        if prefix != site.prefix or kind != "port" or not name:
            continue
        refs = item.get("references") or []
        lines = [f"{path} needs {ref.get('name')}, which is missing" for ref in refs if ref.get("class") == "missing"]
        lines += [f"{path} loads {gap}" for gap in macho.arch_gaps(path, refs, wanted, cache)]
        if lines:
            found.setdefault(name.lower(), []).extend(lines)
            names.setdefault(name.lower(), name)
    code = "ports-broken-binaries"
    out = []
    for key, lines in found.items():
        active = next((p for p in site.inv.packages if p.active and p.name.lower() == key), None)
        name = active.name if active else names[key]
        if active is None:
            remedies = [_note(code, name, "unused", f"brew-ports offers no fix: MacPorts' record has no version of "
                              f"{name} in use.")]
        else:
            def rebuild(pkg: Package = active) -> list[Action]:
                return [actions.upgrade_forced(site.instance, site.host_arch, action_id(code, pkg.name, "rebuild"),
                                               pkg.name, pkg.requested_variants,
                                               homebrew_present=site.homebrew_present)]
            remedies = _port_remedies(site, code, name, rebuild)
        out.append(_issue(code, name, site.prefix, limited(lines, EVIDENCE_LIMIT), remedies, confirm_each=True,
                          repairs_install=True, title=f"Files of {name} cannot load a library they need"))
    return out


# Unregistered files ---------------------------------------------------------------------

def _select_targets(site: _Site) -> dict[str, str]:
    """Map each path `port select` links (a line of `etc/select/<group>/base`) to its group

    @param site  the instance's site
    @returns     the group of each linked path
    """
    out: dict[str, str] = {}
    for group in site.inv.select_groups:
        for line in group.base:
            out.setdefault(os.path.normpath(os.path.join(site.inv.registry_prefix, line)), group.name)
    return out


def _unregistered_file(site: _Site, extras: Mapping[str, Any]) -> list[Issue]:
    """Report the unregistered files under the walked directories: neither base's, a `port select` link nor generated

    A regular file under `REMOVABLE_TOPS` that no select group links and no interpreter extra owns is
    archived to `<run>/backup/strays/` and removed, one issue per file; the rest are listed in one issue.

    @param site    the instance's site
    @param extras  the interpreter-extras scan
    @returns       one finding per removable file, and one that lists the rest
    """
    inv = site.inv
    if not inv.known:
        return []
    progress.step(f"MacPorts {site.prefix}: looking for unregistered files")
    progress.counting("files")
    root = inv.registry_prefix
    info_dir = os.path.join(root, "share", "info", "dir")
    links = _select_targets(site)
    owned = strays.Extras(extras, site.prefix)
    removable: list[str] = []
    listed: dict[str, list[str]] = {}
    for top in STRAY_TOPS:
        for path, st in strays.walk(os.path.join(root, top)):
            if strays.generated(path, info_dir) or inv.is_base_file(path):
                continue
            if stat.S_ISLNK(st.st_mode) and path in links:
                continue
            # `actual_path` counts too: a forced activation renames another port's copy to `<path>.mp_<seconds>`.
            if inv.is_registered(path):
                continue
            reason = _listed_reason(path, st, top, links, owned)
            if reason is None:
                removable.append(path)
            else:
                listed.setdefault(reason, []).append(path)
    out = [_stray(site, path) for path in removable]
    if listed:
        out.append(_left_alone(site, listed))
    return out


def _left_alone(site: _Site, listed: Mapping[str, Sequence[str]]) -> Issue:
    """Build the one finding of the unregistered files that are not offered for removal

    @param site    the instance's site
    @param listed  the files by the reason of `LEFT_ALONE` that keeps each
    @returns       the finding: how many files each reason keeps, then the files
    """
    code = "ports-unregistered-file"
    count = sum(len(paths) for paths in listed.values())
    kinds = sorted(listed, key=lambda reason: -len(listed[reason]))
    evidence = [", ".join(f"{len(listed[reason]):,} {LEFT_ALONE[reason][len(listed[reason]) != 1]}"
                          for reason in kinds)]
    evidence += limited([f"{path} ({LEFT_ALONE[reason][0]})" for reason in kinds for path in listed[reason]],
                        EVIDENCE_LIMIT)
    note = _note(code, site.prefix, "left", "Nothing to do. Uninstalling this MacPorts deletes them with it.")
    return _issue(code, site.prefix, site.prefix, evidence, [note],
                  title=f"{counted(count, 'file')} in {site.prefix} {'was' if count == 1 else 'were'} not installed "
                        f"by any port, and brew-ports leaves {'it' if count == 1 else 'them'} alone")


def _listed_reason(path: str, st: os.stat_result, top: str, links: Mapping[str, str],
                   owned: strays.Extras) -> str | None:
    """Return why an unregistered file is listed and not offered for removal

    @param path   the file
    @param st     its `lstat`
    @param top    the walked directory it lies under, relative to the prefix
    @param links  the group of each path `port select` links
    @param owned  what the interpreter extras own
    @returns      the reason, a key of `LEFT_ALONE`; None for a file offered for removal
    """
    if stat.S_ISLNK(st.st_mode):
        return "link"
    if not stat.S_ISREG(st.st_mode):
        return "special"
    if top not in REMOVABLE_TOPS:
        return "outside"
    if path in links:
        return "select"
    if owned.owns(path):
        return "extras"
    return None


def _stray(site: _Site, path: str) -> Issue:
    """Build the finding of one removable stray: archive it with `tar` under the run, then remove it

    @param site  the instance's site
    @param path  the unregistered file
    @returns     the finding; listed only without a run directory
    """
    code = "ports-unregistered-file"
    title = f"No port installed {path}"
    remove = Action(action_id=action_id(code, path, "rm"), kind="command", argv=[RM, path], sudo=True,
                    description=f"delete {path}, which no port installed")
    if site.run_path is None:
        by_hand = dataclasses.replace(remove, manual=True, description="Fix, if you do not need it")
        return _issue(code, path, site.prefix, [], [by_hand], title=title)
    dst = os.path.join(site.run_path, "backup", "strays", slug(path) + ".tar")
    archive = Action(action_id=action_id(code, path, "tar"), kind="command",
                     argv=[TAR, "-cf", "-", "-C", "/", path.lstrip("/")], sudo=True,
                     description=f"save {path} as {dst}", dst=dst)
    offer = _note(code, path, "offer", offered("saves the file in the run folder, then deletes it"))
    return _issue(code, path, site.prefix, [], [offer, archive, remove], confirm_each=True, title=title)


# Configuration and environment ----------------------------------------------------------------

def _stale_portindex(site: _Site, environ: Mapping[str, str], clock: float) -> list[Issue]:
    """Report a default-source PortIndex that is missing or whose mtime is older than 30 days

    @param site     the instance's site
    @param environ  the environment, whose `HOME` holds the user's macports.conf
    @param clock    the clock's time, in seconds since the epoch
    @returns        the finding, or none
    """
    code = "ports-stale-portindex"
    path = mp_portindex.index_path(site.instance, environ)
    title, evidence = "MacPorts' package list is missing", []
    if path is None:
        note = _note(code, site.prefix, "sources", "brew-ports offers no fix: MacPorts' sources.conf has to name a "
                     "source of ports before `port sync` can download the list.")
        return [_issue(code, site.prefix, site.prefix, ["MacPorts' sources.conf names no source of ports"], [note],
                       title=title)]
    try:
        age = clock - os.stat(path).st_mtime
    except OSError:
        evidence = [f"there is no {path}"]
    else:
        if age <= PORTINDEX_MAX_AGE_S:
            return []
        title = f"MacPorts' package list is {int(age // 86400)} days old"
    remedies = _port_remedies(site, code, site.prefix, lambda: [dataclasses.replace(
        actions.sync(site.instance, site.host_arch, action_id(code, site.prefix, "sync")), manual=True,
        description="")])
    if site.drivable:
        remedies.append(_note(code, site.prefix, "refresh", "`brew-ports plan --target ports --refresh` runs it "
                              "too, for the MacPorts that packages move into."))
    return [_issue(code, site.prefix, site.prefix, evidence, remedies, title=title)]


def _macports_user(site: _Site, runner, cache: dict[str, Any]) -> list[Issue]:
    """Report a missing or odd `macports` user, read with `dscl` once per run, for the default `macportsuser`

    It needs a UniqueID above 500, `UserShell /usr/bin/false` and `NFSHomeDirectory <portdbpath>/home`.

    @param site    the instance's site
    @param runner  the runner that runs `dscl`
    @param cache   the probe results of the run, which keeps the `dscl` result for the next instance
    @returns       the finding, or none
    """
    if (site.inv.config.get("macportsuser") or "macports") != "macports":
        return []
    if "dscl" not in cache:
        cache["dscl"] = runner.run(system.probe("0.ports.macports-user.dscl",
                                                [system.DSCL, ".", "-read", "/Users/macports"],
                                                "the macports user"))
    result = cache["dscl"]
    code = "ports-macports-user"
    account = "The system account `macports`, under which MacPorts builds ports,"
    if result.exit != 0:
        fix = ("Fix: run the MacPorts installer again (https://www.macports.org/install.php), which makes the "
               "account. Your ports stay." if _at_default(site.instance, site.default_prefix)
               else "brew-ports offers no fix: MacPorts' installer makes that account, but it installs to "
                    "/opt/local only.")
        return [_issue(code, "macports", site.prefix, [], [_note(code, site.prefix, "manual", fix)],
                       title=f"{account} is missing")]
    fields = system.parse_dscl(result.stdout())
    uid, shell, home = fields.get("UniqueID", ""), fields.get("UserShell", ""), fields.get("NFSHomeDirectory", "")
    expected_home = os.path.join(site.instance.portdbpath or "", "home")
    problems, remedies = [], []
    if shell != "/usr/bin/false":
        problems.append(f"its shell is {shell or 'missing'}; MacPorts gives it /usr/bin/false")
        remedies.append(_account_field(code, "UserShell", "/usr/bin/false"))
    if os.path.normpath(home or "/") != os.path.normpath(expected_home):
        problems.append(f"its home folder is {home or 'missing'}; MacPorts gives it {expected_home}")
        remedies.append(_account_field(code, "NFSHomeDirectory", expected_home))
    if not uid.isdigit() or int(uid) <= 500:
        problems.append(f"its user id is {uid or 'missing'}; MacPorts gives it one above 500")
        remedies.append(_note(code, site.prefix, "uid", "brew-ports offers no fix that changes the user id."))
    if not problems:
        return []
    return [_issue(code, "macports", site.prefix, problems, remedies, title=f"{account} is not as MacPorts made it")]


def _account_field(code: str, field: str, value: str) -> Action:
    """Build the command, for the user to run, that sets one field of the `macports` account as MacPorts does

    @param code   the finding's code
    @param field  the field's name in the directory service, such as `UserShell`
    @param value  the value MacPorts gives it
    @returns      the command, printed and never run
    """
    return Action(action_id=action_id(code, "macports", field.lower()), kind="command",
                  argv=[system.DSCL, ".", "-create", "/Users/macports", field, value], sudo=True, description="",
                  manual=True)


def _size(kib: int) -> str:
    """Return a size as the report writes it

    @param kib  the size in KiB, as `du -sk` gives it
    @returns    the size in MiB, or in GiB from 1024 MiB on, with one decimal
    """
    mib = kib / 1024.0
    return f"{mib / 1024.0:,.1f} GiB" if mib >= 1024 else f"{mib:,.1f} MiB"


def _disk_usage(site: _Site, runner, notes: list[str]) -> list[Issue]:
    """Report the `du -sk` sizes of the existing `software`, `build` and `distfiles` directories

    @param site    the instance's site
    @param runner  the runner that runs `du`
    @param notes   receives a line when `du` gives no size
    @returns       the finding; none without those directories or their sizes
    """
    base = site.instance.portdbpath
    uses = {"software": "the stored copies of its ports", "build": "build leftovers",
            "distfiles": "downloaded sources"}
    dirs = [d for d in (os.path.join(base or "", sub) for sub in uses) if base and os.path.isdir(d)]
    if not dirs:
        return []
    result = runner.run(system.probe(f"0.ports.{slug(site.prefix)}.du", [DU, "-sk"] + dirs,
                                     f"size of the build, distfile and image directories of {site.prefix}"))
    sizes: dict[str, int] = {}
    for line in result.stdout().splitlines():
        size, _, path = line.partition("\t")
        if size.strip().isdigit() and os.path.basename(path.strip()) in uses:
            sizes[os.path.basename(path.strip())] = int(size)
    if not sizes:
        notes.append(f"How much disk space {site.at} uses: `du` gave no sizes")
        return []
    code = "ports-disk-usage"
    spare = sizes.get("build", 0) + sizes.get("distfiles", 0)
    note = (f"Nothing to do. To free space and keep MacPorts, run `{_port(site.instance, 'reclaim')}`; it asks "
            "before each removal." if spare >= 1024 else "Nothing to do.")
    return [_issue(code, site.prefix, site.prefix,
                   [f"{_size(kib)} for {uses[sub]}" for sub, kib in sizes.items() if kib],
                   [_note(code, site.prefix, "manual", note)],
                   title=f"MacPorts' stored copies of ports, build leftovers and downloads take "
                         f"{_size(sum(sizes.values()))} of disk space")]


def _tcl_true(value: str) -> bool:
    """Return whether a macports.conf value is true as Tcl reads a boolean

    @param value  the value
    @returns      True for yes, true, on or 1, in any case
    """
    return value.strip().lower() in _TRUE_WORDS


def _no_binary_archives(site: _Site) -> list[Issue]:
    """Report the settings that rule out binary archives, so that ports build from source

    A `prefix`, `applications_dir` or `frameworks_dir` other than the archives', a `cxx_stdlib` or
    `delete_la_files` other than base's default for this Darwin, or `buildfromsource always`.

    @param site  the instance's site
    @returns     the finding, or none
    """
    config = site.inv.config
    found = []
    for key, default in ARCHIVE_DEFAULTS:
        value = config.get(key)
        if value and os.path.normpath(value) != default:
            found.append(f"{'MacPorts is installed in' if key == 'prefix' else f'its setting {key} is'} {value}; "
                         f"prebuilt packages are made for {default}")
    platform = site.running
    cxx = config.get("cxx_stdlib")
    default_cxx = mp_inventory.configured_cxx_stdlib({}, platform)
    if cxx and cxx != default_cxx:
        found.append(f"its setting cxx_stdlib is {cxx}; prebuilt packages use {default_cxx or 'none'}")
    la = config.get("delete_la_files")
    default_la = platform[0] == "darwin" and platform[1] >= 13
    if la is not None and la.strip() and _tcl_true(la) != default_la:
        found.append(f"its setting delete_la_files is {la}; prebuilt packages use {'yes' if default_la else 'no'}")
    if (config.get("buildfromsource") or "").strip() == "always":
        found.append("its setting buildfromsource is always")
    if not found:
        return []
    code = "ports-no-binary-archives"
    note = _note(code, site.prefix, "note", "Nothing to do. Installing into this MacPorts takes longer, because it "
                 "builds each port.")
    return [_issue(code, site.prefix, site.prefix, found, [note],
                   title="MacPorts builds every port on this Mac, because its settings rule out prebuilt packages")]


def _same_dir(text: str | None, directory: str) -> bool:
    """Return whether a PATH entry names a directory, as text or as the same file

    @param text       the entry, or None
    @param directory  the directory
    @returns          True when they match
    """
    if not text:
        return False
    return os.path.normpath(text) == os.path.normpath(directory) or system.same_path(text, directory)


def _not_on_path(site: _Site, environment: Mapping[str, Any]) -> list[Issue]:
    """Report a live PATH without `<prefix>/bin`

    The fix named here is the one by hand, which holds for every installation; `doctor` names `env-cleanup` in
    its place for the installation that command keeps.

    @param site         the instance's site
    @param environment  the environment analysis, whose `live` PATH entries are read
    @returns            the finding; none without a live PATH
    """
    live = (environment.get("live") or {}).get("PATH")
    if live is None:
        return []
    bin_dir = os.path.join(site.prefix, "bin")
    if any(_same_dir(entry.get("path") or entry.get("text"), bin_dir) for entry in live):
        return []
    code = "ports-not-on-path"
    return [_issue(code, bin_dir, site.prefix, [],
                   [_note(code, bin_dir, "path", f"Fix, if this is the MacPorts you keep: add {bin_dir} to the PATH "
                          "in your shell's login file."),
                    _note(code, bin_dir, "new-window", "If you have only just installed MacPorts, a new Terminal "
                          "window has it already.")],
                   title=f"{bin_dir} is not on your PATH, so `port` is not found by name")]


def _usr_local_cellar(bundle, usr_local_cellar: str) -> list[Issue]:
    """Report `/usr/local/Cellar` beside a MacPorts instance, as `port diagnose` warns

    The Homebrew finding for several prefixes carries the detail.

    @param bundle            the scan bundle
    @param usr_local_cellar  the path of `/usr/local/Cellar`
    @returns                 the finding; none without a MacPorts instance or the directory
    """
    if not bundle.ports or not os.path.isdir(usr_local_cellar):
        return []
    code = "ports-usr-local-cellar"
    return [_issue(code, usr_local_cellar, None, [],
                   [_note(code, usr_local_cellar, "note", "Nothing to do while you keep that Homebrew.")],
                   title=f"{usr_local_cellar} exists, and a port that MacPorts builds can pick up Homebrew's files "
                         f"from {os.path.dirname(usr_local_cellar)}")]


# Startup items and select groups -------------------------------------------------------------

def _dangling_plist(site: _Site, services: Sequence[Service], uid: int) -> list[Issue]:
    """Report each owned MacPorts plist whose program or symlink target is gone

    The remedy is `launchctl bootout` in its domain (a probe: exit 3 means not loaded), then `sudo rm`.

    @param site      the instance's site
    @param services  the host's launchd jobs
    @param uid       the user's uid, for the `gui/<uid>` domain of a job launchctl did not find loaded
    @returns         one finding per dangling plist
    """
    code = "ports-dangling-plist"
    out = []
    for svc in services:
        if not (svc.owned and svc.package_kind == "port" and svc.instance_prefix == site.prefix):
            continue
        dangling = os.path.islink(svc.plist) and not os.path.exists(svc.plist)
        gone = bool(svc.program and not os.path.exists(svc.program))
        if not (dangling or gone):
            continue
        evidence = [f"its file, {svc.plist}, " + ("is a link to a file that is gone" if dangling
                                                  else f"runs {svc.program}, which is gone")]
        if svc.scope == "system":
            target, sudo = f"system/{svc.label}", True
        else:
            domain = svc.domain or f"gui/{uid}"
            target, sudo = f"{domain}/{svc.label}", False
        bootout = Action(action_id=action_id(code, svc.label, "bootout"), kind="command",
                         argv=[env_services.LAUNCHCTL, "bootout", target], sudo=sudo,
                         description=f"unload the service {svc.label}", on_failure=OnFailure.PROBE)
        remove = Action(action_id=action_id(code, svc.label, "rm"), kind="command", argv=[RM, svc.plist], sudo=True,
                        description=f"delete the service file {svc.plist}")
        out.append(_issue(code, svc.label, site.prefix, evidence, [bootout, remove], confirm_each=True,
                          title=f"The service {svc.label} is left over from a port whose program is gone"))
    return out


def _missing_selection(site: _Site) -> list[Issue]:
    """Report a select group whose `current` option file is gone or belongs to no active port

    The remedy is the manual `sudo port -N select --set <group> none`.

    @param site  the instance's site
    @returns     one finding per group
    """
    inv = site.inv
    if not inv.known:
        return []
    active = {p.name.lower() for p in inv.packages if p.active}
    shown = _display_instance(site.instance, site.host_arch)
    out = []
    for group in inv.select_groups:
        current = group.current
        if not current or current == "none":
            continue
        option = os.path.join(inv.registry_prefix, "etc", "select", group.name, current)
        gone = not os.path.lexists(option)
        owner = None if gone else inv.owner_of(option)
        if owner is not None and owner.lower() in active:
            continue
        evidence = ["the file of that choice is gone" if gone
                    else f"{owner}, which provides that choice, is switched off" if owner is not None
                    else "no installed port provides that choice"]

        def clear(group: mp_inventory.SelectGroup = group) -> list[Action]:
            return [dataclasses.replace(actions.select_set(
                shown, site.host_arch, action_id("ports-missing-selection", group.name, "select"), group.name,
                "none"), manual=True, description="")]
        out.append(_issue("ports-missing-selection", group.name, site.prefix, evidence,
                          _built("ports-missing-selection", group.name, clear),
                          title=f"`port select` points {group.name} at {current}, which no port in use provides"))
    return out


# detect ------------------------------------------------------------------------------------

def _site(bundle, runner, entry: tuple[Instance, Any, mp_inventory.MacPortsInventory],
          platform: locate.Platform | None, default_prefix: str) -> _Site:
    """Return the site of one MacPorts instance of the bundle

    @param bundle          the scan bundle
    @param runner          the runner, whose architecture and run directory the site takes
    @param entry           the instance, its PortIndex or None, and its inventory
    @param platform        the running platform; None reads `uname`
    @param default_prefix  the default MacPorts prefix
    @returns               the site
    """
    inst, index, inv = entry
    run_dir = runner.run_dir
    return _Site(instance=inst, index=index, inv=inv, host_arch=runner.host_arch, homebrew_present=bool(bundle.brew),
                 running=platform or locate.running_platform(), default_prefix=default_prefix,
                 run_path=run_dir.path if run_dir is not None else None)


def detect(bundle, runner, *, platform: locate.Platform | None = None, default_prefix: str = locate.DEFAULT_PREFIX,
           now: float | None = None, usr_local_cellar: str = USR_LOCAL_CELLAR) -> list[Issue]:
    """Run every `ports-` detector over the bundle's MacPorts instances, in code order

    The only probes are `port -N diagnose --quiet`, `dscl . -read /Users/macports` and `du -sk`; the
    keyword arguments stand in for `uname`, `/opt/local`, the clock and `/usr/local/Cellar`.

    @param bundle            the scan bundle
    @param runner            the runner that runs the probes
    @param platform          the running platform; None reads `uname`
    @param default_prefix    the default MacPorts prefix
    @param now               the clock's time in seconds since the epoch; None reads the clock
    @param usr_local_cellar  the path of `/usr/local/Cellar`
    @returns                 the findings
    """
    result = bundle.result
    services = list(result.services or [])
    environment = result.environment or {}
    linkage = result.linkage or {}
    extras = result.interpreter_extras or {}
    uid = (result.system or {}).get("uid")
    uid = uid if isinstance(uid, int) else os.getuid()
    clock = time.time() if now is None else now
    sites = [_site(bundle, runner, entry, platform, default_prefix) for entry in bundle.ports]
    cache: dict[str, Any] = {}
    per_site: list[Callable[[_Site], list[Issue]]] = [
        lambda s: _diagnose_warnings(s, runner, bundle.notes),
        _platform_mismatch, _damaged_registry,
        lambda s: _missing_file(s, _loaded_items(services, s.prefix)),
        _missing_image, _inactive_versions, _unrequested_leaf, _obsolete_port, _built_for_other_os,
        lambda s: _broken_binaries(s, linkage),
        lambda s: _unregistered_file(s, extras),
        lambda s: _stale_portindex(s, runner.environ, clock),
        lambda s: _macports_user(s, runner, cache),
        _registry_busy,
        lambda s: _disk_usage(s, runner, bundle.notes),
        lambda s: _dangling_plist(s, services, uid),
        _missing_selection, _no_binary_archives,
        lambda s: _not_on_path(s, environment),
    ]
    issues: list[Issue] = []
    for detector in per_site:
        for site in sites:
            progress.step(f"MacPorts {site.prefix}: checks")
            issues += detector(site)
    issues += _usr_local_cellar(bundle, usr_local_cellar)
    for detector in (_registry_schema_update, _replaced_port, _cannot_run, _no_registry):
        for site in sites:
            issues += detector(site)
    return _once(issues)


def _once(issues: Sequence[Issue]) -> list[Issue]:
    """Drop the `port diagnose` findings that another finding says more about

    They are the missing files of a port that has a missing-file finding, and a warning that names the Cellar
    folder which the finding about Homebrew in `/usr/local` is about.

    @param issues  the findings
    @returns       the findings, each of those facts reported once
    """
    missing = {(i.instance_prefix, i.subject) for i in issues if i.code == "ports-missing-file"}
    cellars = [i.subject for i in issues if i.code == "ports-usr-local-cellar" and i.subject]

    def told(issue: Issue) -> bool:
        if issue.code != "ports-diagnose-warning":
            return False
        if issue.subject != issue.instance_prefix:
            return (issue.instance_prefix, issue.subject) in missing
        return any(cellar in line for cellar in cellars for line in issue.evidence)

    return [i for i in issues if not told(i)]


def recompute_leaves(prefix: str, runner, bundle) -> list[Issue]:
    """Return the unrequested-leaf issues of one instance from a fresh inventory, for after each removal

    @param prefix  the instance's prefix
    @param runner  the runner that takes the inventory
    @param bundle  the scan bundle
    @returns       the findings; none for a prefix the bundle does not hold
    """
    entry = next((e for e in bundle.ports if e[0].prefix == prefix), None)
    if entry is None:
        return []
    inst, index, _ = entry
    inv = mp_inventory.inventory(runner, inst, index, host_arch=runner.host_arch)
    try:
        return _unrequested_leaf(_site(bundle, runner, (inst, index, inv), None, locate.DEFAULT_PREFIX))
    finally:
        inv.close()


# What doctor --fix needs to know about a remedy ------------------------------------------------

def _port_args(action: Action) -> list[str]:
    """Return the arguments after `<prefix>/bin/port` in a remedy's argv

    @param action  the remedy
    @returns       the arguments; empty for any other action
    """
    if action.kind != "command" or not action.instance_prefix:
        return []
    binary = os.path.join(action.instance_prefix, "bin", "port")
    if binary not in action.argv:
        return []
    return action.argv[action.argv.index(binary) + 1:]


def port_verb(action: Action) -> str | None:
    """Return the `port` action word of a remedy (`uninstall`, `upgrade`, `deactivate`, ...)

    @param action  the remedy
    @returns       the first argument after the binary that is no option; None for another action
    """
    return next((arg for arg in _port_args(action) if not arg.startswith("-")), None)


def needs_terminal_answer(issue: Issue) -> bool:
    """Return whether the issue is a removal `--yes` never answers

    They are, with a remedy: the uninstall of an inactive row without its image, inactive versions,
    unrequested leaves and unregistered files.

    @param issue  the finding
    @returns      True when the user answers its prompt on a terminal
    """
    if all(a.manual for a in issue.remedies):
        return False
    if issue.code in ("ports-inactive-versions", "ports-unrequested-leaf", "ports-unregistered-file"):
        return True
    return issue.code == "ports-missing-image" and any(port_verb(a) == "uninstall" for a in issue.remedies)


def removes_package(issue: Issue) -> tuple[str, str] | None:
    """Return `("port", name)` when a remedy uninstalls, upgrades or reinstalls the port the issue names

    `doctor --fix` then writes the snapshot first and applies the service rules of phase 5.

    @param issue  the finding
    @returns      the kind and name of the port; None for any other remedy
    """
    codes = ("ports-missing-file", "ports-missing-image", "ports-inactive-versions", "ports-unrequested-leaf",
             "ports-broken-binaries", "ports-replaced-port")
    if issue.code not in codes or not issue.subject:
        return None
    if any(port_verb(a) in ("uninstall", "upgrade", "install") for a in issue.remedies):
        return ("port", issue.subject)
    return None


# Post-checks --------------------------------------------------------------------------------

def _instance_of(bundle, prefix: str | None) -> Instance | None:
    """Return the bundle's MacPorts instance at a prefix

    @param bundle  the scan bundle
    @param prefix  the prefix, or None
    @returns       the instance; None when the bundle holds none there
    """
    return next((inst for inst, _, _ in bundle.ports if inst.prefix == prefix), None)


def _uninstall_spec(issue: Issue) -> list[str] | None:
    """Return the `[name, @version]` an issue's uninstall remedy names

    @param issue  the finding
    @returns      the two tokens; None without an uninstall remedy
    """
    for action in issue.remedies:
        args = _port_args(action)
        if port_verb(action) == "uninstall":
            tail = args[args.index("uninstall") + 1:]
            if len(tail) >= 2:
                return tail[:2]
    return None


def _active_with_image(rows: Sequence[registry.PortRow]) -> bool:
    """Return whether the port has an active row and every active row has its image location

    @param rows  the port's registry rows
    @returns     True when the image of every active row is present
    """
    active = [r for r in rows if r.active]
    return bool(active) and all(mp_inventory.location_present(r.location) for r in active)


def _linkage_clean(runner, bundle, inst: Instance, name: str, binaries: list[str]) -> bool:
    """Return whether the linkage scan of a port's binaries finds no `missing` reference and no arch gap

    @param runner    the runner that runs the scan
    @param bundle    the scan bundle, whose instances resolve the references
    @param inst      the MacPorts instance
    @param name      the port's name
    @param binaries  the binaries of its active row
    @returns         True for a clean scan
    """
    report = env_linkage.scan(runner, {_package_key(inst.prefix, name): binaries}, list(bundle.result.instances))
    wanted = _wanted_archs(runner.host_arch, inst)
    for path, item in (report.get("binaries") or {}).items():
        refs = item.get("references") or []
        if any(ref.get("class") == "missing" for ref in refs) or macho.arch_gaps(path, refs, wanted):
            return False
    return True


def verify(issue: Issue, runner, bundle) -> bool | None:
    """Return whether a missing-file, missing-image or broken-binaries repair holds, by a fresh registry backup

    Exit statuses never decide; broken binaries need the missing-image test and then a clean linkage scan
    of the active row.

    @param issue   the repaired finding
    @param runner  the runner that runs the checks
    @param bundle  the scan bundle
    @returns       whether the repair holds; None for an issue without a post-check, False when the backup
                   cannot be taken
    """
    checked = ("ports-missing-file", "ports-missing-image", "ports-broken-binaries")
    if issue.code not in checked or not issue.remedies or not issue.subject:
        return None
    inst = _instance_of(bundle, issue.instance_prefix)
    if inst is None or not inst.portdbpath:
        return False
    try:
        reg = registry.Registry.open_copy(inst.portdbpath)
    except (registry.RegistryMissing, registry.RegistryBusy, sqlite3.DatabaseError, OSError):
        return False
    try:
        rows = [r for r in reg.ports() if r.name.lower() == issue.subject.lower()]
        if issue.code == "ports-missing-file":
            return any(r.active for r in rows)
        spec = _uninstall_spec(issue) if issue.code == "ports-missing-image" else None
        if spec is not None:
            return all(mp_inventory.location_present(r.location) for r in rows if r.spec_args[1] == spec[1])
        if not _active_with_image(rows):
            return False
        if issue.code == "ports-missing-image":
            return True
        active = next(r for r in rows if r.active)
        binaries = [f.location for f in reg.files(active.id) if f.binary and f.active]
        name = active.name
    finally:
        reg.close()
    return _linkage_clean(runner, bundle, inst, name, binaries)


# Manager repairs ------------------------------------------------------------------------------

class _Report:
    """The report lines of one manager repair, shown as they come"""

    def __init__(self, show: Callable[[str], None] | None) -> None:
        """Start an empty report

        @param show  prints each line as it comes; None shows nothing
        """
        self.show = show
        self.lines: list[str] = []

    def __call__(self, text: str) -> None:
        """Add a line to the report and show it, indented under the finding it belongs to

        @param text  the line
        """
        self.lines.append(text)
        if self.show is not None:
            self.show("  " + text)

    def ran(self, result) -> bool:
        """Add a command with its result: `ok`, or `failed` with the exit status and the error line

        @param result  the command's result
        @returns       whether the command worked
        """
        if result.exit == 0 and not result.timed_out:
            self(f"{result.typed} ... ok")
            return True
        line = result.error_line()
        self(f"{result.typed} ... failed (exit {result.exit})" + (f": {line}" if line else ""))
        return False


def _relocate(runner, environ: Mapping[str, str], prefix: str, default_prefix: str,
              platform: locate.Platform | None) -> Instance | None:
    """Locate the instance at `prefix` again

    @param runner          the runner that runs the probes
    @param environ         the environment the instances are located with
    @param prefix          the instance's prefix
    @param default_prefix  the default MacPorts prefix
    @param platform        the running platform; None reads `uname`
    @returns               the instance, matched by identity or by text; None when it is gone
    """
    ident = system.identity(prefix)
    for inst in locate.find_instances(runner, environ, runner.host_arch, platform=platform,
                                      default_prefix=default_prefix):
        if (ident is not None and tuple(inst.identity) == ident) or inst.prefix == prefix:
            return inst
    return None


def _still_holds(code: str, inst: Instance, running: locate.Platform) -> bool:
    """Return whether the condition of a manager repair still holds on the instance located again

    The active ports built for another Darwin major are read from a fresh registry backup; when none can be
    taken, that condition holds.

    @param code     the repair's finding code
    @param inst     the MacPorts instance, located again; for the ports built for another Darwin major, one whose
                    `port` runs
    @param running  the running platform and its Darwin major
    @returns        True when the repair still has something to do
    """
    if code == "ports-registry-schema-update":
        return inst.usability is Usability.READONLY_REGISTRY
    if code == "ports-cannot-run":
        return inst.usability in (Usability.MISSING_BINARY, Usability.CANNOT_RUN)
    if code == "ports-platform-mismatch":
        built = locate.read_autoconf(inst.prefix).get("os_major") or ""
        return inst.usability is Usability.PLATFORM_MISMATCH or (built.isdigit() and int(built) != running[1])
    rows = _fresh_rows(inst.portdbpath)
    return rows is None or any(row.active and _other_major(row.os_major, running[1]) for row in rows)


def _probe_run(runner, action: Action):
    """Run a repair step whose failure is reported, not raised

    @param runner  the runner that runs the step
    @param action  the step, run as a probe
    @returns       the step's result
    """
    return runner.run(dataclasses.replace(action, on_failure=OnFailure.PROBE))


def _sync(runner, inst: Instance, code: str, say: _Report) -> None:
    """Run `sudo port -N sync` after a base repair and report it

    @param runner  the runner that runs the sync
    @param inst    the MacPorts instance
    @param code    the repair's finding code, for the action id
    @param say     the repair's report
    """
    if not say.ran(_probe_run(runner, actions.sync(inst, runner.host_arch, action_id(code, inst.prefix, "sync")))):
        say(f"MacPorts' package list was not updated. Run `{_port(inst, 'sync')}` later.")


def _confirm_procedure(runner, confirm: Callable[[str], bool], say: _Report) -> str | None:
    """Ask the confirmation the base package procedure requires, with its steps

    @param runner   the runner that reads the macOS version
    @param confirm  asks the user a question and returns the answer
    @param say      the repair's report, which records a refusal
    @returns        the macOS version; None when the user declines
    """
    version = system.macos_version(runner)
    steps = bootstrap.describe(bootstrap.macos_major(version))
    if not confirm("\n".join(["The MacPorts base package procedure:"] + ["  " + s for s in steps]
                             + ["Run it now?"])):
        say("Nothing changed.")
        return None
    return version


def _port_services(runner, environ: Mapping[str, str], inst: Instance,
                   reg: registry.Registry | None) -> list[Service]:
    """Return the instance's launchd services, attributed and probed afresh

    @param runner   the runner that probes `launchctl`
    @param environ  the environment, whose `HOME` holds the user's LaunchAgents
    @param inst     the MacPorts instance
    @param reg      the registry copy that attributes the plists to ports, or None
    @returns        the services of the instance
    """
    def owner_of(path: str) -> str | None:
        return reg.owner_of(system.normalise_text_path(path, False)) if reg is not None else None

    home = environ.get("HOME") or os.path.expanduser("~")
    return [svc for svc in env_services.collect(runner, [inst], [], service_labels={}, owner_of=owner_of, home=home,
                                                uid=os.getuid())
            if svc.instance_prefix == inst.prefix]


class _NoBackup(Exception):
    """The registry exists, but its backup into the run directory failed"""


def _migrate_records(runner, run_dir: RunDir, environ: Mapping[str, str],
                     inst: Instance) -> tuple[list[registry.PortRow], list[Service], str]:
    """Write the phase 1 records (registry backup, `installed.txt`, `services.json`) before `migrate --all`

    A registry that exists but cannot be backed up raises, so `migrate` never runs without its backup.

    @param runner                  the runner that probes the services
    @param run_dir                 the run directory that keeps the records
    @param environ                 the environment, whose `HOME` holds the user's LaunchAgents
    @param inst                    the MacPorts instance
    @returns                       the backup's rows, the services and the records' directory
    @throws _NoBackup              the registry exists, but the run directory holds no backup of it
    @throws RegistryBusy           another `port` holds the registry
    @throws sqlite3.DatabaseError  the registry cannot be read as a database
    @throws OSError                the user cannot read the registry
    """
    try:
        reg: registry.Registry | None = registry.Registry.open_copy(inst.portdbpath or "")
    except registry.RegistryMissing:
        reg = None
    try:
        services = _port_services(runner, environ, inst, reg)
    finally:
        if reg is not None:
            reg.close()
    written = snapshot.write_ports_records(run_dir, inst, services)
    directory = snapshot.ports_dir(run_dir, inst.prefix)
    if reg is None:
        return [], services, directory
    backup = os.path.join(directory, snapshot.REGISTRY)
    if backup not in written.values():
        notes = os.path.join(snapshot.snapshot_dir(run_dir), snapshot.NOTES)
        raise _NoBackup(f"no backup in {directory} (see {notes})")
    with registry.Registry.open_backup(backup) as copy:
        return copy.ports(), services, directory


def _fresh_rows(portdbpath: str | None) -> list[registry.PortRow] | None:
    """Return the rows of a fresh registry backup, after a repair changed them

    @param portdbpath  the instance's `portdbpath`
    @returns           the rows; None when the backup cannot be taken
    """
    try:
        reg = registry.Registry.open_copy(portdbpath or "")
    except (registry.RegistryMissing, registry.RegistryBusy, sqlite3.DatabaseError, OSError):
        return None
    try:
        return reg.ports()
    finally:
        reg.close()


def _migrate(runner, run_dir: RunDir, environ: Mapping[str, str], inst: Instance, code: str, *, say: _Report,
             default_prefix: str, platform: locate.Platform | None, then_sync: bool) -> None:
    """Run `migrate --all` after its records; report each port it left inactive and load the startup items again

    `migrate` exits 0 even when rebuilds fail; it deactivates every port, and its restore loads only the
    items that set `startupitem.autostart`. Then `sync`, when asked.

    @param runner          the runner that runs the repair
    @param run_dir         the run directory that keeps the records
    @param environ         the environment the instances are located with
    @param inst            the MacPorts instance
    @param code            the finding's code, for the action ids and the report
    @param say             the repair's report
    @param default_prefix  the default MacPorts prefix, for locating the instance again before `sync`
    @param platform        the running platform; None reads it from the host
    @param then_sync       run `port sync` after the migration
    @throws ActionFailed   `migrate --all` exited non-zero; raised after the report, the loads and a requested `sync`
    """
    host = runner.host_arch
    try:
        rows, services, directory = _migrate_records(runner, run_dir, environ, inst)
    except (registry.RegistryBusy, sqlite3.DatabaseError, OSError, _NoBackup) as exc:
        say(f"MacPorts' record of installed ports could not be saved first ({exc}), so `port migrate` was not run.")
        return
    say(f"Saved MacPorts' record of installed ports in {tilde(directory)}.")
    loaded: dict[str, str] = {}
    for svc in services:
        if svc.owned and svc.package and svc.package_kind == "port" and svc.loaded:
            loaded.setdefault(svc.package.lower(), svc.package)
    result = _probe_run(runner, actions.migrate_all(inst, host, action_id(code, inst.prefix, "migrate")))
    say.ran(result)
    after = _fresh_rows(inst.portdbpath)
    before = os.path.join(directory, "installed.txt")
    if after is None:
        say(f"MacPorts' record cannot be read after `port migrate`. {tilde(before)} lists what was installed.")
    else:
        active_after = {r.name.lower() for r in after if r.active}
        trace = bool(brew_locate.candidate_prefixes(environ))

        def install(row: registry.PortRow) -> str:
            line = actions.install(inst, host, action_id(code, os.path.join(inst.prefix, row.name), "reinstall"),
                                   row.name, row.requested_variant_tokens, homebrew_present=trace, binary_first=False)
            return typed(line.argv, True)
        _not_back(say, [r for r in rows if r.active and r.name.lower() not in active_after],
                  sum(1 for r in rows if r.active), before, install)
        for key, name in sorted(loaded.items()):
            if key not in active_after:
                continue
            load = _probe_run(runner, actions.load(inst, host, action_id(code, os.path.join(inst.prefix, name), "load"),
                                                   name))
            say(f"The service of {name} runs again." if load.exit == 0
                else f"The service of {name} did not start: `{load.typed}` failed (exit {load.exit}).")
    if then_sync:
        _sync(runner, _relocate(runner, environ, inst.prefix, default_prefix, platform) or inst, code, say)
    if result.exit != 0:
        raise ActionFailed(result)


def _not_back(say: _Report, lost: Sequence[registry.PortRow], used: int, before: str,
              install: Callable[[registry.PortRow], str]) -> None:
    """Report the ports that were in use before `port migrate` and are not in use after it

    @param say      the repair's report
    @param lost     the rows that were active before and are not after
    @param used     how many rows were active before
    @param before   the file that lists what was installed before
    @param install  returns the command that installs a row's port again, as the user would type it
    """
    if not lost:
        say(f"All {counted(used, 'port')} that were in use are in use again." if used else "No port was in use.")
        return
    one = len(lost) == 1
    say(f"{counted(len(lost), 'port')} that {'was' if one else 'were'} in use {'is' if one else 'are'} not in use "
        f"again: {some(row.name for row in lost)}")
    for row in lost[:NAMES_SHOWN]:
        say(f"  To bring {row.name} back: {install(row)}")
    if len(lost) > NAMES_SHOWN:
        say(f"  {tilde(before)} lists them all, with their versions.")


@dataclass
class _Repair:
    """What one manager repair works with: the finding, the runner, the run directory and where the instance lies"""

    issue: Issue
    runner: Any
    run_dir: RunDir
    environ: Mapping[str, str]
    default_prefix: str
    platform: locate.Platform | None
    say: _Report

    def relocate(self) -> Instance | None:
        """Locate the finding's instance again

        @returns  the instance; None when it is gone
        """
        return _relocate(self.runner, self.environ, self.issue.instance_prefix or "", self.default_prefix,
                         self.platform)

    def migrate(self, inst: Instance, then_sync: bool) -> None:
        """Run `migrate --all` on an instance, with its records and its report

        @param inst           the MacPorts instance
        @param then_sync      run `port sync` after the migration
        @throws ActionFailed  `migrate --all` exited non-zero
        """
        _migrate(self.runner, self.run_dir, self.environ, inst, self.issue.code, say=self.say,
                 default_prefix=self.default_prefix, platform=self.platform, then_sync=then_sync)

    def verdict(self) -> bool:
        """Say whether the repair worked, read from the instance located again

        @returns  True when the finding's condition is gone and `port` runs
        """
        running = self.platform or locate.running_platform()
        inst = self.relocate()
        if inst is None:
            self.say(f"No MacPorts is found at {self.issue.instance_prefix} any more.")
            return False
        if self.issue.code == "ports-built-for-other-os" and inst.drivable:
            fixed = not _still_holds(self.issue.code, inst, running)
            self.say("Every port in use is built for this version of macOS." if fixed
                     else "Some ports in use are still built for another version of macOS.")
            return fixed
        self.say(f"The `port` command of {at(inst)} works." if inst.drivable else _port_fails(inst, "still "))
        return inst.drivable


def _port_fails(inst: Instance, still: str = "") -> str:
    """Return the sentence that says an installation's `port` command cannot run, with what the probe found

    @param inst   the MacPorts instance
    @param still  `still ` after a repair that was to make it run
    @returns      the sentence
    """
    detail = (inst.usability_detail or "").strip().splitlines()[:1]
    return f"The `port` command of {at(inst)} {still}cannot run" + (f": {detail[0]}" if detail else ".")


def manager_repair(issue: Issue, runner, run_dir: RunDir, environ: Mapping[str, str],
                   show: Callable[[str], None] | None, *, confirm: Callable[[str], bool],
                   default_prefix: str = locate.DEFAULT_PREFIX,
                   platform: locate.Platform | None = None) -> tuple[list[str], bool | None]:
    """Run one of the `MANAGER_REPAIRS`, confirmed by the caller

    The instance is located again first and a cleared condition is skipped; `confirm(text)` is asked
    before a base package procedure, and a failed step raises, `migrate --all` only after its report.
    Ports are built again only by a `port` that runs.

    @param issue            the finding, whose code names the repair
    @param runner           the runner that runs the repair
    @param run_dir          the run directory that keeps the records and the downloads
    @param environ          the environment the instances are located with
    @param show             prints each report line as it comes; None shows nothing
    @param confirm          asks the user a question and returns the answer
    @param default_prefix   the default MacPorts prefix
    @param platform         the running platform; None reads it from the host
    @returns                the report lines, and whether the repair cleared the finding's condition; None when
                            that condition was gone before any step ran
    @throws ActionFailed    a `port` step or the installer failed; `migrate --all` raises after its report
    @throws BootstrapError  the base package cannot be had, is not signed by a pinned signer, or leaves no instance
    """
    if issue.code not in MANAGER_REPAIRS or not issue.instance_prefix:
        raise ValueError(f"{issue.code} is not a MacPorts manager repair")
    say = _Report(show)
    repair = _Repair(issue, runner, run_dir, environ, default_prefix, platform, say)
    inst = repair.relocate()
    if inst is None:
        say(f"No MacPorts is found at {issue.instance_prefix} any more.")
        return say.lines, False
    if issue.code == "ports-built-for-other-os" and not inst.drivable:
        say(_port_fails(inst))
        say("Its ports were not built again.")
        return say.lines, False
    if not _still_holds(issue.code, inst, platform or locate.running_platform()):
        say("Nothing to do: this is in order already.")
        return say.lines, None
    return say.lines, _repair(repair, inst, confirm) and repair.verdict()


def _repair(repair: _Repair, inst: Instance, confirm: Callable[[str], bool]) -> bool:
    """Run the steps of a manager repair on the instance located again

    @param repair           the repair
    @param inst             the instance, on which the finding's condition holds
    @param confirm          asks the user a question and returns the answer
    @returns                whether the steps ran; False when the repair is the user's to make, or was declined
    @throws ActionFailed    a `port` step or the installer failed; `migrate --all` raises after its report
    @throws BootstrapError  the base package cannot be had, is not signed by a pinned signer, or leaves no instance
    """
    code, runner, say = repair.issue.code, repair.runner, repair.say
    mismatch = code == "ports-platform-mismatch"
    if code == "ports-registry-schema-update":
        say.ran(runner.run(actions.version(inst, runner.host_arch, action_id(code, inst.prefix, "version"),
                                           sudo=True)))
        return True
    migrate_ready = "migrate" in inst.features and bool(inst.binary)
    if code == "ports-built-for-other-os" or (mismatch and migrate_ready):
        if not migrate_ready:
            say(_too_old(inst))
            return False
        repair.migrate(inst, then_sync=True)
        return True
    if not _at_default(inst, repair.default_prefix):
        say(_source_build_note(code, inst, mismatch).description)
        return False
    version = _confirm_procedure(runner, confirm, say)
    if version is None:
        return False
    say("Downloading MacPorts' installer, checking its signature and running it. This can take a few minutes.")
    new = bootstrap.bootstrap(runner, repair.run_dir, repair.environ, runner.host_arch, macos_version=version,
                              default_prefix=repair.default_prefix)
    say(f"MacPorts{_release_of(new)} is installed at {new.prefix}, with its package list.")
    if mismatch:
        if "migrate" not in new.features:
            say(f"MacPorts{_release_of(new)} has no `port migrate`, so the ports were not built again for this "
                "version of macOS.")
            return True
        repair.migrate(new, then_sync=False)
    return True

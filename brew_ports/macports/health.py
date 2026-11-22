"""MacPorts health checks: the `ports-` findings of `doctor`, their post-checks and the manager repairs

`detect` probes only through the runner; its `port` actions come from `actions`, and a note may name one as text.
"""

from __future__ import annotations

import dataclasses
import functools
import glob
import hashlib
import os
import re
import shlex
import sqlite3
import stat
import struct
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .. import progress, snapshot, system
from ..env import linkage as env_linkage, services as env_services
from ..homebrew import locate as brew_locate
from ..model import Action, Blocks, Instance, Issue, OnFailure, Package, Service, Severity, Usability
from ..report import limited
from ..runner import RM, ActionFailed
from ..state import RunDir, slug
from . import actions, bootstrap, inventory as mp_inventory, locate, portindex as mp_portindex, registry

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

TITLES = {
    "ports-diagnose-warning": "port diagnose warning",
    "ports-platform-mismatch": "Base compiled for another Darwin major or for Rosetta",
    "ports-damaged-registry": "Registry damaged or unreadable",
    "ports-missing-file": "Active file missing on disk",
    "ports-missing-image": "Image archive or directory missing",
    "ports-inactive-versions": "Inactive versions beside an active one",
    "ports-unrequested-leaf": "Unrequested leaf",
    "ports-obsolete-port": "Obsolete port",
    "ports-built-for-other-os": "Ports built for another Darwin major while base matches",
    "ports-broken-binaries": "Broken binaries",
    "ports-unregistered-file": "Unregistered file in the prefix",
    "ports-stale-portindex": "PortIndex missing or older than 30 days",
    "ports-macports-user": "macports user or group missing or odd",
    "ports-registry-busy": "Another port process holds the registry",
    "ports-disk-usage": "Build, distfile and image directories size",
    "ports-dangling-plist": "Dangling owned MacPorts launchd plist",
    "ports-missing-selection": "Selected port select option not installed",
    "ports-no-binary-archives": "Configuration that disables binary archives",
    "ports-not-on-path": "PATH lacks the prefix's bin",
    "ports-usr-local-cellar": "/usr/local/Cellar present",
    "ports-registry-schema-update": "Registry awaiting its root-only schema update",
    "ports-replaced-port": "Installed port replaced by another",
    "ports-cannot-run": "port missing or unable to run while the registry holds ports",
    "ports-no-registry": "MacPorts prefix without a registry",
}

# Unregistered files: the directories walked, the ones whose regular files may be removed, and
# the generated files every prefix accumulates.
STRAY_TOPS = ("bin", "sbin", "lib", "include", "libexec", "Library/Frameworks",
              "share/man", "share/info", "share/doc", "share/aclocal", "share/pkgconfig")
REMOVABLE_TOPS = ("bin", "sbin", "lib", "include")
GENERATED_NAMES = frozenset(("gschemas.compiled", "mimeinfo.cache", "fonts.dir", "fonts.scale", "whatis"))
GENERATED_SUFFIXES = (".pyc", ".cache")

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
           remedies: Sequence[Action] = (), *, confirm_each: bool = False, repairs_install: bool = False,
           blocks: Sequence[Blocks] = (), title: str | None = None) -> Issue:
    """Build a `ports-` finding at its `SEVERITY`

    A flag holds only when the issue has a remedy the tool runs: a manual one is printed, never applied.

    @param code             the finding's code, which gives its severity and its default title
    @param subject          the port, path, label or group the finding is about, or None
    @param prefix           the instance's prefix, or None
    @param evidence         the evidence lines
    @param remedies         the remedies, in the order they are applied
    @param confirm_each     `doctor --fix` applies the remedies after a per-item prompt
    @param repairs_install  apply phase 2 applies them when the subject is a plan target or its dependency
    @param blocks           the plan contexts the finding blocks
    @param title            the title; None for the code's
    @returns                the finding
    """
    runs = any(not a.manual for a in remedies)
    return Issue(code=code, severity=SEVERITY[code], title=title or TITLES[code], subject=subject,
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


def _built(build: Callable[[], list[Action]]) -> tuple[list[Action], list[str]]:
    """Return the remedies of `build`, or none and the reason when it refuses a name or variant

    @param build  builds the remedies; ValueError for a registry name or variant `actions.py` refuses
    @returns      the remedies and no reason, or no remedies and the reason
    """
    try:
        return build(), []
    except ValueError as exc:
        return [], [f"no remedy: {exc}"]


def _port_remedies(site: _Site, build: Callable[[], list[Action]]) -> tuple[list[Action], list[str]]:
    """Return the remedies of `build` for a drivable instance only

    On an undrivable one, `port` runs only for the manager repairs and the creation of a missing registry.

    @param site   the instance's site
    @param build  builds the remedies
    @returns      the remedies and the reasons there are none, as `_built` gives them
    """
    if not site.drivable:
        return [], [f"no remedy while MacPorts at {site.prefix} is {site.instance.usability.value}"]
    return _built(build)


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


def _procedure_note(code: str, inst: Instance) -> Action:
    """Build the note offering the signed base package over the instance

    @param code  the finding's code
    @param inst  the MacPorts instance at `/opt/local`
    @returns     the note
    """
    return _note(code, inst.prefix, "base-package",
                 f"install the signed MacPorts base package over {inst.prefix}: the latest macports-base release for "
                 "this macOS, downloaded, staged, signature-checked against the pinned signer and installed with sudo "
                 "installer (uses the network; the registry stays)")


def _source_build_note(code: str, inst: Instance, then: str = "") -> Action:
    """Build the note telling the user to build base from source, the only way for a prefix other than `/opt/local`

    @param code  the finding's code
    @param inst  the MacPorts instance
    @param then  the text after the `./configure` command, such as a migrate step
    @returns     the note
    """
    return _note(code, inst.prefix, "source-build",
                 f"the MacPorts installer package installs to /opt/local only: build base {inst.version or ''} from "
                 f"source with ./configure --prefix={inst.prefix}{then}")


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


def _diagnose_issue(site: _Site, subject: str, text: str, evidence: Sequence[str]) -> Issue:
    """Build a `ports-diagnose-warning` finding whose remedy is the warning's text, as a note

    @param site      the instance's site
    @param subject   the port the warning names, or the prefix
    @param text      the warning
    @param evidence  the evidence lines
    @returns         the finding
    """
    return _issue("ports-diagnose-warning", subject, site.prefix, evidence,
                  [_note("ports-diagnose-warning", subject, "warning-" + _digest(text), text)])


def _diagnose_warnings(site: _Site, runner, notes: list[str]) -> list[Issue]:
    """Report each warning of `port -N diagnose --quiet` (drivable instances only), its text as the remedy

    Base warns once per missing file; those warnings fold into one issue per port, and the missing-file
    finding has the detail.

    @param site    the instance's site
    @param runner  the runner that runs `port diagnose`
    @param notes   receives a line when the probe is skipped or times out
    @returns       one finding per warning, or per port for the missing-file warnings
    """
    if not site.drivable:
        notes.append(f"{site.prefix}: port diagnose skipped: MacPorts there is {site.instance.usability.value}")
        return []
    result = runner.run(actions.diagnose(site.instance, site.host_arch, f"0.ports.{slug(site.prefix)}.diagnose"))
    if result.timed_out:
        notes.append(f"{site.prefix}: port diagnose timed out; its warnings may be incomplete")
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
            out.append(_diagnose_issue(site, site.prefix, value, ["port diagnose: " + value]))
            continue
        items = folded[value]
        text = items[0][1] if len(items) == 1 else f"{items[0][1]} (and {len(items) - 1} more files of {value})"
        missing = [f"port diagnose: missing {f}" for f, _ in items]
        out.append(_diagnose_issue(site, value, text, limited(missing, EVIDENCE_LIMIT)))
    return out


# The instance itself --------------------------------------------------------------------

def _migrate_remedies(site: _Site, code: str, inst: Instance) -> list[Action]:
    """Build `sudo port -N migrate --all`, then `sudo port -N sync`

    @param site  the instance's site
    @param code  the finding's code
    @param inst  the MacPorts instance
    @returns     the two remedies
    """
    return [actions.migrate_all(inst, site.host_arch, action_id(code, site.prefix, "migrate")),
            actions.sync(inst, site.host_arch, action_id(code, site.prefix, "sync"))]


def _platform_mismatch(site: _Site) -> list[Issue]:
    """Report base built for another platform: `PLATFORM_MISMATCH`, or another `os_major` in its autoconf

    Base 2.10.0 and newer migrates; an older base is replaced first, by the base package at `/opt/local`
    and elsewhere by a manual source build.

    @param site  the instance's site
    @returns     the finding, or none
    """
    code, inst = "ports-platform-mismatch", site.instance
    built = site.inv.autoconf.get("os_major") or ""
    if inst.usability is Usability.PLATFORM_MISMATCH:
        reason = inst.usability_detail or "base does not match this host"
    elif built.isdigit() and int(built) != site.running[1]:
        reason = f"base is built for Darwin {built}; this host runs Darwin {site.running[1]}"
    else:
        return []
    if "migrate" in inst.features and inst.binary:
        remedies, extra = _built(lambda: _migrate_remedies(site, code, inst))
    elif _at_default(inst, site.default_prefix):
        shown = _display_instance(inst, site.host_arch)
        remedies, extra = _built(lambda: [_procedure_note(code, inst),
                                          actions.sync(shown, site.host_arch, action_id(code, site.prefix, "sync")),
                                          actions.migrate_all(shown, site.host_arch,
                                                              action_id(code, site.prefix, "migrate"))])
    else:
        remedies, extra = [_source_build_note(code, inst, ", then run sudo port -N migrate --all")], []
    return [_issue(code, site.prefix, site.prefix, [reason] + extra, remedies, confirm_each=True,
                   blocks=(Blocks.TARGET,))]


def _damaged_registry(site: _Site) -> list[Issue]:
    """Report a failed registry backup, whatever `usability` says, listing the image archives

    A busy registry is its own finding; there is no remedy.

    @param site  the instance's site
    @returns     the finding, or none
    """
    inst = site.instance
    if inst.inventory_known or locate.registry_busy(inst):
        return []
    evidence = [inst.inventory_error or "the registry cannot be read"]
    archives = site.inv.image_archives
    evidence += [f"image archive: {name}: {', '.join(entries)}" for name, entries in sorted(archives.items())]
    if not archives:
        evidence.append(f"no image archive under {os.path.join(inst.portdbpath or '', 'software')}")
    return [_issue("ports-damaged-registry", site.prefix, site.prefix, evidence,
                   blocks=(Blocks.TARGET, Blocks.REMOVE))]


def _registry_busy(site: _Site) -> list[Issue]:
    """Report a `RegistryBusy` backup: no progress for 30 s, or a registry that keeps changing while it is copied

    @param site  the instance's site
    @returns     the finding, or none
    """
    if not locate.registry_busy(site.instance):
        return []
    code = "ports-registry-busy"
    return [_issue(code, site.prefix, site.prefix, [site.instance.inventory_error or ""],
                   [_note(code, site.prefix, "wait", "wait for the other port process to finish, then run "
                                                     "brew-ports again")],
                   blocks=(Blocks.ANY,))]


def _registry_schema_update(site: _Site) -> list[Issue]:
    """Report `READONLY_REGISTRY`; one root run of `port version` updates the schema

    @param site  the instance's site
    @returns     the finding, or none
    """
    code, inst = "ports-registry-schema-update", site.instance
    if inst.usability is not Usability.READONLY_REGISTRY:
        return []
    remedies, extra = _built(lambda: [actions.version(inst, site.host_arch, action_id(code, site.prefix, "version"),
                                                      sudo=True)])
    return [_issue(code, site.prefix, site.prefix, [inst.usability_detail or "the registry is read-only"] + extra,
                   remedies, confirm_each=True, blocks=(Blocks.TARGET,))]


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
    evidence = [inst.usability_detail or inst.usability.value,
                f"the registry holds {len(site.inv.rows)} port row(s)"]
    if _at_default(inst, site.default_prefix):
        shown = _display_instance(inst, site.host_arch)
        remedies, extra = _built(lambda: [_procedure_note(code, inst),
                                          actions.sync(shown, site.host_arch, action_id(code, site.prefix, "sync"))])
    else:
        remedies, extra = [_source_build_note(code, inst)], []
    return [_issue(code, site.prefix, site.prefix, evidence + extra, remedies, confirm_each=True,
                   blocks=(Blocks.TARGET,))]


def _no_registry(site: _Site) -> list[Issue]:
    """Report `NO_REGISTRY` with the inventory known to be empty (`locate.known_empty`)

    A lost registry with ports still installed is a damaged registry, and nothing recreates its file.

    @param site  the instance's site
    @returns     the finding, or none
    """
    code, inst = "ports-no-registry", site.instance
    if inst.usability is not Usability.NO_REGISTRY or not inst.inventory_known:
        return []
    remedies, extra = _built(lambda: [actions.version(inst, site.host_arch, action_id(code, site.prefix, "version"),
                                                      sudo=True)])
    return [_issue(code, site.prefix, site.prefix, [inst.usability_detail or "registry.db does not exist"] + extra,
                   remedies, confirm_each=True, blocks=(Blocks.TARGET,))]


# Registry rows ---------------------------------------------------------------------------

def _rebuild(site: _Site, code: str, pkg: Package) -> tuple[list[Action], list[str]]:
    """Return the missing-image remedy of an active row

    None for a `replaced_by` port, `upgrade -n` for an outdated one (its description naming the version
    change), else `upgrade_forced`.

    @param site  the instance's site
    @param code  the finding's code
    @param pkg   the active row's package
    @returns     the remedies, and the reasons there are none
    """
    name = pkg.name
    if pkg.renamed_to:
        return [], [f"{name} is replaced by {pkg.renamed_to}: reported only "
                    "(the replaced-port finding offers the replacement)"]
    entry = site.index.get(name) if site.index is not None else None
    if pkg.outdated and entry is not None:
        new = f"{entry.version}_{entry.revision}"

        def upgrade() -> list[Action]:
            act = actions.upgrade(site.instance, site.host_arch, action_id(code, name, "upgrade"), name,
                                  homebrew_present=site.homebrew_present, no_deps=True)
            return [dataclasses.replace(act,
                                        description=f"upgrade {name} from {pkg.version} to {new} in {site.prefix}")]
        return _port_remedies(site, upgrade)
    return _port_remedies(site, lambda: [actions.upgrade_forced(
        site.instance, site.host_arch, action_id(code, name, "rebuild"), name, pkg.requested_variants,
        homebrew_present=site.homebrew_present)])


def _uninstall_row(site: _Site, code: str, pkg: Package) -> tuple[list[Action], list[str]]:
    """Return the `sudo port -N uninstall <spec_args>` of one row

    @param site  the instance's site
    @param code  the finding's code
    @param pkg   the row's package
    @returns     the remedy, and the reasons there is none
    """
    return _port_remedies(site, lambda: [actions.uninstall(
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
        evidence = [f"{len(missing)} registered file(s) of {pkg.name} {pkg.spec_args[1]} are missing on disk"]
        evidence += limited(missing, EVIDENCE_LIMIT)
        if unchecked:
            evidence.append(f"{unchecked} file(s) could not be checked (counted as unchecked, not missing)")
        if not pkg.receipt_ok:
            remedies, extra = _rebuild(site, code, pkg)
            extra = ["its image is missing too: the missing-image remedy applies"] + extra
        else:
            remedies, extra = _port_remedies(site, functools.partial(_reactivate, site, pkg, loaded))
        out.append(_issue(code, pkg.name, site.prefix, evidence + extra, remedies, confirm_each=True,
                          repairs_install=True))
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
        location = row.location if row is not None and row.location else "(none recorded)"
        if pkg.active:
            evidence = [f"the image of the active {pkg.name} {pkg.spec_args[1]} is missing: {location}"]
            remedies, extra = _rebuild(site, code, pkg)
            out.append(_issue(code, pkg.name, site.prefix, evidence + extra, remedies, confirm_each=True,
                              repairs_install=True))
        else:
            evidence = [f"the image of the inactive {pkg.name} {pkg.spec_args[1]} is missing: {location}; "
                        "it can never be activated again"]
            remedies, extra = _uninstall_row(site, code, pkg)
            out.append(_issue(code, pkg.name, site.prefix, evidence + extra, remedies, confirm_each=True))
    return out


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
            versions = ", ".join(p.spec_args[1] for p in inactive)
            out.append(_issue(code, inactive[0].name, site.prefix,
                              [f"{inactive[0].name} has no active version ({versions}): deactivated on purpose, "
                               "not offered for removal"],
                              title="Inactive port without an active version"))
            continue
        for pkg in inactive:
            remedies, extra = _uninstall_row(site, code, pkg)
            out.append(_issue(code, pkg.name, site.prefix,
                              [f"{pkg.name} {pkg.spec_args[1]} is inactive beside the active {active.spec_args[1]}"]
                              + extra,
                              remedies, confirm_each=True))
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
        remedies, extra = _uninstall_row(site, code, pkg)
        out.append(_issue(code, pkg.name, site.prefix,
                          [f"{pkg.name} {pkg.spec_args[1]} is not requested and no installed port depends on it"]
                          + extra, remedies, confirm_each=True))
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
        out.append(_issue("ports-obsolete-port", pkgs[0].name, site.prefix,
                          [f"{pkgs[0].name} is not in the PortIndex {site.index.path}: mapped at plan time through the "
                           "static map and, with plan --repology, Repology"]))
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
        remedies, extra = _port_remedies(site, build)
        out.append(_issue(code, pkg.name, site.prefix, [f"{pkg.name} is replaced by {pkg.renamed_to}"] + extra,
                          remedies, confirm_each=True))
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
    odd = [f"{pkg.name} {pkg.spec_args[1]}: {row.os_platform or ''} {row.os_major}"
           for pkg, row in zip(site.inv.packages, site.inv.rows)
           if pkg.active and _other_major(row.os_major, site.running[1])]
    if not odd:
        return []
    evidence = [f"{len(odd)} active port(s) were built for another Darwin major than {site.running[1]}"]
    evidence += limited(odd, EVIDENCE_LIMIT)
    if "migrate" in inst.features:
        remedies, extra = _built(lambda: _migrate_remedies(site, code, inst))
    else:
        remedies, extra = [_note(code, site.prefix, "manual",
                                 f"base {inst.version or ''} has no port migrate: run sudo port selfupdate "
                                 "(base 2.10.0 and newer have it), then sudo port -N migrate --all")], []
    return [_issue(code, site.prefix, site.prefix, evidence + extra, remedies, confirm_each=True,
                   blocks=(Blocks.TARGET,))]


# Broken binaries -----------------------------------------------------------------------

_CPU_TYPES = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32",
              18: "ppc", 0x01000012: "ppc64"}
_THIN_BE = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
_THIN_LE = (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
_FAT_ENTRY_SIZE = {b"\xca\xfe\xba\xbe": 20, b"\xca\xfe\xba\xbf": 32}
_MAX_FAT_ARCHS = 30


def macho_archs(path: str) -> frozenset[str] | None:
    """Return the architectures in a Mach-O header

    A thin file has one cputype and a fat one several; more than 30 entries is a Java class file.

    @param path  the file
    @returns     the architecture names; None for a file that is no Mach-O or cannot be read
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
            if len(head) < 8:
                return None
            magic = head[:4]
            if magic in _THIN_BE:
                cpus = [struct.unpack(">i", head[4:8])[0]]
            elif magic in _THIN_LE:
                cpus = [struct.unpack("<i", head[4:8])[0]]
            elif magic in _FAT_ENTRY_SIZE:
                count = struct.unpack(">I", head[4:8])[0]
                size = _FAT_ENTRY_SIZE[magic]
                if count > _MAX_FAT_ARCHS:
                    return None
                table = fh.read(count * size)
                if len(table) < count * size:
                    return None
                cpus = [struct.unpack(">i", table[i * size:i * size + 4])[0] for i in range(count)]
            else:
                return None
    except OSError:
        return None
    return frozenset(_CPU_TYPES.get(cpu, f"cpu{cpu}") for cpu in cpus)


def arch_gaps(binary: str, references: Sequence[Mapping[str, Any]], wanted: set[str],
              cache: dict[str, frozenset[str] | None] | None = None) -> list[str]:
    """Return each "missing arch inside the prefix", as `rev-upgrade` decides it

    A library the binary loads from its own prefix (an `own` reference) lacks one of the binary's
    architectures. Only the architectures the host or the instance runs are checked.

    @param binary      the binary
    @param references  the binary's linkage references, with their `class` and `resolved` path
    @param wanted      the architectures to check, the host's and the instance's
    @param cache       the architectures of each path read so far, shared across calls; None for a fresh one
    @returns           one `<library> lacks <archs>` line per gap
    """
    cache = {} if cache is None else cache

    def archs(path: str) -> frozenset[str] | None:
        if path not in cache:
            cache[path] = macho_archs(path)
        return cache[path]

    have = archs(binary)
    need = set(have or ()) & wanted
    if not need:
        return []
    out: list[str] = []
    for ref in references:
        lib = ref.get("resolved")
        if ref.get("class") != "own" or not lib:
            continue
        lib_archs = archs(lib)
        if lib_archs is None:
            continue
        lacking = sorted(need - lib_archs)
        gap = f"{lib} lacks {', '.join(lacking)}"
        if lacking and gap not in out:
            out.append(gap)
    return out


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
        lines = [f"{path}: missing {ref.get('name')}" for ref in refs if ref.get("class") == "missing"]
        lines += [f"{path}: {gap}" for gap in arch_gaps(path, refs, wanted, cache)]
        if lines:
            found.setdefault(name.lower(), []).extend(lines)
            names.setdefault(name.lower(), name)
    out = []
    for key, lines in found.items():
        active = next((p for p in site.inv.packages if p.active and p.name.lower() == key), None)
        remedies: list[Action]
        if active is None:
            remedies, extra = [], [f"no active row of {names[key]} in the registry"]
        else:
            def rebuild(pkg: Package = active) -> list[Action]:
                return [actions.upgrade_forced(
                    site.instance, site.host_arch, action_id("ports-broken-binaries", pkg.name, "rebuild"),
                    pkg.name, pkg.requested_variants, homebrew_present=site.homebrew_present)]
            remedies, extra = _port_remedies(site, rebuild)
        out.append(_issue("ports-broken-binaries", active.name if active else names[key], site.prefix,
                          limited(lines, EVIDENCE_LIMIT) + extra, remedies, confirm_each=True, repairs_install=True))
    return out


# Unregistered files ---------------------------------------------------------------------

def _walk(top: str) -> Iterator[tuple[str, os.stat_result]]:
    """Yield every entry below `top` that is not a real directory, symlinks included, with its `lstat`

    `__pycache__` directories are skipped, and an unreadable directory holds nothing.

    @param top  the directory to walk
    @returns    an iterator over the paths and their `lstat`, in name order
    """
    try:
        with os.scandir(top) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError:
        return
    progress.count(len(entries))
    for entry in entries:
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode):
            if entry.name != "__pycache__":
                yield from _walk(entry.path)
        else:
            yield entry.path, st


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


def _gem_entries(gem_dir: str, name: str | None) -> tuple[list[str], list[str]]:
    """Return the files and directories RubyGems keeps for one installed gem in its gem home

    They are `specifications/<gem>.gemspec`, `cache/<gem>.gem`, `build_info/<gem>.info` and `plugins/<name>_plugin.rb`,
    then the gem directory, `doc/<gem>/` and each `extensions/<platform>/<api version>/<gem>/`; `<gem>` is the gem
    directory's name, and the gem home holds its `gems/`.

    @param gem_dir  the gem's directory, `<gem home>/gems/<name>-<version>[-<platform>]`
    @param name     the gem's name; None when its directory's name gives none
    @returns        the files, then the directories
    """
    home, gem = os.path.dirname(os.path.dirname(gem_dir)), os.path.basename(gem_dir)
    files = [os.path.join(home, sub, gem + ext)
             for sub, ext in (("specifications", ".gemspec"), ("cache", ".gem"), ("build_info", ".info"))]
    if name:
        files.append(os.path.join(home, "plugins", name + "_plugin.rb"))
    dirs = [gem_dir, os.path.join(home, "doc", gem)]
    dirs += glob.glob(os.path.join(glob.escape(home), "extensions", "*", "*", glob.escape(gem)))
    return files, dirs


def _auto_trees(path: str, module: str | None) -> list[str]:
    """Return the `auto/<Module>/` directories of a cpan module, which hold its XS parts and its `.packlist`

    They lie in the directory its module path starts in, or in an architecture directory below that one, where a
    pure-Perl module's `.packlist` goes.

    @param path    the module's `.pm` file
    @param module  the module, such as `JSON::XS`
    @returns       the directories; none when the path does not end in the module's own path
    """
    rel = (module or "").replace("::", "/")
    if not rel or not path.endswith("/" + rel + ".pm"):
        return []
    top = path[:-len(rel + ".pm")]
    return [os.path.join(top, "auto", rel)] + glob.glob(os.path.join(glob.escape(top), "*", "auto", glob.escape(rel)))


class _Extras:
    """What the interpreter-extras scan attributes inside one prefix, which the stray-file removal leaves alone

    They are its `attributed` entry points; each gem with what RubyGems keeps for it; each cpan module with its
    `auto/` trees; the npm directories; and the prefix's site-packages.
    """

    def __init__(self, extras: Mapping[str, Any], prefix: str) -> None:
        """Collect the exact paths and the directory roots the extras of one prefix own

        @param extras  the interpreter-extras scan
        @param prefix  the instance's prefix
        """
        mine = {key: [item for item in extras.get(key) or [] if item.get("instance_prefix") == prefix
                      and item.get("path")] for key in ("npm", "gems", "cpan")}
        exact = list(extras.get("attributed") or []) + [item["path"] for item in mine["cpan"]]
        roots = [item["path"] for item in mine["npm"]]
        for item in mine["gems"]:
            files, dirs = _gem_entries(item["path"], item.get("name"))
            exact += files
            roots += dirs
        for item in mine["cpan"]:
            roots += _auto_trees(item["path"], item.get("module"))
        roots += [item["site_packages"] for item in extras.get("python") or []
                  if item.get("instance_prefix") == prefix and item.get("site_packages")]
        self.exact: set[str] = {os.path.realpath(p) for p in exact}
        self.roots = [os.path.realpath(r).rstrip("/") + "/" for r in roots]

    def owns(self, path: str) -> bool:
        """Return whether an interpreter extra owns a path, compared after symlinks are resolved

        @param path  an absolute path
        @returns     True for an attributed path or one below an owned directory
        """
        real = os.path.realpath(path)
        return real in self.exact or any(real.startswith(root) for root in self.roots)


def _generated(path: str, info_dir: str) -> bool:
    """Return whether a file is one that every prefix generates, such as a cache or the info `dir`

    @param path      the file
    @param info_dir  the prefix's `share/info/dir`
    @returns         True for a generated file
    """
    name = os.path.basename(path)
    return path == info_dir or name in GENERATED_NAMES or name.endswith(GENERATED_SUFFIXES)


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
    owned = _Extras(extras, site.prefix)
    removable: list[str] = []
    listed: list[str] = []
    for top in STRAY_TOPS:
        for path, st in _walk(os.path.join(root, top)):
            if _generated(path, info_dir) or inv.is_base_file(path):
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
                listed.append(f"{path} ({reason})")
    out = [_stray(site, path) for path in removable]
    if listed:
        out.append(_issue("ports-unregistered-file", site.prefix, site.prefix, listed,
                          title="Unregistered files in the prefix (listed)"))
    return out


def _listed_reason(path: str, st: os.stat_result, top: str, links: Mapping[str, str], owned: _Extras) -> str | None:
    """Return why an unregistered file is listed and not offered for removal

    @param path   the file
    @param st     its `lstat`
    @param top    the walked directory it lies under, relative to the prefix
    @param links  the group of each path `port select` links
    @param owned  what the interpreter extras own
    @returns      the reason; None for a file offered for removal
    """
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if not stat.S_ISREG(st.st_mode):
        return "not a regular file"
    if top not in REMOVABLE_TOPS:
        return "outside bin, sbin, lib and include"
    if path in links:
        return f"linked by the port select group {links[path]}"
    if owned.owns(path):
        return "interpreter extras"
    return None


def _stray(site: _Site, path: str) -> Issue:
    """Build the finding of one removable stray: archive it with `tar` under the run, then remove it

    @param site  the instance's site
    @param path  the unregistered file
    @returns     the finding; listed only without a run directory
    """
    code = "ports-unregistered-file"
    evidence = [f"{path} is not registered to any port"]
    if site.run_path is None:
        return _issue(code, path, site.prefix, evidence + ["no run directory to archive it into: listed only"])
    dst = os.path.join(site.run_path, "backup", "strays", slug(path) + ".tar")
    archive = Action(action_id=action_id(code, path, "tar"), kind="command",
                     argv=[TAR, "-cf", "-", "-C", "/", path.lstrip("/")], sudo=True,
                     description=f"archive {path} into {dst}", dst=dst)
    remove = Action(action_id=action_id(code, path, "rm"), kind="command", argv=[RM, path], sudo=True,
                    description=f"remove the unregistered file {path}")
    return _issue(code, path, site.prefix, evidence, [archive, remove], confirm_each=True)


# Configuration and environment ----------------------------------------------------------------

def _stale_portindex(site: _Site, environ: Mapping[str, str], clock: float) -> list[Issue]:
    """Report a default-source PortIndex that is missing or whose mtime is older than 30 days

    @param site     the instance's site
    @param environ  the environment, whose `HOME` holds the user's macports.conf
    @param clock    the clock's time, in seconds since the epoch
    @returns        the finding, or none
    """
    path = mp_portindex.index_path(site.instance, environ)
    if path is None:
        evidence = ["sources.conf names no default source"]
    else:
        try:
            age = clock - os.stat(path).st_mtime
        except OSError:
            evidence = [f"{path} does not exist"]
        else:
            if age <= PORTINDEX_MAX_AGE_S:
                return []
            evidence = [f"{path} is {int(age // 86400)} days old"]
    code = "ports-stale-portindex"
    return [_issue(code, site.prefix, site.prefix, evidence,
                   [_note(code, site.prefix, "refresh", "brew-ports plan --refresh (runs sudo port -N sync)")])]


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
    if result.exit != 0:
        detail = (result.stderr().strip() or f"dscl exited {result.exit}").splitlines()[0]
        problems = [f"the macports user does not exist ({detail})"]
    else:
        fields = system.parse_dscl(result.stdout())
        uid, shell, home = fields.get("UniqueID", ""), fields.get("UserShell", ""), fields.get("NFSHomeDirectory", "")
        expected_home = os.path.join(site.instance.portdbpath or "", "home")
        problems = []
        if not uid.isdigit() or int(uid) <= 500:
            problems.append(f"UniqueID is {uid or 'missing'}, not a number above 500")
        if shell != "/usr/bin/false":
            problems.append(f"UserShell is {shell or 'missing'}, not /usr/bin/false")
        if os.path.normpath(home or "/") != os.path.normpath(expected_home):
            problems.append(f"NFSHomeDirectory is {home or 'missing'}, not {expected_home}")
    if not problems:
        return []
    code = "ports-macports-user"
    return [_issue(code, "macports", site.prefix, problems,
                   [_note(code, site.prefix, "manual", "reinstall the MacPorts base package, whose installer "
                                                       "creates the macports user and group")])]


def _disk_usage(site: _Site, runner) -> list[Issue]:
    """Report the `du -sk` sizes of the existing `build`, `distfiles` and `software` directories

    @param site    the instance's site
    @param runner  the runner that runs `du`
    @returns       the finding; none without those directories
    """
    base = site.instance.portdbpath
    if not base:
        return []
    dirs = [d for d in (os.path.join(base, sub) for sub in ("build", "distfiles", "software")) if os.path.isdir(d)]
    if not dirs:
        return []
    result = runner.run(system.probe(f"0.ports.{slug(site.prefix)}.du", [DU, "-sk"] + dirs,
                                     f"size of the build, distfile and image directories of {site.prefix}"))
    evidence = []
    for line in result.stdout().splitlines():
        size, _, path = line.partition("\t")
        if size.strip().isdigit() and path:
            evidence.append(f"{path.strip()}: {int(size) / 1024.0:.1f} MiB")
    if not evidence:
        evidence = [f"du could not size {', '.join(dirs)}"]
    code = "ports-disk-usage"
    return [_issue(code, site.prefix, site.prefix, evidence,
                   [_note(code, site.prefix, "manual",
                          "sudo port -N clean --all <name> per port, or sudo port reclaim run by you on a terminal "
                          "(without -N it asks before each removal)")])]


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
            found.append(f"{key} {value} (binary archives are built for {default})")
    platform = site.running
    cxx = config.get("cxx_stdlib")
    default_cxx = mp_inventory.configured_cxx_stdlib({}, platform)
    if cxx and cxx != default_cxx:
        found.append(f"cxx_stdlib {cxx} (binary archives use {default_cxx or 'none'})")
    la = config.get("delete_la_files")
    default_la = platform[0] == "darwin" and platform[1] >= 13
    if la is not None and la.strip() and _tcl_true(la) != default_la:
        found.append(f"delete_la_files {la} (binary archives use {'yes' if default_la else 'no'})")
    if (config.get("buildfromsource") or "").strip() == "always":
        found.append("buildfromsource always")
    if not found:
        return []
    return [_issue("ports-no-binary-archives", site.prefix, site.prefix,
                   found + [f"ports of {site.prefix} are built from source"])]


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
    """Report a live PATH without `<prefix>/bin`; `env-cleanup` adds its PATH line

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
    return [_issue(code, bin_dir, site.prefix, [f"{bin_dir} is not on the live PATH"],
                   [_note(code, bin_dir, "env-cleanup",
                          "brew-ports env-cleanup (it adds the PATH line to the login file of your shell)")],
                   title=f"PATH lacks {bin_dir}")]


def _usr_local_cellar(bundle, usr_local_cellar: str) -> list[Issue]:
    """Report `/usr/local/Cellar` beside a MacPorts instance, as `port diagnose` warns

    The Homebrew finding for several prefixes carries the detail.

    @param bundle            the scan bundle
    @param usr_local_cellar  the path of `/usr/local/Cellar`
    @returns                 the finding; none without a MacPorts instance or the directory
    """
    if not bundle.ports or not os.path.isdir(usr_local_cellar):
        return []
    return [_issue("ports-usr-local-cellar", usr_local_cellar, None,
                   [f"{usr_local_cellar} exists: Homebrew in /usr/local (brew-several-prefixes has the detail)"])]


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
        why = "is a symlink whose target is gone" if dangling else f"runs {svc.program}, which is gone"
        evidence = [f"{svc.plist} {why}"]
        if svc.scope == "system":
            target, sudo = f"system/{svc.label}", True
        else:
            domain = svc.domain or f"gui/{uid}"
            target, sudo = f"{domain}/{svc.label}", False
        bootout = Action(action_id=action_id(code, svc.label, "bootout"), kind="command",
                         argv=[env_services.LAUNCHCTL, "bootout", target], sudo=sudo,
                         description=f"unload {target} (exit 3: it was not loaded)", on_failure=OnFailure.PROBE)
        remove = Action(action_id=action_id(code, svc.label, "rm"), kind="command", argv=[RM, svc.plist], sudo=True,
                        description=f"remove the dangling plist {svc.plist}")
        out.append(_issue(code, svc.label, site.prefix, evidence, [bootout, remove], confirm_each=True))
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
        why = "whose option file is gone" if gone else "which no active port provides"
        evidence = [f"the {group.name} group selects {current}, {why}"]

        def clear(group: mp_inventory.SelectGroup = group) -> list[Action]:
            return [dataclasses.replace(actions.select_set(
                shown, site.host_arch, action_id("ports-missing-selection", group.name, "select"), group.name,
                "none"), manual=True)]
        remedies, extra = _built(clear)
        out.append(_issue("ports-missing-selection", group.name, site.prefix, evidence + extra, remedies))
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
        lambda s: _disk_usage(s, runner),
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
    return issues


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
    if not issue.remedies:
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
        if any(ref.get("class") == "missing" for ref in refs) or arch_gaps(path, refs, wanted):
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
    """The report lines of one manager repair, also shown on the console as they come"""

    def __init__(self, code: str, prefix: str, console) -> None:
        """Start an empty report

        @param code     the repair's finding code, which starts every line
        @param prefix   the instance's prefix, after the code
        @param console  where each line is shown as it comes; None shows nothing
        """
        self.code, self.prefix, self.console = code, prefix, console
        self.lines: list[str] = []

    def __call__(self, text: str) -> None:
        """Add a line to the report and show it

        @param text  the line, without the code and the prefix
        """
        line = f"{self.code} {self.prefix}: {text}"
        self.lines.append(line)
        if self.console is not None:
            self.console.info(line)


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
    @param inst     the MacPorts instance, located again
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
    if code == "ports-built-for-other-os" and inst.usability is Usability.USABLE:
        rows = _fresh_rows(inst.portdbpath)
        return rows is None or any(row.active and _other_major(row.os_major, running[1]) for row in rows)
    return inst.usability is Usability.USABLE


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
    result = _probe_run(runner, actions.sync(inst, runner.host_arch, action_id(code, inst.prefix, "sync")))
    outcome = "done" if result.exit == 0 else f"exited {result.exit}; run brew-ports plan --refresh later"
    say(f"sudo port -N sync {outcome}")


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
        say("the base package procedure was declined; nothing changed")
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
        say(f"the registry backup failed ({type(exc).__name__}: {exc}); migrate --all was not run")
        return
    say(f"registry backup, installed.txt and services.json written to {directory}")
    loaded: dict[str, str] = {}
    for svc in services:
        if svc.owned and svc.package and svc.package_kind == "port" and svc.loaded:
            loaded.setdefault(svc.package.lower(), svc.package)
    result = _probe_run(runner, actions.migrate_all(inst, host, action_id(code, inst.prefix, "migrate")))
    say(f"sudo port -N migrate --all exited {result.exit}")
    after = _fresh_rows(inst.portdbpath)
    if after is None:
        say(f"the registry cannot be read after migrate; compare with {os.path.join(directory, 'installed.txt')}")
    else:
        active_after = {r.name.lower() for r in after if r.active}
        trace = bool(brew_locate.candidate_prefixes(environ))
        for row in rows:
            if row.active and row.name.lower() not in active_after:
                line = actions.install(inst, host, action_id(code, os.path.join(inst.prefix, row.name), "reinstall"),
                                       row.name,
                                       row.requested_variant_tokens, homebrew_present=trace, binary_first=False)
                say(f"{row.name} {row.spec_args[1]} was active before migrate and is inactive after it: "
                    f"sudo {shlex.join(line.argv)}")
        for key, name in sorted(loaded.items()):
            if key not in active_after:
                continue
            load = _probe_run(runner, actions.load(inst, host, action_id(code, os.path.join(inst.prefix, name), "load"),
                                                   name))
            outcome = "loaded again" if load.exit == 0 else f"not loaded: sudo port -N load {name} exited {load.exit}"
            say(f"startup item of {name} {outcome}")
    if then_sync:
        _sync(runner, _relocate(runner, environ, inst.prefix, default_prefix, platform) or inst, code, say)
    if result.exit != 0:
        raise ActionFailed(result)


def manager_repair(issue: Issue, runner, run_dir: RunDir, environ: Mapping[str, str], console, *,
                   confirm: Callable[[str], bool], default_prefix: str = locate.DEFAULT_PREFIX,
                   platform: locate.Platform | None = None) -> list[str]:
    """Run one of the `MANAGER_REPAIRS`, confirmed by the caller

    The instance is located again first and a cleared condition is skipped; `confirm(text)` is asked
    before a base package procedure, and a failed step raises, `migrate --all` only after its report.

    @param issue            the finding, whose code names the repair
    @param runner           the runner that runs the repair
    @param run_dir          the run directory that keeps the records and the downloads
    @param environ          the environment the instances are located with
    @param console          where each report line is shown as it comes; None shows nothing
    @param confirm          asks the user a question and returns the answer
    @param default_prefix   the default MacPorts prefix
    @param platform         the running platform; None reads it from the host
    @returns                the report lines
    @throws ActionFailed    a `port` step or the installer failed; `migrate --all` raises after its report
    @throws BootstrapError  the base package cannot be had, is not signed by a pinned signer, or leaves no instance
    """
    if issue.code not in MANAGER_REPAIRS or not issue.instance_prefix:
        raise ValueError(f"{issue.code} is not a MacPorts manager repair")
    say = _Report(issue.code, issue.instance_prefix, console)
    running = platform or locate.running_platform()
    inst = _relocate(runner, environ, issue.instance_prefix, default_prefix, platform)
    if inst is None:
        say("no MacPorts instance is found there any more")
        return say.lines
    if not _still_holds(issue.code, inst, running):
        say(f"the condition has cleared (MacPorts there is {inst.usability.value}); nothing to do")
        return say.lines
    host = runner.host_arch
    mismatch = issue.code == "ports-platform-mismatch"
    if issue.code == "ports-registry-schema-update":
        runner.run(actions.version(inst, host, action_id(issue.code, inst.prefix, "version"), sudo=True))
        relocated = _relocate(runner, environ, inst.prefix, default_prefix, platform)
        say(f"sudo port -N version done; MacPorts there is {relocated.usability.value if relocated else 'not found'}")
        return say.lines
    migrate_ready = "migrate" in inst.features and bool(inst.binary)
    if issue.code == "ports-built-for-other-os" or (mismatch and migrate_ready):
        if not migrate_ready:
            say(f"base {inst.version or ''} has no port migrate: "
                "run sudo port selfupdate, then sudo port -N migrate --all")
            return say.lines
        _migrate(runner, run_dir, environ, inst, issue.code, say=say, default_prefix=default_prefix, platform=platform,
                 then_sync=True)
        return say.lines
    if not _at_default(inst, default_prefix):
        say(_source_build_note(issue.code, inst, ", then run sudo port -N migrate --all"
                               if mismatch else "").description)
        return say.lines
    version = _confirm_procedure(runner, confirm, say)
    if version is None:
        return say.lines
    new = bootstrap.bootstrap(runner, run_dir, environ, host, macos_version=version, default_prefix=default_prefix)
    say(f"MacPorts base {new.version or ''} installed and synced; MacPorts there is {new.usability.value}")
    if mismatch:
        if "migrate" not in new.features:
            say(f"the new base {new.version or ''} has no port migrate")
            return say.lines
        _migrate(runner, run_dir, environ, new, issue.code, say=say, default_prefix=default_prefix, platform=platform,
                 then_sync=False)
    return say.lines

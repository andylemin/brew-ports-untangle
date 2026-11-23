"""`brew-ports doctor`: the system and environment detectors, the rule that blocks a plan, the report and `--fix`

The `brew-*` and `ports-*` detectors live in `homebrew/health.py` and `macports/health.py`, imported on first use.
"""

from __future__ import annotations

import importlib
import os
import sqlite3
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from . import doctor_report, env, envclean, model, progress, scan, servicectl, snapshot, state, system
from .context import Context
from .env import interpreters as env_interpreters, linkage as env_linkage, shell as env_shell
from .homebrew import actions as brew_actions, inventory as brew_inventory, locate as brew_locate
from .homebrew.catalogue import version_key
from .macports import actions as mp_actions, locate as mp_locate, registry
from .model import Action, Blocks, Instance, Issue, Manager, PackageKey, Service, Severity, name_key
from .report import COMMAND_OF, SCAN_REUSED, at, by_kind, counted, limited, series, some, tilde, typed
from .runner import ActionFailed, BaseRunner, EscalationFailed, Interrupted, PreflightError, start_run

# The exit codes of cli.py.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_PREFLIGHT = 3
EXIT_ACTION = 4

GIB = 1024 ** 3
LOW_SPACE_BYTES = 5 * GIB          # system-low-disk-space
EVIDENCE_SHOWN = 3                 # evidence lines under a finding that stops a move; `doctor` shows them all
FAMILY_ORDER = {"system": 0, "brew": 1, "ports": 2, "env": 3}
HEALTH_MODULES = {"brew": "brew_ports.homebrew.health", "ports": "brew_ports.macports.health"}
SPLIT_PAIRS = (("python3", "pip3"), ("perl", "cpan"), ("ruby", "gem"), ("node", "npm"))
DYLD_PREFIX_VARS = ("DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH")
USR_LOCAL = "/usr/local"
LEAF = "ports-unrequested-leaf"
REGISTRY_ERRORS = (registry.RegistryMissing, registry.RegistryBusy, sqlite3.DatabaseError, OSError)
EXTRA_FILES = {"pipx": "pipx-venvs.txt", "npm": "npm-globals.txt", "gems": "gems.txt", "cpan": "cpan-modules.txt"}
EXTRA_LABELS = {"pipx": "pipx tools", "npm": "npm packages", "gems": "Ruby gems", "cpan": "Perl modules"}
EXTRA_TOOLS = {"pipx": "pipx", "npm": "npm", "gems": "gem", "cpan": "cpan"}
# A PATH finding -> the manager whose `env-cleanup --target` mends it, and the fix line of the installation it keeps.
ENV_CLEANUP = {
    "brew-path-order": ("brew", "Fix, if this is the Homebrew you keep: `brew-ports env-cleanup --target brew "
                                "--apply` puts it in front of /usr/bin in your shell's login file; it shows the "
                                "change and asks first."),
    "ports-not-on-path": ("ports", "Fix, if this is the MacPorts you keep: `brew-ports env-cleanup --target ports "
                                   "--apply` adds it to the PATH in your shell's login file; it shows the change "
                                   "and asks first."),
}


# Building issues -------------------------------------------------------------------

def _family_of(code: str) -> str:
    """Return the family of a finding name, the part before its first `-`

    @param code  a finding name, such as `brew-unlinked-keg`
    @returns     the family, such as `brew`
    """
    return code.split("-", 1)[0]


def remedy_id(code: str, subject: str | None, step: str) -> str:
    """Return the action id of a remedy step, each slash of a path subject turned into `%`

    The id is `doctor.<name>.<subject>.<step>`, the subject `host` for a finding about the host.

    @param code     the finding's name
    @param subject  the finding's subject; None for the host
    @param step     the step that ends the id
    @returns        the action id
    """
    return f"doctor.{code}.{state.slug(subject or 'host')}.{step}"


def note(code: str, subject: str | None, text: str) -> Action:
    """Return a remedy the tool never runs, printed verbatim

    @param code     the finding's name
    @param subject  the finding's subject, for the action id; None for the host
    @param text     the text printed
    @returns        the note action
    """
    return Action(action_id=remedy_id(code, subject, "note"), kind="note", argv=[], sudo=False, description=text,
                  manual=True)


def manual(code: str, subject: str | None, step: str, argv: Sequence[str], description: str, *,
           sudo: bool = False) -> Action:
    """Return a command printed for the user to run, never run by the tool

    @param code         the finding's name
    @param subject      the finding's subject, for the action id; None for the host
    @param step         the step that ends the action id
    @param argv         the command
    @param description  the text printed with it
    @param sudo         print it under `sudo`
    @returns            the action
    """
    return Action(action_id=remedy_id(code, subject, step), kind="command", argv=list(argv), sudo=sudo,
                  description=description, manual=True)


def _issue(code: str, severity: Severity, title: str, subject: str | None = None, prefix: str | None = None, *,
           evidence: Iterable[str] = (), remedies: Iterable[Action] = (), auto_fix: bool = False,
           confirm_each: bool = False, repairs_install: bool = False, blocks: Iterable[Blocks] = ()) -> Issue:
    """Return a finding of the host and environment checks

    @param code             the finding's name
    @param severity         how much it matters; a CRITICAL finding blocks every plan
    @param title            the title the report prints with the name
    @param subject          the package, path or service it is about, or None
    @param prefix           the instance it is about, or None
    @param evidence         what the check found
    @param remedies         the remedies, applied in order
    @param auto_fix         `doctor --fix` applies it without a per-item prompt
    @param confirm_each     `doctor --fix` applies it after a per-item prompt
    @param repairs_install  apply phase 2 applies it when the subject is a plan target or its dependency
    @param blocks           the plan contexts it blocks while it holds
    @returns                the finding
    """
    return Issue(code=code, severity=severity, title=title, subject=subject, instance_prefix=prefix,
                 evidence=list(evidence), remedies=list(remedies), auto_fix=auto_fix, confirm_each=confirm_each,
                 repairs_install=repairs_install, blocks=tuple(blocks))


def _line_subject(record: dict[str, Any]) -> str:
    """Return the `file:lineno` subject of a shell file record

    @param record  a record of the shell analysis
    @returns       the file and the line number
    """
    return f"{record.get('file')}:{record.get('lineno')}"


def _line(record: dict[str, Any]) -> str:
    """Return a shell file record's place as the report names it

    @param record  a record of the shell analysis
    @returns       such as `~/.bashrc line 42`
    """
    return f"{tilde(str(record.get('file')))} line {record.get('lineno')}"


def _records(environment: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    """Return the shell analysis records of one kind

    @param environment  the scan's environment analysis
    @param kind         the record kind, such as `dyld`, `build` or `source`
    @returns            the records, in the scan's order
    """
    return [r for r in environment.get("records") or [] if r.get("kind") == kind]


# System ------------------------------------------------------------------------------

def _clt_missing(facts: dict[str, Any]) -> list[Issue]:
    """Flag a failing `xcode-select -p`, or a Command Line Tools directory without its receipt

    @param facts  the scan's system facts
    @returns      at most one finding
    """
    if "developer_dir" not in facts:
        return []
    selected = facts.get("developer_dir")
    no_receipt = bool(facts.get("clt_dir_exists")) and not facts.get("clt_receipt")
    if selected and not no_receipt:
        return []
    evidence = []
    if not selected:
        evidence.append("`xcode-select -p` finds no developer folder")
    if no_receipt:
        evidence.append(f"{system.CLT_DIR} exists, but macOS has no install record of it")
    remedies = [manual("system-clt-missing", None, "install", [system.XCODE_SELECT, "--install"], ""),
                note("system-clt-missing", None, "Or reinstall them through Software Update.")]
    return [_issue("system-clt-missing", Severity.HIGH, "Apple's Command Line Tools are missing, or macOS has no "
                   "record of them", None, None, evidence=evidence, remedies=remedies, blocks=(Blocks.ANY,))]


def _xcode_license(facts: dict[str, Any]) -> list[Issue]:
    """Flag an Xcode.app developer directory whose licence `xcodebuild -license check` rejects

    @param facts  the scan's system facts
    @returns      at most one finding
    """
    if facts.get("xcode_license_ok") is not False:
        return []
    return [_issue("system-xcode-license", Severity.HIGH, "The Xcode licence has not been accepted",
                   facts.get("developer_dir"), None,
                   evidence=[f"`xcodebuild -license check` fails for {facts.get('developer_dir')}"],
                   remedies=[manual("system-xcode-license", None, "license", [system.XCODEBUILD, "-license", "accept"],
                                    "", sudo=True)], blocks=(Blocks.ANY,))]


def _running_as_root(environ: dict[str, str]) -> list[Issue]:
    """Flag running as root or under sudo, which cli.py refuses with exit 3 first

    @param environ  the environment, where `SUDO_USER` shows a run under sudo
    @returns        at most one finding
    """
    if os.geteuid() != 0 and "SUDO_USER" not in environ:
        return []
    evidence = ["effective uid 0"] if os.geteuid() == 0 else ["SUDO_USER is set"]
    return [_issue("system-running-as-root", Severity.CRITICAL, "brew-ports is running as root or under sudo", None,
                   None, evidence=evidence,
                   remedies=[note("system-running-as-root", None, "Fix: run brew-ports as yourself, without sudo.")],
                   blocks=(Blocks.ANY,))]


def _running_inside_prefix(facts: dict[str, Any], instances: Sequence[Instance]) -> list[Issue]:
    """Flag a Python or a brew-ports copy inside a prefix, where the plan's own installs and removals reach it

    The paths are judged by file identity alone: they exist while the tool runs.

    @param facts      the scan's system facts, with `python_path` and `tool_path`
    @param instances  every instance the scan found
    @returns          one finding per path that lies inside a prefix
    """
    index = env.PrefixIndex(instances)
    out = []
    for key, what in (("python_path", "The Python that runs brew-ports"), ("tool_path", "brew-ports")):
        path = facts.get(key)
        inst = index.by_identity(path) if path else None
        if inst is None:
            continue
        out.append(_issue("system-running-inside-prefix", Severity.CRITICAL, f"{what} is inside {at(inst)}, which a "
                          "move may change", path, inst.prefix, evidence=[f"it is {path}"],
                          remedies=[note("system-running-inside-prefix", inst.prefix, "Fix: unpack a release of "
                                         "brew-ports outside every Homebrew and MacPorts folder, such as ~/.local, "
                                         "and run its bin/brew-ports.")],
                          blocks=(Blocks.ANY,)))
    return out


def _low_disk_space(instances: Sequence[Instance]) -> list[Issue]:
    """Flag each prefix whose volume has less than 5 GiB free (`f_frsize * f_bavail`)

    @param instances  every instance the scan found
    @returns          one finding per prefix short of space
    """
    out = []
    for inst in instances:
        free = system.free_bytes(inst.prefix)
        if free is None or free >= LOW_SPACE_BYTES:
            continue
        out.append(_issue("system-low-disk-space", Severity.HIGH, f"Only {free / GIB:.1f} GiB is free on the disk of "
                          f"{at(inst)}; a move needs 5", inst.prefix, inst.prefix,
                          remedies=[note("system-low-disk-space", inst.prefix, "Fix: free up space on that disk.")],
                          blocks=(Blocks.ANY,)))
    return out


def _rosetta_shell(facts: dict[str, Any]) -> list[Issue]:
    """Flag a shell that runs under Rosetta (`sysctl.proc_translated` is 1)

    @param facts  the scan's system facts
    @returns      at most one finding
    """
    if not facts.get("translated"):
        return []
    return [_issue("system-rosetta-shell", Severity.INFO, "This Terminal runs under Rosetta (Intel emulation)", None,
                   None, remedies=[note("system-rosetta-shell", None, "Nothing to do: brew-ports runs each `brew` and "
                                        "`port` command in the mode its installation needs.")])]


def _dyld_export(environment: dict[str, Any]) -> list[Issue]:
    """Flag the `DYLD_*` exports in the shell files

    @param environment  the scan's environment analysis
    @returns            one finding per export line
    """
    out = []
    for rec in _records(environment, "dyld"):
        if rec.get("var") in DYLD_PREFIX_VARS and rec.get("instance_prefixes"):
            continue                    # the finding of a library path that names an installation covers it
        subject = _line_subject(rec)
        out.append(_issue("system-dyld-export", Severity.MEDIUM, f"{_line(rec)} sets a DYLD_ variable, which changes "
                          "the libraries every program loads", subject, None,
                          evidence=[(rec.get("text") or "").strip()],
                          remedies=[note("system-dyld-export", subject, "Fix: remove the line unless you know that "
                                         "you need it. A move removes it only when it points into an installation "
                                         "that the move uninstalls.")]))
    return out


def system_issues(bundle, runner) -> list[Issue]:
    """Return the `system-*` findings from the scan's system facts, the prefixes and the shell analysis

    @param bundle  the scan
    @param runner  the runner, whose environment shows a run under sudo
    @returns       the findings, in detector order
    """
    facts = bundle.result.system
    return (_clt_missing(facts) + _xcode_license(facts) + _running_as_root(runner.environ)
            + _running_inside_prefix(facts, bundle.result.instances)
            + _low_disk_space(bundle.result.instances) + _rosetta_shell(facts)
            + _dyld_export(bundle.result.environment))


# Environment -------------------------------------------------------------------------

class _Host:
    """The scan's view the `env-*` detectors share"""

    def __init__(self, bundle, runner) -> None:
        """Index the scan's instances by prefix and by path

        @param bundle  the scan
        @param runner  the runner, whose architecture the rebuild remedies take
        """
        self.bundle = bundle
        self.runner = runner
        self.result = bundle.result
        self.environment: dict[str, Any] = self.result.environment
        self.instances: list[Instance] = list(self.result.instances)
        self.by_prefix: dict[str, Instance] = {inst.prefix: inst for inst in self.instances}
        self.index = env.PrefixIndex(self.instances)

    def manager_of(self, prefix: str | None) -> Manager | None:
        """Return the manager of the instance at a prefix

        @param prefix  an instance prefix, or None
        @returns       the manager; None for no instance there
        """
        inst = self.by_prefix.get(prefix or "")
        return inst.manager if inst else None

    def at(self, prefix: str | None) -> str:
        """Return the installation at a prefix as the report names it

        @param prefix  an instance prefix, or None
        @returns       such as `MacPorts at /opt/local`; the prefix itself for no instance there
        """
        inst = self.by_prefix.get(prefix or "")
        return at(inst) if inst is not None else prefix or "no installation"

    def foreign(self, prefix: str | None) -> bool:
        """Return whether an instance of the other manager exists beside the one at `prefix`

        @param prefix  an instance prefix, or None
        @returns       True when one does; False also without an instance at `prefix`
        """
        mine = self.manager_of(prefix)
        return mine is not None and any(inst.manager is not mine for inst in self.instances)

    def packages(self, prefix: str) -> list[model.Package]:
        """Return the scanned packages of one instance

        @param prefix  the instance's prefix
        @returns       its packages, in scan order
        """
        return [p for p in self.result.packages if p.instance_prefix == prefix]


def _both_managers(host: _Host) -> list[Issue]:
    """Flag at least one instance of each manager holding packages

    @param host  the scan's view
    @returns     at most one finding, its evidence a line per instance
    """
    lines: dict[Manager, list[str]] = {Manager.BREW: [], Manager.PORTS: []}
    for inst in host.instances:
        pkgs = host.packages(inst.prefix)
        if pkgs:
            lines[inst.manager].append(f"{at(inst)}: {by_kind(p.kind for p in pkgs)}")
    if not lines[Manager.BREW] or not lines[Manager.PORTS]:
        return []
    return [_issue("env-both-managers", Severity.INFO, "Homebrew and MacPorts both hold packages", None, None,
                   evidence=lines[Manager.BREW] + lines[Manager.PORTS],
                   remedies=[note("env-both-managers", None,
                                  "Next: `brew-ports recommend` compares a move in each direction.")])]


def _shadowed_commands(host: _Host) -> list[Issue]:
    """Flag the commands that the `bin` and `sbin` of two or more instances provide

    @param host  the scan's view
    @returns     at most one finding, its evidence a line per command
    """
    shadowed = host.environment.get("shadowed") or []
    if not shadowed:
        return []
    winners: dict[str, list[str]] = {}
    for s in shadowed:
        inst = host.index.by_text(s.get("winner")) if s.get("winner") else None
        winners.setdefault(at(inst) if inst is not None else "", []).append(str(s.get("command")))
    evidence = [f"Typing one runs the copy of {who}: {some(names)}" if who
                else f"Not on your PATH at all: {some(names)}" for who, names in winners.items()]
    return [_issue("env-shadowed-commands", Severity.MEDIUM, f"{counted(len(shadowed), 'command')} "
                   f"{'exists' if len(shadowed) == 1 else 'exist'} in more than one installation", None, None,
                   evidence=evidence,
                   remedies=[note("env-shadowed-commands", None, "Nothing to do: after a move, the installation you "
                                  "keep comes first on your PATH.")])]


def cross_reference(ref: dict[str, Any], owner_prefix: str | None, index: env.PrefixIndex) -> bool:
    """Return whether a binary's reference points into another prefix or `/usr/local`

    Classes `other` and `usrlocal` do; a `missing` reference does when its path names such a prefix.

    @param ref           one reference of the linkage scan
    @param owner_prefix  the prefix of the binary's own instance, or None
    @param index         the instances by path
    @returns             True for a cross-prefix reference
    """
    cls = ref.get("class")
    if cls in ("other", "usrlocal"):
        return True
    if cls != "missing":
        return False
    path = ref.get("resolved") or ref.get("name") or ""
    if not path.startswith("/"):
        return False
    inst = index.by_text(path)
    if inst is not None:
        return inst.prefix != owner_prefix
    at_usr_local = bool(owner_prefix and system.text_names_prefix(owner_prefix, (USR_LOCAL,), False))
    return system.text_names_prefix(path, (USR_LOCAL,), False) and not at_usr_local


def _rebuild_remedies(host: _Host, inst: Instance | None, kind: str, name: str) -> list[Action]:
    """Return the rebuild of a cross-linked package: `brew reinstall`, a forced `port upgrade`, else a note

    @param host  the scan's view
    @param inst  the package's instance, or None when the scan lacks it
    @param kind  the package kind, formula or port
    @param name  the package name
    @returns     one action: the rebuild, or a note when the instance cannot run it
    """
    code = "env-cross-prefix-linkage"
    if inst is not None and inst.drivable:
        try:
            if kind == "formula" and inst.manager is Manager.BREW:
                return [brew_actions.reinstall(inst, host.runner.host_arch, remedy_id(code, name, "reinstall"),
                                               [name])]
            if kind == "port" and inst.manager is Manager.PORTS:
                row = next((p for p in host.packages(inst.prefix) if p.name == name and p.active), None)
                if row is not None:
                    brew_present = any(i.manager is Manager.BREW for i in host.instances)
                    return [mp_actions.upgrade_forced(inst, host.runner.host_arch, remedy_id(code, name, "rebuild"),
                                                      name, row.requested_variants, homebrew_present=brew_present)]
        except ValueError:
            pass
    command = f"`{COMMAND_OF[inst.manager]}`" if inst is not None else "its manager's"
    return [note(code, name, f"Fix: install {name} again once the {command} command there can run.")]


def _cross_prefix_linkage(host: _Host) -> list[Issue]:
    """Flag the binaries of one instance that reference another prefix or `/usr/local`

    @param host  the scan's view
    @returns     one finding per package
    """
    found: dict[str, list[str]] = {}
    for path, report in sorted((host.result.linkage.get("binaries") or {}).items()):
        key = report.get("package")
        if not key:
            continue
        for ref in report.get("references") or []:
            if cross_reference(ref, report.get("instance_prefix"), host.index):
                found.setdefault(key, []).append(f"{path} loads {ref.get('resolved') or ref.get('name')}")
    out = []
    for key in sorted(found):
        prefix, _, rest = key.partition("|")
        kind, _, name = rest.partition("|")
        inst = host.by_prefix.get(prefix)
        remedies = _rebuild_remedies(host, inst, kind, name)
        runnable = any(not a.manual for a in remedies)
        where = at(inst) if inst is not None else prefix
        out.append(_issue("env-cross-prefix-linkage", Severity.HIGH, f"{name} in {where} uses libraries from another "
                          "installation, and breaks when that one goes", name, prefix,
                          evidence=limited(found[key]), remedies=remedies, confirm_each=runnable))
    return out


def _local_builds(host: _Host) -> list[Issue]:
    """Flag the locally built packages, whose binaries the linkage scan always reads, a port's only while it is active

    @param host  the scan's view
    @returns     one finding per instance that holds any
    """
    out = []
    for inst in host.instances:
        names = sorted(p.name for p in host.packages(inst.prefix) if p.built_locally)
        if names:
            out.append(_issue("env-local-builds", Severity.INFO, f"{counted(len(names), 'package')} of {at(inst)} "
                              f"{'was' if len(names) == 1 else 'were'} built on this Mac, not installed prebuilt",
                              inst.prefix, inst.prefix, evidence=[some(names)],
                              remedies=[note("env-local-builds", inst.prefix, "Nothing to do.")]))
    return out


def _dyld_library_path(host: _Host) -> list[Issue]:
    """Flag `DYLD_LIBRARY_PATH` or `DYLD_FALLBACK_LIBRARY_PATH` naming a prefix, in a shell file or the environment

    @param host  the scan's view
    @returns     one finding per shell file line and per variable of the environment
    """
    code = "env-dyld-library-path"
    out = []
    for rec in _records(host.environment, "dyld"):
        prefixes = rec.get("instance_prefixes") or []
        if rec.get("var") in DYLD_PREFIX_VARS and prefixes:
            subject = _line_subject(rec)
            names = series(host.at(p) for p in prefixes)
            out.append(_issue(code, Severity.HIGH, f"{_line(rec)} makes every program load libraries from {names}",
                              subject, prefixes[0], evidence=[(rec.get("text") or "").strip()],
                              remedies=[note(code, subject, "Fix: remove the line. A move that uninstalls that "
                                             "installation removes it too.")]))
    live = host.environment.get("live") or {}
    for var in DYLD_PREFIX_VARS:
        named = sorted({e.get("instance_prefix") for e in live.get(var) or [] if e.get("instance_prefix")})
        if named:
            names = series(host.at(p) for p in named)
            out.append(_issue(code, Severity.HIGH, f"{var} in this Terminal makes every program load libraries "
                              f"from {names}", var, named[0],
                              remedies=[note(code, var, "Fix: remove the line that sets it from your shell files, "
                                             "then open a new Terminal window.")]))
    return out


def _build_variables(host: _Host) -> list[Issue]:
    """Flag a build variable that names a prefix while the other manager builds on this host

    @param host  the scan's view
    @returns     one finding per shell file line and per variable of the environment
    """
    code = "env-build-variables"
    why = "Software built with the other installation can pick up files of this one through it."
    out = []
    for rec in _records(host.environment, "build"):
        named = [p for p in rec.get("instance_prefixes") or [] if host.foreign(p)]
        if named:
            subject = _line_subject(rec)
            names = series(host.at(p) for p in named)
            out.append(_issue(code, Severity.MEDIUM, f"{_line(rec)} points {rec.get('var')} into {names}", subject,
                              named[0], evidence=[(rec.get("text") or "").strip(), why],
                              remedies=[note(code, subject, "Nothing to do while you keep that installation. A move "
                                             "that uninstalls it removes this line.")]))
    live = host.environment.get("live") or {}
    for var in env_shell.BUILD_VARS:
        named = sorted({e.get("instance_prefix") for e in live.get(var) or []
                        if e.get("instance_prefix") and host.foreign(e.get("instance_prefix"))})
        if named:
            names = series(host.at(p) for p in named)
            out.append(_issue(code, Severity.MEDIUM, f"{var} in this Terminal points into {names}", var, named[0],
                              evidence=[why],
                              remedies=[note(code, var, "Nothing to do while you keep that installation.")]))
    return out


def _which(command: str, directories: Sequence[str]) -> str | None:
    """Return the first executable of a name along the PATH directories, the one the shell runs

    @param command      a command name
    @param directories  the PATH directories, in order
    @returns            its path; None when no directory holds it
    """
    for directory in directories:
        candidate = os.path.join(directory, command)
        if env_shell.is_command(candidate):
            return candidate
    return None


def _split_interpreters(host: _Host) -> list[Issue]:
    """Flag an interpreter and its package tool that resolve, along the live PATH, to different prefixes

    @param host  the scan's view
    @returns     at most one finding per pair of `SPLIT_PAIRS`
    """
    entries = (host.environment.get("live") or {}).get("PATH") or []
    directories = [e.get("path") for e in entries if e.get("path")]
    out = []
    for interpreter, tool in SPLIT_PAIRS:
        first, second = _which(interpreter, directories), _which(tool, directories)
        if not first or not second:
            continue
        a, b = host.index.prefix_of(first), host.index.prefix_of(second)
        if a == b:
            continue
        outside = "outside Homebrew and MacPorts"
        out.append(_issue("env-split-interpreters", Severity.MEDIUM, f"{interpreter} and {tool} run from different "
                          f"places, so {tool} installs where {interpreter} does not look",
                          f"{interpreter}/{tool}", a or b,
                          evidence=[f"{interpreter} is {first} ({host.at(a) if a else outside})",
                                    f"{tool} is {second} ({host.at(b) if b else outside})"],
                          remedies=[note("env-split-interpreters", f"{interpreter}/{tool}", "Fix: call both by "
                                         "their full path, or put the installation you use first on your PATH.")]))
    return out


def _language_packages(host: _Host) -> list[Issue]:
    """Flag the language packages outside both managers, from the scan's interpreter extras

    @param host  the scan's view
    @returns     one finding per Python site, and per instance for each other kind
    """
    code = "env-language-packages"
    extras = host.result.interpreter_extras
    counts: dict[str, list[str]] = {}          # per installation, "" for the home folder
    tools: dict[str, list[str]] = {}
    for item in extras.get("python") or []:
        if item.get("dists"):
            where = item.get("instance_prefix") or ""
            counts.setdefault(where, []).append(f"Python {item.get('version', '')}: {len(item['dists'])}")
            tools.setdefault(where, []).append("pip")
    for kind in sorted(EXTRA_FILES):
        for where in sorted({item.get("instance_prefix") or "" for item in extras.get(kind) or []}):
            found = sum(1 for item in extras.get(kind) or [] if (item.get("instance_prefix") or "") == where)
            counts.setdefault(where, []).append(f"{EXTRA_LABELS[kind]}: {found}")
            tools.setdefault(where, []).append(EXTRA_TOOLS[kind])
    run_dir = getattr(host.runner, "run_dir", None)
    folder = tilde(run_dir.path) if run_dir is not None else "the run folder"
    out = []
    for where in sorted(counts):
        used = list(dict.fromkeys(tools[where]))
        by = f"{', '.join(used[:-1])} or {used[-1]}" if len(used) > 1 else used[0]
        if where:
            out.append(_issue(code, Severity.MEDIUM, f"{host.at(where)} holds packages that {by} installed; a move "
                              "does not move them", where, where, evidence=[", ".join(counts[where])],
                              remedies=[note(code, where, f"Their names are saved in {folder}, for you to install "
                                             "them again after a move.")]))
        else:
            out.append(_issue(code, Severity.INFO, f"Your home folder holds packages that {by} installed", "home",
                              None, evidence=[", ".join(counts[where])],
                              remedies=[note(code, "home", "Nothing to do: a move does not touch them.")]))
    return out


def _services_of_both(host: _Host) -> list[Issue]:
    """Flag owned services with data directories under both managers

    @param host  the scan's view
    @returns     at most one finding
    """
    with_data = [s for s in host.result.services if s.owned and s.data_dirs]
    if len({host.manager_of(s.instance_prefix) for s in with_data} - {None}) < 2:
        return []
    evidence = [f"{s.label} ({host.at(s.instance_prefix)}): its data is in {', '.join(s.data_dirs)}" for s in with_data]
    return [_issue("env-services-of-both", Severity.MEDIUM, "Homebrew and MacPorts both run services that keep data",
                   None, None, evidence=evidence,
                   remedies=[note("env-services-of-both", None, "Nothing to do: a plan lists the services it stops "
                                  "and where their data is.")])]


def _dead_path_entries(host: _Host) -> list[Issue]:
    """Flag duplicate or dead PATH entries in the environment and the shell files

    @param host  the scan's view
    @returns     at most one finding
    """
    dead: dict[str, str] = {}                  # the folder as written or expanded -> where it is added
    for rec in _records(host.environment, "assign"):
        if rec.get("var") != "PATH":
            continue
        for entry in rec.get("entries") or []:
            if entry.get("exists") is False:
                dead.setdefault(str(entry.get("path") or entry.get("text")),
                                f"{entry.get('text')} (added by {_line(rec)})")
    for entry in (host.environment.get("live") or {}).get("PATH") or []:
        if entry.get("exists") is False:
            dead.setdefault(str(entry.get("path") or entry.get("text")), tilde(str(entry.get("text"))))
    twice = [tilde(str(text)) for text in (host.environment.get("live_duplicates") or {}).get("PATH") or []]
    if not dead and not twice:
        return []
    parts = [f"{counted(len(dead), 'folder')} that {'does' if len(dead) == 1 else 'do'} not exist"] if dead else []
    if twice:
        parts.append(f"{counted(len(twice), 'folder')} twice")
    evidence = list(dead.values()) + [f"{text} is listed more than once" for text in twice]
    return [_issue("env-dead-path-entries", Severity.LOW, f"Your PATH lists {' and '.join(parts)}", "PATH", None,
                   evidence=limited(evidence),
                   remedies=[note("env-dead-path-entries", "PATH", "Fix: delete them from your shell files yourself; "
                                  "brew-ports leaves them. They do no harm.")])]


def _etc_paths(host: _Host) -> list[Issue]:
    """Flag `/etc/paths` or `/etc/paths.d` entries for a prefix, except the stock `/usr/local` lines

    @param host  the scan's view
    @returns     one finding per line
    """
    out = []
    for line in host.environment.get("etc_paths") or []:
        entry = line.get("entry") or {}
        if entry.get("instance_prefix") and not line.get("stock"):
            subject = f"{line.get('file')}:{line.get('lineno')}"
            out.append(_issue("env-etc-paths", Severity.MEDIUM, f"{line.get('file')} puts {entry.get('text')} on "
                              "every user's PATH", subject, entry.get("instance_prefix"),
                              remedies=[note("env-etc-paths", subject, "Nothing to do while you keep "
                                             f"{host.at(entry.get('instance_prefix'))}. A move that uninstalls it "
                                             "removes this line, with sudo.")]))
    return out


def _gui_path(host: _Host) -> list[Issue]:
    """Flag a GUI PATH (`launchctl getenv PATH`) that names a prefix

    @param host  the scan's view
    @returns     at most one finding
    """
    gui = host.environment.get("gui_path") or []
    named = [e for e in gui if e.get("instance_prefix")]
    if not named:
        return []
    kept = ":".join(e.get("text", "") for e in gui if not e.get("instance_prefix"))
    folders = series(e.get("text", "") for e in named)
    return [_issue("env-gui-path", Severity.LOW, f"Apps opened from Finder get a PATH that includes {folders}",
                   "GUI PATH", named[0].get("instance_prefix"),
                   remedies=[manual("env-gui-path", None, "path",
                                    [servicectl.LAUNCHCTL, "config", "user", "path", kept],
                                    "Nothing to do while you keep that installation. To take it off that PATH",
                                    sudo=True)])]


def _shell_markers(host: _Host) -> list[Issue]:
    """List the MacPorts installer markers and `brew shellenv` lines, which `env-cleanup` edits

    @param host  the scan's view
    @returns     at most one INFO finding
    """
    recs = _records(host.environment, "marker") + _records(host.environment, "shellenv")
    if not recs:
        return []
    recs.sort(key=lambda r: (str(r.get("file")), r.get("lineno") or 0))
    evidence = [f"{_line(r)}: {(r.get('text') or '').strip()}" for r in recs]
    files = series(dict.fromkeys(tilde(str(r.get("file"))) for r in recs))
    return [_issue("env-shell-markers", Severity.INFO, f"{counted(len(recs), 'line')} of {files} "
                   f"{'sets' if len(recs) == 1 else 'set'} up Homebrew or MacPorts", None, None,
                   evidence=limited(evidence),
                   remedies=[note("env-shell-markers", None, "Nothing to do: a move removes the lines of an "
                                  "installation that it uninstalls.")])]


def _user_launchd_job(host: _Host) -> list[Issue]:
    """Flag a user's own launchd job (`owned=False`) that runs a manager's binary; the tool never touches it

    @param host  the scan's view
    @returns     one finding per job
    """
    out = []
    for svc in host.result.services:
        if svc.owned:
            continue
        program = svc.program or f"a program in {svc.instance_prefix}"
        out.append(_issue("env-user-launchd-job", Severity.MEDIUM, f"Your own service {svc.label} runs a program "
                          f"from {host.at(svc.instance_prefix)}", svc.plist, svc.instance_prefix,
                          evidence=[f"{tilde(svc.plist)} runs {program}"],
                          remedies=[note("env-user-launchd-job", svc.plist, "Fix: edit or delete that service file "
                                         "before a move uninstalls the program. brew-ports never stops or deletes "
                                         "a service of your own.")]))
    return out


def _login_shell(host: _Host) -> list[Issue]:
    """Flag a login shell that lies, or whose realpath lies, under an instance's owned roots

    @param host  the scan's view
    @returns     at most one finding
    """
    shell = host.environment.get("login_shell")
    owner = host.environment.get("login_shell_prefix")
    if not shell or not owner:
        return []
    real = host.environment.get("login_shell_realpath")
    return [_issue("env-login-shell", Severity.HIGH, f"Your login shell {shell} is part of {host.at(owner)}", shell,
                   owner, evidence=[f"it is the file {real}"] if real and real != shell else [],
                   remedies=[note("env-login-shell", shell, "Nothing to do: a move out of that installation changes "
                                  "your login shell to the replacement before it uninstalls the old one, or leaves "
                                  "the shell's package where it is and says so.")])]


def _sourced_files(host: _Host) -> list[Issue]:
    """Flag a shell file line that sources or runs a file from a prefix, or runs `brew` by name

    @param host  the scan's view
    @returns     one finding per line
    """
    out = []
    for rec in _records(host.environment, "source"):
        prefixes = rec.get("instance_prefixes") or []
        if not prefixes and rec.get("brew") != "":
            continue
        subject = _line_subject(rec)
        what = f"uses a path inside {host.at(prefixes[0])}" if prefixes else "runs `brew` by name"
        out.append(_issue("env-sourced-files", Severity.LOW, f"{_line(rec)} {what}", subject,
                          prefixes[0] if prefixes else None, evidence=[(rec.get("text") or "").strip()],
                          remedies=[note("env-sourced-files", subject, "Nothing to do while you keep that "
                                         "installation. A move that uninstalls it disables this line and keeps "
                                         "the original as a comment.")]))
    return out


ENV_DETECTORS: tuple[Callable[[_Host], list[Issue]], ...] = (
    _both_managers, _shadowed_commands, _cross_prefix_linkage, _local_builds, _dyld_library_path, _build_variables,
    _split_interpreters, _language_packages, _services_of_both, _dead_path_entries, _etc_paths, _gui_path,
    _shell_markers, _user_launchd_job, _login_shell, _sourced_files)


def env_issues(bundle, runner) -> list[Issue]:
    """Return the `env-*` findings from the scan

    @param bundle  the scan
    @param runner  the runner, whose architecture the rebuild remedies take
    @returns       the findings, in `ENV_DETECTORS` order
    """
    host = _Host(bundle, runner)
    out: list[Issue] = []
    for detector in ENV_DETECTORS:
        out.extend(detector(host))
    return out


# Aggregation -------------------------------------------------------------------------

def health_module(family: str) -> Any:
    """Return the module of the `brew-*` or `ports-*` detectors, imported on first use

    @param family  `brew` or `ports`
    @returns       the health module of that manager
    """
    return importlib.import_module(HEALTH_MODULES[family])


def _runnable(issue: Issue) -> list[Action]:
    """Return the remedies of a finding that the tool runs: its commands that are not manual

    @param issue  a finding
    @returns      the actions, in order
    """
    return doctor_report.runs(issue)


def _defer_cross_linkage(issues: list[Issue]) -> None:
    """Drop the rebuild of a cross-prefix linkage whose package a broken-linkage remedy rebuilds; keep its evidence

    @param issues  every finding; a deferred one is changed in place
    """
    rebuilt = {(i.instance_prefix, i.subject): i.code for i in issues
               if i.code in ("brew-broken-linkage", "ports-broken-binaries") and _runnable(i)}
    for issue in issues:
        code = rebuilt.get((issue.instance_prefix, issue.subject)) if issue.code == "env-cross-prefix-linkage" else None
        if code:
            issue.remedies = [note(issue.code, issue.subject, f"The fix of the other finding about {issue.subject} "
                                   f"installs {issue.subject} again, which mends this too.")]
            issue.confirm_each = False


def path_fixes(issues: Sequence[Issue], kept: Mapping[str, str | None]) -> None:
    """Name `env-cleanup` as the fix of a PATH finding about the installation which that command keeps

    A health module names the fix by hand, which holds for every installation of its manager.

    @param issues  every finding; one about a kept installation is changed in place
    @param kept    the prefix of the installation that `env-cleanup --target <manager>` keeps, by manager name
    """
    for issue in issues:
        manager, fix = ENV_CLEANUP.get(issue.code, ("", ""))
        if manager and issue.remedies and issue.instance_prefix and issue.instance_prefix == kept.get(manager):
            issue.remedies[0] = replace(issue.remedies[0], description=fix)


def sort_issues(issues: Sequence[Issue]) -> list[Issue]:
    """Sort by severity, CRITICAL first, then by family in `FAMILY_ORDER`, then in detection order

    @param issues  the findings
    @returns       a sorted copy
    """
    order = sorted(enumerate(issues), key=lambda pair: (-int(pair[1].severity),
                                                        FAMILY_ORDER.get(_family_of(pair[1].code), len(FAMILY_ORDER)),
                                                        pair[0]))
    return [issue for _, issue in order]


def detect_all(bundle, runner) -> list[Issue]:
    """Return every finding, the `brew-*` and `ports-*` ones from their health modules, sorted

    @param bundle  the scan
    @param runner  the runner the detectors probe through
    @returns       the findings, in `sort_issues` order
    """
    progress.step("system and environment checks")
    issues = system_issues(bundle, runner) + env_issues(bundle, runner)
    for family, name in (("brew", "Homebrew"), ("ports", "MacPorts")):
        progress.step(f"{name} checks")
        issues.extend(health_module(family).detect(bundle, runner))
    _defer_cross_linkage(issues)
    return sort_issues(issues)


def needs_terminal_answer(issue: Issue) -> bool:
    """Return whether the remedy removes packages, kegs or files, which needs an answer `--yes` never gives

    @param issue  a finding
    @returns      True when only an answer on a terminal applies it
    """
    family = _family_of(issue.code)
    return family in HEALTH_MODULES and bool(health_module(family).needs_terminal_answer(issue))


def removes_package(issue: Issue) -> tuple[str, str] | None:
    """Return the `(package_kind, name)` a remedy removes or replaces, for the snapshot and the service stops

    @param issue  a finding
    @returns      the package; None for a remedy that removes or replaces none
    """
    family = _family_of(issue.code)
    if family in HEALTH_MODULES:
        return health_module(family).removes_package(issue)
    if issue.code == "env-cross-prefix-linkage" and issue.subject:
        profile = next((a.env_profile for a in _runnable(issue)), None)
        if profile == "brew":
            return ("formula", issue.subject)
        if profile == "ports":
            return ("port", issue.subject)
    return None


# The cross-prefix linkage post-check --------------------------------------------------

def formula_binaries(inst: Instance, name: str) -> list[str] | None:
    """Return the binaries of the keg `opt/<name>` names, else of the newest keg

    @param inst  the Homebrew instance
    @param name  the formula
    @returns     the keg's Mach-O files; None without a keg
    """
    opt = os.path.join(inst.prefix, "opt", name)
    keg = os.path.realpath(opt) if os.path.isdir(opt) else None
    if keg is None:
        rack = os.path.join(inst.prefix, "Cellar", name)
        try:
            versions = [v for v in os.listdir(rack) if not v.startswith(".") and os.path.isdir(os.path.join(rack, v))]
        except OSError:
            versions = []
        keg = os.path.join(rack, max(versions, key=version_key)) if versions else None
    return env_linkage.keg_binaries(keg) if keg else None


def port_binaries(inst: Instance, name: str) -> list[str] | None:
    """Return the binaries of the port's active row, read from a fresh registry backup

    @param inst  the MacPorts instance
    @param name  the port
    @returns     the registered binaries of the active row; None when no row is active or the registry cannot be read
    """
    if not inst.portdbpath:
        return None
    try:
        with registry.Registry.open_copy(inst.portdbpath) as reg:
            row = next((r for r in reg.ports() if r.name.lower() == name.lower() and r.active), None)
            if row is None:
                return None
            return [f.location for f in reg.files(row.id) if f.binary and f.active]
    except REGISTRY_ERRORS:
        return None


def verify_cross_linkage(issue: Issue, runner, bundle) -> bool | None:
    """Return True when a rescan of the package's binaries finds no cross-prefix reference

    False without a keg, or for a port without an active row in a fresh registry backup or without a readable registry.

    @param issue   an `env-cross-prefix-linkage` finding
    @param runner  the runner the rescan reads the binaries through
    @param bundle  the scan
    @returns       True repaired, False not; None when the finding names no known instance or no package
    """
    inst = next((i for i in bundle.result.instances if i.prefix == issue.instance_prefix), None)
    if inst is None or not issue.subject:
        return None
    kind = "formula" if inst.manager is Manager.BREW else "port"
    binaries = (formula_binaries if kind == "formula" else port_binaries)(inst, issue.subject)
    if binaries is None:
        return False
    key = f"{inst.prefix}|{kind}|{issue.subject}"
    report = env_linkage.scan(runner, {key: binaries}, bundle.result.instances)
    index = env.PrefixIndex(bundle.result.instances)
    for item in (report.get("binaries") or {}).values():
        for ref in item.get("references") or []:
            if cross_reference(ref, item.get("instance_prefix") or inst.prefix, index):
                return False
    return True


def verify(issue: Issue, runner, bundle) -> bool | None:
    """Run the post-check of a remedy: True repaired, False not repaired, None without a check

    @param issue   the finding whose remedy ran
    @param runner  the runner the check probes through
    @param bundle  the scan
    @returns       the check's verdict, or None
    """
    family = _family_of(issue.code)
    if family in HEALTH_MODULES:
        return health_module(family).verify(issue, runner, bundle)
    if issue.code == "env-cross-prefix-linkage":
        return verify_cross_linkage(issue, runner, bundle)
    return None


# Blocking ----------------------------------------------------------------------------

@dataclass
class PlanContext:
    """The plan an issue is weighed against: its target and the source prefixes it acts on

    `cask_prefixes` lose their casks (`--casks drop|map`); `exempt_prefixes` began their phase 6 deletion this run.
    """

    target_prefix: str | None
    uninstall_prefixes: tuple[str, ...] = ()
    cask_prefixes: tuple[str, ...] = ()
    remove_prefixes: tuple[str, ...] = ()
    exempt_prefixes: tuple[str, ...] = ()


def _applies(issue: Issue, context: PlanContext) -> bool:
    """Return whether one of a finding's `blocks` matches the role its instance plays in the plan

    @param issue    a finding
    @param context  the plan it is weighed against
    @returns        True when one does
    """
    prefix = issue.instance_prefix
    for block in issue.blocks:
        if block is Blocks.ANY:
            return True
        if block is Blocks.TARGET and prefix is not None and prefix == context.target_prefix:
            return True
        if block is Blocks.CASKS and prefix in context.cask_prefixes:
            return True
        if block is Blocks.UNINSTALL and prefix in context.uninstall_prefixes:
            return True
        if block is Blocks.REMOVE and prefix in context.remove_prefixes:
            return True
    return False


def blocking(issues: Iterable[Issue], plan_context: PlanContext) -> list[Issue]:
    """Return the issues that stop a plan with this context: the CRITICAL ones and those whose `blocks` match

    An issue about an instance whose phase 6 deletion has begun never blocks: the deletion removes it.

    @param issues        the findings
    @param plan_context  the plan they are weighed against
    @returns             the blocking findings, in order
    """
    out = []
    for issue in issues:
        if issue.instance_prefix is not None and issue.instance_prefix in plan_context.exempt_prefixes:
            continue
        if issue.severity is Severity.CRITICAL or _applies(issue, plan_context):
            out.append(issue)
    return out


def blocked_by_lines(found: Sequence[Issue], instances: Sequence[Instance]) -> list[str]:
    """Return a line for each finding that stops the move, with what was found and how to fix it

    @param found      the blocking findings
    @param instances  the installations of the scan the findings come from
    @returns          the lines; the evidence and the remedies are indented under their finding
    """
    by_prefix = doctor_report.known(instances)
    lines = []
    for issue in found:
        lines.append(f"this stops the move: {doctor_report.named(issue, by_prefix)}")
        lines.extend(f"    {line}" for line in issue.evidence[:EVIDENCE_SHOWN])
        more = len(issue.evidence) - EVIDENCE_SHOWN
        if more > 0:
            lines.append(f"    and {counted(more, 'more line')} (`brew-ports doctor --verbose` shows them)")
        lines.extend(f"    {line}" for line in doctor_report.fix_lines(issue, doctor_report.refused(issue, found)))
    return lines


def _plain_targets(instances: Sequence[Instance], host_arch: str, environ: dict[str, str]) -> dict[str, str | None]:
    """Return per manager the target prefix of a plan without `--target-prefix`, or None

    @param instances  every instance the scan found
    @param host_arch  the host's architecture
    @param environ    the environment
    @returns          the target prefix by manager name; None where no instance is a target
    """
    brew = brew_locate.choose_target(instances, host_arch, None, environ)
    try:
        ports = mp_locate.choose_target(instances, host_arch, None)
    except ValueError:
        ports = None
    return {"brew": brew.prefix if brew else None, "ports": ports.prefix if ports else None}


def _plain_context(instances: Sequence[Instance], target_prefix: str | None,
                   packages: Sequence[model.Package] | None) -> PlanContext:
    """Return a plain plan's context: it uninstalls from every drivable source that holds packages

    It removes no manager and no cask: a `brew` target adopts the casks, and `ports` defaults to `--casks keep`.

    @param instances      every instance the scan found
    @param target_prefix  the plan's target prefix, or None
    @param packages       the scanned packages; None counts every source as holding some
    @returns              the context
    """
    holding = None if packages is None else {p.instance_prefix for p in packages}
    sources = tuple(i.prefix for i in instances
                    if i.prefix != target_prefix and i.drivable and i.inventory_known
                    and (holding is None or i.prefix in holding))
    return PlanContext(target_prefix=target_prefix, uninstall_prefixes=sources)


def blocks_apply(issues: Sequence[Issue], instances: Sequence[Instance], *, host_arch: str = "arm64",
                 environ: dict[str, str] | None = None, packages: Sequence[model.Package] | None = None,
                 targets: dict[str, str | None] | None = None) -> dict[str, list[str]]:
    """Return `DoctorResult.blocks_apply`: per target manager, the findings that block a plain plan

    @param issues     the findings
    @param instances  every instance the scan found
    @param host_arch  the host's architecture, for the choice of the targets
    @param environ    the environment, for the choice of the Homebrew target; None for an empty one
    @param packages   the scanned packages; None counts every source as holding some
    @param targets    the target prefix by manager name; None to choose them as a plain plan does
    @returns          the names of the blocking findings by manager name, `brew` and `ports`, each name once
    """
    targets = targets if targets is not None else _plain_targets(instances, host_arch, environ or {})
    out: dict[str, list[str]] = {}
    for name in ("brew", "ports"):
        codes: list[str] = []
        for issue in blocking(issues, _plain_context(instances, targets.get(name), packages)):
            if issue.code not in codes:
                codes.append(issue.code)
        out[name] = codes
    return out


# The report --------------------------------------------------------------------------

def describe(action: Action) -> str:
    """Return an action as the user would type it, `sudo` included

    @param action  a remedy
    @returns       the shell-quoted command, without the `arch` wrapper; the text of a note
    """
    if action.kind != "command":
        return action.description
    return typed(action.argv, action.sudo)


def findings_exit(issues: Sequence[Issue]) -> int:
    """Return exit 1 when a finding calls for action: it stops a move, or something is broken

    @param issues  the findings
    @returns       `EXIT_FINDINGS` or `EXIT_OK`
    """
    return EXIT_FINDINGS if doctor_report.problems(issues) else EXIT_OK


# --fix -------------------------------------------------------------------------------

class _Stopped(Exception):
    """A remedy failed or a service did not stop: `doctor --fix` ends with exit 4"""


def _key(issue: Issue) -> tuple[str, str | None, str | None]:
    """Return an issue's name, instance and subject, which a recomputed issue shares

    @param issue  a finding
    @returns      the key that names it across a recomputation
    """
    return (issue.code, issue.instance_prefix, issue.subject)


def _versions(issue: Issue) -> set[str]:
    """Return the `@<version>_<revision><variants>` tokens of the remedies that run, the port rows they act on

    @param issue  a finding
    @returns      the tokens; none for remedies that name no row
    """
    return {token for a in _runnable(issue) for token in list(a.argv) + list(a.retry_argv) if token.startswith("@")}


def _brew_owner(prefix: str, path: str) -> tuple[str, str] | None:
    """Return the formula or cask whose `Cellar`, `opt` or `Caskroom` entry holds a path of a Homebrew prefix

    A symlink counts by the path its text names.

    @param prefix  the Homebrew prefix
    @param path    an absolute path below it
    @returns       `("formula", rack or opt name)` or `("cask", token)`; None for any other path
    """
    if os.path.islink(path):
        try:
            path = os.path.normpath(os.path.join(os.path.dirname(path), os.readlink(path)))
        except OSError:
            return None
    for top, kind in (("Cellar", "formula"), ("opt", "formula"), ("Caskroom", "cask")):
        head = os.path.join(prefix, top) + os.sep
        name = path[len(head):].split(os.sep, 1)[0] if path.startswith(head) else ""
        if name:
            return kind, name
    return None


class _Fixer:
    """`doctor --fix`: the `auto_fix` remedies behind one question, then each `confirm_each` one by one

    A finding about a package that an earlier remedy of the run changed is skipped, and the output says so.
    """

    def __init__(self, ctx: Context, runner, run_dir: state.RunDir, bundle, issues: Sequence[Issue]) -> None:
        """Prepare a `--fix` run over the report's findings

        @param ctx      the command context: the arguments, the console, the prompts and the state
        @param runner   the runner the remedies run through
        @param run_dir  the run's directory, for the snapshots and the journal
        @param bundle   the scan
        @param issues   the report's findings
        """
        self.ctx: Context = ctx
        self.runner = runner
        self.run_dir = run_dir
        self.bundle = bundle
        self.issues = list(issues)
        self.instances = {inst.prefix: inst for inst in bundle.result.instances}
        uid = bundle.result.system.get("uid")
        self.uid = uid if isinstance(uid, int) else os.getuid()
        self.dry_run = ctx.args.dry_run
        self.fixed: set[int] = set()
        # Findings that are gone without a fix: leaves a recomputation replaced, a repair with nothing left to do.
        self.superseded: set[int] = set()
        self.declined: set[tuple[str, str | None, str | None]] = set()
        self.snapshotted: set[str] = set()
        self.repaired: set[str | None] = set()
        self.about: dict[int, set[PackageKey]] = {}     # the packages of each finding, read before any remedy runs
        self.changed: dict[PackageKey, str] = {}        # a package a remedy changed -> that remedy's finding
        self.touched = False

    def say(self, text: str = "") -> None:
        """Print one line of the `--fix` output; under `--json` it goes to the error stream, beside the JSON

        @param text  the line; empty for a blank line
        """
        if self.ctx.console.json_mode:
            self.ctx.console.warn(text)
        else:
            self.ctx.console.out(text)

    def named(self, issue: Issue) -> str:
        """Return a finding as the `--fix` output names it

        @param issue  a finding
        @returns      its title, with its installation when the title does not name it
        """
        return doctor_report.named(issue, self.instances)

    # Which remedies ------------------------------------------------------------

    def is_manager_repair(self, issue: Issue) -> bool:
        """Return whether a finding is one of the repairs the MacPorts health module runs itself

        @param issue  a finding
        @returns      True for a code in `MANAGER_REPAIRS`
        """
        return _family_of(issue.code) == "ports" and issue.code in health_module("ports").MANAGER_REPAIRS

    def refused(self, issue: Issue) -> bool:
        """Return whether a `brew.env` line that changes what the profile sets refuses the issue's `brew` remedy

        @param issue  a finding
        @returns      True when `brew-env-override` holds for its instance and one of its commands runs brew
        """
        return doctor_report.refused(issue, self.issues)

    def ordered(self, issues: Iterable[Issue]) -> list[Issue]:
        """Sort by family; manager repairs go first among `ports-*`, as they replace the ports the others came from

        @param issues  the findings
        @returns       a sorted copy, in detection order within a group
        """
        indexed = list(enumerate(issues))
        indexed.sort(key=lambda p: (FAMILY_ORDER.get(_family_of(p[1].code), len(FAMILY_ORDER)),
                                    0 if self.is_manager_repair(p[1]) else 1, p[0]))
        return [issue for _, issue in indexed]

    def services_of(self, issue: Issue, pair: tuple[str, str]) -> list[Service]:
        """Return the owned services whose `(instance_prefix, package_kind, package)` match

        @param issue  the finding, whose instance the services belong to
        @param pair   the package kind and name
        @returns      the services
        """
        kind, name = pair
        return [s for s in self.bundle.result.services if s.owned and s.instance_prefix == issue.instance_prefix
                and s.package_kind == kind and s.package == name]

    def active_version(self, prefix: str | None, name: str) -> str | None:
        """Return the `@<version>_<revision><variants>` token of the port's active row, or None

        @param prefix  the MacPorts instance's prefix, or None
        @param name    the port name
        @returns       the token, as `port` takes it; None without an active row
        """
        inv = self.bundle.macports(prefix) if prefix else None
        rows = inv.packages if inv is not None else [p for p in self.bundle.result.packages
                                                     if p.instance_prefix == prefix]
        row = next((p for p in rows if p.kind == "port" and p.active and p.name.lower() == name.lower()), None)
        return row.spec_args[1] if row is not None and len(row.spec_args) == 2 else None

    def touches_active(self, issue: Issue, pair: tuple[str, str]) -> bool:
        """Return whether a remedy acts on a port's active row or on the whole port, not only on inactive versions

        Inactive rows own no services, so a remedy that only touches them leaves the services running.

        @param issue  the finding
        @param pair   the package kind and name the remedy removes or replaces
        @returns      True also for any kind but a port
        """
        kind, name = pair
        if kind != "port":
            return True
        versions = _versions(issue)
        if not versions:
            return True
        active = self.active_version(issue.instance_prefix, name)
        return active is not None and active in versions

    def stoppable(self, issue: Issue, pair: tuple[str, str] | None) -> list[Service]:
        """Return the services a removal or replacement stops first and deals with after it

        @param issue  the finding
        @param pair   the package kind and name the remedy removes or replaces, or None
        @returns      the services; none when the remedy leaves the package's services running
        """
        if not pair or not self.touches_active(issue, pair):
            return []
        return self.services_of(issue, pair)

    def needs_sudo(self, issues: Sequence[Issue]) -> bool:
        """Return whether any remedy, snapshot step or service stop needs sudo, so the preflight runs first

        @param issues  the findings `--fix` applies
        @returns       True when one of them escalates
        """
        for issue in issues:
            if any(a.sudo for a in _runnable(issue)) or self.is_manager_repair(issue):
                return True
            pair = removes_package(issue)
            if not pair:
                continue
            inst = self.instances.get(issue.instance_prefix or "")
            if inst is not None and inst.manager is Manager.PORTS and inst.drivable and "snapshot" in inst.features:
                return True
            if any(s.domain == "system" or s.scope == "system" for s in self.stoppable(issue, pair)):
                return True
        return False

    # Findings a remedy made stale --------------------------------------------

    def rack_names(self, prefix: str, name: str) -> set[str]:
        """Return a formula's name with the names of its racks, which an unmigrated rename keeps under the old name

        @param prefix  the Homebrew instance's prefix
        @param name    the formula, or the name of a rack
        @returns       the names
        """
        inv = next((inv for inst, _, inv in self.bundle.brew if inst.prefix == prefix and inv is not None), None)
        kegs = inv.kegs.get(name) if inv is not None else None
        return {name} | {os.path.basename(os.path.dirname(keg)) for keg in kegs or []}

    def packages_of(self, issue: Issue) -> set[PackageKey]:
        """Return the packages a finding is about, read from the host the first time it is asked for that finding

        They are the package its remedy removes or replaces; the owner of the owned service its subject names; the
        formula or cask whose rack, `opt` link or Caskroom directory holds its path subject or that symlink's target;
        else the package its subject names when a remedy runs that package's manager. A formula counts under the names
        of its racks too.

        @param issue  a finding
        @returns      the packages, as `(instance prefix, kind, name key)`; none for a finding about no package
        """
        known = self.about.get(id(issue))
        if known is not None:
            return known
        prefix, subject = issue.instance_prefix or "", issue.subject or ""
        found: set[tuple[str, str]] = set()
        pair = removes_package(issue)
        if pair:
            found.add(pair)
        svc = next((s for s in self.bundle.result.services if s.owned and s.instance_prefix == prefix
                    and s.label == subject), None)
        manager = next((a for a in _runnable(issue) if a.env_profile in ("brew", "ports")), None)
        inst = self.instances.get(prefix)
        if svc is not None and svc.package and svc.package_kind:
            found.add((svc.package_kind, svc.package))
        elif os.path.isabs(subject):
            owner = _brew_owner(prefix, subject) if inst is not None and inst.manager is Manager.BREW else None
            if owner:
                found.add(owner)
        elif subject and manager is not None:
            kind = "port" if manager.env_profile == "ports" else ("cask" if "--cask" in manager.argv else "formula")
            found.add((kind, brew_inventory.short_name(subject)))
        known = {(prefix, kind, name_key(kind, alias)) for kind, name in found if prefix
                 for alias in (self.rack_names(prefix, name) if kind == "formula" else (name,))}
        self.about[id(issue)] = known
        return known

    def changes_package(self, issue: Issue) -> bool:
        """Return whether a remedy changes its packages as a whole: it runs their manager, on more than inactive rows

        Removing one keg, link, plist or file changes that item alone, which no other finding is about.

        @param issue  a finding whose remedy ran
        @returns      True when the evidence of the other findings about its packages may be stale
        """
        managed = any(a.env_profile in ("brew", "ports") for a in _runnable(issue))
        versions = _versions(issue)
        if not managed or not versions or not issue.subject:
            return managed
        active = self.active_version(issue.instance_prefix, issue.subject)
        return active is None or active in versions

    def skipped(self, issue: Issue) -> bool:
        """Say that a finding is skipped and return True when an earlier remedy of the run changed what it is about

        A manager repair changes its whole instance; another remedy, the packages `changes_package` counts.

        @param issue  a finding still to apply
        @returns      True when the finding is skipped
        """
        changed = sorted(key for key in self.packages_of(issue) if key in self.changed)
        inst = self.instances.get(issue.instance_prefix or "")
        if issue.instance_prefix in self.repaired:
            what = at(inst) if inst is not None else str(issue.instance_prefix)
        elif changed:
            what = changed[0][2]
        else:
            return False
        self.say()
        self.say(f"Skipped: {self.named(issue)}")
        self.say(f"  An earlier fix of this run changed {what}, so this finding may be out of date. `brew-ports "
                 "doctor` checks again.")
        return True

    # Prompts -------------------------------------------------------------------

    def first(self, issue: Issue) -> list[str]:
        """Return what `--fix` does before the commands of a fix that removes or replaces a package

        @param issue  the finding
        @returns      the steps, as the words that follow `y `: the record it saves for undo, the services it stops
        """
        pair = removes_package(issue)
        if not pair:
            return []
        inst = self.instances.get(issue.instance_prefix or "")
        steps = []
        if inst is not None and inst.prefix not in self.snapshotted:
            steps.append(f"saves what is installed in {at(inst)}, for `brew-ports rollback`")
        services = [s for s in self.stoppable(issue, pair) if s.loaded]
        if services:
            steps.append(f"stops {series('the service ' + s.label for s in services)}")
        return steps

    def offer(self, issue: Issue, how: str) -> list[str]:
        """Return the lines that present a fix: the finding, what `--fix` does for it, and what else to know

        @param issue  the finding
        @param how    `ask` when a question follows, `dry` or `dry-yes` in a dry run, `run` when the commands
                      follow unasked
        @returns      the lines
        """
        lines = doctor_report.offer(issue, self.instances, self.first(issue), how)
        pair = removes_package(issue)
        services = self.stoppable(issue, pair) if pair else []
        loaded = [s for s in services if s.loaded]
        if loaded:
            one = len(loaded) == 1
            lines.append(f"  Afterwards it starts {'that service' if one else 'those services'} again; when the "
                         f"package is gone, it deletes {'its service file' if one else 'their service files'} "
                         "instead.")
        data = sorted({d for s in services for d in s.data_dirs})
        if pair and data:
            lines.append(f"  The data of {pair[1]} is in {series(data)}.")
        return lines

    def ask(self, issue: Issue) -> bool:
        """Present a fix and ask whether to make it; a removal takes only an answer on a terminal

        @param issue  the finding
        @returns      True when the user agrees
        """
        removal = needs_terminal_answer(issue)
        asked = self.ctx.tty and (removal or not self.ctx.yes)
        self.say()
        for line in self.offer(issue, "ask" if asked else "run"):
            self.say(line)
        if removal:
            if self.ctx.yes and not self.ctx.tty:
                self.say("  Not asked: this is one of the fixes that take your own answer on a terminal.")
            return self.ctx.confirm_terminal(doctor_report.QUESTION)
        return self.ctx.confirm(doctor_report.QUESTION, default=False)

    # Applying ------------------------------------------------------------------

    def touch(self) -> None:
        """Set the dirty marker once, immediately before the first change to the host"""
        if not self.touched:
            self.ctx.state.touch_dirty(self.run_dir.run_id, "doctor --fix")
            self.touched = True

    def snapshot(self, inst: Instance) -> None:
        """Write the phase 1 snapshot of the instance a removal acts on, once per run

        @param inst  the instance
        """
        if inst.prefix in self.snapshotted:
            return
        first = not self.snapshotted
        earlier = snapshot.noted(self.run_dir)
        written = snapshot.write(self.runner, self.run_dir, self.bundle, [inst], id_prefix="doctor",
                                 local_snapshot=first, uid=self.uid)
        self.snapshotted.add(inst.prefix)
        folder = f"the run folder, {tilde(self.run_dir.path)}," if first else "the run folder,"
        self.say(f"  Saved what is installed in {at(inst)} in {folder} for `brew-ports rollback`.")
        for line in snapshot.outcome(written, first, earlier):
            self.say("  " + line)

    def still_installed(self, inst: Instance | None, pair: tuple[str, str]) -> bool:
        """Return whether the package is still on disk or in a fresh registry backup

        When that cannot be told it counts as installed, so its services start again.

        @param inst  the package's instance, or None
        @param pair  the package kind and name
        @returns     True also when it cannot be told
        """
        kind, name = pair
        if inst is None:
            return True
        if kind == "formula":
            rack = os.path.join(inst.prefix, "Cellar", name)
            if os.path.islink(rack) or not os.path.isdir(rack):
                return False
            try:
                versions = os.listdir(rack)
            except OSError:
                return True
            return any(not v.startswith(".") and os.path.isdir(os.path.join(rack, v))
                       and not os.path.islink(os.path.join(rack, v)) for v in versions)
        if kind == "cask":
            room = os.path.join(inst.prefix, "Caskroom", name)
            return os.path.isdir(room) and not os.path.islink(room)
        if kind == "port" and inst.portdbpath:
            try:
                with registry.Registry.open_copy(inst.portdbpath) as reg:
                    return any(r.name.lower() == name.lower() for r in reg.ports())
            except REGISTRY_ERRORS:
                return True
        return True

    def after(self, issue: Issue, pair: tuple[str, str], services: Sequence[Service],
              booted: Sequence[Service]) -> None:
        """Delete the plists of a package the remedy removed, else start its services again

        @param issue     the finding whose remedy ran
        @param pair      the package kind and name
        @param services  the services stopped for it
        @param booted    those of them booted out, which start again
        """
        inst = self.instances.get(issue.instance_prefix or "")
        prefix = remedy_id(issue.code, issue.subject, "service")
        if not self.still_installed(inst, pair):
            for svc, gone in servicectl.delete_plists(self.runner, services, id_prefix=prefix):
                self.say(f"  Deleted the service file {tilde(svc.plist)}." if gone
                         else f"  Could not delete the service file {tilde(svc.plist)}; delete it yourself.")
            return
        for svc, ok in servicectl.restart(self.runner, booted, list(self.instances.values()), id_prefix=prefix):
            self.say(f"  Started the service {svc.label} again." if ok
                     else f"  Could not start the service {svc.label} again; start it yourself.")

    def execute(self, issue: Issue, services: Sequence[Service], booted: list[Service]) -> str | None:
        """Stop the services, run the actions and the post-check; return the failure text, or None

        @param issue              the finding
        @param services           the services to stop first
        @param booted             receives the services booted out, which `after` starts again
        @returns                  the failure text; None when the remedy worked
        @throws ActionFailed      a `STOP` action failed
        @throws EscalationFailed  sudo itself failed
        @throws Interrupted       a signal arrived before a command started
        """
        if services:
            stopped = servicectl.stop(self.runner, services, self.uid,
                                      id_prefix=remedy_id(issue.code, issue.subject, "service"))
            booted.extend(stopped.booted)
            if stopped.error is not None:
                return str(stopped.error)
            if stopped.still_running:
                return "; ".join(reason for _, reason in stopped.still_running)
            for svc in stopped.booted:
                self.say(f"  Stopped the service {svc.label}.")
        actions = _runnable(issue)
        results = []
        for action in actions:
            results.append(self.runner.run(action, defer_result=True))
            self.ran(action, results[-1])
        # A post-check decides whatever the exit statuses said; without one they decide.
        checked = verify(issue, self.runner, self.bundle)
        ok = checked if checked is not None else all(r.ok for r in results)
        for action in actions:
            if not action.read_only:
                self.runner.record_result(action, ok)
        if checked is False:
            return f"the commands ran, but a check afterwards still finds the problem: {issue.title}"
        if not ok:
            return str(ActionFailed(next(r for r in results if not r.ok)))
        return None

    def ran(self, action: Action, result) -> None:
        """Print a command that worked, and where its output was saved; a failure is the error that ends the run

        @param action  the command
        @param result  its result
        """
        if result.ok:
            self.say(f"  {describe(action)} ... ok" + (f", saved as {tilde(action.dst)}" if action.dst else ""))

    def apply(self, issue: Issue) -> None:
        """Apply one remedy, with the snapshot and the service stops of a removal, and note the packages it changed

        @param issue      the finding
        @throws _Stopped  a command, sudo, the post-check or a service stop failed, or a signal arrived
        """
        pair = removes_package(issue)
        inst = self.instances.get(issue.instance_prefix or "")
        services = self.stoppable(issue, pair)
        booted: list[Service] = []
        self.touch()
        failure: str | None = None
        try:
            if pair and inst is not None:
                self.snapshot(inst)
            failure = self.execute(issue, services, booted)
        except (ActionFailed, EscalationFailed, Interrupted) as exc:
            failure = str(exc)
        finally:
            if pair and services:
                self.after(issue, pair, services, booted)
        if failure:
            raise _Stopped(failure)
        self.fixed.add(id(issue))
        if self.changes_package(issue):
            for key in self.packages_of(issue):
                self.changed.setdefault(key, issue.code)

    @staticmethod
    def answered(_question: str) -> bool:
        """Answer yes to the installer's own question: the fix's question said what the installer does

        @param _question  the procedure's question
        @returns          True
        """
        return True

    def manager_repair(self, issue: Issue) -> None:
        """Run one of the MacPorts module's `MANAGER_REPAIRS` through that module and print its report

        @param issue      the finding
        @throws _Stopped  a step of the repair or sudo failed, or a signal arrived
        """
        self.touch()
        try:
            _, fixed = health_module("ports").manager_repair(issue, self.runner, self.run_dir, self.ctx.environ,
                                                             self.say, confirm=self.answered)
        except (ActionFailed, EscalationFailed, Interrupted) as exc:
            raise _Stopped(str(exc)) from None
        self.repaired.add(issue.instance_prefix)
        if fixed:
            self.fixed.add(id(issue))
        elif fixed is None:
            self.superseded.add(id(issue))

    # The run -------------------------------------------------------------------

    def candidates(self) -> tuple[list[Issue], list[Issue], list[Issue]]:
        """Return the fixes `--fix` makes after one answer for them all, and those it asks about one by one

        A single fix of the first kind is asked about like the others.

        @returns  both lists, ordered, and the findings whose brew remedy `brew-env-override` refuses, which are in
                  neither
        """
        auto = [i for i in self.issues if i.auto_fix and _runnable(i)]
        each = [i for i in self.issues if i.confirm_each and not i.auto_fix
                and (_runnable(i) or self.is_manager_repair(i))]
        kept_auto, kept_each, refused = [], [], []
        for issue in auto + each:
            if self.refused(issue):
                refused.append(issue)
            elif issue.auto_fix:
                kept_auto.append(issue)
            else:
                kept_each.append(issue)
        if len(kept_auto) == 1:
            return [], self.ordered(kept_auto + kept_each), refused
        return self.ordered(kept_auto), self.ordered(kept_each), refused

    def listed(self, auto: Sequence[Issue], each: Sequence[Issue]) -> None:
        """Print what a dry run leaves undone: the fixes that take one answer together, then each of the others

        @param auto  the findings whose fixes take one answer for them all
        @param each  the findings asked about one by one
        """
        if auto:
            self.say()
            for line in doctor_report.together(auto, self.instances, False, self.ctx.yes):
                self.say(line)
        for issue in each:
            self.say()
            asks = not self.ctx.yes or needs_terminal_answer(issue)
            for line in self.offer(issue, "dry" if asks else "dry-yes"):
                self.say(line)

    def together(self, auto: Sequence[Issue]) -> None:
        """Present the fixes that take one answer for them all, ask once and make them

        @param auto       the findings
        @throws _Stopped  a command, sudo or a post-check failed, or a signal arrived
        """
        if not auto:
            return
        asked = self.ctx.tty and not self.ctx.yes
        self.say()
        if not self.ctx.yes:
            for line in doctor_report.together(auto, self.instances, asked):
                self.say(line)
        if not self.ctx.confirm(doctor_report.QUESTIONS % len(auto), default=False):
            return
        for issue in auto:
            if not self.skipped(issue):
                if not asked:
                    self.say(self.named(issue))
                self.apply(issue)

    def one_by_one(self, each: Sequence[Issue]) -> None:
        """Ask about each fix in turn and make the ones the user agrees to

        @param each       the findings
        @throws _Stopped  a command, sudo, a post-check or a service stop failed, or a signal arrived
        """
        queue = list(each)
        while queue:
            issue = queue.pop(0)
            if self.skipped(issue):
                continue
            if not self.ask(issue):
                self.declined.add(_key(issue))
                continue
            if self.is_manager_repair(issue):
                self.manager_repair(issue)
                continue
            self.apply(issue)
            if issue.code == LEAF:
                queue = self.recomputed_leaves(issue.instance_prefix, queue)

    def run(self) -> int | None:
        """Run `--fix`; return its exit code, or None when the report's code stands: no fix to make, or `--dry-run`

        @returns                the exit code, or None
        @throws PreflightError  sudo caches no credentials for a remedy that escalates
        """
        auto, each, refused = self.candidates()
        if self.dry_run:
            self.say(doctor_report.DRY_RUN)
        if not auto and not each:
            self.say(doctor_report.NOTHING_TO_FIX)
            for line in doctor_report.not_offered(refused, self.instances) + doctor_report.unchanged(self.issues):
                self.say(line)
            return None
        # Without a terminal and without --yes no fix is made, so no password is asked for.
        sudo = self.needs_sudo(auto + each) and (self.ctx.tty or self.ctx.yes)
        opening = doctor_report.fix_opening(len(auto) + len(each), sudo, self.dry_run, self.ctx.yes, self.ctx.tty)
        for line in opening + doctor_report.not_offered(refused, self.instances):
            self.say(line)
        if self.dry_run:
            self.listed(auto, each)
            for line in ["", doctor_report.DRY_RUN_END] + doctor_report.unchanged(self.issues):
                self.say(line)
            return None
        if sudo:
            self.runner.sudo_preflight()
        # Read before any remedy runs: a remedy can replace the keg or the link a finding queued behind it names.
        for issue in auto + each:
            self.packages_of(issue)
        try:
            self.together(auto)
            self.one_by_one(each)
        except _Stopped as exc:
            self.ctx.console.error(str(exc))
            undo = self.run_dir.run_id if self.snapshotted else None
            for line in doctor_report.fix_stopped(tilde(self.run_dir.path), len(self.fixed), undo):
                self.ctx.console.warn(line)
            return EXIT_ACTION
        left = [i for i in self.issues if id(i) not in self.fixed and id(i) not in self.superseded]
        undo = self.run_dir.run_id if self.snapshotted else None
        for line in doctor_report.fix_closing(len(self.fixed), left, undo):
            self.say(line)
        return EXIT_FINDINGS if doctor_report.problems(left) else EXIT_OK

    def recomputed_leaves(self, prefix: str | None, queue: list[Issue]) -> list[Issue]:
        """Return the queue after a leaf removal, with the leaves recomputed from a fresh registry backup

        The recomputed leaves replace the instance's queued ones; a leaf the user declined is not offered again.

        @param prefix  the MacPorts instance's prefix
        @param queue   the findings still to ask about
        @returns       the queue to go on with
        """
        fresh = [i for i in health_module("ports").recompute_leaves(prefix, self.runner, self.bundle) if i.code == LEAF]
        stale = [i for i in queue if i.code == LEAF and i.instance_prefix == prefix]
        self.superseded.update(id(i) for i in stale)
        self.issues.extend(fresh)
        offered = [i for i in fresh if _runnable(i) and i.confirm_each and _key(i) not in self.declined
                   and not self.refused(i)]
        return offered + [i for i in queue if not (i.code == LEAF and i.instance_prefix == prefix)]


# The command -------------------------------------------------------------------------

def _report(ctx: Context, runner, run_dir: state.RunDir, bundle, reused: bool) -> list[Issue]:
    """Detect every finding, write `doctor.json` and print the report, as text or under `--json`

    @param ctx      the command context
    @param runner   the runner the detectors probe through
    @param run_dir  the run's directory, which receives `doctor.json`
    @param bundle   the scan
    @param reused   whether the scan is a recent one reused, whose requirements files this run writes again
    @returns        the findings, sorted
    """
    if reused:
        env_interpreters.write_requirements(run_dir.path, bundle.result.interpreter_extras)
    scan_notes = list(bundle.notes)
    issues = detect_all(bundle, runner)
    if any(issue.code in ENV_CLEANUP for issue in issues):
        path_fixes(issues, {name: envclean.kept_prefix(ctx.state, bundle, name, runner.host_arch, ctx.environ)
                            for name in ("brew", "ports")})
    instances = bundle.result.instances
    blocks = blocks_apply(issues, instances, host_arch=runner.host_arch, environ=ctx.environ,
                          packages=bundle.result.packages)
    # The detectors add their notes to the bundle, so both are read after detect_all.
    result = model.DoctorResult(created=state.now_iso(), issues=issues, blocks_apply=blocks, notes=list(bundle.notes))
    data = model.to_plain(result)
    run_dir.write_json("doctor.json", model.to_json(data))
    if ctx.args.json:
        if reused:
            ctx.console.info(SCAN_REUSED)
        ctx.console.json(data)
    elif ctx.args.fix or ctx.args.dry_run:
        for line in [doctor_report.checked(instances)] + ([SCAN_REUSED] if reused else []):
            ctx.console.out(line)
    else:
        lines = doctor_report.render(issues, instances, bundle.notes[len(scan_notes):], reused=reused,
                                     verbose=ctx.console.verbose, scan_notes=scan_notes)
        for line in lines + doctor_report.closing(issues, len(instances) > 1):
            ctx.console.out(line)
    return issues


def cmd_doctor(ctx: Context, make_runner: Callable[[Context, state.RunDir], BaseRunner] | None = None) -> int:
    """Run `brew-ports doctor`: the scan, `doctor.json`, the report, then `--fix` or `--dry-run`

    A scan younger than ten minutes is reused unless a mutating command ran since or `--rescan` or `--deep` is given.

    @param ctx          the command context
    @param make_runner  makes the run's runner from the context and the run directory; None for the command runner
    @returns            the exit code
    """
    args = ctx.args
    ctx.console.echo = False        # `--fix` prints each command once, with its result
    run_dir, runner = start_run(ctx, 0, make_runner)
    with runner.signals():
        bundle, reused = scan.obtain(ctx.state, run_dir, runner, ctx.environ, rescan=args.rescan or args.deep,
                                     deep=args.deep)
        try:
            issues = _report(ctx, runner, run_dir, bundle, reused)
            code = findings_exit(issues)
            if not (args.fix or args.dry_run):
                return code
            try:
                fixed = _Fixer(ctx, runner, run_dir, bundle, issues).run()
            except PreflightError as exc:
                ctx.console.error(str(exc))
                return EXIT_PREFLIGHT
            return code if fixed is None else fixed
        finally:
            bundle.close()

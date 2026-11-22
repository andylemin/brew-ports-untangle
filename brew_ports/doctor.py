"""`brew-ports doctor`: the system and environment detectors, the rule that blocks a plan, the report and `--fix`

The `brew-*` and `ports-*` detectors live in `homebrew/health.py` and `macports/health.py`, imported on first use.
"""

from __future__ import annotations

import importlib
import os
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from . import env, model, progress, scan, servicectl, snapshot, state, system
from .context import Context
from .env import interpreters as env_interpreters, linkage as env_linkage, shell as env_shell
from .homebrew import actions as brew_actions, inventory as brew_inventory, locate as brew_locate
from .homebrew.catalogue import version_key
from .macports import actions as mp_actions, bootstrap as mp_bootstrap, locate as mp_locate, registry
from .model import Action, Blocks, Instance, Issue, Manager, PackageKey, Service, Severity, name_key
from .report import limited, typed
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


def _records(environment: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    """Return the shell analysis records of one kind

    @param environment  the scan's environment analysis
    @param kind         the record kind, such as `dyld`, `build` or `source`
    @returns            the records, in the scan's order
    """
    return [r for r in environment.get("records") or [] if r.get("kind") == kind]


def _cleanup(code: str, subject: str | None, edits: str, what: str) -> Action:
    """Return the remedy note of a finding that `brew-ports env-cleanup --apply` deals with

    @param code     the finding's name
    @param subject  the finding's subject; None for the host
    @param edits    the `env-cleanup` edits that act on it
    @param what     what the cleanup does about it
    @returns        the note action
    """
    return note(code, subject, f"`brew-ports env-cleanup --apply` {what} ({edits})")


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
        evidence.append("xcode-select -p fails: no developer directory is selected")
    if no_receipt:
        evidence.append(f"{system.CLT_DIR} exists, but pkgutil --pkg-info=com.apple.pkg.CLTools_Executables fails")
    remedies = [manual("system-clt-missing", None, "install", [system.XCODE_SELECT, "--install"],
                       "install the Command Line Tools"),
                note("system-clt-missing", None, "or reinstall them through Software Update, as the MacPorts "
                                                 "ProblemHotlist describes")]
    return [_issue("system-clt-missing", Severity.HIGH, "Command Line Tools missing or receipt missing", None, None,
                   evidence=evidence, remedies=remedies, blocks=(Blocks.ANY,))]


def _xcode_license(facts: dict[str, Any]) -> list[Issue]:
    """Flag an Xcode.app developer directory whose licence `xcodebuild -license check` rejects

    @param facts  the scan's system facts
    @returns      at most one finding
    """
    if facts.get("xcode_license_ok") is not False:
        return []
    return [_issue("system-xcode-license", Severity.HIGH, "Xcode licence not accepted", facts.get("developer_dir"),
                   None, evidence=[f"xcodebuild -license check exits non-zero for {facts.get('developer_dir')}"],
                   remedies=[manual("system-xcode-license", None, "license", [system.XCODEBUILD, "-license", "accept"],
                                    "accept the Xcode licence", sudo=True)], blocks=(Blocks.ANY,))]


def _running_as_root(environ: dict[str, str]) -> list[Issue]:
    """Flag running as root or under sudo, which cli.py refuses with exit 3 first

    @param environ  the environment, where `SUDO_USER` shows a run under sudo
    @returns        at most one finding
    """
    if os.geteuid() != 0 and "SUDO_USER" not in environ:
        return []
    evidence = ["effective uid 0"] if os.geteuid() == 0 else ["SUDO_USER is set"]
    return [_issue("system-running-as-root", Severity.CRITICAL, "Running as root or under sudo", None, None,
                   evidence=evidence,
                   remedies=[note("system-running-as-root", None, "run brew-ports as yourself, without sudo")],
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
    for key, what in (("python_path", "the Python running brew-ports"), ("tool_path", "brew-ports")):
        path = facts.get(key)
        inst = index.by_identity(path) if path else None
        if inst is None:
            continue
        out.append(_issue("system-running-inside-prefix", Severity.CRITICAL, "brew-ports runs from inside a prefix",
                          path, inst.prefix, evidence=[f"{what} is {path}, inside {inst.prefix}"],
                          remedies=[note("system-running-inside-prefix", inst.prefix, "run the bin/brew-ports of a "
                                         "release bundle unpacked outside every Homebrew and MacPorts prefix, such as "
                                         "~/.local")],
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
        out.append(_issue("system-low-disk-space", Severity.HIGH, "Less than 5 GiB free on the volume of a prefix",
                          inst.prefix, inst.prefix,
                          evidence=[f"{free / GIB:.1f} GiB free on the volume of {inst.prefix}"],
                          remedies=[note("system-low-disk-space", inst.prefix,
                                         f"free at least 5 GiB on the volume of {inst.prefix}")],
                          blocks=(Blocks.ANY,)))
    return out


def _rosetta_shell(facts: dict[str, Any]) -> list[Issue]:
    """Flag a shell that runs under Rosetta (`sysctl.proc_translated` is 1)

    @param facts  the scan's system facts
    @returns      at most one finding
    """
    if not facts.get("translated"):
        return []
    return [_issue("system-rosetta-shell", Severity.INFO, "Shell translated by Rosetta", None, None,
                   evidence=["sysctl -n sysctl.proc_translated is 1"],
                   remedies=[note("system-rosetta-shell", None, "none needed: every manager command runs under arch "
                                                                "with its instance's architecture")])]


def _dyld_export(environment: dict[str, Any]) -> list[Issue]:
    """Flag the `DYLD_*` exports in the shell files

    @param environment  the scan's environment analysis
    @returns            one finding per export line
    """
    out = []
    for rec in _records(environment, "dyld"):
        subject = _line_subject(rec)
        out.append(_issue("system-dyld-export", Severity.MEDIUM, "DYLD_* export in a shell file", subject, None,
                          evidence=[(rec.get("text") or "").strip()],
                          remedies=[_cleanup("system-dyld-export", subject, "build exports", "removes the export")]))
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
        if not pkgs:
            continue
        if inst.manager is Manager.BREW:
            formulae, casks = sum(p.kind == "formula" for p in pkgs), sum(p.kind == "cask" for p in pkgs)
            lines[Manager.BREW].append(f"{inst.prefix}: {formulae} formulae, {casks} casks")
        else:
            active = sum(p.active for p in pkgs)
            lines[Manager.PORTS].append(f"{inst.prefix}: {len(pkgs)} ports ({active} active)")
    if not lines[Manager.BREW] or not lines[Manager.PORTS]:
        return []
    return [_issue("env-both-managers", Severity.INFO, "Both managers present", None, None,
                   evidence=lines[Manager.BREW] + lines[Manager.PORTS],
                   remedies=[note("env-both-managers", None,
                                  "`brew-ports recommend` compares migrating in both directions")])]


def _shadowed_commands(host: _Host) -> list[Issue]:
    """Flag the commands that the `bin` and `sbin` of two or more instances provide

    @param host  the scan's view
    @returns     at most one finding, its evidence a line per command
    """
    shadowed = host.environment.get("shadowed") or []
    if not shadowed:
        return []
    evidence = [f"{s.get('command')}: runs {s.get('winner') or 'nothing on PATH'} "
                f"(provided by {', '.join(s.get('prefixes') or [])})" for s in shadowed]
    return [_issue("env-shadowed-commands", Severity.MEDIUM, "Shadowed commands", None, None,
                   evidence=limited(evidence),
                   remedies=[_cleanup("env-shadowed-commands", None, "PATH order",
                                      "orders PATH so the surviving manager wins")])]


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
    return [note(code, name, f"rebuild {name} in its own manager once that instance can run it")]


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
                found.setdefault(key, []).append(f"{path} -> {ref.get('resolved') or ref.get('name')} "
                                                 f"({ref.get('class')})")
    out = []
    for key in sorted(found):
        prefix, _, rest = key.partition("|")
        kind, _, name = rest.partition("|")
        inst = host.by_prefix.get(prefix)
        remedies = _rebuild_remedies(host, inst, kind, name)
        runnable = any(not a.manual for a in remedies)
        out.append(_issue("env-cross-prefix-linkage", Severity.HIGH, "Cross-prefix linkage", name, prefix,
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
            out.append(_issue("env-local-builds", Severity.INFO, "Locally built packages", inst.prefix, inst.prefix,
                              evidence=[f"{len(names)} built locally: {', '.join(names)}"]))
    return out


def _dyld_library_path(host: _Host) -> list[Issue]:
    """Flag `DYLD_LIBRARY_PATH` or `DYLD_FALLBACK_LIBRARY_PATH` naming a prefix, in a shell file or the environment

    @param host  the scan's view
    @returns     one finding per shell file line and per variable of the environment
    """
    code, title = "env-dyld-library-path", "DYLD library path naming a prefix"
    out = []
    for rec in _records(host.environment, "dyld"):
        prefixes = rec.get("instance_prefixes") or []
        if rec.get("var") in DYLD_PREFIX_VARS and prefixes:
            subject = _line_subject(rec)
            out.append(_issue(code, Severity.HIGH, title, subject, prefixes[0],
                              evidence=[f"{rec.get('var')} names {', '.join(prefixes)}: "
                                        f"{(rec.get('text') or '').strip()}"],
                              remedies=[_cleanup(code, subject, "build exports", "removes the export")]))
    live = host.environment.get("live") or {}
    for var in DYLD_PREFIX_VARS:
        named = sorted({e.get("instance_prefix") for e in live.get(var) or [] if e.get("instance_prefix")})
        if named:
            out.append(_issue(code, Severity.HIGH, title, var, named[0],
                              evidence=[f"{var} in the environment names {', '.join(named)}"],
                              remedies=[_cleanup(code, var, "build exports",
                                                 "removes the export from the shell files")]))
    return out


def _build_variables(host: _Host) -> list[Issue]:
    """Flag a build variable that names a prefix while the other manager builds on this host

    @param host  the scan's view
    @returns     one finding per shell file line and per variable of the environment
    """
    code, title = "env-build-variables", "Build variable naming the other prefix"
    out = []
    for rec in _records(host.environment, "build"):
        named = [p for p in rec.get("instance_prefixes") or [] if host.foreign(p)]
        if named:
            subject = _line_subject(rec)
            out.append(_issue(code, Severity.MEDIUM, title, subject, named[0],
                              evidence=[f"{rec.get('var')} names {', '.join(named)}: "
                                        f"{(rec.get('text') or '').strip()}"],
                              remedies=[_cleanup(code, subject, "build exports", "removes the export")]))
    live = host.environment.get("live") or {}
    for var in env_shell.BUILD_VARS:
        named = sorted({e.get("instance_prefix") for e in live.get(var) or []
                        if e.get("instance_prefix") and host.foreign(e.get("instance_prefix"))})
        if named:
            out.append(_issue(code, Severity.MEDIUM, title, var, named[0],
                              evidence=[f"{var} in the environment names {', '.join(named)}"],
                              remedies=[_cleanup(code, var, "build exports",
                                                 "removes the export from the shell files")]))
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
        out.append(_issue("env-split-interpreters", Severity.MEDIUM, "Split interpreters",
                          f"{interpreter}/{tool}", a or b,
                          evidence=[f"{interpreter} runs {first} ({a or 'outside both managers'})",
                                    f"{tool} runs {second} ({b or 'outside both managers'})"]))
    return out


def _extra_name(item: dict[str, Any]) -> str:
    """Return the name of a language package the interpreter scan found

    @param item  a package of the interpreter extras
    @returns     its `name`, else its `module`, else `?`
    """
    return str(item.get("name") or item.get("module") or "?")


def _language_packages(host: _Host) -> list[Issue]:
    """Flag the language packages outside both managers, from the scan's interpreter extras

    @param host  the scan's view
    @returns     one finding per Python site, and per instance for each other kind
    """
    code, title = "env-language-packages", "Language packages outside both managers"
    extras = host.result.interpreter_extras
    out = []
    for item in extras.get("python") or []:
        dists = item.get("dists") or []
        if dists:
            where = item.get("instance_prefix")
            version = item.get("version", "")
            subject = f"python{version}"
            site = item.get("site_packages") or where or "user site"
            names = ", ".join(_extra_name(d) for d in dists)
            out.append(_issue(code, Severity.MEDIUM, title, subject, where, evidence=[f"{site}: {names}"],
                              remedies=[note(code, subject,
                                             f"listed in requirements-python{version}.txt in the run directory")]))
    for kind, filename in sorted(EXTRA_FILES.items()):
        groups: dict[str, list[str]] = {}
        for item in extras.get(kind) or []:
            groups.setdefault(item.get("instance_prefix") or "", []).append(_extra_name(item))
        for where in sorted(groups):
            out.append(_issue(code, Severity.MEDIUM, title, kind, where or None,
                              evidence=[f"{kind} ({where or 'user'}): {', '.join(groups[where])}"],
                              remedies=[note(code, kind, f"listed in {filename} in the run directory; a move does "
                                                         "not reinstall them")]))
    return out


def _services_of_both(host: _Host) -> list[Issue]:
    """Flag owned services with data directories under both managers

    @param host  the scan's view
    @returns     at most one finding
    """
    with_data = [s for s in host.result.services if s.owned and s.data_dirs]
    if len({host.manager_of(s.instance_prefix) for s in with_data} - {None}) < 2:
        return []
    evidence = [f"{s.label} ({s.instance_prefix}): {', '.join(s.data_dirs)}" for s in with_data]
    return [_issue("env-services-of-both", Severity.MEDIUM, "Services from both managers", None, None,
                   evidence=evidence,
                   remedies=[note("env-services-of-both", None,
                                  "a plan stops and starts these services and lists their data directories")])]


def _dead_path_entries(host: _Host) -> list[Issue]:
    """Flag duplicate or dead PATH entries in the environment and the shell files

    @param host  the scan's view
    @returns     at most one finding
    """
    evidence = []
    for text in (host.environment.get("live_duplicates") or {}).get("PATH") or []:
        evidence.append(f"PATH lists {text} more than once")
    for entry in (host.environment.get("live") or {}).get("PATH") or []:
        if entry.get("exists") is False:
            evidence.append(f"PATH entry {entry.get('text')} does not exist")
    for rec in _records(host.environment, "assign"):
        if rec.get("var") != "PATH":
            continue
        for entry in rec.get("entries") or []:
            if entry.get("exists") is False:
                evidence.append(f"{_line_subject(rec)} adds {entry.get('text')}, which does not exist")
    if not evidence:
        return []
    return [_issue("env-dead-path-entries", Severity.LOW, "Duplicate or dead PATH entries", "PATH", None,
                   evidence=limited(evidence),
                   remedies=[_cleanup("env-dead-path-entries", "PATH", "path entries, dead entries", "drops them")])]


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
            out.append(_issue("env-etc-paths", Severity.MEDIUM, "/etc/paths entry for a prefix", subject,
                              entry.get("instance_prefix"), evidence=[f"{subject} names {entry.get('text')}"],
                              remedies=[_cleanup("env-etc-paths", subject, "system paths",
                                                 "rewrites the file with sudo")]))
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
    return [_issue("env-gui-path", Severity.LOW, "GUI PATH names a prefix", "GUI PATH",
                   named[0].get("instance_prefix"),
                   evidence=[f"launchctl getenv PATH names {', '.join((e.get('text', '') for e in named))}"],
                   remedies=[manual("env-gui-path", None, "path",
                                    [servicectl.LAUNCHCTL, "config", "user", "path", kept],
                                    "set the GUI PATH without the prefix entries", sudo=True)])]


def _shell_markers(host: _Host) -> list[Issue]:
    """List the MacPorts installer markers and `brew shellenv` lines, which `env-cleanup` edits

    @param host  the scan's view
    @returns     at most one INFO finding
    """
    recs = _records(host.environment, "marker") + _records(host.environment, "shellenv")
    if not recs:
        return []
    recs.sort(key=lambda r: (str(r.get("file")), r.get("lineno") or 0))
    evidence = [f"{_line_subject(r)} {(r.get('text') or '').strip()}" for r in recs]
    return [_issue("env-shell-markers", Severity.INFO, "Installer and shellenv markers", None, None,
                   evidence=limited(evidence),
                   remedies=[note("env-shell-markers", None, "lines `brew-ports env-cleanup` edits")])]


def _user_launchd_job(host: _Host) -> list[Issue]:
    """Flag a user's own launchd job (`owned=False`) that runs a manager's binary; the tool never touches it

    @param host  the scan's view
    @returns     one finding per job
    """
    out = []
    for svc in host.result.services:
        if svc.owned:
            continue
        program = svc.program or f"a program under {svc.instance_prefix}"
        out.append(_issue("env-user-launchd-job", Severity.MEDIUM, "A user's own launchd job runs a manager's binary",
                          svc.plist, svc.instance_prefix, evidence=[f"{svc.plist} runs {program}"],
                          remedies=[note("env-user-launchd-job", svc.plist, "edit or remove it by hand before its "
                                         "program's package or prefix goes; the tool never stops or deletes it")]))
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
    shown = shell if not real or real == shell else f"{shell} ({real})"
    return [_issue("env-login-shell", Severity.HIGH, "Login shell provided by a package", shell, owner,
                   evidence=[f"the login shell {shown} lies under {owner}"],
                   remedies=[note("env-login-shell", shell, "a plan that removes its package needs an accepted "
                                                            "mapping for it, and phase 5 switches the login shell "
                                                            "before any removal")])]


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
        out.append(_issue("env-sourced-files", Severity.LOW, "Shell file sources files from a prefix", subject,
                          prefixes[0] if prefixes else None, evidence=[(rec.get("text") or "").strip()],
                          remedies=[_cleanup("env-sourced-files", subject, "sourced files",
                                             "neutralises the line when that prefix is removed")]))
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
    return [a for a in issue.remedies if a.kind == "command" and not a.manual]


def _defer_cross_linkage(issues: list[Issue]) -> None:
    """Drop the rebuild of a cross-prefix linkage whose package a broken-linkage remedy rebuilds; keep its evidence

    @param issues  every finding; a deferred one is changed in place
    """
    rebuilt = {(i.instance_prefix, i.subject): i.code for i in issues
               if i.code in ("brew-broken-linkage", "ports-broken-binaries") and _runnable(i)}
    for issue in issues:
        code = rebuilt.get((issue.instance_prefix, issue.subject)) if issue.code == "env-cross-prefix-linkage" else None
        if code:
            issue.remedies = [note(issue.code, issue.subject, f"rebuilt by the {code} remedy")]
            issue.confirm_each = False


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


def blocked_by_lines(found: Iterable[Issue]) -> list[str]:
    """Return a line for each finding that stops the move, with what was found and how to fix it

    @param found  the blocking findings
    @returns      the lines; the evidence and the remedies are indented under their finding
    """
    lines = []
    for issue in found:
        subject = f": {issue.subject}" if issue.subject else ""
        where = f" ({issue.instance_prefix})" if issue.instance_prefix not in (None, issue.subject) else ""
        lines.append(f"this stops the move: {issue.title}{subject}{where}")
        lines.extend(f"    {line}" for line in issue.evidence[:EVIDENCE_SHOWN])
        lines.extend(f"    Fix: {describe(a)}" for a in issue.remedies)
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


def _tag(issue: Issue, action: Action) -> str:
    """Return the report's label of a remedy: a note, a manual command, or a fix and how it is confirmed

    @param issue   the finding
    @param action  one of its remedies
    @returns       `note:`, `manual:`, `fix [auto]:`, `fix [confirm]:` or `fix:`
    """
    if action.kind == "note":
        return "note:"
    if action.manual:
        return "manual:"
    return "fix [auto]:" if issue.auto_fix else ("fix [confirm]:" if issue.confirm_each else "fix:")


def issue_lines(issue: Issue) -> list[str]:
    """Return the report lines of one finding: its name and title, its evidence, then its remedies

    @param issue  a finding
    @returns      the lines, indented for the report
    """
    head = f"  {issue.code}  {issue.title}"
    if issue.subject:
        head += f": {issue.subject}"
    if issue.instance_prefix and issue.instance_prefix != issue.subject:
        head += f"  ({issue.instance_prefix})"
    lines = [head] + [f"        {line}" for line in issue.evidence]
    lines += [f"        {_tag(issue, a)} {describe(a)}" for a in issue.remedies]
    return lines


def render(issues: Sequence[Issue], blocks: dict[str, list[str]], notes: Sequence[str] = ()) -> list[str]:
    """Return the text report: the issues by severity, what blocks a plain plan per target, then the notes

    @param issues  the findings, sorted
    @param blocks  the names of the blocking findings by target manager
    @param notes   the scan's notes
    @returns       the report lines
    """
    if not issues:
        lines = ["doctor: no findings"]
    else:
        lines = []
        for severity in sorted(Severity, reverse=True):
            group = [i for i in issues if i.severity is severity]
            if group:
                lines.append(severity.name)
                for issue in group:
                    lines.extend(issue_lines(issue))
    lines.append("")
    for target in ("brew", "ports"):
        lines.append(f"blocks apply (target {target}): {', '.join(blocks.get(target) or []) or 'none'}")
    lines.extend(f"note: {text}" for text in notes)
    return lines


def findings_exit(issues: Sequence[Issue]) -> int:
    """Return exit 1 when an issue above INFO is present, else 0

    @param issues  the findings
    @returns       `EXIT_FINDINGS` or `EXIT_OK`
    """
    return EXIT_FINDINGS if any(i.severity > Severity.INFO for i in issues) else EXIT_OK


# --fix -------------------------------------------------------------------------------

class _Stopped(Exception):
    """A remedy failed or a service did not stop: `doctor --fix` ends with exit 4"""


def _key(issue: Issue) -> tuple[str, str | None, str | None]:
    """Return an issue's name, instance and subject, which a recomputed issue shares

    @param issue  a finding
    @returns      the key that names it across a recomputation
    """
    return (issue.code, issue.instance_prefix, issue.subject)


def _at_macports_default(inst: Instance) -> bool:
    """Return whether the instance is at `/opt/local`, the base package's only prefix: by identity, else by text

    @param inst  a MacPorts instance
    @returns     True at `/opt/local`
    """
    ident = system.identity(mp_locate.DEFAULT_PREFIX)
    if ident is not None and tuple(inst.identity) == ident:
        return True
    return os.path.normpath(inst.prefix) == os.path.normpath(mp_locate.DEFAULT_PREFIX)


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
    """`doctor --fix`: the `auto_fix` remedies behind one confirmation, then each `confirm_each` one by one

    A finding about a package that an earlier remedy of the run changed is skipped, with the rescan note.
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
        self.env_overrides = {i.instance_prefix for i in self.issues if i.code == "brew-env-override"}
        self.fixed: set[int] = set()
        self.superseded: set[int] = set()        # unrequested leaves a recomputation replaced
        self.declined: set[tuple[str, str | None, str | None]] = set()
        self.snapshotted: set[str] = set()
        self.repaired: set[str | None] = set()
        self.about: dict[int, set[PackageKey]] = {}     # the packages of each finding, read before any remedy runs
        self.changed: dict[PackageKey, str] = {}        # a package a remedy changed -> that remedy's finding
        self.touched = False

    def say(self, text: str) -> None:
        """Print one line of the `--fix` output

        @param text  the line
        """
        self.ctx.console.out(text)

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
        if not self.env_overrides:
            return False
        uses_brew = any(a.env_profile == "brew" for a in _runnable(issue))
        return uses_brew and (issue.instance_prefix in self.env_overrides or None in self.env_overrides)

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

    def procedure_steps(self, issue: Issue) -> list[str]:
        """Return the base package procedure's steps for the prompt and `--dry-run`; empty when the repair skips it

        Only `ports-cannot-run`, and `ports-platform-mismatch` on a base without `port migrate`, run it.

        @param issue  a finding
        @returns      the step lines
        """
        if issue.code not in ("ports-platform-mismatch", "ports-cannot-run") or not self.is_manager_repair(issue):
            return []
        inst = self.instances.get(issue.instance_prefix or "")
        if inst is None or not _at_macports_default(inst):
            return []
        if issue.code == "ports-platform-mismatch" and "migrate" in inst.features and inst.binary:
            return []
        try:
            major = mp_bootstrap.macos_major(self.bundle.result.system.get("macos"))
        except mp_bootstrap.BootstrapError:
            return ["the MacPorts base package procedure (the macOS version is not known yet)"]
        return mp_bootstrap.describe(major)

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
        if issue.instance_prefix in self.repaired:
            why = f"the manager repair changed {issue.instance_prefix}"
        elif changed:
            why = f"the {self.changed[changed[0]]} remedy changed {changed[0][2]}"
        else:
            return False
        self.say(f"  {issue.code} {issue.subject or ''}: skipped, {why}; run `brew-ports doctor --rescan`")
        return True

    # Prompts -------------------------------------------------------------------

    def describe_remedy(self, issue: Issue) -> list[str]:
        """Return the lines that present a finding before `--fix` applies it: its remedies and what runs first

        @param issue  the finding
        @returns      the lines, indented for the prompt
        """
        subject = f": {issue.subject}" if issue.subject else ""
        where = f"  ({issue.instance_prefix})" if issue.instance_prefix else ""
        lines = [f"  {issue.code}  {issue.title}{subject}{where}"]
        lines += [f"      {describe(a)}" for a in _runnable(issue)]
        pair = removes_package(issue)
        if pair:
            services = self.stoppable(issue, pair)
            lines.append(f"      first: the phase 1 snapshot of {issue.instance_prefix or 'the instance'}")
            if services:
                lines.append(f"      first: stop {', '.join((s.label for s in services))} and wait for them to exit")
            data = sorted({d for s in services for d in s.data_dirs})
            if data:
                lines.append(f"      data directories of {pair[1]}: {', '.join(data)}")
        if self.is_manager_repair(issue):
            lines.append(f"      a manager repair of {issue.instance_prefix}")
            steps = self.procedure_steps(issue)
            if steps:
                lines.append("      the MacPorts base package procedure:")
                lines += [f"        {step}" for step in steps]
        if needs_terminal_answer(issue):
            lines.append("      needs an answer on a terminal")
        return lines

    def ask(self, issue: Issue) -> bool:
        """Present a finding and ask whether to apply it; a removal takes only an answer on a terminal

        @param issue  the finding
        @returns      True when the user agrees
        """
        for line in self.describe_remedy(issue):
            self.say(line)
        question = f"Apply {issue.code} to {issue.subject or issue.instance_prefix or 'this host'}?"
        if needs_terminal_answer(issue):
            answer = self.ctx.confirm_terminal(question)
            if not answer and not self.ctx.tty:
                self.say(f"  {issue.code} needs an answer on a terminal: not applied")
            return answer
        return self.ctx.confirm(question, default=False)

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
        snapshot.write(self.runner, self.run_dir, self.bundle, [inst], id_prefix="doctor",
                       local_snapshot=not self.snapshotted, uid=self.uid)
        self.snapshotted.add(inst.prefix)
        self.say(f"  snapshot of {inst.prefix} in {snapshot.snapshot_dir(self.run_dir)}")

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
                if not gone:
                    self.say(f"  could not delete {svc.plist}")
            return
        for svc, ok in servicectl.restart(self.runner, booted, list(self.instances.values()), id_prefix=prefix):
            if not ok:
                self.say(f"  could not start {svc.label} again from {svc.plist}")

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
        actions = _runnable(issue)
        results = [self.runner.run(action, defer_result=True) for action in actions]
        # A post-check decides whatever the exit statuses said; without one they decide.
        checked = verify(issue, self.runner, self.bundle)
        ok = checked if checked is not None else all(r.ok for r in results)
        for action in actions:
            if not action.read_only:
                self.runner.record_result(action, ok)
        if checked is False:
            return f"the post-check of {issue.code} found it unrepaired"
        if not ok:
            return f"a command of {issue.code} failed"
        return None

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
            raise _Stopped(f"{issue.code} {issue.subject or ''}: {failure}")
        self.fixed.add(id(issue))
        if self.changes_package(issue):
            for key in self.packages_of(issue):
                self.changed.setdefault(key, issue.code)
        self.say(f"  {issue.code} {issue.subject or ''}: done")

    @staticmethod
    def answered(_question: str) -> bool:
        """Answer yes to the base package procedure's question: the repair's own prompt showed its steps

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
            lines = health_module("ports").manager_repair(issue, self.runner, self.run_dir, self.ctx.environ,
                                                          self.ctx.console, confirm=self.answered)
        except (ActionFailed, EscalationFailed, Interrupted) as exc:
            raise _Stopped(f"{issue.code} {issue.instance_prefix or ''}: {exc}") from None
        for line in lines:
            self.say("  " + line)
        self.repaired.add(issue.instance_prefix)
        self.fixed.add(id(issue))

    # The run -------------------------------------------------------------------

    def candidates(self) -> tuple[list[Issue], list[Issue]]:
        """Return the findings `--fix` applies after one confirmation, and those it asks about one by one

        @returns  both lists, ordered; a finding whose brew remedy `brew-env-override` refuses is in neither
        """
        auto = [i for i in self.issues if i.auto_fix and _runnable(i)]
        each = [i for i in self.issues if i.confirm_each and not i.auto_fix
                and (_runnable(i) or self.is_manager_repair(i))]
        kept_auto, kept_each = [], []
        for issue in auto + each:
            if self.refused(issue):
                self.say(f"  {issue.code} {issue.subject or ''}: brew-env-override holds for {issue.instance_prefix}, "
                         "so its brew remedy is not run")
            elif issue.auto_fix:
                kept_auto.append(issue)
            else:
                kept_each.append(issue)
        return self.ordered(kept_auto), self.ordered(kept_each)

    def print_plan(self, auto: Sequence[Issue], each: Sequence[Issue]) -> None:
        """Print what `--fix` would apply, in its two groups, without running anything

        @param auto  the findings applied after one confirmation
        @param each  the findings asked about one by one
        """
        self.say("doctor --fix --dry-run: nothing is run")
        if auto:
            self.say("after one confirmation:")
            for issue in auto:
                for line in self.describe_remedy(issue):
                    self.say(line)
        if each:
            self.say("one by one, each behind its own prompt:")
            for issue in each:
                for line in self.describe_remedy(issue):
                    self.say(line)

    def run(self) -> int | None:
        """Run `--fix`; return its exit code, or None when the report's code stands: no remedy to run, or `--dry-run`

        @returns                the exit code, or None
        @throws PreflightError  sudo caches no credentials for a remedy that escalates
        """
        auto, each = self.candidates()
        if not auto and not each:
            self.say("doctor --fix: no remedy the tool runs")
            return None
        if self.dry_run:
            self.print_plan(auto, each)
            return None
        if self.needs_sudo(auto + each):
            self.runner.sudo_preflight()
        # Read before any remedy runs: a remedy can replace the keg or the link a finding queued behind it names.
        for issue in auto + each:
            self.packages_of(issue)
        try:
            if auto:
                self.say("remedies applied without a per-item prompt:")
                for issue in auto:
                    for line in self.describe_remedy(issue):
                        self.say(line)
                if self.ctx.confirm(f"Apply these {len(auto)} remedies?", default=False):
                    for issue in auto:
                        if not self.skipped(issue):
                            self.apply(issue)
                else:
                    self.say("  not applied")
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
        except _Stopped as exc:
            self.ctx.console.warn(f"brew-ports: doctor --fix stopped: {exc}")
            return EXIT_ACTION
        left = [i for i in self.issues if i.severity > Severity.INFO and id(i) not in self.fixed
                and id(i) not in self.superseded]
        return EXIT_FINDINGS if left else EXIT_OK

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
        ctx.console.info("doctor: reusing the scan of the last ten minutes (--rescan takes a fresh one)")
    issues = detect_all(bundle, runner)
    blocks = blocks_apply(issues, bundle.result.instances, host_arch=runner.host_arch, environ=ctx.environ,
                          packages=bundle.result.packages)
    # The detectors add their notes to the bundle, so both are read after detect_all.
    result = model.DoctorResult(created=state.now_iso(), issues=issues, blocks_apply=blocks, notes=list(bundle.notes))
    data = model.to_plain(result)
    run_dir.write_json("doctor.json", model.to_json(data))
    if ctx.args.json:
        ctx.console.json(data)
    else:
        for line in render(issues, blocks, bundle.notes):
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
                ctx.console.warn(f"brew-ports: {exc}")
                return EXIT_PREFLIGHT
            return code if fixed is None else fixed
        finally:
            bundle.close()

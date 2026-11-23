"""What a plan fixes ahead of the run: the target upgrades, phases 2 and 3, and the phase 6 previews

`apply` computes the other phases when they run, so the plan lists them without actions.
"""

from __future__ import annotations

import dataclasses
import glob
import os
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import doctor, env, system
from .homebrew import actions as brew_actions, locate as brew_locate
from .macports import actions as mp_actions
from .model import Action, Instance, Issue, Manager, Mapping, OnFailure, Package, Phase, Plan, Service
from .report import at, series, typed
from .runner import BREW_NAMED_ONLY, RM, arch_argv
from .state import slug

# the findings phase 2 repairs, in the order it repairs them
PHASE2_CODES = ("brew-keg-without-receipt", "brew-unlinked-keg", "brew-missing-dependency", "brew-broken-linkage",
                "brew-renamed-keg", "ports-missing-file", "ports-missing-image", "ports-broken-binaries")
# the findings whose remedies replace a target package in place
REINSTALL_CODES = ("brew-keg-without-receipt", "brew-broken-linkage", "ports-missing-image", "ports-broken-binaries")
TAR = system.TAR
SYSTEM_LIBRARY = "/Library"
PROTECTED = ("/", "/usr", "/usr/local", "/opt", "/Applications", "/Library", "/System", "/private", "/var", "/etc",
             "/Users")
MACPORTS_VAR_SKIPPED = ("macports", "run", "log", "cache", "tmp")
MACPORTS_LEGACY = ("/Applications/DarwinPorts", "/Library/Receipts/DarwinPorts*.pkg",
                   "/Library/Receipts/MacPorts*.pkg", "/Library/StartupItems/DarwinPortsStartup",
                   "/Library/Tcl/darwinports1.0", "/Library/Tcl/macports1.0")
HOMEBREW_REPOSITORY_FILES = (
    ".git", ".gitattributes", ".gitignore", ".github", ".devcontainer", ".oss-scanner", ".dockerignore",
    ".editorconfig", ".irb_config", ".ruby-version", ".shellcheckrc", ".vale.ini", ".yardopts", ".sublime",
    ".vscode", ".cursor", ".claude", ".codex", "AGENTS.md", "CLAUDE.md", "CHANGELOG.md", "CODEOWNERS",
    "CONTRIBUTING.md", "Dockerfile", "Dockerfile.test.yml", "LICENSE.txt", "README.md", "Library", "bin/brew",
    "completions", "docs", "manpages", "package")
HOMEBREW_PREFIX_FILES = (
    "Cellar", "Caskroom", "bin/brew", "etc/bash_completion.d/brew", "share/doc/homebrew", "share/man/man1/brew.1",
    "share/man/man1/brew-cask.1", "share/man/man1/README.md", "share/zsh/site-functions/_brew",
    "share/zsh/site-functions/_brew_cask", "share/fish/vendor_completions.d/brew.fish", "var/homebrew")
PHASE_NAMES = {0: "checks before starting", 1: "save a record for undo", 2: "repair the installation that stays",
               3: "install the replacements", 4: "check the replacements", 5: "uninstall the old packages",
               6: "uninstall the old managers", 7: "clean up the shell files", 8: "final check"}
PHASE_3_ALL = "install the replacements and upgrade the other packages"     # phase 3 of a plan with `--upgrade-all`
# What `brew upgrade --cask` does with the apps that the cask tells it to quit, unless the user turned that off.
OPEN_APPS = "Homebrew may close an app that is open for its upgrade, and then opens it again."
NEWEST = "the newest version"       # stands for the version an upgrade installs, where `brew outdated` names none


# The target's dependency closure ----------------------------------------------------------------

def runtime_deps(entry: dict[str, Any] | None) -> list[str]:
    """Return a catalogue formula's run-time dependencies

    The plain names of `stable_dependencies` count, and the tagged ones not needed only to build, test or as an option.

    @param entry  the formula's catalogue entry, or None
    @returns      the dependency names, without their tap
    """
    out: list[str] = []
    for dep in (entry or {}).get("stable_dependencies") or []:
        items = [(dep, [])] if isinstance(dep, str) else list(dep.items()) if isinstance(dep, dict) else []
        for name, tags in items:
            words = {str(t).lstrip(":") for t in (tags if isinstance(tags, list) else [tags])}
            if not words & {"build", "test", "optional"}:
                out.append(str(name).rsplit("/", 1)[-1])
    return out


def port_deps(entry: Any) -> list[str]:
    """Return the port names of a PortIndex entry's `depends_lib`, `depends_run` and `depends_build`

    `port:zlib`, `lib:libz:zlib` and `path:bin/perl:perl5` all end in the port.

    @param entry  the port's PortIndex entry
    @returns      the port names, each once
    """
    out = []
    for dep in list(entry.depends_lib) + list(entry.depends_run) + list(entry.depends_build):
        name = str(dep).rsplit(":", 1)[-1]
        if name and name not in out:
            out.append(name)
    return out


class TargetView:
    """The target instance's installed packages and catalogue, by the target manager's rules"""

    def __init__(self, target: Instance, installed: Sequence[Package], catalogue: Any = None,
                 portindex: Any = None) -> None:
        """Index the target's installed packages by key, with the packages that depend on each

        @param target     the target instance
        @param installed  the target's packages; a port counts only when it is active
        @param catalogue  a Homebrew target's offline catalogue, or None
        @param portindex  a MacPorts target's PortIndex, or None
        """
        self.target = target
        self.brew = target.manager is Manager.BREW
        self.catalogue = catalogue
        self.portindex = portindex
        self.formulae: dict[str, Package] = {}
        self.casks: dict[str, Package] = {}
        for pkg in installed:
            if pkg.kind == "formula":
                self.formulae[pkg.name] = pkg
            elif pkg.kind == "cask":
                self.casks[pkg.name] = pkg
            elif pkg.kind == "port" and pkg.active:
                self.formulae[pkg.name.lower()] = pkg
        self.dependents: dict[str, set[str]] = {}
        for pkg in self.formulae.values():
            for dep in pkg.deps:
                self.dependents.setdefault(self.key(dep), set()).add(self.key(pkg.name))

    def key(self, name: str) -> str:
        """Return the key a target package is known by: a formula's current catalogue name, a port's lower case

        @param name  a formula or port name
        @returns     the key
        """
        if self.brew:
            canon = self.catalogue.canonical(name) if self.catalogue is not None else None
            return canon or name
        return name.lower()

    def installed(self, name: str) -> Package | None:
        """Return the installed target package of a name

        @param name  a formula or port name, an alias or old name included
        @returns     the package, or None when the target lacks it
        """
        return self.formulae.get(self.key(name))

    def catalogue_deps(self, name: str) -> list[str]:
        """Return a target package's dependencies as the catalogue or PortIndex lists them

        @param name  a formula or port name
        @returns     a formula's run-time dependencies, or a port's library, run and build dependencies
        """
        if self.brew:
            return runtime_deps(self.catalogue.formula(name)) if self.catalogue is not None else []
        entry = self.portindex.get(name) if self.portindex is not None else None
        return port_deps(entry) if entry is not None else []

    def closure(self, names: Iterable[str]) -> list[str]:
        """Return the names and everything they need, by recorded and catalogue dependencies

        MacPorts build dependencies count, since `port install` upgrades those too when it builds.

        @param names  target package names
        @returns      their keys and their dependencies' keys, breadth first
        """
        out: list[str] = []
        seen: set[str] = set()
        todo = [self.key(n) for n in names]
        while todo:
            name = todo.pop(0)
            if name in seen:
                continue
            seen.add(name)
            out.append(name)
            pkg = self.installed(name)
            todo.extend(self.key(d) for d in (list(pkg.deps) if pkg else []) + self.catalogue_deps(name))
        return out

    def dependents_of(self, names: Iterable[str]) -> list[str]:
        """Return every installed package that depends on one of `names`, transitively

        @param names  target package names
        @returns      the dependents' keys, nearest first
        """
        out: list[str] = []
        todo = sorted(set(self.key(n) for n in names))
        seen = set(todo)
        while todo:
            for dep in sorted(self.dependents.get(todo.pop(0), ())):
                if dep not in seen:
                    seen.add(dep)
                    out.append(dep)
                    todo.append(dep)
        return out

    def version_change(self, name: str, outdated_versions: dict[str, str]) -> str:
        """Return a target package's installed version and the one it upgrades to, as the plan report shows them

        @param name               a target package name
        @param outdated_versions  the version each outdated formula upgrades to, as `brew outdated` names it
        @returns                  such as `3.5.0 -> 3.6.0`; a port whose epoch changes shows both epochs
        """
        pkg = self.installed(name)
        old = (pkg.version if pkg else "") or "?"
        if self.brew:
            new = outdated_versions.get(self.key(name)) or (outdated_versions.get(pkg.name) if pkg else None)
            return f"{old} -> {new or NEWEST}"
        entry = self.portindex.get(name) if self.portindex is not None else None
        if entry is None:
            return f"{old} -> {NEWEST}"
        new = f"{entry.version}_{entry.revision}"
        if pkg is not None and entry.epoch != pkg.epoch:
            return f"{old} (epoch {pkg.epoch}) -> {new} (epoch {entry.epoch})"
        return f"{old} -> {new}"


# Target upgrades -----------------------------------------------------------------------------

@dataclass
class Upgrades:
    """The target upgrades a plan causes, why and to which version, and the pinned ones that block it"""

    names: list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)
    versions: dict[str, str] = field(default_factory=dict)
    explicit: list[str] = field(default_factory=list)          # phase 3 upgrades them by name, for the replacements
    pinned: dict[str, list[str]] = field(default_factory=dict)  # pinned blocker -> the roots whose mappings need it
    checked: list[str] = field(default_factory=list)   # in `names` for the check after the upgrades, not upgraded
    # Pins, as the user answered: the formulae and the casks whose pin the plan removes, each with its version
    # change, and the pinned ones that stay, each with its version change, what the user runs for it, and
    # whether the user answered no for it.
    unpin: dict[str, str] = field(default_factory=dict)
    unpin_casks: dict[str, str] = field(default_factory=dict)
    kept_pins: dict[str, tuple[str, str, bool]] = field(default_factory=dict)
    asked: bool = False                                # a terminal and no --yes: questions about pins can be put
    asking: bool = False                               # and the plan is not refused so far, so they are put
    # With `--upgrade-all`: the formulae or ports it upgrades by name; those of them that no replacement's
    # upgrades reach; those of these that no replacement uses either, so that the move does not need them; the
    # casks with their version change; the formulae and the casks that stay as they are, with the reason.
    also: list[str] = field(default_factory=list)
    others: list[str] = field(default_factory=list)
    optional: list[str] = field(default_factory=list)
    casks: dict[str, str] = field(default_factory=dict)
    left: dict[str, str] = field(default_factory=dict)
    left_casks: dict[str, str] = field(default_factory=dict)


def upgrades(view: TargetView, targets: dict[str, list[str]], reinstalled: Sequence[str],
             outdated_versions: dict[str, str]) -> Upgrades:
    """Return the target upgrades the plan causes, and the pinned packages among them as blockers

    The outdated mapped targets, companions and reinstalled packages are upgraded, with what a mapped target
    needs when phase 3 installs or upgrades that target. Every package that depends on one of them is only
    checked after the upgrades: a command of phase 3 upgrades what it names and what that needs, with either
    manager.

    @param view               the target's installed packages and catalogue
    @param targets            the roots that need each mapped target and companion, by target name
    @param reinstalled        the target packages the plan reinstalls or rebuilds
    @param outdated_versions  the version each outdated formula upgrades to, as `brew outdated` names it
    @returns                  the upgrades
    """
    out = Upgrades()
    cause: dict[str, set[str]] = {}
    closures = {name: view.closure([name]) for name in targets}

    def add(name: str, reason: str, roots: Iterable[str], upgraded: bool = True) -> None:
        pkg = view.installed(name)
        if pkg is None:
            return
        key = view.key(name)
        if key not in out.names:
            out.names.append(key)
            out.reasons[key] = reason
            if pkg.outdated and upgraded:
                out.versions[key] = view.version_change(key, outdated_versions)
            else:
                out.versions[key] = pkg.version or "?"
                out.checked.append(key)
        cause.setdefault(key, set()).update(roots)

    for name, roots in targets.items():
        pkg = view.installed(name)
        if pkg is not None and pkg.outdated:
            add(name, "a replacement", roots)
            if view.key(name) not in out.explicit:
                out.explicit.append(view.key(name))
    for name in reinstalled:
        pkg = view.installed(name)
        roots = [r for t, rs in targets.items() for r in rs if view.key(name) in closures[t]]
        if pkg is not None and pkg.outdated:
            add(name, "reinstalled by the plan", roots)
        # `brew reinstall` brings what the formula needs up to date as an install does. A port is rebuilt
        # without its dependencies.
        for dep in view.closure([name])[1:] if view.brew else []:
            found = view.installed(dep)
            if found is not None and found.outdated:
                add(dep, f"a dependency of {name}", roots)
    again = {view.key(name) for name in reinstalled}
    for name, roots in targets.items():
        pkg = view.installed(name)
        if pkg is not None and not pkg.outdated and view.key(name) not in again:
            continue                    # installed and current: phase 3 runs nothing that upgrades what it needs
        for dep in closures[name][1:]:
            pkg = view.installed(dep)
            if pkg is not None and pkg.outdated:
                add(dep, f"a dependency of {name}", roots)
    upgraded = list(out.names)
    for name in upgraded:
        for dependent in view.dependents_of([name]):
            add(dependent, f"depends on {name}", cause.get(name, ()), upgraded=False)
    for name in out.names:
        pkg = view.installed(name)
        if pkg is not None and pkg.pinned:
            out.pinned[name] = sorted(cause.get(name, ()))
    return out


def command(view: TargetView, host_arch: str, *args: str) -> str:
    """Return a `brew` or `port` command of the target for the user to run, as they would type it

    @param view       the target's installed packages
    @param host_arch  the host's architecture
    @param args       the arguments after the binary
    @returns          the command; a `port` command under sudo
    """
    if view.brew:
        return brew_actions.typed_line(view.target, args, host_arch)
    return typed([view.target.binary or os.path.join(view.target.prefix, "bin", "port"), *args], True)


def unpin_commands(view: TargetView, host_arch: str, name: str, cask: bool = False, upgrade: bool = True) -> str:
    """Return what the user runs to remove a pin and upgrade the package, as a sentence of the plan report

    @param view       the Homebrew target's installed packages
    @param host_arch  the host's architecture
    @param name       the pinned formula, or the pinned cask's token
    @param cask       whether the package is a cask
    @param upgrade    whether the package has a newer version
    @returns          `To upgrade it:` and the two commands, each in backticks; `To remove the pin:` and the
                      first of them for a package without a newer version
    """
    unpin = f"`{command(view, host_arch, 'unpin', *(['--cask'] if cask else []), name)}`"
    if not upgrade:
        return f"To remove the pin: {unpin}"
    newest = command(view, host_arch, "upgrade", "--cask" if cask else "--formula", name)
    return f"To upgrade it: {unpin}, then `{newest}`"


def unpinned(view: TargetView, ups: Upgrades, name: str) -> None:
    """Take a pinned blocker out of the way, as the user answered: its pin goes, and a newer version is installed

    @param view  the target's installed packages
    @param ups   the upgrades the replacements cause
    @param name  a key of `ups.pinned`
    """
    del ups.pinned[name]
    ups.unpin[name] = ups.versions.get(name, "")
    pkg = view.installed(name)
    if pkg is not None and pkg.outdated and name not in ups.explicit:
        ups.explicit.append(name)


def _why_left(view: TargetView, host_arch: str, ups: Upgrades, pkg: Package, trace: bool = False) -> str | None:
    """Return why `--upgrade-all` leaves an outdated formula or port as it is, with the command that upgrades it

    Nothing changes under a pin that stays: an upgrade can break the pinned formula that uses the package, and
    Homebrew refuses a formula that needs the newest version of a pinned one. `port upgrade` puts the successor
    of a replaced port in its place, which the checks of the move would take for a loss.

    @param view       the target's installed packages and catalogue
    @param host_arch  the host's architecture, for the command
    @param ups        the upgrades so far, with the pins the user answered to remove
    @param pkg        an outdated formula or port of the target that is not pinned itself
    @param trace      whether a Homebrew stays after the move, so that the `port` command builds in trace mode
    @returns          the reason and the command, as the words that follow the package's name; None for a
                      package to upgrade
    """
    name = view.key(pkg.name)
    if not view.brew:
        if not pkg.renamed_to:
            return None
        replace = command(view, host_arch, *(["-t"] if trace else []), "upgrade", pkg.name)
        return f"MacPorts replaced it with {pkg.renamed_to}. To make that change: `{replace}`"

    def pinned(other: str) -> bool:
        found = view.installed(other)
        return found is not None and found.pinned and other not in ups.unpin

    def users(other: str) -> list[str]:
        return [d for d in view.dependents_of([other]) if pinned(d)]

    def outdated(other: str) -> bool:
        found = view.installed(other)
        return found is not None and found.outdated

    upgrade = command(view, host_arch, "upgrade", "--formula", name)
    held = users(name)
    if held:
        return (f"{series(held)}, which {'is' if len(held) == 1 else 'are'} pinned, "
                f"{'uses' if len(held) == 1 else 'use'} it. To upgrade it all the same: `{upgrade}`")
    needed = [d for d in view.closure([name])[1:] if outdated(d)]
    pins = [d for d in needed if pinned(d)]
    if pins:
        return (f"it needs the newest {series(pins)}, which {'is' if len(pins) == 1 else 'are'} pinned. To upgrade "
                f"it: `{command(view, host_arch, 'unpin', *pins)}`, then `{upgrade}`")
    under = [d for d in needed if users(d)]
    if under:
        return (f"its upgrade would also upgrade {series(under)}, which a pinned formula uses. To upgrade it all "
                f"the same: `{upgrade}`")
    return None


# Asks whether to remove a pin: the package's name, its version change, whether it is a cask, and the formulae
# that the pin alone keeps from an upgrade.
Unpin = Callable[[str, str, bool, Sequence[str]], bool]


def _formula_pins(view: TargetView, host_arch: str, ups: Upgrades, outdated_versions: dict[str, str],
                  unpin: Unpin) -> None:
    """Put each pinned formula that `--upgrade-all` would upgrade, or that keeps others from an upgrade, to the user

    A pinned formula at its newest version is asked about when a formula that it uses has a newer one: the
    option leaves those as they are while the pin stays. A plan that is refused already asks nothing.

    @param view               the target's installed packages and catalogue
    @param host_arch          the host's architecture, for the commands printed for the user
    @param ups                the upgrades so far, which gain the pins to remove and the pins that stay
    @param outdated_versions  the version each outdated formula upgrades to, as `brew outdated` names it
    @param unpin              asks whether to remove a pin
    """
    for pkg in sorted(view.formulae.values(), key=lambda p: p.name):
        name = view.key(pkg.name)
        if not pkg.pinned or name in ups.unpin or name in ups.pinned:
            continue
        held: list[str] = []
        if pkg.outdated:
            change = view.version_change(name, outdated_versions)
        else:
            change = pkg.version or "?"
            held = [d for d in view.closure([name])[1:] if (dep := view.installed(d)) is not None and dep.outdated]
            if not held:
                continue
        if ups.asking and unpin(name, change, False, held):
            ups.unpin[name] = change
        else:
            how = unpin_commands(view, host_arch, name, upgrade=pkg.outdated)
            ups.kept_pins[name] = (change, how, ups.asking)


def _casks(view: TargetView, host_arch: str, ups: Upgrades, versions: dict[str, str], unpin: Unpin) -> None:
    """Add the outdated casks of the target to the upgrades of `--upgrade-all`, or to what it leaves

    A cask that asks for the password stays as it is: brew-ports turns sudo off for every `brew` command it
    runs. A pinned cask is put to the user.

    @param view       the target's installed packages
    @param host_arch  the host's architecture, for the commands printed for the user
    @param ups        the upgrades so far, which gain the casks
    @param versions   the version each outdated cask upgrades to
    @param unpin      asks whether to remove a pin
    """
    for token, cask in sorted(view.casks.items()):
        if not cask.outdated:
            continue
        change = f"{cask.version or '?'} -> {versions.get(token) or NEWEST}"
        if cask.privileged_install or cask.privileged_uninstall:
            if cask.pinned:
                why = "it is pinned, and Homebrew asks for your password for its upgrade. "
                ups.left_casks[token] = why + unpin_commands(view, host_arch, token, cask=True)
            else:
                ups.left_casks[token] = ("Homebrew asks for your password for its upgrade. To upgrade it: "
                                         f"`{command(view, host_arch, 'upgrade', '--cask', token)}`")
        elif cask.pinned and not (ups.asking and unpin(token, change, True, ())):
            ups.kept_pins[f"{token} (app)"] = (change, unpin_commands(view, host_arch, token, cask=True), ups.asking)
        else:
            if cask.pinned:
                ups.unpin_casks[token] = change
            ups.casks[token] = change


def every_upgrade(view: TargetView, host_arch: str, ups: Upgrades, versions: tuple[dict[str, str], dict[str, str]],
                  unpin: Unpin, *, trace: bool = False) -> None:
    """Add every other outdated package of the target to the upgrades, as `--upgrade-all` asks

    The pinned packages are put to the user first.

    @param view       the target's installed packages and catalogue
    @param host_arch  the host's architecture, for the commands printed for the user
    @param ups        the upgrades the replacements cause, which gain the others
    @param versions   the version each outdated formula upgrades to, as `brew outdated` names it, then the
                      same for the casks
    @param unpin      asks whether to remove the pin of a package
    @param trace      whether a Homebrew stays after the move, for the `port` commands printed for the user
    """
    _formula_pins(view, host_arch, ups, versions[0], unpin)
    for pkg in sorted(view.formulae.values(), key=lambda p: p.name):
        name = view.key(pkg.name)
        if not pkg.outdated or name in ups.explicit or name in ups.pinned or name in ups.kept_pins:
            continue
        # A yes to the question about its pin is a yes to its upgrade, whatever else uses the package.
        why = None if name in ups.unpin else _why_left(view, host_arch, ups, pkg, trace)
        if name in ups.names and name not in ups.checked:
            if why is None:
                ups.also.append(name)
        elif why is not None:
            ups.left[name] = why
        else:
            if name in ups.checked:     # it uses an upgraded package: only the option upgrades it
                ups.checked.remove(name)
            else:
                ups.names.append(name)
            ups.also.append(name)
            ups.others.append(name)
            ups.versions[name] = view.version_change(name, versions[0])
    _casks(view, host_arch, ups, versions[1], unpin)


# Phase 2 -----------------------------------------------------------------------------------------

def _runnable(issue: Issue) -> list[Action]:
    """Return the remedies of a finding that the tool runs itself

    @param issue  a finding
    @returns      its command remedies that are not manual
    """
    return [a for a in issue.remedies if a.kind == "command" and not a.manual]


def _subject_in(issue: Issue, view: TargetView, closure: set[str]) -> bool:
    """Return whether a finding's subject, or the name the catalogue renames it to, is in the closure

    @param issue    a finding of the target
    @param view     the target's installed packages and catalogue
    @param closure  the keys of the plan's targets, companions and their dependencies
    @returns        True when the plan needs the subject
    """
    subject = issue.subject or ""
    names = {view.key(subject)}
    if view.brew and view.catalogue is not None:
        renamed = view.catalogue.renamed_to(subject)
        if renamed:
            names.add(view.key(renamed))
    return bool(names & closure)


def phase2_issues(issues: Sequence[Issue], view: TargetView, closure: set[str]) -> list[Issue]:
    """Return the target's repair findings whose subject is a plan target, a companion or a dependency of one

    They come in `PHASE2_CODES` order.

    @param issues   the findings of every instance
    @param view     the target's installed packages and catalogue
    @param closure  the keys of the plan's targets, companions and their dependencies
    @returns        the findings phase 2 repairs
    """
    chosen = [(i, issue) for i, issue in enumerate(issues)
              if issue.repairs_install and issue.instance_prefix == view.target.prefix
              and issue.code in PHASE2_CODES and _runnable(issue) and _subject_in(issue, view, closure)]
    chosen.sort(key=lambda pair: (PHASE2_CODES.index(pair[1].code), pair[0]))
    return [issue for _, issue in chosen]


def phase2(issues: Sequence[Issue]) -> list[Action]:
    """Return the remedies of the phase 2 findings, each description naming its finding

    Their `doctor.<code>.<subject>.<step>` ids become `2.<code>.<subject>.<step>`. A `brew` command runs under
    `BREW_NAMED_ONLY`, as those of phase 3 do: Homebrew upgrades no formula that uses a repaired one.

    @param issues  the findings phase 2 repairs, in their order
    @returns       the actions of phase 2
    """
    out = []
    for issue in issues:
        for action in _runnable(issue):
            rest = action.action_id.split(".", 1)[1] if action.action_id.startswith("doctor.") else action.action_id
            profile = BREW_NAMED_ONLY if action.env_profile == "brew" else action.env_profile
            out.append(dataclasses.replace(action, action_id="2." + rest, env_profile=profile,
                                           description=f"{issue.code} {issue.subject}: {action.description}"))
    return out


def installed_by(actions: Sequence[Action]) -> list[str]:
    """Return the formulae that the `brew install` and `brew reinstall` commands among the actions name

    Such a command brings what its formulae need up to date, so the plan counts that among its upgrades.

    @param actions  the actions of phase 2
    @returns        the names, each once, in action order
    """
    out: list[str] = []
    for action in actions:
        if action.env_profile != BREW_NAMED_ONLY or "--cask" in action.argv:
            continue
        verbs = [index for index, word in enumerate(action.argv) if word in ("install", "reinstall")]
        if verbs:
            out += [word for word in action.argv[verbs[0] + 1:] if not word.startswith("-") and word not in out]
    return out


# Phase 3 -------------------------------------------------------------------------------------------

def _probe_policy(action: Action) -> Action:
    """Return the action with its failure left to the phase 4 gate, so it does not end the phase

    @param action  a phase 3 action
    @returns       the action, a `STOP` failure policy turned into `PROBE`
    """
    return dataclasses.replace(action, on_failure=OnFailure.PROBE) if action.on_failure is OnFailure.STOP else action


@dataclass
class Install:
    """One target package phase 3 needs: a mapped target or a companion"""

    kind: str                       # formula, cask, port; "" for a companion, the target manager's own kind
    name: str
    variants: list[str] = field(default_factory=list)
    adopt: bool = False


def installs(mappings: Sequence[Mapping]) -> tuple[list[Install], list[str]]:
    """Return the target packages of the accepted mappings and companions, each once, and the pipx projects

    They keep the order of `mappings`, so adoptions keep the dependencies-first order they come in.

    @param mappings  the accepted mappings, in plan order
    @returns         the installs, and the PyPI projects pipx installs
    """
    out: list[Install] = []
    projects: list[str] = []
    seen: set[tuple[str, str]] = set()

    def add(item: Install) -> None:
        ident = ("cask" if item.kind == "cask" else "package", item.name.lower())
        if ident not in seen:
            seen.add(ident)
            out.append(item)

    for m in mappings:
        if m.target_kind == "pip" and m.target_name:
            for companion in m.companions:
                add(Install("", companion))
            if m.target_name not in projects:
                projects.append(m.target_name)
            continue
        if m.target_kind not in ("formula", "cask", "port") or not m.target_name:
            continue
        variants = list(m.source.requested_variants) if m.source.kind == "port" and m.target_kind == "port" else []
        add(Install(m.target_kind, m.target_name, variants, adopt=m.adopt))
        for companion in m.companions:
            add(Install("", companion))
    return out, projects


def _pipx(target: Instance, host_arch: str, project: str) -> Action:
    """Return `<target prefix>/bin/pipx install <project>`, run as the user under the target's profile

    @param target     the target instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param project    the PyPI project
    @returns          the phase 3 action, whose failure the phase 4 gate weighs
    """
    argv = arch_argv(target.arch, host_arch, [os.path.join(target.prefix, "bin", "pipx"), "install", project])
    return Action(action_id=f"3.pipx.{project}", kind="command", argv=argv, sudo=False,
                  description=f"install the PyPI project {project} with pipx",
                  env_profile="brew" if target.manager is Manager.BREW else "ports",
                  on_failure=OnFailure.PROBE, instance_prefix=target.prefix)


def phase3_brew(view: TargetView, host_arch: str, items: Sequence[Install], *, projects: Sequence[str],
                ups: Upgrades, rebuilds: Sequence[str]) -> list[Action]:
    """Return the phase 3 actions of a Homebrew target

    The pins the user answered to remove go first; then the upgrades the replacements need, those that
    `--upgrade-all` adds, formulae before casks, the installs, one adoption per cask, the requested marks,
    pipx and the rebuilds. The upgrades that the option adds are a command of their own, so that a failure
    in it is not one of the upgrades the replacements need.

    Each command runs under `BREW_NAMED_ONLY`: Homebrew upgrades what the command names and what that needs,
    and no formula that uses one of them. The plan lists what is upgraded, and phase 3 checks the users itself.

    @param view       the target's installed packages and catalogue
    @param host_arch  the host's architecture
    @param items      the target packages of the accepted mappings and companions
    @param projects   the PyPI projects pipx installs
    @param ups        the upgrades of the plan and the pins it removes
    @param rebuilds   the target formulae to reinstall
    @returns          the actions
    """
    target = view.target
    out: list[Action] = []
    if ups.unpin:
        out.append(brew_actions.unpin(target, host_arch, "3.unpin.formulae", list(ups.unpin)))
    if ups.unpin_casks:
        out.append(brew_actions.unpin(target, host_arch, "3.unpin.casks", list(ups.unpin_casks), casks=True))
    if ups.explicit:
        out.append(brew_actions.upgrade_formulae(target, host_arch, "3.upgrade.formulae", ups.explicit))
    if ups.also:
        out.append(brew_actions.upgrade_formulae(target, host_arch, "3.upgrade.others", ups.also))
    if ups.casks:
        out.append(brew_actions.upgrade_casks(target, host_arch, "3.upgrade.casks", list(ups.casks)))
    formulae = [i.name for i in items if i.kind in ("formula", "") and view.installed(i.name) is None]
    bottled = [n for n in formulae if view.catalogue is not None and view.catalogue.has_bottle(n)]
    built = [n for n in formulae if n not in bottled]
    if bottled:
        out.append(brew_actions.install_formulae(target, host_arch, "3.install.bottled", bottled))
    if built:
        out.append(brew_actions.install_formulae(target, host_arch, "3.install.built", built))
    casks = [i.name for i in items if i.kind == "cask" and not i.adopt and i.name not in view.casks]
    if casks:
        out.append(brew_actions.install_casks(target, host_arch, "3.install.casks", casks))
    for item in items:
        if item.kind == "cask" and item.adopt and item.name not in view.casks:
            out.append(brew_actions.adopt_cask(target, host_arch, f"3.adopt.{item.name}", item.name))
    for item in items:
        pkg = view.installed(item.name) if item.kind in ("formula", "") else None
        if pkg is not None and pkg.requested is False:
            out.append(_probe_policy(brew_actions.tab_installed_on_request(
                target, host_arch, f"3.mark.{pkg.name}", [pkg.name])))
    out.extend(_pipx(target, host_arch, p) for p in projects)
    for name in rebuilds:
        out.append(brew_actions.reinstall(target, host_arch, f"3.{name}.rebuild", [name],
                                          on_failure=OnFailure.PROBE))
    return [dataclasses.replace(action, env_profile=BREW_NAMED_ONLY) for action in out]


def phase3_ports(view: TargetView, host_arch: str, items: Sequence[Install], *, projects: Sequence[str],
                 homebrew_present: bool, rebuilds: Sequence[str], others: Sequence[str] = ()) -> list[Action]:
    """Return the phase 3 actions of a MacPorts target

    An upgrade keeps an outdated target's variants; an install tries the binary archive before a
    trace-mode build, default variants first.

    @param view              the target's installed packages and PortIndex
    @param host_arch         the host's architecture
    @param items             the target packages of the accepted mappings and companions
    @param projects          the PyPI projects pipx installs
    @param homebrew_present  whether a Homebrew prefix exists, which puts builds in trace mode
    @param rebuilds          the target ports to rebuild
    @param others            the ports that `--upgrade-all` upgrades by name
    @returns                 the actions
    """
    target = view.target
    out: list[Action] = []
    ports = [i for i in items if i.kind in ("port", "")]
    upgraded: list[str] = []
    mapped = [item.name for item in ports]
    for name in mapped + list(others):
        pkg = view.installed(name)
        if pkg is not None and pkg.outdated and pkg.name not in upgraded:
            upgraded.append(pkg.name)
            # An upgrade of the option must put no successor in the place of a replaced port, which the plan
            # leaves as it is and the checks of the move would take for a loss.
            out.append(_probe_policy(mp_actions.upgrade(target, host_arch, f"3.upgrade.{pkg.name}", pkg.name,
                                                        homebrew_present=homebrew_present,
                                                        no_replace=name not in mapped)))
    fresh = [i for i in ports if view.installed(i.name) is None]
    for item in sorted(fresh, key=lambda i: bool(i.variants)):
        out.append(mp_actions.install(target, host_arch, f"3.install.{item.name}", item.name, item.variants,
                                      homebrew_present=homebrew_present, binary_first=True))
    for item in ports:
        pkg = view.installed(item.name)
        if pkg is not None and pkg.requested is False:
            out.append(_probe_policy(mp_actions.setrequested(target, host_arch, f"3.mark.{pkg.name}", [pkg.name])))
    out.extend(_pipx(target, host_arch, p) for p in projects)
    for name in rebuilds:
        pkg = view.installed(name)
        out.append(mp_actions.upgrade_forced(target, host_arch, f"3.{name}.rebuild", name,
                                             pkg.requested_variants if pkg else (),
                                             homebrew_present=homebrew_present))
    return out


# Rebuilds of target packages linked into what the plan removes ---------------------------------

def _owner_in(inst: Instance, path: str, owner_of: Callable[[str], str | None],
              formulae: dict[str, str]) -> tuple[str, str] | None:
    """Return the `(kind, name key)` of the source package that holds `path`

    A Homebrew path names a rack or an `opt` link, which a formula rename can leave under the old name.

    @param inst      the source instance the path lies in
    @param path      a file a target binary references
    @param owner_of  returns the port that registered a path, or None
    @param formulae  the formula each of the instance's racks holds, by rack, where the two names differ
    @returns         the pair, or None when no package of the instance holds the path
    """
    if inst.manager is Manager.PORTS:
        owner = owner_of(path)
        return ("port", owner.lower()) if owner else None
    for base in list(inst.spellings) + [inst.prefix, os.path.realpath(inst.prefix)]:
        for sub in ("Cellar", "opt"):
            root = os.path.join(base, sub).rstrip("/") + "/"
            if path.startswith(root):
                name = path[len(root):].split("/", 1)[0]
                return ("formula", formulae.get(name, name))
    return None


def cross_prefix_rebuilds(linkage: dict[str, Any], target: Instance, instances: Sequence[Instance], *,
                          removed: dict[str, set[tuple[str, str]]], racks: dict[str, dict[str, str]],
                          gone: set[str], owner_of: Callable[[str], str | None]) -> tuple[list[str], list[str]]:
    """Return the target packages to rebuild, and the report lines of the cross-prefix links that remain

    A package is rebuilt when its binaries reference `/usr/local`, a prefix phase 6 removes (`gone`) or no
    instance holds, or a file of a removed package (`removed`: prefix -> `(kind, name key)`).

    @param linkage    the scan's linkage report
    @param target     the target instance
    @param instances  every instance the scan found
    @param removed    the `(kind, name key)` of each package the plan removes, by prefix
    @param racks      each formula's rack of a Homebrew source, as `ScanBundle.formula_racks` names it, by prefix
    @param gone       the prefixes phase 6 removes
    @param owner_of   returns the port that registered a path, or None
    @returns          the packages to rebuild, and the lines of the links that remain
    """
    formulae = {prefix: {rack: name for name, rack in held.items() if rack != name} for prefix, held in racks.items()}
    index = env.PrefixIndex(instances)
    rebuild: list[str] = []
    remaining: list[str] = []
    for path, report in sorted((linkage.get("binaries") or {}).items()):
        prefix, _, rest = str(report.get("package") or "").partition("|")
        name = rest.partition("|")[2]
        if prefix != target.prefix or not name:
            continue
        for ref in report.get("references") or []:
            if not doctor.cross_reference(ref, report.get("instance_prefix") or prefix, index):
                continue
            where = ref.get("resolved") or ref.get("name") or ""
            inst = index.by_identity(where) or index.by_text(where)
            if ref.get("class") == "usrlocal" or inst is None or inst.prefix in gone:
                hit = True
            else:
                owner = _owner_in(inst, where, owner_of, formulae.get(inst.prefix, {}))
                hit = bool(owner and owner in removed.get(inst.prefix, set()))
            if hit:
                if name not in rebuild:
                    rebuild.append(name)
            else:
                remaining.append(f"{name} ({path}) still uses {where}, which stays: nothing to do")
    return rebuild, remaining


# Phase 6 previews ------------------------------------------------------------------------------------

def unsafe(path: str, target: Instance, home: str) -> str | None:
    """Return why phase 6 must never delete `path`

    That is the target prefix and what lies under it, a system directory, the home directory and its parents.

    @param path    a path phase 6 would delete
    @param target  the target instance
    @param home    the user's home directory
    @returns       the reason, or None when the path may go
    """
    norm = os.path.normpath(path)
    ident = tuple(target.identity) if target.identity else ()
    # An identity is (st_dev, st_ino); no other shape can match the prefix.
    if len(ident) == 2 and system.lies_under(norm, ident):
        return f"it belongs to {at(target)}, which stays"
    if system.text_names_prefix(norm, list(target.spellings) + [target.prefix], False):
        return f"it belongs to {at(target)}, which stays"
    if norm in PROTECTED:
        return "it is a system folder"
    home = os.path.normpath(home)
    if norm == home or home.startswith(norm.rstrip("/") + "/"):
        return "it is your home folder, or holds it"
    return None


def macports_archive_list(inst: Instance, home: str) -> list[str]:
    """Return what phase 6 archives of a MacPorts instance: the data in `var`, then `etc` and `~/.macports`

    @param inst  the named MacPorts instance
    @param home  the user's home directory
    @returns     the existing directories
    """
    out = []
    var = os.path.join(inst.prefix, "var")
    for name in sorted(os.listdir(var)) if os.path.isdir(var) else []:
        if name not in MACPORTS_VAR_SKIPPED and os.path.isdir(os.path.join(var, name)):
            out.append(os.path.join(var, name))
    for path in (os.path.join(inst.prefix, "etc"), os.path.join(home, ".macports")):
        if os.path.isdir(path):
            out.append(path)
    return out


def macports_delete_list(inst: Instance, home: str, services: Sequence[Service], others_survive: bool) -> list[str]:
    """Return what phase 6 deletes of a MacPorts instance

    The legacy paths and `~/.macports` go only when no other MacPorts instance survives.

    @param inst            the named MacPorts instance
    @param home            the user's home directory
    @param services        the scan's services; the instance's owned plists go too
    @param others_survive  whether another MacPorts instance stays
    @returns               the paths, each once
    """
    out = [inst.prefix]
    if inst.portdbpath and not system.text_names_prefix(inst.portdbpath, [inst.prefix], False):
        out.append(inst.portdbpath)
    apps = inst.applications_dir
    if apps and os.path.normpath(apps) not in ("/Applications", os.path.join(home, "Applications")):
        out.append(apps)
    out += sorted({s.plist for s in services if s.owned and s.instance_prefix == inst.prefix})
    if not others_survive:
        for pattern in MACPORTS_LEGACY:
            out += sorted(glob.glob(pattern))
        if os.path.isdir(os.path.join(home, ".macports")):
            out.append(os.path.join(home, ".macports"))
    return list(dict.fromkeys(out))


def homebrew_archive_list(inst: Instance) -> list[str]:
    """Return what phase 6 archives of a Homebrew instance: `var`, `etc` and the repository's taps

    @param inst  the named Homebrew instance
    @returns     the existing directories
    """
    repository = inst.repository or inst.prefix
    paths = (os.path.join(inst.prefix, "var"), os.path.join(inst.prefix, "etc"),
             os.path.join(repository, "Library", "Taps"))
    return [p for p in paths if os.path.isdir(p)]


def homebrew_delete_list(inst: Instance, services: Sequence[Service]) -> list[str]:
    """Return what phase 6 deletes of a Homebrew instance, as the official uninstall script lists it

    The links into the Cellar and a dedicated prefix's other entries are found when the phase runs.

    @param inst      the named Homebrew instance
    @param services  the scan's services; the instance's owned plists go too
    @returns         the existing paths, each once
    """
    repository = inst.repository or inst.prefix
    out = []
    if os.path.normpath(repository) != os.path.normpath(inst.prefix):
        out.append(repository)
    else:
        out += [os.path.join(repository, f) for f in HOMEBREW_REPOSITORY_FILES
                if os.path.lexists(os.path.join(repository, f))]
    out += [os.path.join(inst.prefix, f) for f in HOMEBREW_PREFIX_FILES
            if os.path.lexists(os.path.join(inst.prefix, f))]
    out += sorted({s.plist for s in services if s.owned and s.instance_prefix == inst.prefix})
    return list(dict.fromkeys(out))


def homebrew_shared_caches(home: str, library: str) -> list[str]:
    """Return the caches and logs that every Homebrew instance of the user shares

    @param home     the user's home directory
    @param library  the system `Library` directory
    @returns        `~/Library/Caches/Homebrew`, `~/Library/Logs/Homebrew`, `<library>/Caches/Homebrew` and
                    `~/.cache/Homebrew`
    """
    return [os.path.join(home, "Library", "Caches", "Homebrew"), os.path.join(home, "Library", "Logs", "Homebrew"),
            os.path.join(library, "Caches", "Homebrew"), os.path.join(home, ".cache", "Homebrew")]


def marker_missing(inst: Instance) -> str | None:
    """Return why nothing under the prefix may be deleted: it lacks its manager's marker files

    @param inst  the named instance
    @returns     the reason, or None when the markers are there
    """
    if inst.manager is Manager.PORTS:
        if not os.path.exists(os.path.join(inst.prefix, "etc", "macports", "macports.conf")):
            return f"{inst.prefix} has no etc/macports/macports.conf, so it does not look like MacPorts"
        return None
    if not (os.path.lexists(os.path.join(inst.prefix, "bin", "brew"))
            or os.path.isdir(os.path.join(inst.prefix, "Cellar"))):
        return f"{inst.prefix} has neither bin/brew nor a Cellar, so it does not look like Homebrew"
    return None


def _note(prefix: str, topic: str, text: str) -> Action:
    """Build a phase 6 note: a manual action that runs nothing

    @param prefix  the named instance's prefix
    @param topic   the last part of the action id
    @param text    what the note says
    @returns       the action `6.note.<prefix slug>.<topic>`
    """
    return Action(action_id=f"6.note.{slug(prefix)}.{topic}", kind="note", argv=[], sudo=False,
                  description=text, manual=True, instance_prefix=prefix)


def _dedicated_notes(inst: Instance, deletes: Sequence[str], target: Instance, home: str) -> list[Action]:
    """Return the notes of what phase 6 deletes last of a dedicated Homebrew prefix: what remains, then the prefix

    `/usr/local`, which other installers share, is never a dedicated prefix: phase 6 only lists what remains there.

    @param inst     the named Homebrew instance, which holds its marker files
    @param deletes  the paths of its delete list
    @param target   the target instance, which the safety rules protect
    @param home     the user's home directory
    @returns        the notes; none at `/usr/local`
    """
    prefix = inst.prefix
    if brew_locate.is_usr_local(prefix):
        return []
    listed = {os.path.normpath(p) for p in deletes}
    try:
        names = sorted(os.listdir(prefix))
    except OSError:
        names = []
    left = [n for n in names if os.path.normpath(os.path.join(prefix, n)) not in listed]
    held = f"; besides the paths above it holds {', '.join(left)} as this plan is made" if left else ""
    out = [_note(prefix, "remaining", f"then `apply` asks again (--yes answers) before it saves in the run folder and "
                 f"deletes whatever is left in {prefix}; a no keeps {prefix} with it{held}")]
    why = unsafe(prefix, target, home)
    out.append(_note(prefix, f"skipped.{slug(prefix)}", f"{prefix} stays: {why}") if why else
               _note(prefix, "prefix", f"then {prefix} itself (rm -d), once nothing is left in it"))
    return out


def _caches_notes(named: Sequence[Instance], survivors: Sequence[Instance], home: str) -> list[Action]:
    """Return the note of the shared Homebrew caches and logs, which phase 6 deletes last when no Homebrew stays

    @param named      the old installations the plan uninstalls
    @param survivors  the instances that stay
    @param home       the user's home directory
    @returns          the note; none while a Homebrew instance stays, or when none of the caches exists
    """
    brews = [i for i in named if i.manager is Manager.BREW]
    present = [p for p in homebrew_shared_caches(home, SYSTEM_LIBRARY) if os.path.lexists(p)]
    if not brews or not present or any(i.manager is Manager.BREW for i in survivors):
        return []
    return [_note(brews[0].prefix, "caches", "last, when no Homebrew is left on this Mac, the caches and logs that all "
                  f"Homebrew installations share are deleted, without a saved copy: {', '.join(present)}")]


def phase6(named: Sequence[Instance], target: Instance, services: Sequence[Service], environ: dict[str, str],
           survivors: Sequence[Instance]) -> list[Action]:
    """Return manual previews of phase 6 for every old installation the plan uninstalls

    They show the archives, the deletions and the paths the safety rules refuse as they stand at plan time,
    then what goes last: a dedicated Homebrew prefix's remaining entries and the prefix, and the shared Homebrew
    caches; `apply` recomputes every action of this phase. The planner names no installation that lacks its
    manager's marker files, which `apply` would leave whole.

    @param named      the old installations the plan uninstalls
    @param target     the target instance, which the safety rules protect
    @param services   the scan's services
    @param environ    the environment, for `HOME`
    @param survivors  the instances that stay
    @returns          the preview actions, all manual
    """
    home = environ.get("HOME") or os.path.expanduser("~")
    out: list[Action] = []
    for inst in named:
        brew = inst.manager is Manager.BREW
        out.append(_note(inst.prefix, "checks", f"first `apply` checks that no package is left in {inst.prefix}, that "
                         "no running program uses it, and that the disk has room for the saved copies plus 1 GiB"))
        archives = homebrew_archive_list(inst) if brew else macports_archive_list(inst, home)
        for path in archives:
            out.append(Action(action_id=f"6.archive.{slug(path)}", kind="command",
                              argv=[TAR, "-czf", "-", "-C", "/", path.lstrip("/")], sudo=True,
                              description=f"save {path} in the run folder as data-archive/{slug(path)}.tar.gz",
                              manual=True, instance_prefix=inst.prefix))
        if brew:
            out.append(_note(inst.prefix, "repository", "Homebrew's own repository is saved in the run folder too when "
                             "git shows local changes in it (status, local commits, stash)"))
            deletes = homebrew_delete_list(inst, services)
        else:
            others = any(i.manager is Manager.PORTS and i.prefix != inst.prefix for i in survivors)
            deletes = macports_delete_list(inst, home, services, others)
            if not others:
                out.append(_note(inst.prefix, "macports-user", "the macports user and group are deleted first when "
                                 f"their home lies under {inst.prefix}"))
        for path in deletes:
            why = unsafe(path, target, home)
            if why:
                out.append(_note(inst.prefix, f"skipped.{slug(path)}", f"{path} stays: {why}"))
                continue
            sudo = not brew or not os.access(os.path.dirname(path) or "/", os.W_OK)
            out.append(Action(action_id=f"6.delete.{slug(path)}", kind="command", argv=[RM, "-rf", path],
                              sudo=sudo, description=f"delete {path}", manual=True, instance_prefix=inst.prefix))
        if brew:
            out.append(_note(inst.prefix, "links", "then every link under %s/{bin,sbin,lib,include,share,etc,opt,"
                             "Frameworks} into its Cellar, Caskroom or opt, /etc/paths.d/homebrew when it names only "
                             "%s/bin, and the Applications links into the Cellar" % (inst.prefix, inst.prefix)))
            out += _dedicated_notes(inst, deletes, target, home)
        jobs = [s for s in services if not s.owned and s.instance_prefix == inst.prefix]
        for svc in jobs:
            out.append(_note(inst.prefix, f"job.{slug(svc.plist)}",
                             f"will stop working: {svc.plist} runs {svc.program or inst.prefix}; edit or remove it by "
                             "hand (phase 6 stops while it runs)"))
    return out + _caches_notes(named, survivors, home)


# Assembly ------------------------------------------------------------------------------------------

def assemble(phase2_actions: list[Action], phase3_actions: list[Action], phase6_actions: list[Action],
             remove: bool) -> list[Phase]:
    """Return phases 0 to 8, with phase 6 only when the plan uninstalls an old installation

    `apply` computes the phases without actions.

    @param phase2_actions  the repairs of the target
    @param phase3_actions  the installs, upgrades, marks and rebuilds
    @param phase6_actions  the manual previews of the removals
    @param remove          whether the plan uninstalls an old installation
    @returns               the phases, with the ones that ask first marked `confirm`
    """
    actions = {2: phase2_actions, 3: phase3_actions, 6: phase6_actions}
    return [Phase(number=n, name=PHASE_NAMES[n], actions=list(actions.get(n, [])), confirm=n in (1, 2, 3, 5, 6, 7))
            for n in range(9) if n != 6 or remove]


def phase_name(plan: Plan, number: int) -> str:
    """Return the name of a phase as the plan report and the run print it, in lower case

    @param plan    the plan
    @param number  the phase number
    @returns       the name; phase 3 of a plan that upgrades more than the replacements need says so
    """
    if number == 3 and (plan.optional_upgrades or plan.optional_casks):
        return PHASE_3_ALL
    return PHASE_NAMES.get(number, "")


def refresh_actions(target: Instance, host_arch: str) -> list[Action]:
    """Return the actions of `plan --refresh`: `brew update`, or `sudo port -N sync` for a MacPorts target

    @param target     the target instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @returns          the one action
    """
    if target.manager is Manager.BREW:
        return [brew_actions.update(target, host_arch, f"0.brew.{slug(target.prefix)}.update")]
    return [mp_actions.sync(target, host_arch, f"0.ports.{slug(target.prefix)}.sync")]
